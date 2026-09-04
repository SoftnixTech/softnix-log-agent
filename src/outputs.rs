//! Output workers: one task per destination, reading from that destination's
//! persistent queue with batch send, retry/backoff and health tracking.

use crate::buffer::DiskQueue;
use crate::config::{Framing, OutputConfig, OutputFormat, OutputKind, SyslogProtocol};
use crate::event::{severity_name, Event};
use crate::metrics::{Metrics, OutputStatus, StatusRegistry};
use crate::tls;
use anyhow::{anyhow, Context, Result};
use chrono::SecondsFormat;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

/// A destination becomes unhealthy after this many consecutive failures
/// (used for failover routing decisions).
const UNHEALTHY_AFTER: u64 = 3;

/// Maximum UDP payload for IPv4 (65535 total − 20 IP − 8 UDP headers). A single
/// event larger than this can never be sent as one datagram, so it is dropped
/// rather than retried forever (which would block the whole queue behind it).
const MAX_UDP_PAYLOAD: usize = 65507;

enum Sink {
    Stdout,
    Udp(UdpSocket),
    Tcp(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Disconnected,
}

pub struct OutputWorker {
    cfg: OutputConfig,
    queue: Arc<DiskQueue>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
}

impl OutputWorker {
    pub fn new(cfg: &OutputConfig, queue: Arc<DiskQueue>) -> Result<Self> {
        let tls_config = if cfg.kind == OutputKind::Syslog && cfg.protocol == SyslogProtocol::Tls {
            let opts = cfg.tls.clone().unwrap_or_default();
            Some(
                tls::client_config(&opts)
                    .with_context(|| format!("output {}: TLS setup", cfg.id))?,
            )
        } else {
            None
        };
        Ok(OutputWorker {
            cfg: cfg.clone(),
            queue,
            tls_config,
        })
    }

    pub fn spawn(
        self,
        status: Arc<StatusRegistry>,
        metrics: Arc<Metrics>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        status.set_output(OutputStatus {
            id: self.cfg.id.clone(),
            kind: match self.cfg.kind {
                OutputKind::Syslog => format!("syslog/{:?}", self.cfg.protocol).to_lowercase(),
                OutputKind::Stdout => "stdout".to_string(),
            },
            detail: self.cfg.address.clone().unwrap_or_default(),
            healthy: true,
            connected: false,
            events_sent: 0,
            retries: 0,
            consecutive_failures: 0,
            last_error: None,
        });
        tokio::spawn(async move { self.run(status, metrics, cancel).await })
    }

    async fn run(
        self,
        status: Arc<StatusRegistry>,
        metrics: Arc<Metrics>,
        cancel: CancellationToken,
    ) {
        let id = self.cfg.id.clone();
        let mut sink = Sink::Disconnected;
        let mut backoff = self.cfg.retry.initial_backoff_ms;

        loop {
            self.queue.wait_data(&cancel).await;
            if cancel.is_cancelled() {
                // Final drain attempt: send whatever is connected & pending, briefly.
                break;
            }

            let batch = match self.queue.peek_batch(self.cfg.retry.batch_size) {
                Ok(b) if b.is_empty() => continue,
                Ok(b) => b,
                Err(e) => {
                    metrics.record_error(format!("output {id}: queue read: {e}"));
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            match self.send_batch(&mut sink, &batch, &metrics).await {
                Ok(()) => {
                    let n = batch.len() as u64;
                    if let Err(e) = self.queue.ack(n) {
                        metrics.record_error(format!("output {id}: queue ack: {e}"));
                    }
                    metrics
                        .events_sent
                        .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                    backoff = self.cfg.retry.initial_backoff_ms;
                    status.update_output(&id, |s| {
                        s.events_sent += n;
                        s.healthy = true;
                        s.connected = !matches!(sink, Sink::Disconnected);
                        s.consecutive_failures = 0;
                        s.last_error = None;
                    });
                }
                Err(e) => {
                    sink = Sink::Disconnected;
                    self.queue.reset_peek();
                    metrics
                        .events_failed
                        .fetch_add(batch.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    metrics.record_error(format!("output {id}: {e}"));
                    status.update_output(&id, |s| {
                        s.retries += 1;
                        s.consecutive_failures += 1;
                        s.connected = false;
                        s.healthy = s.consecutive_failures < UNHEALTHY_AFTER;
                        s.last_error = Some(e.to_string());
                    });
                    tracing::warn!("output {id}: send failed ({e}); retrying in {backoff}ms");
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_millis(backoff)) => {}
                        _ = cancel.cancelled() => break,
                    }
                    backoff = (backoff * 2).min(self.cfg.retry.max_backoff_ms);
                }
            }
        }

        // Graceful shutdown: one bounded attempt to flush remaining events.
        if let Ok(batch) = self.queue.peek_batch(self.cfg.retry.batch_size) {
            if !batch.is_empty() {
                let flush = self.send_batch(&mut sink, &batch, &metrics);
                if let Ok(Ok(())) =
                    tokio::time::timeout(std::time::Duration::from_secs(3), flush).await
                {
                    let _ = self.queue.ack(batch.len() as u64);
                    metrics
                        .events_sent
                        .fetch_add(batch.len() as u64, std::sync::atomic::Ordering::Relaxed);
                } else {
                    self.queue.reset_peek();
                }
            }
        }
        status.update_output(&id, |s| s.connected = false);
    }

    async fn send_batch(&self, sink: &mut Sink, batch: &[Event], metrics: &Metrics) -> Result<()> {
        if matches!(sink, Sink::Disconnected) {
            *sink = self.connect().await?;
        }
        let mut payload = Vec::with_capacity(batch.len() * 256);
        for ev in batch {
            let line = format_event(ev, self.cfg.format);
            match self.cfg.framing {
                Framing::Newline => {
                    payload.extend_from_slice(line.as_bytes());
                    payload.push(b'\n');
                }
                Framing::OctetCounting => {
                    payload.extend_from_slice(format!("{} ", line.len()).as_bytes());
                    payload.extend_from_slice(line.as_bytes());
                }
            }
        }
        match sink {
            Sink::Stdout => {
                let mut out = tokio::io::stdout();
                out.write_all(&payload).await?;
                out.flush().await?;
            }
            Sink::Udp(sock) => {
                // UDP is datagram-based: one event per datagram, no framing.
                for ev in batch {
                    let line = format_event(ev, self.cfg.format);
                    // An event larger than a single datagram can never be sent;
                    // drop it (counted) so it doesn't wedge the head of the queue
                    // and starve every subsequent event behind it.
                    if line.len() > MAX_UDP_PAYLOAD {
                        metrics
                            .events_dropped
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        metrics.record_error(format!(
                            "output {}: dropped oversized event ({} bytes > {} UDP limit)",
                            self.cfg.id,
                            line.len(),
                            MAX_UDP_PAYLOAD
                        ));
                        tracing::warn!(
                            "output {}: dropped oversized event ({} bytes) — exceeds UDP datagram limit",
                            self.cfg.id,
                            line.len()
                        );
                        continue;
                    }
                    sock.send(line.as_bytes()).await?;
                }
            }
            Sink::Tcp(stream) => {
                stream.write_all(&payload).await?;
                stream.flush().await?;
            }
            Sink::Tls(stream) => {
                stream.write_all(&payload).await?;
                stream.flush().await?;
            }
            Sink::Disconnected => unreachable!(),
        }
        Ok(())
    }

    async fn connect(&self) -> Result<Sink> {
        match self.cfg.kind {
            OutputKind::Stdout => Ok(Sink::Stdout),
            OutputKind::Syslog => {
                let addr = self
                    .cfg
                    .address
                    .as_deref()
                    .ok_or_else(|| anyhow!("missing address"))?;
                let timeout = std::time::Duration::from_secs(10);
                match self.cfg.protocol {
                    SyslogProtocol::Udp => {
                        let sock = UdpSocket::bind("0.0.0.0:0").await?;
                        sock.connect(addr)
                            .await
                            .with_context(|| format!("cannot resolve {addr}"))?;
                        Ok(Sink::Udp(sock))
                    }
                    SyslogProtocol::Tcp => {
                        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
                            .await
                            .map_err(|_| anyhow!("connect timeout to {addr}"))?
                            .with_context(|| format!("cannot connect to {addr}"))?;
                        stream.set_nodelay(true).ok();
                        Ok(Sink::Tcp(stream))
                    }
                    SyslogProtocol::Tls => {
                        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
                            .await
                            .map_err(|_| anyhow!("connect timeout to {addr}"))?
                            .with_context(|| format!("cannot connect to {addr}"))?;
                        stream.set_nodelay(true).ok();
                        let host = self
                            .cfg
                            .tls
                            .as_ref()
                            .and_then(|t| t.server_name.clone())
                            .unwrap_or_else(|| {
                                addr.rsplit_once(':')
                                    .map(|(h, _)| h.to_string())
                                    .unwrap_or_else(|| addr.to_string())
                            });
                        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
                            .map_err(|_| anyhow!("invalid TLS server name {host:?}"))?;
                        let connector =
                            tokio_rustls::TlsConnector::from(self.tls_config.clone().unwrap());
                        let tls_stream =
                            tokio::time::timeout(timeout, connector.connect(server_name, stream))
                                .await
                                .map_err(|_| anyhow!("TLS handshake timeout with {addr}"))?
                                .with_context(|| format!("TLS handshake with {addr} failed"))?;
                        Ok(Sink::Tls(Box::new(tls_stream)))
                    }
                }
            }
        }
    }
}

/// Render an event in the configured wire format.
pub fn format_event(ev: &Event, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string(ev).unwrap_or_else(|_| ev.message.clone()),
        OutputFormat::Raw => ev.message.clone(),
        OutputFormat::Rfc5424 => {
            let pri = pri_of(ev);
            let ts = ev.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true);
            let host = ev.hostname.as_deref().unwrap_or("-");
            let app = ev.application.as_deref().unwrap_or("softnix-log-agent");
            let pid = ev.process_id.as_deref().unwrap_or("-");
            let sd = rfc5424_structured_data(ev);
            format!("<{pri}>1 {ts} {host} {app} {pid} - {sd} {}", ev.message)
        }
        OutputFormat::Rfc3164 => {
            let pri = pri_of(ev);
            let ts = ev.timestamp.format("%b %e %H:%M:%S");
            let host = ev.hostname.as_deref().unwrap_or("-");
            let tag = ev.application.as_deref().unwrap_or("softnix");
            match &ev.process_id {
                Some(pid) => format!("<{pri}>{ts} {host} {tag}[{pid}]: {}", ev.message),
                None => format!("<{pri}>{ts} {host} {tag}: {}", ev.message),
            }
        }
    }
}

/// Build the RFC 5424 STRUCTURED-DATA element from the event's custom fields
/// (enrichment, parsed attributes, etc.). Returns the NILVALUE `-` when there
/// is nothing to emit. Without this, enriched fields such as
/// `environment=production` are silently dropped on the rfc5424 wire format.
fn rfc5424_structured_data(ev: &Event) -> String {
    let mut params = String::new();
    for (key, val) in &ev.fields {
        // `structured_data` holds the original raw SD text from a parsed
        // rfc5424 input; re-wrapping it as a param would be malformed, skip it.
        if key == "structured_data" {
            continue;
        }
        let Some(value) = value_to_param(val) else {
            continue;
        };
        // PARAM-NAME must be a valid SD-NAME (no space, '=', ']', '"').
        if key.is_empty()
            || key
                .chars()
                .any(|c| c == ' ' || c == '=' || c == ']' || c == '"' || (c as u32) < 33)
        {
            continue;
        }
        params.push(' ');
        params.push_str(key);
        params.push_str("=\"");
        params.push_str(&sd_escape(&value));
        params.push('"');
    }
    if params.is_empty() {
        "-".to_string()
    } else {
        format!("[softnix@32473{params}]")
    }
}

/// Render a field value as an SD PARAM-VALUE string. Scalars become their
/// natural text; arrays/objects are JSON-encoded so nothing is lost.
fn value_to_param(val: &serde_json::Value) -> Option<String> {
    use serde_json::Value;
    match val {
        Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        other => Some(other.to_string()),
    }
}

/// Escape the three characters that are special inside an SD PARAM-VALUE per
/// RFC 5424 §6.3.3: '"', '\' and ']'.
fn sd_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '"' || c == '\\' || c == ']' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn pri_of(ev: &Event) -> u8 {
    let facility = ev.facility.unwrap_or(1); // user-level
    let severity = ev.severity.unwrap_or(6); // info
    facility * 8 + severity.min(7)
}

#[allow(dead_code)]
fn severity_label(ev: &Event) -> &'static str {
    severity_name(ev.severity.unwrap_or(6))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5424_format() {
        let mut ev = Event::new("s", "syslog", "hello world");
        ev.hostname = Some("web1".into());
        ev.application = Some("nginx".into());
        ev.severity = Some(4);
        ev.facility = Some(16);
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert!(line.starts_with("<132>1 "));
        assert!(line.contains(" web1 nginx "));
        assert!(line.ends_with("hello world"));
        // No custom fields -> NILVALUE structured data.
        assert!(line.contains(" - - hello world"));
    }

    #[test]
    fn rfc5424_emits_enrichment_as_structured_data() {
        // PIPE-001 regression: enrichment fields must reach the rfc5424 wire,
        // not just json. They belong in the STRUCTURED-DATA element.
        let mut ev = Event::new("s", "syslog", "enrich test line");
        ev.fields.insert(
            "environment".into(),
            serde_json::Value::String("production".into()),
        );
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert!(
            line.contains("[softnix@32473 environment=\"production\"]"),
            "{line}"
        );
        // The SD slot must carry the element, not the NILVALUE, right before msg.
        assert!(
            line.ends_with("[softnix@32473 environment=\"production\"] enrich test line"),
            "{line}"
        );
    }

    #[test]
    fn rfc5424_escapes_and_skips_raw_structured_data() {
        let mut ev = Event::new("s", "syslog", "msg");
        ev.fields.insert(
            "note".into(),
            serde_json::Value::String(r#"a"b]c\d"#.into()),
        );
        // structured_data holds raw parsed SD text and must not be re-wrapped.
        ev.fields.insert(
            "structured_data".into(),
            serde_json::Value::String("[orig x=1]".into()),
        );
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert!(line.contains(r#"note="a\"b\]c\\d""#), "{line}");
        assert!(!line.contains("structured_data="), "{line}");
    }

    #[test]
    fn rfc3164_format() {
        let mut ev = Event::new("s", "syslog", "msg");
        ev.hostname = Some("h".into());
        ev.application = Some("app".into());
        ev.process_id = Some("42".into());
        let line = format_event(&ev, OutputFormat::Rfc3164);
        assert!(line.contains("app[42]: msg"), "{line}");
    }

    #[test]
    fn json_format_roundtrips() {
        let ev = Event::new("s", "file", "data");
        let line = format_event(&ev, OutputFormat::Json);
        let back: Event = serde_json::from_str(&line).unwrap();
        assert_eq!(back.message, "data");
    }
}
