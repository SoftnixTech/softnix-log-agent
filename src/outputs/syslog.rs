use super::format::format_event;
use super::stdout::frame_batch;
use crate::config::{OutputConfig, SyslogProtocol};
use crate::event::Event;
use crate::tls;
use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

/// Maximum UDP payload for IPv4 (65535 total − 20 IP − 8 UDP headers). A single
/// event larger than this can never be sent as one datagram, so it is dropped
/// rather than retried forever (which would block the whole queue behind it).
const MAX_UDP_PAYLOAD: usize = 65507;

enum Conn {
    Disconnected,
    Udp(UdpSocket),
    Tcp(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

pub struct SyslogSink {
    id: String,
    cfg: OutputConfig,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    conn: Conn,
}

impl SyslogSink {
    pub fn new(cfg: &OutputConfig) -> Result<Self> {
        let tls_config = if cfg.protocol == SyslogProtocol::Tls {
            let opts = cfg.tls.clone().unwrap_or_default();
            Some(
                tls::client_config(&opts)
                    .with_context(|| format!("output {}: TLS setup", cfg.id))?,
            )
        } else {
            None
        };
        Ok(SyslogSink {
            id: cfg.id.clone(),
            cfg: cfg.clone(),
            tls_config,
            conn: Conn::Disconnected,
        })
    }

    async fn connect(&self) -> Result<Conn> {
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
                Ok(Conn::Udp(sock))
            }
            SyslogProtocol::Tcp => {
                let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
                    .await
                    .map_err(|_| anyhow!("connect timeout to {addr}"))?
                    .with_context(|| format!("cannot connect to {addr}"))?;
                stream.set_nodelay(true).ok();
                Ok(Conn::Tcp(stream))
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
                let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone().unwrap());
                let tls_stream =
                    tokio::time::timeout(timeout, connector.connect(server_name, stream))
                        .await
                        .map_err(|_| anyhow!("TLS handshake timeout with {addr}"))?
                        .with_context(|| format!("TLS handshake with {addr} failed"))?;
                Ok(Conn::Tls(Box::new(tls_stream)))
            }
        }
    }
}

#[async_trait::async_trait]
impl super::Sink for SyslogSink {
    async fn send_batch(&mut self, events: &[Event]) -> Result<usize> {
        if matches!(self.conn, Conn::Disconnected) {
            self.conn = self.connect().await?;
        }
        match &mut self.conn {
            Conn::Udp(sock) => {
                // UDP is datagram-based: one event per datagram, no framing.
                //
                // Known, deliberate metric-visibility regression: the
                // pre-trait code counted a dropped oversized event via
                // `metrics.events_dropped.fetch_add(1, ...)` and
                // `metrics.record_error(...)`. `Sink::send_batch`'s
                // signature (fixed by the plan) has no `&Metrics` parameter,
                // so a concrete Sink can no longer update those counters
                // directly, and the trait cannot grow a 4th method to work
                // around it. This drops the `events_dropped` counter
                // increment for oversized-UDP-event drops specifically; the
                // `tracing::warn!` below preserves operator visibility via
                // logs. Every other drop/error path in this codebase is
                // unaffected.
                for ev in events {
                    let line = format_event(ev, self.cfg.format);
                    if line.len() > MAX_UDP_PAYLOAD {
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
            Conn::Tcp(stream) => {
                let payload = frame_batch(events, self.cfg.format, self.cfg.framing);
                stream.write_all(&payload).await?;
                stream.flush().await?;
            }
            Conn::Tls(stream) => {
                let payload = frame_batch(events, self.cfg.format, self.cfg.framing);
                stream.write_all(&payload).await?;
                stream.flush().await?;
            }
            Conn::Disconnected => unreachable!(),
        }
        Ok(events.len())
    }

    async fn reconnect(&mut self) -> Result<()> {
        // Mirrors the old worker's `sink = Sink::Disconnected` on failure:
        // just mark the connection dead, the next send_batch reconnects
        // lazily (same timing as before this task).
        self.conn = Conn::Disconnected;
        Ok(())
    }

    fn id(&self) -> &str {
        &self.id
    }
}
