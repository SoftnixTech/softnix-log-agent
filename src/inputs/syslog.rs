//! Syslog receiver: UDP, TCP and TLS listeners with RFC3164/RFC5424/JSON/raw
//! parsing and newline framing for stream transports.

use crate::config::{SyslogInputConfig, SyslogProtocol};
use crate::event::Event;
use crate::metrics::{InputStatus, Metrics, StatusRegistry};
use crate::pipeline::parse_syslog_into;
use crate::tls;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncRead;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};
use tokio_util::sync::CancellationToken;

const MAX_MSG: usize = 64 * 1024;

pub struct SyslogInput {
    cfg: SyslogInputConfig,
    source_type: String,
}

impl SyslogInput {
    pub fn new(cfg: &SyslogInputConfig) -> Self {
        SyslogInput {
            source_type: cfg
                .source_type
                .clone()
                .unwrap_or_else(|| "syslog".to_string()),
            cfg: cfg.clone(),
        }
    }

    /// Bind and spawn the listener. Binding happens here so configuration
    /// errors (port in use, bad certs) fail engine startup.
    pub async fn spawn(
        self,
        tx: mpsc::Sender<Event>,
        status: Arc<StatusRegistry>,
        metrics: Arc<Metrics>,
        cancel: CancellationToken,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let addr: SocketAddr = format!("{}:{}", self.cfg.bind, self.cfg.port)
            .parse()
            .context("invalid bind address")?;
        let id = self.cfg.id.clone();
        status.set_input(InputStatus {
            id: id.clone(),
            kind: format!("syslog/{:?}", self.cfg.protocol).to_lowercase(),
            detail: format!("{addr}"),
            active: true,
            events: 0,
            last_error: None,
        });

        let handle = match self.cfg.protocol {
            SyslogProtocol::Udp => {
                let sock = UdpSocket::bind(addr)
                    .await
                    .with_context(|| format!("cannot bind UDP {addr}"))?;
                tracing::info!("syslog input {id}: listening on udp://{addr}");
                tokio::spawn(self.run_udp(sock, tx, status, metrics, cancel))
            }
            SyslogProtocol::Tcp => {
                let listener = TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("cannot bind TCP {addr}"))?;
                tracing::info!("syslog input {id}: listening on tcp://{addr}");
                tokio::spawn(self.run_tcp(listener, None, tx, status, metrics, cancel))
            }
            SyslogProtocol::Tls => {
                let tls_opts = self
                    .cfg
                    .tls
                    .as_ref()
                    .context("tls protocol requires tls options")?;
                let tls_cfg = tls::server_config(tls_opts)
                    .with_context(|| format!("syslog input {id}: TLS setup failed"))?;
                let listener = TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("cannot bind TLS {addr}"))?;
                tracing::info!("syslog input {id}: listening on tls://{addr}");
                let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
                tokio::spawn(self.run_tcp(listener, Some(acceptor), tx, status, metrics, cancel))
            }
        };
        Ok(handle)
    }

    async fn run_udp(
        self,
        sock: UdpSocket,
        tx: mpsc::Sender<Event>,
        status: Arc<StatusRegistry>,
        metrics: Arc<Metrics>,
        cancel: CancellationToken,
    ) {
        let mut buf = vec![0u8; MAX_MSG];
        loop {
            tokio::select! {
                res = sock.recv_from(&mut buf) => {
                    match res {
                        Ok((n, peer)) => {
                            let text = String::from_utf8_lossy(&buf[..n]);
                            for line in text.lines() {
                                let line = line.trim();
                                if line.is_empty() { continue; }
                                let ev = self.make_event(line, &peer);
                                metrics.events_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                status.update_input(&self.cfg.id, |s| s.events += 1);
                                if tx.send(ev).await.is_err() { return; }
                            }
                        }
                        Err(e) => {
                            let msg = format!("syslog {} udp recv: {e}", self.cfg.id);
                            tracing::warn!("{msg}");
                            metrics.record_error(&msg);
                            status.update_input(&self.cfg.id, |s| s.last_error = Some(e.to_string()));
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
                _ = cancel.cancelled() => {
                    status.update_input(&self.cfg.id, |s| s.active = false);
                    return;
                }
            }
        }
    }

    async fn run_tcp(
        self,
        listener: TcpListener,
        acceptor: Option<tokio_rustls::TlsAcceptor>,
        tx: mpsc::Sender<Event>,
        status: Arc<StatusRegistry>,
        metrics: Arc<Metrics>,
        cancel: CancellationToken,
    ) {
        let me = Arc::new(self);
        loop {
            tokio::select! {
                res = listener.accept() => {
                    let (stream, peer) = match res {
                        Ok(x) => x,
                        Err(e) => {
                            let msg = format!("syslog {} accept: {e}", me.cfg.id);
                            tracing::warn!("{msg}");
                            metrics.record_error(&msg);
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    let me = me.clone();
                    let tx = tx.clone();
                    let status = status.clone();
                    let metrics = metrics.clone();
                    let cancel = cancel.clone();
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let result = match acceptor {
                            Some(acc) => match acc.accept(stream).await {
                                Ok(tls_stream) => {
                                    me.read_stream(tls_stream, peer, tx, &status, &metrics, cancel).await
                                }
                                Err(e) => {
                                    tracing::debug!("syslog {}: TLS handshake from {peer} failed: {e}", me.cfg.id);
                                    Ok(())
                                }
                            },
                            None => me.read_stream(stream, peer, tx, &status, &metrics, cancel).await,
                        };
                        if let Err(e) = result {
                            tracing::debug!("syslog {}: connection {peer} ended: {e}", me.cfg.id);
                        }
                    });
                }
                _ = cancel.cancelled() => {
                    status.update_input(&me.cfg.id, |s| s.active = false);
                    return;
                }
            }
        }
    }

    async fn read_stream<S: AsyncRead + Unpin>(
        &self,
        stream: S,
        peer: SocketAddr,
        tx: mpsc::Sender<Event>,
        status: &StatusRegistry,
        metrics: &Metrics,
        cancel: CancellationToken,
    ) -> Result<()> {
        let mut frames = FramedRead::new(stream, LinesCodec::new_with_max_length(MAX_MSG));
        loop {
            tokio::select! {
                frame = frames.next() => {
                    match frame {
                        Some(Ok(line)) => {
                            let line = line.trim();
                            if line.is_empty() { continue; }
                            let ev = self.make_event(line, &peer);
                            metrics.events_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            status.update_input(&self.cfg.id, |s| s.events += 1);
                            if tx.send(ev).await.is_err() { return Ok(()); }
                        }
                        Some(Err(e)) => return Err(e.into()),
                        None => return Ok(()),
                    }
                }
                _ = cancel.cancelled() => return Ok(()),
            }
        }
    }

    fn make_event(&self, line: &str, peer: &SocketAddr) -> Event {
        let mut ev = Event::new(&format!("{}:{}", self.cfg.id, peer.ip()), &self.source_type, line);
        parse_syslog_into(&mut ev, line, self.cfg.format);
        if ev.hostname.is_none() {
            ev.hostname = Some(peer.ip().to_string());
        }
        ev.fields.insert(
            "remote_addr".to_string(),
            serde_json::Value::String(peer.ip().to_string()),
        );
        ev
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SyslogFormat;

    fn test_cfg(proto: SyslogProtocol, port: u16) -> SyslogInputConfig {
        SyslogInputConfig {
            id: "test".into(),
            protocol: proto,
            bind: "127.0.0.1".into(),
            port,
            format: SyslogFormat::Auto,
            tls: None,
            source_type: None,
        }
    }

    #[tokio::test]
    async fn udp_receives_rfc3164() {
        let cfg = test_cfg(SyslogProtocol::Udp, 0);
        // Bind manually on port 0 to get an ephemeral port.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let input = SyslogInput::new(&cfg);
        let (tx, mut rx) = mpsc::channel(16);
        let status = Arc::new(StatusRegistry::default());
        status.set_input(InputStatus { id: "test".into(), ..Default::default() });
        let metrics = Arc::new(Metrics::default());
        let cancel = CancellationToken::new();
        tokio::spawn(input.run_udp(sock, tx, status, metrics, cancel.clone()));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(b"<13>Jun 10 12:00:00 host1 app[7]: hello udp", addr)
            .await
            .unwrap();

        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ev.message, "hello udp");
        assert_eq!(ev.hostname.as_deref(), Some("host1"));
        assert_eq!(ev.severity, Some(5));
        cancel.cancel();
    }

    #[tokio::test]
    async fn tcp_receives_lines() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let input = SyslogInput::new(&test_cfg(SyslogProtocol::Tcp, 0));
        let (tx, mut rx) = mpsc::channel(16);
        let status = Arc::new(StatusRegistry::default());
        status.set_input(InputStatus { id: "test".into(), ..Default::default() });
        let metrics = Arc::new(Metrics::default());
        let cancel = CancellationToken::new();
        tokio::spawn(input.run_tcp(listener, None, tx, status, metrics, cancel.clone()));

        use tokio::io::AsyncWriteExt;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"<165>1 2026-06-10T22:14:15Z h1 app 1 - - tcp line one\nraw second line\n")
            .await
            .unwrap();
        conn.flush().await.unwrap();

        let e1 = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(e1.message, "tcp line one");
        let e2 = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(e2.message, "raw second line");
        cancel.cancel();
    }
}
