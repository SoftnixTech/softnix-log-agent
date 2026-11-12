//! Syslog receiver: UDP, TCP and TLS listeners with RFC3164/RFC5424/JSON/raw
//! parsing. Stream transports accept newline and octet-counted framing (RFC 6587).

use crate::config::{parse_ip_net, InputFraming, SyslogInputConfig, SyslogProtocol};
use crate::engine::EventSender;
use crate::event::Event;
use crate::metrics::{InputStatus, Metrics, StatusRegistry};
use crate::pipeline::parse_syslog_into;
use crate::tls;
use anyhow::{Context, Result};
use bytes::{Buf, BytesMut};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio_stream::StreamExt;
use tokio_util::codec::{Decoder, FramedRead};
use tokio_util::sync::CancellationToken;

const MAX_MSG: usize = 64 * 1024;

/// Longest MSG-LEN the decoder reads. Six digits cover `MAX_MSG` (65536).
const MAX_LEN_DIGITS: usize = 6;

/// What the start of the buffer says about RFC 6587 octet-counting.
enum OctetHeader {
    /// `MSG-LEN SP` is complete: `header_len` bytes of header, then a
    /// message of `msg_len` bytes.
    Frame { header_len: usize, msg_len: usize },
    /// Still a possible header prefix (such as `12`); more bytes decide.
    Undecided,
    /// Not an octet-counting header.
    No,
}

/// Read `MSG-LEN SP` at the start of `buf` (which must not be empty).
/// MSG-LEN is 1 to `MAX_LEN_DIGITS` ASCII digits with no leading zero. With
/// `need_msg_start`, the byte after the space must also be `<` (a syslog
/// PRI) or `{` (JSON): that is what tells a real header from a plain-text
/// line that happens to begin with a number, such as `200 OK`.
fn octet_header(buf: &[u8], need_msg_start: bool) -> OctetHeader {
    let digits = buf
        .iter()
        .take(MAX_LEN_DIGITS + 1)
        .take_while(|b| b.is_ascii_digit())
        .count();
    if digits == 0 || digits > MAX_LEN_DIGITS || buf[0] == b'0' {
        return OctetHeader::No;
    }
    match buf.get(digits) {
        None => return OctetHeader::Undecided,
        Some(b' ') => {}
        Some(_) => return OctetHeader::No,
    }
    if need_msg_start {
        match buf.get(digits + 1) {
            None => return OctetHeader::Undecided,
            Some(b'<' | b'{') => {}
            Some(_) => return OctetHeader::No,
        }
    }
    let msg_len = buf[..digits]
        .iter()
        .fold(0usize, |n, d| n * 10 + usize::from(d - b'0'));
    OctetHeader::Frame {
        header_len: digits + 1,
        msg_len,
    }
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn too_long(len: usize, max: usize) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("syslog frame of {len} bytes exceeds the {max}-byte limit"),
    )
}

/// Frame decoder for the TCP/TLS input (RFC 6587): octet-counted frames
/// (`MSG-LEN SP MSG`, §3.4.1) and newline-terminated lines (§3.4.2), detected
/// per frame in `auto` mode so both can share one connection.
///
/// Unlike `LinesCodec`, which this replaces, invalid UTF-8 is decoded lossily
/// (as the UDP path does) instead of ending the connection, so one
/// legacy-encoded byte cannot drop everything still buffered behind it.
struct SyslogFrameCodec {
    mode: InputFraming,
    max: usize,
    /// How much of the pending newline frame was already searched for `\n`.
    scanned: usize,
}

impl SyslogFrameCodec {
    fn new(mode: InputFraming, max: usize) -> Self {
        Self {
            mode,
            max,
            scanned: 0,
        }
    }

    fn header(&self, buf: &[u8]) -> OctetHeader {
        match self.mode {
            InputFraming::Newline => OctetHeader::No,
            InputFraming::Auto => octet_header(buf, true),
            InputFraming::OctetCounting => octet_header(buf, false),
        }
    }

    /// One newline-terminated line, without its `\n` and one trailing `\r`.
    /// A line longer than `max` is an error, as with `LinesCodec`.
    fn decode_line(&mut self, buf: &mut BytesMut) -> std::io::Result<Option<String>> {
        let from = self.scanned.min(buf.len());
        match buf[from..].iter().position(|b| *b == b'\n') {
            Some(off) => {
                let end = from + off;
                self.scanned = 0;
                if end > self.max {
                    return Err(too_long(end, self.max));
                }
                let line = buf.split_to(end + 1);
                let line = &line[..end];
                Ok(Some(lossy(line.strip_suffix(b"\r").unwrap_or(line))))
            }
            None if buf.len() > self.max => Err(too_long(buf.len(), self.max)),
            None => {
                self.scanned = buf.len();
                Ok(None)
            }
        }
    }
}

impl Decoder for SyslogFrameCodec {
    type Item = String;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> std::io::Result<Option<String>> {
        // Between frames, skip CR/LF: an empty line, or the LF some senders
        // add after an octet-counted frame.
        if self.scanned == 0 {
            let skip = buf
                .iter()
                .take_while(|b| matches!(**b, b'\r' | b'\n'))
                .count();
            buf.advance(skip);
        }
        if buf.is_empty() {
            return Ok(None);
        }
        match self.header(buf) {
            OctetHeader::Frame {
                header_len,
                msg_len,
            } => {
                if msg_len > self.max {
                    return Err(too_long(msg_len, self.max));
                }
                let total = header_len + msg_len;
                if buf.len() < total {
                    buf.reserve(total - buf.len());
                    return Ok(None);
                }
                buf.advance(header_len);
                Ok(Some(lossy(&buf.split_to(msg_len))))
            }
            OctetHeader::Undecided => Ok(None),
            OctetHeader::No if self.mode == InputFraming::OctetCounting => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed octet-counting header (expected `MSG-LEN SP`)",
                ))
            }
            OctetHeader::No => self.decode_line(buf),
        }
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> std::io::Result<Option<String>> {
        if let Some(frame) = self.decode(buf)? {
            return Ok(Some(frame));
        }
        if buf.is_empty() {
            return Ok(None);
        }
        // What is left is a frame the sender never finished.
        let truncated_octet = match self.header(buf) {
            OctetHeader::Frame { .. } => true,
            OctetHeader::Undecided => self.mode == InputFraming::OctetCounting,
            OctetHeader::No => false,
        };
        self.scanned = 0;
        let rest = buf.split_to(buf.len());
        if truncated_octet {
            // Not a valid message: drop it rather than deliver a partial event.
            tracing::debug!(
                "syslog: dropping a truncated octet-counted frame ({} bytes) at end of stream",
                rest.len()
            );
            return Ok(None);
        }
        // A last line without its `\n` (or a lone header prefix such as
        // `12 `) is delivered, as `LinesCodec` did.
        let line = rest.strip_suffix(b"\r").unwrap_or(&rest);
        Ok(Some(lossy(line)))
    }
}

/// Log a rejection (allowlist or connection-cap) at most once every 100
/// occurrences per `counter`, mirroring the shedding-log idiom already used
/// for the router's per-destination backpressure counters (see
/// `engine::route`) — visible without letting a scanner fill the log buffer.
///
/// On the same throttled tick, also surface the rejection to `status` (as
/// `last_error`) so a misconfigured allowlist or an undersized
/// `max_connections` doesn't silently drop traffic while `/api/status`
/// keeps reporting the input as healthy — mirroring the existing UDP
/// receive-error path below, which reports to both `metrics` and `status`.
/// Gated on the same throttle as the log line (rather than firing on every
/// rejection) to avoid taking the status-registry lock on every packet from
/// a flood.
fn log_rejection_rate_limited(
    counter: &AtomicU64,
    id: &str,
    peer: IpAddr,
    reason: &str,
    status: &StatusRegistry,
) {
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if n % 100 == 1 {
        tracing::warn!(
            input = %id,
            peer = %peer,
            rejected_total = n,
            "syslog {reason} (logged every 100th occurrence)"
        );
        status.update_input(id, |s| s.last_error = Some(format!("{n} {reason}")));
    }
}

/// Canonicalize an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its
/// underlying `IpAddr::V4` before allowlist matching.
///
/// `ipnet::IpNet::contains` returns `false` on any IP-family mismatch
/// (`IpNet::V4` vs an `IpAddr::V6`). On a dual-stack listener (`bind: "::"`,
/// the common Linux default with `net.ipv6.bindv6only=0`), an IPv4 client's
/// peer address arrives as an IPv4-mapped IPv6 address rather than a plain
/// `IpAddr::V4` — so without this, an `allowed_senders` entry like
/// `10.0.0.0/8` would never match, silently rejecting every IPv4 sender.
fn canonicalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

pub struct SyslogInput {
    cfg: SyslogInputConfig,
    source_type: String,
    allowed_senders: Vec<IpNet>,
    rejected_by_allowlist: AtomicU64,
    rejected_over_cap: AtomicU64,
}

impl SyslogInput {
    pub fn new(cfg: &SyslogInputConfig) -> Self {
        // `config::validate` already rejects unparsable entries before an
        // input is ever spawned, so `filter_map` here is just defensive
        // (e.g. against a `SyslogInput` built directly in a test without
        // going through validation) rather than a silent-failure path in
        // production use.
        let allowed_senders = cfg
            .allowed_senders
            .iter()
            .filter_map(|s| parse_ip_net(s).ok())
            .collect();
        SyslogInput {
            source_type: cfg
                .source_type
                .clone()
                .unwrap_or_else(|| "syslog".to_string()),
            cfg: cfg.clone(),
            allowed_senders,
            rejected_by_allowlist: AtomicU64::new(0),
            rejected_over_cap: AtomicU64::new(0),
        }
    }

    /// Empty `allowed_senders` preserves today's behavior: allow everyone.
    fn sender_allowed(&self, ip: IpAddr) -> bool {
        let ip = canonicalize(ip);
        self.allowed_senders.is_empty() || self.allowed_senders.iter().any(|n| n.contains(&ip))
    }

    /// Bind and spawn the listener. Binding happens here so configuration
    /// errors (port in use, bad certs) fail engine startup.
    pub async fn spawn(
        self,
        tx: EventSender,
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
        tx: EventSender,
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
                            if !self.sender_allowed(peer.ip()) {
                                // Counted for every rejected datagram (cheap
                                // atomic increment), unlike the throttled
                                // log/status below — matches how
                                // `events_dropped` is used elsewhere for
                                // "received but not processed" accounting.
                                metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                                log_rejection_rate_limited(
                                    &self.rejected_by_allowlist,
                                    &self.cfg.id,
                                    peer.ip(),
                                    "datagrams rejected: sender not in allowed_senders",
                                    &status,
                                );
                                continue;
                            }
                            let text = String::from_utf8_lossy(&buf[..n]);
                            // RFC 5426 §3.1: one syslog message per datagram.
                            // Do not split on LF: a multi-line message (a
                            // Windows event) is still one event.
                            let line = text.trim();
                            if line.is_empty() { continue; }
                            let ev = self.make_event(line, &peer);
                            metrics.events_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            status.update_input(&self.cfg.id, |s| s.events += 1);
                            if tx.send(ev).await.is_err() { return; }
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
        tx: EventSender,
        status: Arc<StatusRegistry>,
        metrics: Arc<Metrics>,
        cancel: CancellationToken,
    ) {
        let me = Arc::new(self);
        // Sized once from config, not per-accept: caps concurrently open
        // TCP/TLS connections so an unauthenticated remote party opening
        // many idle connections cannot exhaust the process's file
        // descriptor limit and starve legitimate senders (and the agent's
        // own outbound connections).
        let limit = Arc::new(Semaphore::new(me.cfg.max_connections));
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

                    if !me.sender_allowed(peer.ip()) {
                        // A rejected CONNECTION isn't the same unit as a
                        // rejected EVENT, so (unlike the UDP datagram path)
                        // this doesn't touch `metrics.events_dropped` — the
                        // throttled status/log signal below is the intended
                        // observability surface here.
                        log_rejection_rate_limited(
                            &me.rejected_by_allowlist,
                            &me.cfg.id,
                            peer.ip(),
                            "connections rejected: sender not in allowed_senders",
                            &status,
                        );
                        continue; // `stream` dropped here => connection closed, no task spawned
                    }

                    let permit = match limit.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            log_rejection_rate_limited(
                                &me.rejected_over_cap,
                                &me.cfg.id,
                                peer.ip(),
                                "connections rejected: over max_connections limit",
                                &status,
                            );
                            continue; // `stream` dropped here => connection closed, no task spawned
                        }
                    };

                    let me = me.clone();
                    let tx = tx.clone();
                    let status = status.clone();
                    let metrics = metrics.clone();
                    let cancel = cancel.clone();
                    let acceptor = acceptor.clone();
                    let handshake_timeout = Duration::from_secs(me.cfg.handshake_timeout_secs);
                    tokio::spawn(async move {
                        // Held for the connection's whole lifetime and released
                        // automatically when this task ends (clean close, read
                        // error, idle timeout or cancellation) — no explicit
                        // release needed.
                        let _permit = permit;
                        let result = match acceptor {
                            Some(acc) => match tokio::time::timeout(handshake_timeout, acc.accept(stream)).await {
                                Ok(Ok(tls_stream)) => {
                                    me.read_stream(tls_stream, peer, tx, &status, &metrics, cancel).await
                                }
                                Ok(Err(e)) => {
                                    tracing::debug!("syslog {}: TLS handshake from {peer} failed: {e}", me.cfg.id);
                                    Ok(())
                                }
                                Err(_elapsed) => {
                                    // Handshake didn't complete in time: don't
                                    // hold the permit/fd on a stalled peer.
                                    tracing::debug!(
                                        "syslog {}: TLS handshake from {peer} timed out after {handshake_timeout:?}",
                                        me.cfg.id
                                    );
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
        tx: EventSender,
        status: &StatusRegistry,
        metrics: &Metrics,
        cancel: CancellationToken,
    ) -> Result<()> {
        let mut frames = FramedRead::new(stream, SyslogFrameCodec::new(self.cfg.framing, MAX_MSG));
        // Slowloris guard: a peer that opens the connection and then sends
        // (or reads) nothing must not hold the connection-limit slot and its
        // file descriptor forever.
        let idle_timeout = Duration::from_secs(self.cfg.idle_timeout_secs);
        loop {
            tokio::select! {
                frame = tokio::time::timeout(idle_timeout, frames.next()) => {
                    match frame {
                        Ok(Some(Ok(line))) => {
                            let line = line.trim();
                            if line.is_empty() { continue; }
                            let ev = self.make_event(line, &peer);
                            metrics.events_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            status.update_input(&self.cfg.id, |s| s.events += 1);
                            if tx.send(ev).await.is_err() { return Ok(()); }
                        }
                        Ok(Some(Err(e))) => return Err(e.into()),
                        Ok(None) => return Ok(()),
                        Err(_elapsed) => {
                            tracing::debug!(
                                "syslog {}: connection {peer} idle for {idle_timeout:?}, closing",
                                self.cfg.id
                            );
                            return Ok(());
                        }
                    }
                }
                _ = cancel.cancelled() => return Ok(()),
            }
        }
    }

    fn make_event(&self, line: &str, peer: &SocketAddr) -> Event {
        let mut ev = Event::new(
            &format!("{}:{}", self.cfg.id, peer.ip()),
            &self.source_type,
            line,
        );
        // `message` and `raw_message` genuinely differ for syslog (PRI,
        // timestamp, hostname and tag are stripped from `message`), so
        // capture the original wire line before parsing when asked to.
        if self.cfg.keep_raw_message {
            ev.preserve_raw(line);
        }
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
    use tokio::sync::mpsc;

    fn test_cfg(proto: SyslogProtocol, port: u16) -> SyslogInputConfig {
        SyslogInputConfig {
            id: "test".into(),
            protocol: proto,
            bind: "127.0.0.1".into(),
            port,
            format: SyslogFormat::Auto,
            framing: InputFraming::Auto,
            tls: None,
            source_type: None,
            keep_raw_message: false,
            max_connections: 512,
            idle_timeout_secs: 300,
            handshake_timeout_secs: 10,
            allowed_senders: Vec::new(),
        }
    }

    fn test_cfg_keep_raw(proto: SyslogProtocol, port: u16) -> SyslogInputConfig {
        SyslogInputConfig {
            keep_raw_message: true,
            ..test_cfg(proto, port)
        }
    }

    #[test]
    fn sender_allowed_allows_everyone_when_list_is_empty() {
        let input = SyslogInput::new(&test_cfg(SyslogProtocol::Udp, 0));
        assert!(input.sender_allowed("203.0.113.9".parse().unwrap()));
        assert!(input.sender_allowed("::1".parse().unwrap()));
    }

    #[test]
    fn sender_allowed_matches_cidrs_and_bare_ips() {
        let mut cfg = test_cfg(SyslogProtocol::Udp, 0);
        cfg.allowed_senders = vec!["10.0.0.0/8".to_string(), "192.168.1.5".to_string()];
        let input = SyslogInput::new(&cfg);

        assert!(input.sender_allowed("10.1.2.3".parse().unwrap()));
        assert!(input.sender_allowed("192.168.1.5".parse().unwrap()));
        assert!(!input.sender_allowed("192.168.1.6".parse().unwrap()));
        assert!(!input.sender_allowed("203.0.113.9".parse().unwrap()));
    }

    /// H-5 fix round 1: on a dual-stack listener (`bind: "::"`), an IPv4
    /// sender's peer address arrives as an IPv4-mapped IPv6 address
    /// (`::ffff:10.1.2.3`), not a plain `IpAddr::V4`. Without canonicalizing
    /// it first, `ipnet::IpNet::contains` would return `false` on the
    /// family mismatch and silently reject every IPv4 sender even though
    /// `10.0.0.0/8` is in `allowed_senders` — this would have failed before
    /// the `canonicalize` fix.
    #[test]
    fn sender_allowed_canonicalizes_ipv4_mapped_ipv6() {
        let mut cfg = test_cfg(SyslogProtocol::Udp, 0);
        cfg.allowed_senders = vec!["10.0.0.0/8".to_string()];
        let input = SyslogInput::new(&cfg);

        let mapped: std::net::Ipv4Addr = "10.1.2.3".parse().unwrap();
        let mapped = IpAddr::V6(mapped.to_ipv6_mapped());
        assert!(input.sender_allowed(mapped));

        // A mapped address outside the allowlisted range must still be
        // rejected — canonicalizing must not widen the match.
        let not_mapped: std::net::Ipv4Addr = "203.0.113.9".parse().unwrap();
        let not_mapped = IpAddr::V6(not_mapped.to_ipv6_mapped());
        assert!(!input.sender_allowed(not_mapped));
    }

    #[tokio::test]
    async fn udp_drops_datagrams_from_disallowed_senders() {
        let mut cfg = test_cfg(SyslogProtocol::Udp, 0);
        // 127.0.0.1 (loopback, what the test client sends from) is not in
        // this range, so the datagram must be dropped before parsing.
        cfg.allowed_senders = vec!["203.0.113.0/24".to_string()];
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let input = SyslogInput::new(&cfg);
        let (raw_tx, mut rx) = mpsc::channel(16);
        let tx = EventSender::with_budget(raw_tx, 16 * 1024 * 1024);
        let status = Arc::new(StatusRegistry::default());
        status.set_input(InputStatus {
            id: "test".into(),
            ..Default::default()
        });
        let metrics = Arc::new(Metrics::default());
        let cancel = CancellationToken::new();
        tokio::spawn(input.run_udp(sock, tx, status, metrics, cancel.clone()));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(b"<13>Jun 10 12:00:00 host1 app[7]: should be dropped", addr)
            .await
            .unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await;
        assert!(
            result.is_err(),
            "datagram from a disallowed sender must not produce an event"
        );
        cancel.cancel();
    }

    #[tokio::test]
    async fn tcp_closes_connections_from_disallowed_senders_without_processing() {
        let mut cfg = test_cfg(SyslogProtocol::Tcp, 0);
        cfg.allowed_senders = vec!["203.0.113.0/24".to_string()];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let input = SyslogInput::new(&cfg);
        let (raw_tx, mut rx) = mpsc::channel(16);
        let tx = EventSender::with_budget(raw_tx, 16 * 1024 * 1024);
        let status = Arc::new(StatusRegistry::default());
        status.set_input(InputStatus {
            id: "test".into(),
            ..Default::default()
        });
        let metrics = Arc::new(Metrics::default());
        let cancel = CancellationToken::new();
        tokio::spawn(input.run_tcp(listener, None, tx, status, metrics, cancel.clone()));

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Actually send a real, valid syslog line before checking for
        // closure/no-event: otherwise "no event received" is vacuous (a
        // connection nothing was ever written to also produces no event,
        // rejected or not). The server already dropped the stream at
        // accept-time without spawning a reader, so this write may itself
        // fail (broken pipe/reset) if the peer has already reset the
        // connection — that failure is expected and consistent with
        // rejection, not a test bug, so it's intentionally not unwrapped.
        let _ = conn
            .write_all(b"<13>Jun 10 12:00:00 host1 app[7]: should never be processed\n")
            .await;
        // The server drops the stream without reading it, so depending on
        // the platform the client sees either a clean EOF (n == 0) or a
        // reset (the dropped socket had unread/unflushed data pending) —
        // both mean "closed without being served".
        let mut buf = [0u8; 1];
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), conn.read(&mut buf))
            .await
            .expect("disallowed connection should be closed promptly, not held");
        match result {
            Ok(n) => assert_eq!(n, 0, "expected EOF on the rejected connection"),
            Err(e) => assert_eq!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset,
                "unexpected error closing rejected connection: {e}"
            ),
        }

        let result = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
        assert!(
            result.is_err(),
            "no event should be produced for a disallowed sender"
        );
        cancel.cancel();
    }

    #[tokio::test]
    async fn tcp_enforces_max_connections() {
        let mut cfg = test_cfg(SyslogProtocol::Tcp, 0);
        cfg.max_connections = 2;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let input = SyslogInput::new(&cfg);
        let (raw_tx, _rx) = mpsc::channel(16);
        let tx = EventSender::with_budget(raw_tx, 16 * 1024 * 1024);
        let status = Arc::new(StatusRegistry::default());
        status.set_input(InputStatus {
            id: "test".into(),
            ..Default::default()
        });
        let metrics = Arc::new(Metrics::default());
        let cancel = CancellationToken::new();
        tokio::spawn(input.run_tcp(listener, None, tx, status, metrics, cancel.clone()));

        // Fill both connection slots and hold them open.
        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(tokio::net::TcpStream::connect(addr).await.unwrap());
        }
        // Give the acceptor loop a moment to admit both.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        use tokio::io::AsyncReadExt;
        // The third connection is accepted at the TCP layer (backlog) but
        // must be closed immediately by the cap rather than served.
        let mut third = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), third.read(&mut buf))
            .await
            .expect("over-cap connection should be closed, not held")
            .unwrap();
        assert_eq!(n, 0, "expected EOF on the over-cap connection");

        drop(held);
        cancel.cancel();
    }

    #[tokio::test]
    async fn tcp_closes_idle_connections_after_the_configured_timeout() {
        let mut cfg = test_cfg(SyslogProtocol::Tcp, 0);
        cfg.idle_timeout_secs = 1;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let input = SyslogInput::new(&cfg);
        let (raw_tx, _rx) = mpsc::channel(16);
        let tx = EventSender::with_budget(raw_tx, 16 * 1024 * 1024);
        let status = Arc::new(StatusRegistry::default());
        status.set_input(InputStatus {
            id: "test".into(),
            ..Default::default()
        });
        let metrics = Arc::new(Metrics::default());
        let cancel = CancellationToken::new();
        tokio::spawn(input.run_tcp(listener, None, tx, status, metrics, cancel.clone()));

        use tokio::io::AsyncReadExt;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Send nothing at all: the server must close after ~1s of silence
        // rather than holding the connection (and its fd) forever.
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), conn.read(&mut buf))
            .await
            .expect("idle connection should be closed once idle_timeout_secs elapses")
            .unwrap();
        assert_eq!(n, 0, "expected EOF once the idle timeout elapses");
        cancel.cancel();
    }

    #[tokio::test]
    async fn udp_receives_rfc3164() {
        let cfg = test_cfg(SyslogProtocol::Udp, 0);
        // Bind manually on port 0 to get an ephemeral port.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let input = SyslogInput::new(&cfg);
        let (raw_tx, mut rx) = mpsc::channel(16);
        let tx = EventSender::with_budget(raw_tx, 16 * 1024 * 1024);
        let status = Arc::new(StatusRegistry::default());
        status.set_input(InputStatus {
            id: "test".into(),
            ..Default::default()
        });
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

    /// Start a UDP input on an ephemeral port; returns where to send and the
    /// channel its events arrive on.
    async fn start_udp() -> (SocketAddr, mpsc::Receiver<Event>, CancellationToken) {
        let cfg = test_cfg(SyslogProtocol::Udp, 0);
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let input = SyslogInput::new(&cfg);
        let (raw_tx, rx) = mpsc::channel(16);
        let tx = EventSender::with_budget(raw_tx, 16 * 1024 * 1024);
        let status = Arc::new(StatusRegistry::default());
        status.set_input(InputStatus {
            id: "test".into(),
            ..Default::default()
        });
        let metrics = Arc::new(Metrics::default());
        let cancel = CancellationToken::new();
        tokio::spawn(input.run_udp(sock, tx, status, metrics, cancel.clone()));
        (addr, rx, cancel)
    }

    /// RFC 5426 says one syslog message per datagram, so a multi-line
    /// message (a Windows event) must arrive as one event, not one per line.
    #[tokio::test]
    async fn udp_datagram_is_one_event() {
        let (addr, mut rx, cancel) = start_udp().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(
                b"<13>Jun 10 12:00:00 host1 app[7]: line one\r\nline two\r\nline three",
                addr,
            )
            .await
            .unwrap();

        let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ev.message, "line one\r\nline two\r\nline three");
        assert!(
            tokio::time::timeout(Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "the datagram was split into several events"
        );
        cancel.cancel();
    }

    #[tokio::test]
    async fn udp_trailing_newline_still_one_event() {
        let (addr, mut rx, cancel) = start_udp().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(b"<13>Jun 10 12:00:00 host1 app[7]: hello\n", addr)
            .await
            .unwrap();

        let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ev.message, "hello");
        assert!(
            tokio::time::timeout(Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "a trailing newline must not produce a second, empty event"
        );
        cancel.cancel();
    }

    #[tokio::test]
    async fn tcp_receives_lines() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let input = SyslogInput::new(&test_cfg(SyslogProtocol::Tcp, 0));
        let (raw_tx, mut rx) = mpsc::channel(16);
        let tx = EventSender::with_budget(raw_tx, 16 * 1024 * 1024);
        let status = Arc::new(StatusRegistry::default());
        status.set_input(InputStatus {
            id: "test".into(),
            ..Default::default()
        });
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

    /// Octet-counted frames are delivered one event per frame while
    /// the connection is still open, and a line break inside a frame stays.
    #[tokio::test]
    async fn tcp_receives_octet_counted_frames() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let input = SyslogInput::new(&test_cfg(SyslogProtocol::Tcp, 0));
        let (raw_tx, mut rx) = mpsc::channel(16);
        let tx = EventSender::with_budget(raw_tx, 16 * 1024 * 1024);
        let status = Arc::new(StatusRegistry::default());
        status.set_input(InputStatus {
            id: "test".into(),
            ..Default::default()
        });
        let metrics = Arc::new(Metrics::default());
        let cancel = CancellationToken::new();
        tokio::spawn(input.run_tcp(listener, None, tx, status, metrics, cancel.clone()));

        let mut payload = Vec::new();
        for msg in ["first", "line a\r\nline b", "third"] {
            let frame = format!("<165>1 2026-06-10T22:14:15Z h1 app 1 - - {msg}");
            payload.extend_from_slice(format!("{} {frame}", frame.len()).as_bytes());
        }
        use tokio::io::AsyncWriteExt;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(&payload).await.unwrap();
        conn.flush().await.unwrap();

        // `conn` stays open: every event must arrive without waiting for EOF.
        for want in ["first", "line a\r\nline b", "third"] {
            let ev = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                .await
                .expect("an octet-counted frame must be delivered before the sender closes")
                .unwrap();
            assert_eq!(ev.message, want);
            assert_eq!(ev.application.as_deref(), Some("app"));
        }
        drop(conn);
        cancel.cancel();
    }

    /// `framing: octet_counting` on the input carries payloads that
    /// `auto` cannot detect, because they do not start with `<` or `{` (the
    /// agent's own `format: raw` output is one).
    #[tokio::test]
    async fn tcp_explicit_octet_counting_receives_raw_payloads() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut cfg = test_cfg(SyslogProtocol::Tcp, 0);
        cfg.framing = InputFraming::OctetCounting;
        cfg.format = SyslogFormat::Raw;
        let input = SyslogInput::new(&cfg);
        let (raw_tx, mut rx) = mpsc::channel(16);
        let tx = EventSender::with_budget(raw_tx, 16 * 1024 * 1024);
        let status = Arc::new(StatusRegistry::default());
        status.set_input(InputStatus {
            id: "test".into(),
            ..Default::default()
        });
        let metrics = Arc::new(Metrics::default());
        let cancel = CancellationToken::new();
        tokio::spawn(input.run_tcp(listener, None, tx, status, metrics, cancel.clone()));

        use tokio::io::AsyncWriteExt;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"5 hello9 two\nlines").await.unwrap();
        conn.flush().await.unwrap();

        for want in ["hello", "two\nlines"] {
            let ev = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                .await
                .expect("a raw octet-counted frame must be delivered before the sender closes")
                .unwrap();
            assert_eq!(ev.message, want);
        }
        drop(conn);
        cancel.cancel();
    }

    fn codec(mode: InputFraming) -> SyslogFrameCodec {
        SyslogFrameCodec::new(mode, MAX_MSG)
    }

    /// Decode until the codec asks for more bytes.
    fn decode_all(c: &mut SyslogFrameCodec, buf: &mut BytesMut) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(frame) = c.decode(buf).unwrap() {
            out.push(frame);
        }
        out
    }

    #[test]
    fn octet_frames_decode_one_per_frame() {
        let mut buf = BytesMut::from(&b"12 <14>1 a b\r\nc5 <1>xy"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["<14>1 a b\r\nc", "<1>xy"]
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn octet_frame_split_across_reads() {
        let mut c = codec(InputFraming::Auto);
        let mut buf = BytesMut::from(&b"1"[..]);
        assert_eq!(c.decode(&mut buf).unwrap(), None);
        buf.extend_from_slice(b"2 <14>1");
        assert_eq!(c.decode(&mut buf).unwrap(), None);
        buf.extend_from_slice(b" a b\r\nc");
        assert_eq!(
            c.decode(&mut buf).unwrap().as_deref(),
            Some("<14>1 a b\r\nc")
        );
        assert_eq!(c.decode(&mut buf).unwrap(), None);
    }

    #[test]
    fn mixed_frames_on_one_connection() {
        let mut buf = BytesMut::from(&b"<13>line one\n5 <1>xy<13>line two\n"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["<13>line one", "<1>xy", "<13>line two"]
        );
    }

    #[test]
    fn newline_line_starting_with_digits_stays_a_line() {
        let mut buf = BytesMut::from(&b"200 OK fine\n"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["200 OK fine"]
        );
    }

    #[test]
    fn crlf_line_ending_is_stripped() {
        let mut buf = BytesMut::from(&b"<13>dos line\r\n"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["<13>dos line"]
        );
    }

    #[test]
    fn octet_frame_too_long_is_an_error() {
        let mut buf = BytesMut::from(&b"70000 <14>1 x"[..]);
        assert!(codec(InputFraming::Auto).decode(&mut buf).is_err());
    }

    #[test]
    fn invalid_utf8_is_decoded_lossily() {
        let mut buf = BytesMut::from(&b"<13>caf\xff one\n10 <13>caf\xff 2"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["<13>caf\u{fffd} one", "<13>caf\u{fffd} 2"]
        );
    }

    #[test]
    fn explicit_octet_counting_accepts_raw_payload() {
        let mut buf = BytesMut::from(&b"5 hello"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::OctetCounting), &mut buf),
            ["hello"]
        );
        // The same bytes in `auto` are a line: no `<` or `{` after the header.
        let mut buf = BytesMut::from(&b"5 hello\n"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["5 hello"]
        );
    }

    #[test]
    fn explicit_octet_counting_rejects_bad_header() {
        let mut buf = BytesMut::from(&b"hello\n"[..]);
        assert!(codec(InputFraming::OctetCounting).decode(&mut buf).is_err());
    }

    #[test]
    fn explicit_newline_mode_is_linescodec() {
        let mut buf = BytesMut::from(&b"12 <14>1 a b\n"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Newline), &mut buf),
            ["12 <14>1 a b"]
        );
    }

    #[test]
    fn partial_header_waits_then_decides() {
        let mut c = codec(InputFraming::Auto);
        let mut buf = BytesMut::from(&b"12"[..]);
        assert_eq!(c.decode(&mut buf).unwrap(), None);
        buf.extend_from_slice(b" ");
        assert_eq!(c.decode(&mut buf).unwrap(), None);
        buf.extend_from_slice(b"OK\n");
        assert_eq!(c.decode(&mut buf).unwrap().as_deref(), Some("12 OK"));
    }

    #[test]
    fn trailing_lf_after_octet_frame_is_skipped() {
        let mut buf = BytesMut::from(&b"5 <1>xy\n5 <1>zz"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["<1>xy", "<1>zz"]
        );
    }

    #[test]
    fn newline_line_too_long_is_an_error() {
        let mut c = codec(InputFraming::Auto);
        // Exactly MAX_MSG bytes with no `\n` yet may still grow into a line...
        let mut buf = BytesMut::from(&vec![b'x'; MAX_MSG][..]);
        assert_eq!(c.decode(&mut buf).unwrap(), None);
        // ...one more byte may not.
        buf.extend_from_slice(b"x");
        assert!(c.decode(&mut buf).is_err());
    }

    #[test]
    fn eof_drops_incomplete_octet_frame() {
        let mut buf = BytesMut::from(&b"12 <14>1 a"[..]);
        assert_eq!(
            codec(InputFraming::Auto).decode_eof(&mut buf).unwrap(),
            None
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn eof_returns_pending_line_and_undecided_prefix() {
        let mut c = codec(InputFraming::Auto);
        let mut buf = BytesMut::from(&b"last line"[..]);
        assert_eq!(
            c.decode_eof(&mut buf).unwrap().as_deref(),
            Some("last line")
        );
        assert_eq!(c.decode_eof(&mut buf).unwrap(), None);

        let mut buf = BytesMut::from(&b"12 "[..]);
        assert_eq!(c.decode_eof(&mut buf).unwrap().as_deref(), Some("12 "));
    }

    #[test]
    fn make_event_preserves_raw_message_when_enabled() {
        let cfg = test_cfg_keep_raw(SyslogProtocol::Udp, 0);
        let input = SyslogInput::new(&cfg);
        let peer: SocketAddr = "127.0.0.1:514".parse().unwrap();
        let line = "<13>Jun 10 12:00:00 host1 app[7]: hello udp";

        let ev = input.make_event(line, &peer);

        assert_eq!(ev.message, "hello udp");
        assert_eq!(ev.raw_message.as_deref(), Some(line));
        assert_ne!(ev.raw_message.as_deref(), Some(ev.message.as_str()));
    }

    #[test]
    fn make_event_omits_raw_message_by_default() {
        let cfg = test_cfg(SyslogProtocol::Udp, 0);
        let input = SyslogInput::new(&cfg);
        let peer: SocketAddr = "127.0.0.1:514".parse().unwrap();
        let line = "<13>Jun 10 12:00:00 host1 app[7]: hello udp";

        let ev = input.make_event(line, &peer);

        assert_eq!(ev.message, "hello udp");
        assert!(ev.raw_message.is_none());
    }
}
