//! End-to-end tests: full engine wiring from inputs through the persistent
//! queue to real network outputs.

use softnix_log_agent::config;
use softnix_log_agent::engine::Engine;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;

async fn wait_for<F: Fn() -> bool>(cond: F, secs: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    cond()
}

/// File input -> pipeline (transform/enrich) -> TCP syslog output.
#[tokio::test]
async fn file_to_tcp_syslog_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("app.log");
    std::fs::write(&log_path, "").unwrap();

    // Fake syslog server collecting received bytes.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(String::new()));
    {
        let received = received.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let received = received.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        received
                            .lock()
                            .await
                            .push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                });
            }
        });
    }

    let yaml = format!(
        r#"
agent:
  data_dir: {data}
inputs:
  files:
    - id: app
      paths: ["{glob}"]
      poll_interval_ms: 100
      read_from_start: true
pipeline:
  transforms:
    - type: add_field
      field: env
      value: testing
  enrich:
    environment: e2e
outputs:
  - id: collector
    type: syslog
    protocol: tcp
    address: 127.0.0.1:{port}
    format: json
    retry:
      initial_backoff_ms: 100
      batch_size: 50
"#,
        data = dir.path().join("data").display(),
        glob = log_path.display(),
        port = sink_addr.port(),
    );
    let (cfg, _w) = config::parse(&yaml).unwrap();
    let engine = Engine::start(cfg).await.unwrap();

    std::fs::write(&log_path, "first event\nsecond event\n").unwrap();

    let got = {
        let received = received.clone();
        wait_for(
            move || {
                let s = received.try_lock().map(|g| g.clone()).unwrap_or_default();
                s.contains("first event") && s.contains("second event")
            },
            10,
        )
        .await
    };
    assert!(got, "events did not arrive at TCP sink");

    let text = received.lock().await.clone();
    let first_line = text.lines().next().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(first_line).unwrap();
    assert_eq!(parsed["fields"]["env"], "testing");
    assert_eq!(parsed["fields"]["environment"], "e2e");
    assert_eq!(parsed["source_type"], "file");

    assert_eq!(
        engine.shared.metrics.snapshot().events_sent,
        2,
        "expected exactly 2 sent events"
    );
    engine.stop().await;
}

/// UDP syslog input -> queue survives an engine restart -> delivered after
/// the destination comes back (outage simulation).
#[tokio::test]
async fn syslog_in_queue_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    // Reserve ports: UDP listener port for input, TCP port for output.
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let in_port = probe.local_addr().unwrap().port();
    drop(probe);
    let out_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let out_port = out_listener.local_addr().unwrap().port();
    drop(out_listener); // destination is DOWN initially

    let yaml = format!(
        r#"
agent:
  data_dir: {data}
inputs:
  syslog:
    - id: net
      protocol: udp
      bind: 127.0.0.1
      port: {in_port}
outputs:
  - id: fwd
    type: syslog
    protocol: tcp
    address: 127.0.0.1:{out_port}
    format: rfc5424
    retry:
      initial_backoff_ms: 100
      max_backoff_ms: 300
"#,
        data = dir.path().join("data").display(),
    );
    let (cfg, _) = config::parse(&yaml).unwrap();

    // Phase 1: receive events while destination is down; they must queue.
    let engine = Engine::start(cfg.clone()).await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(
            "<14>Jun 10 10:00:00 h1 app: outage event".as_bytes(),
            ("127.0.0.1", in_port),
        )
        .await
        .unwrap();

    let queues = engine.shared.queues.clone();
    assert!(
        wait_for(
            move || queues.get("fwd").map(|q| !q.is_empty()).unwrap_or(false),
            5
        )
        .await,
        "event was not queued during outage"
    );
    engine.stop().await; // simulated restart with data on disk

    // Phase 2: destination comes back; restart engine; queued event flows.
    let listener = TcpListener::bind(("127.0.0.1", out_port)).await.unwrap();
    let received = Arc::new(Mutex::new(String::new()));
    {
        let received = received.clone();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 4096];
            while let Ok(n) = sock.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                received
                    .lock()
                    .await
                    .push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
    }

    let engine = Engine::start(cfg).await.unwrap();
    let got = {
        let received = received.clone();
        wait_for(
            move || {
                received
                    .try_lock()
                    .map(|g| g.contains("outage event"))
                    .unwrap_or(false)
            },
            10,
        )
        .await
    };
    assert!(got, "queued event was not delivered after restart");
    let text = received.lock().await.clone();
    assert!(
        text.starts_with("<14>1 "),
        "expected RFC5424 framing: {text}"
    );
    engine.stop().await;
}

/// Conditional routing: events fan out to matching destinations only.
#[tokio::test]
async fn conditional_routing_to_multiple_destinations() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("app.log");
    std::fs::write(&log_path, "").unwrap();

    async fn sink() -> (std::net::SocketAddr, Arc<Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let data = Arc::new(Mutex::new(String::new()));
        let d = data.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let d = d.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        d.lock().await.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                });
            }
        });
        (addr, data)
    }

    let (all_addr, all_data) = sink().await;
    let (err_addr, err_data) = sink().await;

    let yaml = format!(
        r#"
agent:
  data_dir: {data}
inputs:
  files:
    - id: app
      paths: ["{glob}"]
      poll_interval_ms: 100
      read_from_start: true
      parser:
        mode: json
outputs:
  - id: everything
    type: syslog
    protocol: tcp
    address: 127.0.0.1:{all_port}
    format: raw
    retry: {{ initial_backoff_ms: 100 }}
  - id: errors_only
    type: syslog
    protocol: tcp
    address: 127.0.0.1:{err_port}
    format: raw
    when: {{ field: severity, op: lt, value: 4 }}
    retry: {{ initial_backoff_ms: 100 }}
"#,
        data = dir.path().join("data").display(),
        glob = log_path.display(),
        all_port = all_addr.port(),
        err_port = err_addr.port(),
    );
    let (cfg, _) = config::parse(&yaml).unwrap();
    let engine = Engine::start(cfg).await.unwrap();

    std::fs::write(
        &log_path,
        "{\"level\":\"info\",\"msg\":\"routine info\"}\n{\"level\":\"error\",\"msg\":\"bad failure\"}\n",
    )
    .unwrap();

    let ok = {
        let all = all_data.clone();
        let err = err_data.clone();
        wait_for(
            move || {
                let a = all.try_lock().map(|g| g.clone()).unwrap_or_default();
                let e = err.try_lock().map(|g| g.clone()).unwrap_or_default();
                a.contains("routine info") && a.contains("bad failure") && e.contains("bad failure")
            },
            10,
        )
        .await
    };
    assert!(ok, "routing did not deliver expected events");
    let err_text = err_data.lock().await.clone();
    assert!(
        !err_text.contains("routine info"),
        "info event leaked into errors_only destination"
    );
    engine.stop().await;
}

/// C-3 regression guard: a destination whose queue backs up must not stall
/// delivery to a healthy sibling destination. Before the per-destination
/// router split, a single pipeline task routed to every destination
/// sequentially, so a stuck destination stalled the healthy one too - and
/// eventually every input.
#[tokio::test]
async fn a_backed_up_destination_does_not_stop_its_peers() {
    // Destination A has a 2 MiB queue (split into 1 MiB segments) and a TCP
    // peer that accepts but never reads, so its queue fills and stays full.
    // Destination B is a UDP peer we read from. B must keep receiving.
    //
    // Queue must span more than one segment: with max_size_mb == segment_size_mb
    // (a single, never-rolling segment), `DiskQueue` can reach a state where
    // every record in that segment gets acked (count reaches 0) without the
    // segment ever being deleted (only segments strictly behind the write
    // segment are reclaimed) - `bytes` then stays pinned just under the cap
    // forever, `is_full()` reports false (it short-circuits on count == 0),
    // and `push()` simultaneously keeps rejecting everything as `Full`. That
    // wedge is a pre-existing `DiskQueue` accounting quirk, not something this
    // test means to exercise - giving the queue room to roll across several
    // segments avoids it.
    let dir = tempfile::tempdir().unwrap();

    let stuck = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stuck_port = stuck.local_addr().unwrap().port();
    tokio::spawn(async move {
        // Accept and hold, never read.
        let mut held = Vec::new();
        while let Ok((s, _)) = stuck.accept().await {
            held.push(s);
        }
    });

    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sink_port = sink.local_addr().unwrap().port();

    let in_port = {
        let l = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };

    let yaml = format!(
        r#"
agent:
  data_dir: {data}
buffer:
  max_size_mb: 2
  segment_size_mb: 1
inputs:
  syslog:
    - id: in
      protocol: udp
      bind: 127.0.0.1
      port: {in_port}
outputs:
  - id: stuck
    type: syslog
    protocol: tcp
    address: 127.0.0.1:{stuck_port}
    full_policy: block
  - id: healthy
    type: syslog
    protocol: udp
    address: 127.0.0.1:{sink_port}
    # drop_oldest so the healthy destination's own 2 MiB queue (it shares
    # `buffer.max_size_mb` with "stuck" - there is no per-output size
    # override) never itself blocks under the same flood of filler events;
    # otherwise the test would conflate "healthy self-throttling on its own
    # queue" with the isolation property actually under test. UDP delivery is
    # near-instant, so in practice this destination is never really behind -
    # this only guards the test's own filler flood.
    full_policy: drop_oldest
web:
  enabled: false
"#,
        data = dir.path().display(),
        in_port = in_port,
        stuck_port = stuck_port,
        sink_port = sink_port,
    );
    let (cfg, _w) = softnix_log_agent::config::parse(&yaml).unwrap();
    let engine = softnix_log_agent::engine::Engine::start(cfg).await.unwrap();

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Phase 1: flood "stuck" past the point where it can possibly still be
    // absorbing events unimpeded, so its router genuinely parks in
    // `push_blocking` on a full disk queue. Rather than guessing a single
    // fixed volume up front (fragile: the OS's UDP receive buffer - a few
    // hundred KB - drops an unpredictable, host- and scheduling-dependent
    // fraction of a single burst before the agent ever sees it, so a count
    // picked on one host/run can silently stop being enough on another), keep
    // sending small batches and polling `is_full()` between them until it
    // actually reports full (or a generous deadline elapses). Polling in
    // between batches also gives the input listener and the engine's
    // internal tasks scheduling turns to actually drain and process what has
    // been sent so far.
    // R-2 note: `raw_message` is no longer duplicated onto every event (it's
    // opt-in via `keep_raw_message`), so each filler record now takes roughly
    // half the disk-queue bytes it used to for the same line - reaching the
    // queue's 2 MiB cap needs about twice as many successfully-delivered
    // filler events as before. The line can't simply get bigger to
    // compensate (UDP datagrams over loopback cap out around 9216 bytes on
    // this OS, well below double `padding`'s size), so the deadline below is
    // widened instead to give the retry loop enough room under lossy UDP.
    let padding = "x".repeat(8192);
    let mut filler_sent = 0usize;
    let fill_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !engine.shared.queues["stuck"].is_full() && tokio::time::Instant::now() < fill_deadline {
        for _ in 0..200 {
            let line = format!("<14>Jun 10 10:00:00 h1 app: filler {filler_sent} {padding}");
            client
                .send_to(line.as_bytes(), ("127.0.0.1", in_port))
                .await
                .unwrap();
            filler_sent += 1;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Confirm the filler actually achieved its purpose before relying on it:
    // if it never did, the assertion below would pass under both this fix AND
    // the (hypothetical) still-broken pre-fix code, defeating this test's
    // purpose as a regression guard. Fail loudly instead if the precondition
    // wasn't met.
    assert!(
        engine.shared.queues["stuck"].is_full(),
        "precondition not met: \"stuck\" destination's disk queue never became full \
         after sending {filler_sent} filler events, so this test cannot actually \
         exercise the isolation property it claims to guard (kernel socket buffers \
         on this host may be absorbing more of the filler than expected)"
    );

    // Phase 2: with "stuck" now genuinely backed up, send events that only
    // the healthy destination should keep receiving. Under the pre-fix
    // blocking `tx.send`, the fan-out loop in `route_event` stalls forever on
    // the full "stuck" channel and none of these ever reach the healthy
    // sink - this is exactly the C-3 bug re-appearing one layer up. Under the
    // fix (`try_send`), "stuck" sheds the marker events it can't accept and
    // "healthy" keeps flowing untouched.
    const MARKERS: usize = 50;
    for i in 0..MARKERS {
        let line = format!("<14>Jun 10 10:00:00 h1 app: MARKER {i}");
        client
            .send_to(line.as_bytes(), ("127.0.0.1", in_port))
            .await
            .unwrap();
    }

    let mut buf = vec![0u8; 65535];
    let mut markers_received = 0;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline && markers_received < MARKERS {
        if let Ok(Ok((n, _))) = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            sink.recv_from(&mut buf),
        )
        .await
        {
            if n > 0 && buf[..n].windows(6).any(|w| w == b"MARKER") {
                markers_received += 1;
            }
        }
    }
    engine.stop().await;
    assert!(
        markers_received >= MARKERS / 2,
        "healthy destination only got {markers_received}/{MARKERS} marker events sent \
         after the stuck destination backed up"
    );
}

/// A partial `Engine::start` failure must not leak any already-spawned task:
/// the successfully-bound listener from an earlier input must be torn down
/// when a later input fails to bind, so ports are free for the next attempt.
#[tokio::test]
async fn failed_start_releases_bound_ports() {
    use softnix_log_agent::config::Config;
    use softnix_log_agent::engine::Engine;

    let dir = tempfile::tempdir().unwrap();
    // Bind a port first so the agent's second listener is guaranteed to fail.
    let squatter = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let taken = squatter.local_addr().unwrap().port();
    let free = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };

    // Input 1 binds `free` successfully; input 2 then fails on `taken`.
    let yaml = format!(
        r#"
agent:
  data_dir: {data}
inputs:
  syslog:
    - id: ok
      protocol: tcp
      bind: 127.0.0.1
      port: {free}
    - id: doomed
      protocol: tcp
      bind: 127.0.0.1
      port: {taken}
outputs:
  - id: out
    type: stdout
web:
  enabled: false
"#,
        data = dir.path().display(),
        free = free,
        taken = taken,
    );
    let (cfg, _warnings): (Config, Vec<String>) =
        softnix_log_agent::config::parse(&yaml).expect("config must parse");

    assert!(
        Engine::start(cfg).await.is_err(),
        "start must fail on the taken port"
    );

    // The successfully-bound listener from input 1 must have been torn down.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        tokio::net::TcpListener::bind(("127.0.0.1", free))
            .await
            .is_ok(),
        "port {free} is still held by a leaked listener task"
    );
}
