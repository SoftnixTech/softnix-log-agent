# Architecture

## Component overview

```
                ┌──────────────────────────────────────────────────────────┐
                │                        Engine                            │
 files ───────▶│ FileInput ──┐                                            │
 (glob/poll)   │             │   mpsc channel    ┌─ DiskQueue A ─▶ OutputWorker A ─▶ syslog TLS
 udp/tcp/tls ─▶│ SyslogInput ┼──────────────────▶│ Pipeline      ├─ DiskQueue B ─▶ OutputWorker B ─▶ syslog TCP
                │             │  (bounded, 8192)  │ transform     └─ DiskQueue C ─▶ OutputWorker C ─▶ stdout
                │             │                   │ enrich/route  │
                └─────────────┴───────────────────┴───────────────┘
                       ▲                ▲                 ▲
                  StateManager      Metrics +        cursor.json +
                  (state.json)    StatusRegistry     *.seg files
                       │
        ┌──────────────┴──────────────┐
        │  main control loop          │  ◀── signals (SIGTERM/SIGHUP/Ctrl-C)
        │  (reload / rollback)        │  ◀── ControlMsg from Web API
        └──────────────┬──────────────┘
                       │
                 Web server (axum, outside the engine, survives reloads)
```

Modules map 1:1 to the suggested component list:

| Component | Module |
|---|---|
| Config Manager | `src/config.rs` |
| State Manager | `src/state.rs` |
| File Tailer | `src/inputs/file.rs` |
| Syslog Receiver | `src/inputs/syslog.rs` |
| Parser / Transform / Normalize / Enrich engines | `src/pipeline.rs` |
| Routing Engine | `src/engine.rs` (`route_event`) |
| Persistent Queue | `src/buffer.rs` |
| Output Manager | `src/outputs.rs` |
| Metrics + Health | `src/metrics.rs`, `/healthz`, `/metrics` |
| Web UI Server | `src/web.rs` + `src/ui.html` |
| Service Manager | `src/service.rs` |
| TLS | `src/tls.rs` |

## Key design decisions

**Rust + Tokio, 2 worker threads.** Async fits the workload (many idle sockets and timers, bursty IO). The runtime is capped at two worker threads to keep CPU/memory predictable on endpoints; throughput is IO-bound, not CPU-bound.

**Restartable engine = config reload.** All inputs/pipeline/outputs live inside an `Engine` value built purely from a `Config`. Reload = validate new config → stop engine → start new engine; if the new engine fails to start (e.g. port conflict), the previous config file is restored from backup and the old engine is restarted. The web server lives *outside* the engine so the GUI stays available during/after a failed reload. This is dramatically simpler and safer than incremental hot-reconfiguration, at the cost of a sub-second pipeline gap (queues are durable, file offsets persist — nothing buffered is lost).

**Per-destination persistent queue (segmented log).** Each destination has its own directory of append-only segment files (`[len][crc32][json]` records, 8 MB segments by default). The pipeline appends; the output worker *peeks* a batch, sends, then *acks*, which advances a persisted cursor (`cursor.json`) and deletes fully-consumed segments. A crash before ack ⇒ the batch is re-sent ⇒ at-least-once. Torn tail records are truncated on startup; CRC failures stop the reader at the bad record. Full-queue policies: `block` (backpressure into the bounded channel and ultimately the inputs), `drop_oldest` (delete oldest segment), `drop_newest`.

**Polling file tailer, identity-keyed offsets.** Polling (default 500 ms) was chosen over inotify/ReadDirectoryChangesW deliberately: identical semantics on both platforms, no watch-descriptor leaks, robust against network filesystems and editor quirks, and discovery + change detection in a single mechanism. Cost is negligible at endpoint scale. Offsets are keyed by `(input_id, file identity)` where identity = device:inode on Unix and creation time on Windows, which makes rename-rotation and recreation detectable; truncation is detected by `size < offset`. Offsets only advance past complete lines, so partially written lines are never emitted or skipped.

**Normalization is the schema, not a stage.** Every parser emits the same `Event` struct (timestamp, hostname, source, source_type, severity, facility, application, process_id, message, raw_message, collector_version, received_at + extensible `fields` map), so downstream stages and outputs are parser-agnostic.

**Routing decides per destination at enqueue time.** Each output may declare a `when` condition and/or `failover_for: <primary>`; a standby destination only receives events while its primary is unhealthy (3+ consecutive send failures). Because each destination has its own durable queue, events already queued to a recovering primary are still delivered — no loss, possible overlap, consistent with at-least-once.

**rustls (ring) everywhere.** One TLS stack for listeners and clients, mTLS both directions, no OpenSSL system dependency — simplifies cross-compilation and keeps the binary self-contained. Verification-off mode exists but is explicit and logged as a warning.

**Web GUI: one embedded HTML file.** No frontend framework, no build step, no websockets — plain `fetch` + 3 s polling against tiny JSON endpoints. The page is `include_str!`-ed into the binary. This keeps the GUI cost near zero and the attack surface small; auth is an optional bearer token, and binding beyond localhost produces a logged security warning.

**State writes are atomic and lazy.** `state.json` (file cursors) is written via tmp-file + rename, flushed every 5 s and on shutdown; queue cursors are written per ack. Worst-case crash window: a few seconds of file-offset progress (re-read ⇒ duplicates, not loss) and one un-acked batch per destination.
