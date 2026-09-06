# Testing guide

## Automated tests

```bash
cargo test            # unit + integration (116 tests: 110 unit + 6 integration)
```

**Unit tests** (in-module):

- `config` — sample parsing, env-var expansion (`${VAR}`, `${VAR:-default}`, missing-var error), duplicate-id rejection, unknown-field rejection, public-bind security warning.
- `buffer` — push/peek/ack roundtrip, redelivery after failed send (`reset_peek`), crash recovery across reopen, `drop_newest`/`drop_oldest` full policies, multi-segment rollover.
- `inputs::file` — tailing with partial-line handling, rename rotation, copy-truncate rotation, exclude patterns, offset resume across restart.
- `inputs::syslog` — live UDP datagram parsing (RFC3164), live TCP newline framing (RFC5424 + raw).
- `pipeline` — RFC3164/RFC5424/JSON/KV/regex parsers, severity mapping, transforms (add/rename/mask/drop), type conversion, enrichment.
- `state`, `event`, `outputs` — cursor persistence, field accessors, RFC5424/RFC3164/JSON output formatting.

**Integration tests** (`tests/e2e.rs`, real sockets and real disk queues):

1. `file_to_tcp_syslog_end_to_end` — file write → tail → transform/enrich → persistent queue → TCP syslog sink; asserts content, enrichment fields and exact sent count.
2. `syslog_in_queue_survives_restart` — UDP syslog ingest while the destination is **down**, engine stop ("crash"), destination comes up, engine restart → the queued event is delivered in RFC5424 format. Covers disk buffering, retry, queue recovery and state survival.
3. `conditional_routing_to_multiple_destinations` — JSON-parsed events fan out to an "everything" destination while only `severity < 4` reaches the errors destination.
4. `a_backed_up_destination_does_not_stop_its_peers` — one destination's on-disk queue is driven genuinely full behind a TCP peer that accepts but never reads, while a second, healthy UDP destination keeps receiving events the whole time; guards the non-blocking per-destination fan-out (a full destination sheds its own events instead of stalling the router for every other destination).
5. `failed_start_releases_bound_ports` — a config with two inputs where the first bind succeeds and the second fails (port already taken) must fail `Engine::start` as a whole *and* release the first, already-bound listener, so the port is free again immediately after; guards against a partial-start task leak.
6. `syslog_tcp_enforces_the_connection_cap` — opening far more TCP connections than `max_connections` must not exhaust file descriptors: connections past the cap are accepted at the TCP layer but closed immediately by the agent rather than served.

## Manual smoke test

```bash
cargo build --release
mkdir -p /tmp/smoke/demo && cd /tmp/smoke
cp <repo>/examples/minimal.yaml agent.yaml
<repo>/target/release/softnix-log-agent run --config agent.yaml &

echo "hello"                       >> demo/app.log     # → JSON on stdout
mv demo/app.log demo/app.log.1; echo "fresh" >> demo/app.log   # rotation
printf '<13>Jun 10 12:00:00 h app: hi' | nc -u -w1 127.0.0.1 5514  # if syslog input configured

curl -s localhost:8080/healthz
curl -s -H "Authorization: Bearer $(cat /tmp/smoke/data/web-token)" localhost:8080/metrics   # needs the auth token; /healthz stays public
open http://127.0.0.1:8080        # GUI: all seven pages
```

Outage drill: point an output at a closed port, push events, watch Buffer page grow, then start a listener (`nc -l <port>`) and watch the queue drain.

Reload drill: edit config in the GUI → Validate → Save & Reload; then break it on purpose (e.g. occupied port) → Reload → confirm the error is reported and the agent keeps running on the previous config.

Resource check (expect <20 MB RSS, ~0% idle CPU):

```bash
ps -o rss,pcpu -p $(pgrep -f softnix-log-agent)
```

## CI recommendation

`cargo test` on `ubuntu-latest` and `windows-latest`, plus `cargo build --release --target x86_64-unknown-linux-musl`. Tests use ephemeral ports and tempdirs only — safe for parallel CI.

## Checking the Windows-only code from macOS or Linux

`src/inputs/eventlog.rs` is behind `#[cfg(windows)]`, so a normal
`cargo check` never compiles it. Before pushing a change that touches it:

```bash
cargo install cargo-zigbuild        # once; also needs zig on PATH
cargo zigbuild --release --target x86_64-pc-windows-gnu
```

This builds the entire crate for Windows in roughly 35 s and reports the same
type errors the CI Windows job would. It is a pre-flight, not a replacement:
`-gnu` is not `-msvc`, and the 8 eventlog unit tests only run in CI's
`test-windows` job.
