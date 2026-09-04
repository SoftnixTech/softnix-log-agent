# Operational guide

## Configuration lifecycle

1. **Edit** — directly on disk or via web GUI → Configuration.
2. **Validate** — `softnix-log-agent validate --config <file>`, the GUI **Validate** button, or `POST /api/config/validate`. Validation checks structure, unknown fields, globs, regexes, ports, condition operators, and TLS file existence, and reports warnings (e.g. non-localhost web bind).
3. **Save** — the GUI saves only after successful validation and writes a backup to `<config>.yaml.bak` first.
4. **Reload** — GUI **Save & Reload**, `POST /api/config/reload`, or `SIGHUP` (Linux). The engine restarts with the new config; on failure the previous config is restored automatically and the agent keeps running.
5. **Rollback** — GUI **Rollback to backup** or `POST /api/config/rollback` restores `<config>.yaml.bak` and reloads.

Environment variables: `${VAR}` (required) and `${VAR:-default}` (optional). Expansion is textual and happens before YAML parsing — it also applies inside comments, so always use the `:-` form for variables that may be unset.

## Web GUI

Default: `http://127.0.0.1:8080`, localhost-only. Pages: Overview (status, throughput, queue, destinations), Inputs, Outputs, Buffer (usage, oldest event age, drops), Configuration (edit/validate/save/reload/rollback), Logs (recent agent log entries, level filter), About.

To expose it beyond localhost set `web.bind: 0.0.0.0` **and** `web.auth_token` — the agent logs a security warning at startup and on validation. API clients then send `Authorization: Bearer <token>` (or `X-Auth-Token`). Prefer a firewall/SSH tunnel over public exposure; the GUI is plain HTTP.

## Monitoring

- `GET /healthz` — 200 (`{"status":"ok"}`) when the engine is running and no `block`-policy destination queue is full; 503 when the engine is not running, or when a `block`-policy destination queue is full (`{"status":"degraded","queues_full":[...]}`) — see [Backpressure and the full-queue policy](#backpressure-and-the-full-queue-policy) below. A full `drop_oldest`/`drop_newest` queue does **not** trigger this — it is shedding load exactly as configured, not stalled. Wire into your existing checks, but see the liveness-probe note below.
- `GET /metrics` — Prometheus-style text: `agent_events_received_total`, `agent_events_sent_total`, `agent_events_failed_total`, `agent_events_dropped_total`, `agent_errors_total`, `agent_queue_events{destination=…}`, `agent_queue_bytes{…}`, `agent_queue_dropped_total{…}`, `agent_queue_full{output=…}` (1 when that destination's queue is full **and** its policy is `block`, 0 otherwise — same policy-aware gating as `/healthz`), `agent_router_shed_total{destination=…}` (events shed because that destination's in-memory router channel was momentarily full — see [Backpressure and the full-queue policy](#backpressure-and-the-full-queue-policy)), `agent_output_healthy{…}`, `agent_uptime_seconds`.
- `GET /api/status|inputs|outputs|buffer|logs|about` — JSON equivalents used by the GUI.

Alert suggestions: `agent_output_healthy == 0` for >5 min; `agent_queue_bytes` approaching `buffer.max_size_mb`; `agent_queue_full == 1` for any destination (collection may be stalled for that destination — see below); `agent_events_dropped_total` increasing; `agent_router_shed_total` increasing for a destination whose queue is *not* full (brief lock contention, not a stalled destination — worth watching but not urgent on its own); `agent_uptime_seconds` resets (crash loop).

## Backpressure and the full-queue policy

`buffer.full_policy: block` is the shipped **default**, and it is correct for
compliance collection: the agent never silently discards a log beyond a
brief, bounded in-flight buffer per destination — sustained backpressure is
visible via `agent_router_shed_total` and, once the destination's own disk
queue fills, `/healthz`. Each destination has its own on-disk queue and its
own routing task, fed by its own bounded in-memory channel, so a slow or
unreachable destination only ever backs up *its own* queue — it does not
stall delivery to any other, healthy destination. The fan-out from the
pipeline to each destination's channel uses a non-blocking send: if a
specific destination's channel is full, that one event is dropped for that
destination only (counted in `agent_events_dropped_total` and, per
destination, in `agent_router_shed_total{destination="<id>"}`, with a
rate-limited warning logged) and the pipeline immediately moves on to the
next destination and the next event. No destination's state can block
another destination's channel, the pipeline, or any input.

The tradeoff of `block` is that when a destination's queue genuinely fills
(the destination has been down, or too slow, for long enough to exhaust
`buffer.max_size_mb`), that destination's router correctly stops accepting
new events and waits for space — collection for that destination stalls
until the destination recovers or the operator intervenes. This is the
intended meaning of "never drop a log," but it must not go unnoticed:

- `GET /healthz` returns `503` with `{"status":"degraded","queues_full":[...]}`
  naming every full `block`-policy queue.
- `GET /metrics` exposes `agent_queue_full{output="<id>"} 1` for the same
  destinations.

Under sustained backpressure, `block` still means "never drop while there's
room" — but room is now bounded by the destination's ~4096-event in-memory
channel *plus* its on-disk queue capacity, not infinite blocking. That
in-memory channel is deliberately generous: its main job is absorbing brief,
routine contention on the destination's disk-queue lock (shared with the
output worker's ack/peek_batch, which holds it across `fsync`), not just
outright destination outages — a healthy destination should rarely, if ever,
shed. Once both the channel and the on-disk queue are full, new events for
that destination are shed (and counted, both in `agent_events_dropped_total`
and per destination in `agent_router_shed_total`) rather than stalling the
agent, while the destination's queue itself continues obeying `block`
semantics for everything already accepted into it. A config reload or
graceful stop is the one exception: the drain that runs at that point
force-delivers everything still sitting in the in-memory channel into each
destination's on-disk queue instead of shedding, so a routine `SIGHUP` or
Save & Reload does not itself lose events that were only waiting in that
channel — the one case it cannot save is a destination whose on-disk queue
is *already* full at that moment, since there is genuinely nowhere left to
put those events; they are still counted as dropped
(`agent_events_dropped_total`).

If a particular destination is noisy or non-critical and you would rather
shed load than stall, override the policy for that output alone:

```yaml
outputs:
  - id: noisy-siem
    type: syslog
    address: siem.example.com:514
    full_policy: drop_oldest   # or drop_newest
```

Leave `full_policy` unset on outputs where loss is unacceptable — they keep
inheriting `buffer.full_policy` (`block` by default).

### `/healthz` is readiness-shaped, not pure liveness

Because `/healthz` now returns `503` specifically when a `block`-policy
destination's queue is stuck full, it is telling you "a destination is
stuck," not "the agent is broken." If it is wired to a restart trigger
(systemd `Restart=`, a Kubernetes liveness probe), a stuck destination will
cause the agent to be restarted repeatedly — and a restart does not fix a
stuck downstream target, it just adds redelivery churn on top of an already
degraded destination. Prefer wiring `/healthz` to an alert or to a
**readiness** probe (taking the instance out of rotation, not restarting it)
rather than a liveness/restart trigger. If you need a pure liveness signal
(agent process is alive at all, independent of destination health), use
`agent_uptime_seconds` from `/metrics` instead.

## Sizing & tuning

| Knob | Default | Notes |
|---|---|---|
| `inputs.files[].poll_interval_ms` | 500 | Lower = fresher + slightly more CPU; min 50. |
| `buffer.max_size_mb` | 1024 | Per destination. Outage capacity ≈ rate × event size × outage duration. |
| `buffer.full_policy` | block | `block` never blocks inputs directly: the pipeline fans out to each destination with a non-blocking send and sheds (per destination, counted and logged) once that destination's ~4096-event in-memory buffer is exhausted — room beyond that depends on the destination's own on-disk queue capacity. `drop_oldest` favors fresh data; `drop_newest` favors history. |
| `outputs[].retry.batch_size` | 200 | Larger batches = higher throughput, larger duplicate window on crash. |
| `outputs[].retry.*_backoff_ms` | 500 / 30000 | Exponential, per destination. |

## Troubleshooting

| Symptom | Check |
|---|---|
| No events from a file input | Inputs page error column; glob quoting (quote patterns containing `*` in YAML); file readable by the service user; on first run pre-existing content is skipped unless `read_from_start: true`. |
| Events missing after rotation | Prefer rename rotation; ensure rotated files leave the glob scope *after* the last poll; check agent logs for `truncated` messages. |
| No events from an eventlog input (Windows) | Confirm running on Windows (ignored elsewhere with a validation warning); channel name spelled exactly (`Microsoft-Windows-Sysmon/Operational`); for the `Security` channel the service must run as LocalSystem / Event Log Readers; check the Inputs page error column and the agent log for `eventlog … channel …` errors; verify the XPath `query` is valid. |
| Eventlog message shows raw data, not a description | The provider's message DLL is missing/unavailable on this host; the agent falls back to joined `EventData` (the full XML is in `raw_message` only if `keep_raw_message: true` is set). |
| Destination unhealthy | Outputs page last error; TLS: cert chain/hostname (`tls.server_name` to override SNI), mTLS cert/key pair; reachability with `nc`/`Test-NetConnection`. |
| Queue grows during normal operation | Destination slower than ingest; raise `batch_size`, check destination, or add a second destination with routing. |
| Duplicates at destination | Expected (at-least-once) after crash/restart of agent or destination; window ≤ one batch per destination. |
| Reload fails | The response/agent log carries the validation or bind error; the previous config was restored automatically. |
| Web GUI unreachable | `web.enabled`, bind/port; remote access requires non-loopback bind (plus token) or an SSH tunnel: `ssh -L 8080:127.0.0.1:8080 host`. |

Agent self-logs go to stderr (journald under systemd) and to the GUI Logs page (last 500 entries, in memory). Increase verbosity with `agent.log_level: debug` or `RUST_LOG=debug`.

## Security notes

- Run least-privileged: the agent needs read access to log sources and write access to `data_dir` only. The shipped systemd unit applies sandbox hardening.
- Secrets in the config (e.g. `web.auth_token`) are best injected via `${ENV_VARS}` so the file itself can stay secret-free; the agent never logs token values. Restrict config file permissions (`chmod 600`) — queue files contain raw event data, restrict `data_dir` likewise (`chmod 700`).
- Mask sensitive payload data with the `mask` transform; remember to also mask or `remove_field: raw_message`.
- Keep `tls.verify: true` (default); verification-off is for lab use and is loudly warned about.
