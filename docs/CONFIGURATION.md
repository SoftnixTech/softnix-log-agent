# Configuration Manual

> 🌐 ภาษาไทย: [CONFIGURATION.th.md](CONFIGURATION.th.md)

Complete reference for the Softnix Log Agent configuration file. The config is a
single YAML file (commonly `agent.yaml`). Every section is optional and falls
back to the defaults documented below.

- **Validate:** `softnix-log-agent validate --config agent.yaml`
- **Apply changes:** edit the file, then reload (web GUI **Save & Reload**,
  `POST /api/config/reload`, or `SIGHUP` on Linux). Reloads are validated first
  and roll back automatically on failure.
- **Reference example:** [`examples/agent.yaml`](../examples/agent.yaml) ·
  **Minimal:** [`examples/minimal.yaml`](../examples/minimal.yaml) ·
  **Windows:** [`examples/windows.yaml`](../examples/windows.yaml)

Unknown keys are rejected (`deny_unknown_fields`) — a typo fails validation
rather than being silently ignored.

## Top-level structure

```yaml
agent:    { … }      # process-wide settings
inputs:   { … }      # where logs come from (files / syslog / eventlog)
pipeline: { … }      # transform + enrich stages
buffer:   { … }      # per-destination disk queue
outputs:  [ … ]      # where logs are sent
web:      { … }      # management GUI / API
```

## Environment variables

Anywhere in the file you may reference environment variables:

| Syntax | Meaning |
|---|---|
| `${VAR}` | Required — validation fails if `VAR` is unset. |
| `${VAR:-default}` | Optional — uses `default` when `VAR` is unset. |

Expansion is **textual** and runs **before** YAML parsing (it also affects
comments). Always use the `:-` form for variables that may be unset.

```yaml
enrich:
  environment: ${ENVIRONMENT:-production}
```

Do not use the `:-` default form for `web.auth_token` (or any other secret):
`${WEB_TOKEN:-}` with `WEB_TOKEN` unset expands to an empty string, which the
agent now treats as "not configured" and replaces with a freshly generated
token — but an empty string is never a safe stand-in for a real secret. Use
the required form instead so a missing variable fails validation loudly:

```yaml
web:
  auth_token: ${WEB_TOKEN}
```

---

## `agent`

Process-wide settings.

| Key | Type | Default | Description |
|---|---|---|---|
| `data_dir` | path | `data` | Base directory for state (file offsets, Event Log bookmarks) and the persistent queue. Service installs set an absolute path (`/var/lib/softnix-log-agent`, `C:\ProgramData\Softnix\LogAgent`). |
| `log_level` | string | `info` | Agent's own log verbosity: `trace`, `debug`, `info`, `warn`, `error`. |

```yaml
agent:
  data_dir: /var/lib/softnix-log-agent
  log_level: info
```

---

## `inputs`

Three input families, each a list. You may define any number of each.

```yaml
inputs:
  files:    [ … ]
  syslog:   [ … ]
  eventlog: [ … ]   # Windows-only
```

Every input has a unique `id` (shared namespace with outputs — no duplicates).

### `inputs.files`

Tail local files with glob discovery and rotation handling.

| Key | Type | Default | Description |
|---|---|---|---|
| `id` | string | — (required) | Unique identifier. |
| `paths` | list | — (required) | Glob patterns. Supports `*`, recursive `**`, and Windows paths (`C:\Logs\*.log`). |
| `exclude` | list | `[]` | Glob patterns to skip. |
| `poll_interval_ms` | int | `500` | File-change/discovery poll interval. Minimum `50`. Lower = fresher, slightly more CPU. |
| `read_from_start` | bool | `false` | On first run, read pre-existing content from the beginning. By default existing content is skipped and only new lines are read. (Files discovered *later* are always read from the start.) |
| `parser` | object | `mode: raw` | See [Parsers](#parsers). |
| `source_type` | string | `file` | Overrides the `source_type` field on emitted events. |

```yaml
inputs:
  files:
    - id: app-logs
      paths:
        - /var/log/*.log
        - /app/logs/**/*.log
      exclude: ["**/*.gz"]
      poll_interval_ms: 500
      read_from_start: false
      parser: { mode: json }
```

**Rotation:** rename rotation, copy-truncate, truncation and recreation are
handled; offsets persist across restarts. On Windows, file identity uses
creation time plus a hash of the file's first line (see
[Known limitations](../README.md#known-limitations)).

### `inputs.syslog`

Receive syslog over the network.

| Key | Type | Default | Description |
|---|---|---|---|
| `id` | string | — (required) | Unique identifier. |
| `protocol` | enum | `udp` | `udp`, `tcp`, or `tls`. |
| `bind` | IP | `0.0.0.0` | Local address to listen on. |
| `port` | int | — (required) | Port (1–65535). |
| `format` | enum | `auto` | `auto`, `rfc3164`, `rfc5424`, `json`, `raw`. `auto` tries RFC5424 → RFC3164 → JSON → raw. |
| `tls` | object | — | Required when `protocol: tls`. See below. |
| `source_type` | string | `syslog` | Overrides `source_type` on emitted events. |

**`tls` (server) options** — required for `protocol: tls`:

| Key | Type | Description |
|---|---|---|
| `cert` | path | Server certificate (PEM). |
| `key` | path | Server private key (PEM). |
| `client_ca` | path | CA bundle to verify client certificates — enables **mutual TLS**. |

```yaml
inputs:
  syslog:
    - id: udp514
      protocol: udp
      port: 514
    - id: tls6514
      protocol: tls
      port: 6514
      tls:
        cert: /etc/softnix-log-agent/tls/server.crt
        key:  /etc/softnix-log-agent/tls/server.key
        # client_ca: /etc/softnix-log-agent/tls/clients-ca.crt   # mTLS
```

> TCP/TLS syslog input uses newline framing only.

### `inputs.eventlog` (Windows-only)

Collect Windows Event Log channels natively via `wevtapi`. On non-Windows
platforms a configured eventlog input is ignored with a validation warning.

| Key | Type | Default | Description |
|---|---|---|---|
| `id` | string | — (required) | Unique identifier. |
| `channels` | list | — (required, ≥1) | Channel names: `Application`, `System`, `Security`, or custom (e.g. `Microsoft-Windows-Sysmon/Operational`). |
| `query` | string | `*` | XPath filter applied to each channel. `*` = all events. |
| `read_existing` | bool | `false` | On first run (no saved bookmark), read existing events from the oldest record. Default collects only events arriving after start. |
| `source_type` | string | `eventlog` | Overrides `source_type` on emitted events. |

```yaml
inputs:
  eventlog:
    - id: winevents
      channels: [Application, System, Security]
      # Critical/Error/Warning only:
      query: "*[System[(Level=1 or Level=2 or Level=3)]]"
      read_existing: false
```

**Behaviour & notes:**

- Progress is checkpointed with an Event Log **bookmark** persisted under
  `agent.data_dir` → at-least-once delivery that resumes after a restart.
- The human-readable message is resolved from the publisher's metadata; if the
  provider's message DLL is unavailable it falls back to the joined `EventData`.
  The full event XML is always kept in `raw_message`.
- Mapped event fields: `Level` → `severity`, `Provider` → `application`,
  `Computer` → `hostname`, plus `event_id`, `channel`, `record_id`, `keywords`
  and each `EventData` item as `data_<Name>`.
- Reading the **`Security`** channel requires elevated privilege. The Windows
  Service runs as LocalSystem, which satisfies this.

### Parsers

Used by `inputs.files[].parser`. Syslog inputs parse via their own `format`.

| `mode` | Description | Relevant keys |
|---|---|---|
| `raw` *(default)* | Keep the line as `message`, no parsing. | — |
| `json` | Parse each line as a JSON object into fields. | — |
| `kv` | Parse `key=value` pairs. | `pair_separator` (default space), `kv_separator` (default `=`). |
| `regex` | Extract named capture groups into fields. | `pattern` (required), `timestamp_format`. |
| `syslog` | Parse the line as syslog (RFC5424/RFC3164). | — |

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | enum | `raw` | One of the above. |
| `pattern` | string | — | Regex with named groups, e.g. `(?P<status>\d+)`. Required for `regex`. |
| `pair_separator` | string | `" "` | Separator between pairs (`kv`). |
| `kv_separator` | string | `=` | Separator between key and value (`kv`). |
| `timestamp_format` | string | — | `chrono` format to parse a captured `timestamp` group, e.g. `%d/%b/%Y:%H:%M:%S %z`. |

```yaml
parser:
  mode: regex
  pattern: '^(?P<remote>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<bytes>\d+)'
  timestamp_format: "%d/%b/%Y:%H:%M:%S %z"
```

---

## `pipeline`

Runs after parsing, in order: **transforms** then **enrich**.

```yaml
pipeline:
  transforms: [ … ]
  enrich:     { … }
```

### `pipeline.transforms`

An ordered list. Each step has a `type`. Steps with a `when` condition run only
when it matches (see [Conditions](#conditions)).

| `type` | Keys | Effect |
|---|---|---|
| `add_field` | `field`, `value`, `when?` | Set a field to a literal value. |
| `remove_field` | `field`, `when?` | Delete a field. |
| `rename_field` | `from`, `to`, `when?` | Rename a field. |
| `convert` | `field`, `to`, `when?` | Convert a field type. `to`: `int`, `float`, `string`, `bool`. |
| `mask` | `field`, `pattern`, `replacement?`, `when?` | Regex-replace within a field. `replacement` default `****`. **Masking `message` also masks `raw_message`.** |
| `drop` | `when` *(required)* | Discard events matching `when`. |
| `keep` | `when` *(required)* | Keep only events matching `when`; drop the rest. |

```yaml
pipeline:
  transforms:
    - type: add_field
      field: team
      value: platform
    - type: convert
      field: status
      to: int
    - type: mask
      field: message
      pattern: '\b\d{13,16}\b'
      replacement: "[REDACTED]"
    - type: drop
      when: { field: message, op: contains, value: "health-check" }
    - type: add_field
      field: alert
      value: true
      when: { field: severity, op: lt, value: 3 }
```

### Conditions

Used by `when` on transforms and by output routing (`when` / implicitly).

```yaml
when: { field: <name>, op: <operator>, value: <value> }
```

| `op` | Needs `value` | Matches when… |
|---|---|---|
| `eq` | yes | field equals value |
| `ne` | yes | field does not equal value |
| `contains` | yes | string field contains value |
| `matches` | yes | string field matches the regex value |
| `gt` | yes | numeric field greater than value |
| `lt` | yes | numeric field less than value |
| `exists` | no | field is present |
| `not_exists` | no | field is absent |

`field` may be any event field — core (`message`, `severity`, `facility`,
`hostname`, `application`, `source`, `source_type`, `process_id`, …) or a custom
field produced by a parser/transform/enrich.

### `pipeline.enrich`

Adds static/host metadata to every event. Existing fields are never overwritten.

| Key | Type | Default | Description |
|---|---|---|---|
| `hostname` | bool | `true` | Add the local hostname (if event has none). |
| `os_info` | bool | `true` | Add `os` (name + arch). |
| `agent_version` | bool | `true` | Tag events with the collector version. |
| `local_ip` | bool | `false` | Add the detected local IP. |
| `environment` | string | — | e.g. `production`. |
| `site` | string | — | e.g. `dc-bkk-1`. |
| `tenant` | string | — | Tenant identifier. |
| `customer` | string | — | Customer identifier. |
| `tags` | list | `[]` | Free-form tags. |
| `fields` | map | `{}` | Arbitrary extra key/values. |

```yaml
pipeline:
  enrich:
    hostname: true
    os_info: true
    local_ip: true
    environment: ${ENVIRONMENT:-production}
    site: dc-bkk-1
    tenant: softnix
    tags: [edge, th]
    fields: { rack: r12 }
```

---

## `buffer`

Per-destination, crash-safe disk queue between the pipeline and each output.

| Key | Type | Default | Description |
|---|---|---|---|
| `dir` | path | `<data_dir>/queue` | Queue directory. |
| `max_size_mb` | int | `1024` | Maximum on-disk size **per destination**. |
| `segment_size_mb` | int | `8` | Size of each queue segment file. |
| `full_policy` | enum | `block` | Behaviour when a queue is full (below). |

**`full_policy`:**

| Value | Behaviour |
|---|---|
| `block` | Back-pressure inputs. File reading pauses (no loss); for UDP syslog the kernel may drop. |
| `drop_oldest` | Evict the oldest queued events to make room — favors fresh data. |
| `drop_newest` | Reject new events when full — favors history. |

> Sizing: outage capacity ≈ event rate × average event size × outage duration.

```yaml
buffer:
  max_size_mb: 1024
  segment_size_mb: 8
  full_policy: block
```

---

## `outputs`

A list of destinations. Each event is routed to every output whose `when`
condition matches (or all outputs, if no `when`), subject to failover.

| Key | Type | Default | Description |
|---|---|---|---|
| `id` | string | — (required) | Unique identifier. |
| `type` | enum | — (required) | `syslog` or `stdout`. |
| `address` | `host:port` | — | Required for `syslog`. |
| `protocol` | enum | `udp` | `udp`, `tcp`, `tls` (syslog). |
| `format` | enum | `rfc5424` | `rfc5424`, `rfc3164`, `json`, `raw`. |
| `framing` | enum | `newline` | `newline` or `octet_counting` (TCP/TLS). |
| `tls` | object | — | Client TLS options (below). |
| `when` | condition | — | Only route matching events here. |
| `failover_for` | string | — | Receive traffic only while the named output is unhealthy. |
| `retry` | object | see below | Send/retry tuning. |

**`tls` (client) options:**

| Key | Type | Default | Description |
|---|---|---|---|
| `ca` | path | system roots | CA bundle to verify the server. |
| `cert` | path | — | Client certificate for mTLS. |
| `key` | path | — | Client private key for mTLS. |
| `verify` | bool | `true` | Verify the server certificate. **Do not disable in production.** |
| `server_name` | string | — | Override SNI / certificate hostname. |

**`retry` options:**

| Key | Type | Default | Description |
|---|---|---|---|
| `initial_backoff_ms` | int | `500` | First retry delay (doubles each failure). |
| `max_backoff_ms` | int | `30000` | Maximum retry delay. |
| `batch_size` | int | `200` | Events per send batch. Larger = higher throughput, larger duplicate window on crash. |

**Notes on formats/transports:**

- `rfc5424` output emits enrichment/custom fields in the STRUCTURED-DATA element.
- `json` emits the full event including `raw_message`.
- UDP sends one event per datagram; events larger than ~64 KB are dropped
  (counted in `events_dropped`) so they cannot block the queue.

```yaml
outputs:
  - id: siem-primary
    type: syslog
    protocol: tls
    address: siem.example.com:6514
    format: rfc5424
    tls:
      ca:   /etc/softnix-log-agent/tls/siem-ca.crt
      cert: /etc/softnix-log-agent/tls/agent.crt
      key:  /etc/softnix-log-agent/tls/agent.key
    retry: { batch_size: 200, max_backoff_ms: 30000 }

  - id: siem-backup
    type: syslog
    protocol: tcp
    address: siem-backup.example.com:514
    format: rfc5424
    failover_for: siem-primary

  - id: alerts
    type: syslog
    protocol: udp
    address: alerting.example.com:514
    when: { field: severity, op: lt, value: 4 }
```

---

## `web`

Built-in management GUI and JSON/metrics API.

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Serve the GUI/API. |
| `bind` | IP | `127.0.0.1` | Listen address. Localhost-only by default. |
| `port` | int | `8080` | Listen port. |
| `auth_token` | string | — | Bearer token required for all API requests. |

To expose the GUI beyond localhost, set `bind: 0.0.0.0` **and** `auth_token`
(the agent warns at startup otherwise). Clients then send
`Authorization: Bearer <token>` (or `X-Auth-Token`). Prefer a firewall or SSH
tunnel — the GUI is plain HTTP.

```yaml
web:
  enabled: true
  bind: 127.0.0.1
  port: 8080
  # auth_token: ${WEB_TOKEN}
```

---

## Common recipes

**Windows servers → central SIEM:**

```yaml
inputs:
  eventlog:
    - id: win
      channels: [Application, System, Security]
pipeline:
  enrich: { site: hq, environment: production }
outputs:
  - id: siem
    type: syslog
    protocol: tcp
    address: siem.corp.local:514
    format: rfc5424
```

**Tail JSON app logs, redact secrets, ship over TLS:**

```yaml
inputs:
  files:
    - id: app
      paths: ["/app/logs/*.json"]
      parser: { mode: json }
pipeline:
  transforms:
    - type: mask
      field: message
      pattern: '\b\d{13,16}\b'
      replacement: "[REDACTED]"
outputs:
  - id: siem
    type: syslog
    protocol: tls
    address: siem.example.com:6514
    format: rfc5424
    tls: { ca: /etc/softnix/ca.crt }
```

**Drop noise, keep only errors:**

```yaml
pipeline:
  transforms:
    - type: keep
      when: { field: severity, op: lt, value: 5 }
```

See [OPERATIONS.md](OPERATIONS.md) for reload, monitoring and tuning guidance.
