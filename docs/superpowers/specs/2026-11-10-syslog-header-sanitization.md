# Syslog header-field sanitization (Windows provider names with spaces) — design spec

Status: **draft, pending owner review** (2026-11-10). Branch:
`develop_fix_bug_windows-provider-name`. No code has been changed yet; this
document defines what the fix must do and how it will be verified.

## Problem

Windows Event Log providers frequently have spaces in their names —
`Service Control Manager` (System 7036/7040/7045, one of the most common
events on any Windows host), `Application Error`, `Application Hang`,
`Windows Error Reporting`, `Microsoft-Windows-Windows Defender`,
`Microsoft-Windows-User Profiles Service`, and so on.

The value flows unmodified into the RFC 5424 header:

1. `src/inputs/eventlog.rs` (`build_event`: `ev.application = Some(p.provider.clone())`)
   copies `<Provider Name='…'/>` into `Event.application`.
2. `src/outputs/format.rs` (`format_event`, `OutputFormat::Rfc5424` arm)
   interpolates it verbatim:
   `format!("<{pri}>1 {ts} {host} {app} {pid} - {sd} {}", ev.message)`.

RFC 5424 §6 defines `APP-NAME = NILVALUE / 1*48PRINTUSASCII` where
`PRINTUSASCII = %d33-126` — no space, no tab, no non-ASCII, at most 48
octets. A space shifts every following header field by one token.

### Evidence (smoke test, 2026-11-10)

Two real agent processes (sender → receiver), 6 rounds × 36 cases = 216
lines, TCP-newline / TCP-octet-counting / UDP, receiver in `rfc5424` and
`auto` mode, checked against an independent strict ABNF validator. The
eventlog input is Windows-only, so the json parser populated the same
`Event` fields (`application`, `hostname`, `process_id`, `event_id`,
`record_id`, `channel`) that reach the same formatter.

| Case group | ABNF-valid | APP-NAME correct | Receiver parsed correctly |
|---|---|---|---|
| Real provider names **with** spaces (9 names) | 18/54 | **0/54** | **0/36** |
| Real provider names without spaces | 30/30 | 30/30 | 20/20 |
| Fuzz names containing space/tab | 9/48 | 0/48 | 1/28 |
| Fuzz names without whitespace | 24/24 | 24/24 | 20/20 |
| len 49 / len 60 / tab / non-ASCII | 0/24 | 0/24 | (lenient own parser accepts some) |

Example — `Service Control Manager`, event 7036:

```text
<14>1 2026-11-10T08:58:07.110Z WIN-SRV01 Service Control Manager 4321 - [softnix@32473 channel="System" event_id="7036" record_id="10000"] SMOKE-1-000 The service entered the running state.
```

Receiver result: `app="Service"`, `procid="Control"`,
`message="4321 - [softnix@32473 channel=…"` — PID lost, structured data
lost, message polluted.

The most dangerous variant is a **two-word name** (`Application Error`):
the line stays *syntactically valid* (`APP-NAME=Application`,
`PROCID=Error`, `MSGID=4321`, `SD=-`), so a strict receiver accepts it and
stores wrong values silently. 18 of the 54 real-name lines were in this
category.

The same root cause also produces invalid lines for names longer than 48
octets (`Microsoft-Windows-Windows Firewall With Advanced Security`, 57),
names with tabs, non-ASCII names, and an empty-string application
(`Some("")` renders as two adjacent spaces).

RFC 3164 output (`OutputFormat::Rfc3164` arm) interpolates the same value
into `TAG` (`{tag}[{pid}]:`). By code inspection it has the same defect
(`Service Control Manager[4321]:` → receivers take `TAG=Service`); this was
not part of the smoke run and will be confirmed by the regression tests.

## Goals

1. Every RFC 5424 line the agent emits has a header that is valid per the
   RFC 5424 ABNF, **for any input value** of `hostname`, `application` and
   `process_id`.
2. The original, unmodified value is not lost: it is recoverable from the
   same RFC 5424 line.
3. Output for values that are already valid is **byte-identical** to
   today's output (no churn for existing receivers / SIEM parsers).
4. Same guarantee for the RFC 3164 `HOSTNAME` and `TAG` fields (Part B).

## Non-goals

- Changing `Event.application` (or any `Event` field) itself. JSON/raw
  output, `when:` conditions, `failover_for` routing and transforms keep
  seeing the original provider name (`application eq "Service Control
  Manager"` must keep working).
- Sanitizing at the input side (eventlog/syslog/file). The constraint is a
  property of the wire format, so it is enforced where the wire format is
  produced; this also covers every other source of `application`
  (json/kv/regex parsers, syslog relay, `add_field`/`rename_field`).
- New configuration options. The behavior is not configurable (see Open
  questions).

## Design

All changes live in `src/outputs/format.rs`.

### Header token rule

A new private helper, applied to each free-form header field before
interpolation:

```rust
/// Make `raw` a valid RFC 5424 header token (PRINTUSASCII, <= max octets)
/// or the NILVALUE "-". Returns Cow::Borrowed when `raw` is already valid.
fn header_token(raw: &str, max: usize) -> Cow<'_, str>
```

Algorithm, in order:

1. **Trim** leading/trailing Unicode whitespace.
2. If the result is empty → `-` (NILVALUE).
3. **Replace** every character outside `%d33-126` (space, tab, control
   characters, any non-ASCII) with `_`. A run of consecutive replaced
   characters collapses to a single `_`. Characters that were already `_`
   in the input are kept as-is (not collapsed).
4. **Truncate** to `max` octets. The string is pure ASCII after step 3, so
   this never splits a character.
5. If the result consists only of `_` → `-` (nothing meaningful survived,
   e.g. a fully non-ASCII name).

If no step changed anything, the borrowed input is returned unchanged,
which gives Goal 3.

| Field | `max` | Source | When the value is `None` |
|---|---|---|---|
| HOSTNAME | 255 | `ev.hostname` | `-` (unchanged) |
| APP-NAME | 48 | `ev.application` | `softnix-log-agent` (unchanged) |
| PROCID | 128 | `ev.process_id` | `-` (unchanged) |
| MSGID | 32 | always `-` today | unchanged |

A literal `-` input stays `-`, so it continues to mean NILVALUE — the
current behavior is kept.

### Expected APP-NAME values

| Input `application` | Emitted APP-NAME |
|---|---|
| `Microsoft-Windows-Security-Auditing` | unchanged |
| `Service Control Manager` | `Service_Control_Manager` |
| `Application Error` | `Application_Error` |
| `Microsoft-Windows-User Profiles Service` | `Microsoft-Windows-User_Profiles_Service` |
| `Microsoft-Windows-Windows Firewall With Advanced Security` | `Microsoft-Windows-Windows_Firewall_With_Advanced` (48) |
| `" LeadingSpace"` / `"TrailingSpace "` | `LeadingSpace` / `TrailingSpace` |
| `"Double  Space"` | `Double_Space` |
| `"Tab\tSeparated"` | `Tab_Separated` |
| `"ระบบ บันทึก"` (non-ASCII only) | `-` |
| `"A" × 48` | unchanged |
| `"B" × 49` | `"B" × 48` |
| `""` (`Some("")`) | `-` |
| `-` | `-` |
| `Odd"Name]x` (valid PRINTUSASCII) | unchanged |
| `None` | `softnix-log-agent` |

### Preserving the original value

When `header_token` changed a field (that is, the result is not the
borrowed input), the original value is added as an SD-PARAM in the
existing `[softnix@32473 …]` element:

| Header field | SD-PARAM name |
|---|---|
| APP-NAME | `application` |
| HOSTNAME | `hostname` |
| PROCID | `process_id` |

The names match the `Event` JSON field names, so a receiver can map them
back without a lookup table. The value goes through the existing
`sd_escape` (`"`, `\`, `]`). UTF-8 is allowed in PARAM-VALUE, so
non-ASCII originals survive intact.

Rules:

- The parameter is emitted **only** when the header value was altered.
  Valid values add nothing, which keeps Goal 3.
- If `ev.fields` already has a key with the same name, the existing field
  wins and no second parameter is added. This avoids duplicate PARAM-NAMEs.
- If `ev.fields` is otherwise empty, the element is created only for this
  parameter (today it would have been `-`).

Example after the fix:

```text
<14>1 2026-11-10T08:58:07.110Z WIN-SRV01 Service_Control_Manager 4321 - [softnix@32473 application="Service Control Manager" channel="System" event_id="7036" record_id="10000"] The service entered the running state.
```

Parameter order: the preserved-original parameters come first, followed by
`ev.fields` in its current iteration order.

### Part B — RFC 3164

Apply `header_token` to RFC 3164 `HOSTNAME` (max 255) and `TAG`. For
`TAG`, `[`, `]` and `:` are also replaced, because they delimit PID and
CONTENT in the `{tag}[{pid}]:` form. RFC 3164 has no structured data, so
the original value **cannot** be preserved on the 3164 wire. This is a
documented limitation: operators who need the exact provider name should
use `rfc5424` or `json`.

Whether to also cap `TAG` at 32 characters (RFC 3164 §4.1.3) is an open
question. Capping it would change current output for common names such as
`Microsoft-Windows-Security-Auditing` (35).

## Compatibility and rollout

- Valid values: no change to the bytes on the wire.
- Values that were broken before: header tokens change. For example, a
  SIEM rule that keyed on the corrupted `app=Service` now sees
  `Service_Control_Manager`. The release note must state this, with a
  before/after example.
- Ships as a patch release (0.1.x). No config or state migration is
  needed.
- Update the docs that describe the field mapping:
  - `docs/CONFIGURATION.md` and `docs/CONFIGURATION.th.md`
    (`Provider` → `application` mapping; note the wire sanitization and the
    `application` SD-PARAM)
  - `docs/INSTALL-WINDOWS.md` (Messages note)

## Verification

### Unit tests (`src/outputs/format.rs` `mod tests`)

1. **Table test**: every row of "Expected APP-NAME values" above, asserting
   the exact emitted token.
2. **Byte-identical regression**: the existing `rfc5424_format`,
   `rfc5424_emits_enrichment_as_structured_data` and
   `rfc5424_escapes_and_skips_raw_structured_data` tests pass unchanged.
   The real no-space provider list also produces byte-identical output
   compared with the pre-fix formatter (captured as literal expected
   strings).
3. **Original preserved**: for a changed value, the SD contains
   `application="<original>"`, escaped. For an unchanged value, no
   `application` parameter is present. On a key collision with
   `ev.fields`, there is exactly one `application` parameter.
4. **HOSTNAME / PROCID**: the same rule, with max 255 and 128.
5. **Property loop**: about 2,000 random strings, seeded `rand` (already a
   dependency), drawn from ASCII, whitespace, control characters, CJK and
   Thai, with lengths 0–80. For each one, assert that the header splits
   into exactly `PRI-VERSION TS HOST APP PROCID MSGID SD MSG`, that APP
   matches `^(-|[\x21-\x7e]{1,48})$`, and that the SD is well-formed.
6. **Round-trip through our own parser**: format, then call
   `crate::pipeline::syslog::parse_syslog_into(.., SyslogFormat::Rfc5424)`.
   Assert that `application == header_token(original)`,
   `process_id == pid` and `message == original message`.
7. **RFC 3164 (Part B)**: `Service Control Manager` + pid `4321` produces
   `Service_Control_Manager[4321]: msg`, and the round-trip through the
   3164 parser yields the same tag, pid and message.

### Smoke test (re-run of the 2026-11-10 harness)

Re-run the same harness (6 rounds, 216 lines) against the fixed binary.
"Expected" now means `header_token(name)`, not the raw name.

- Strict ABNF validity: **216/216**.
- APP-NAME equals the expected sanitized value: **216/216**.
- On newline transports, the receiver's `application`, `process_id` and
  `message` all match: **144/144** (rounds 1, 3, 4 and 6). Octet-counting
  rounds are excluded; see Out of scope.

### Manual check on a real Windows host (before release)

1. Install the patched build with an `eventlog` input on `System`, and a
   `syslog` output (rfc5424, tcp) pointing at a test receiver.
2. Trigger a 7036 event with `Restart-Service Spooler`.
3. Confirm the receiver shows `APP-NAME=Service_Control_Manager`,
   `PROCID=<pid>`, an SD containing
   `application="Service Control Manager"`, and the rendered message intact.
4. Repeat with an `Application Error` event (1000). An easy way to raise
   one is to crash a test process.

### Gate

`cargo test`, `cargo clippy --all-targets -- -D warnings` and
`cargo fmt --check` are all clean. The Windows target also compiles
(`cargo check --target x86_64-pc-windows-gnu`).

## Out of scope (found during the investigation — separate issues)

1. **The syslog TCP/TLS input only understands newline framing.**
   `src/inputs/syslog.rs` uses `LinesCodec`. When one agent sends
   `framing: octet_counting` to another agent, every event in a
   connection becomes a single message: 36 of 36 lost in smoke rounds 2
   and 5. RFC 6587 octet-counting is what most TCP senders use.
2. **Agent self-logs go to stdout, not stderr.** In `src/main.rs`,
   `tracing_subscriber::fmt::layer()` defaults to stdout, despite the
   comment saying "stderr". With a `type: stdout` output, the agent's own
   log lines are mixed into the event stream (seen in smoke output).
3. **The SD-ID enterprise number `32473`** is the number RFC 5612 reserves
   for documentation examples. A production SD-ID should use a registered
   IANA Private Enterprise Number. Changing it is a wire-format change for
   SIEM parsers, so it needs its own decision.

## Open questions for the owner

1. **Replacement character**: `_` (proposed), `-`, or removing the
   character? `_` is unambiguous, while `-` can visually blur with
   NILVALUE and with existing hyphens in `Microsoft-Windows-…`.
2. **When to emit the original value**: only when the value was altered
   (proposed, to keep the output byte-identical), or always? Always is
   simpler for SIEM parsers, but it changes every line.
3. **RFC 3164 `TAG` length**: cap at 32 per RFC 3164, or leave it uncapped
   as today (proposed: uncapped)?
4. **Part B in the same patch, or a follow-up?** The proposal is the same
   patch: same function, same root cause, small diff.
