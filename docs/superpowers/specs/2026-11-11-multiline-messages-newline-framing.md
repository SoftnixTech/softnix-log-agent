# Multi-line event messages are split into several events — design spec

Status: **approved, 2026-11-11.** The owner chose **option B** (each line
break becomes one space) for open question 1. Open questions 2–4 take the
proposed answers. A prototype in a throw-away worktree passed every test
and the end-to-end harness (see [Prototype results](#prototype-results-2026-11-11)).
Implementation plan:
`docs/superpowers/plans/2026-11-11-multiline-messages-newline-framing.md`.
Related: the TCP/TLS input octet-counting framing issue (the agent's TCP/TLS
input cannot decode octet-counting) gets its **own spec**,
`2026-11-11-tcp-input-octet-counting.md`. It is the receiver-side half of
the "use octet-counting" workaround, and this spec depends on it only for
that workaround. The fix for Eventlog `EventData` values with XML entities
truncated and split (`2026-11-11-eventlog-xml-text-entities.md`, fixed in
`f6fb143`) adds a new way for CR/LF to reach the wire: `&#13;&#10;` in EventData now becomes real CR/LF in `data_*`.
Branch: `develop_fix_bug_known-issues`.

## Problem

Windows renders many event messages over several lines (CRLF plus tabs):
Security 4624/4625/4688, Service Control Manager 7045, Application Error
1000, Sysmon. `format_message` (`src/inputs/eventlog.rs:667`) trims only
*trailing* `\0`/`\r`/`\n`, which is correct, because the embedded line
breaks are part of the message. The defect is in how those line breaks
are carried, in three separate places:

| # | Where | Code | What goes wrong |
| --- | --- | --- | --- |
| 1 | **Sender**, TCP/TLS (and `stdout`) with `framing: newline` | `frame_batch`, `src/outputs/stdout.rs:46-49`, shared by `SyslogSink` TCP/TLS (`src/outputs/syslog.rs:138`, `:143`) and `StdoutSink` | The formatted line is written as it is, then `\n` is appended. A line that already contains CR/LF becomes several frames. **Every** newline-framed receiver splits it, the agent or third-party. RFC 6587 §3.4.2 (non-transparent framing) cannot carry an LF inside a message. |
| 2 | **Receiver**, the agent's UDP input | `src/inputs/syslog.rs:200-202`: `for line in text.lines()` | The sender correctly sends one event per datagram (`src/outputs/syslog.rs:110`, RFC 5426 §3.1), but the agent's receiver splits each datagram on LF anyway. |
| 3 | **Receiver**, the agent's TCP/TLS input | `src/inputs/syslog.rs:343`: `LinesCodec` | Correct for newline framing, which is the only framing it supports. Carrying multi-line messages agent-to-agent needs octet-counting: **the octet-counting input fix (`2026-11-11-tcp-input-octet-counting.md`), out of scope here.** |

Where it happens, by output setting:

| Output | `format` | Affected? |
| --- | --- | --- |
| syslog TCP/TLS, `framing: newline` (the **default**) | `rfc5424`, `rfc3164`, `raw` | **Yes, for every receiver** (row 1) |
| syslog TCP/TLS, `framing: octet_counting` | any | Third-party receivers that decode octet-counting: no. The agent's own input: yes (until the octet-counting input fix). |
| syslog UDP | any | The sender is fine. The agent's own UDP input: yes (row 2). |
| any | `json` | **No.** serde escapes CR/LF as `\r`/`\n` inside the JSON string. |
| stdout, `framing: newline` | `rfc5424`, `rfc3164`, `raw` | Yes, for line-based consumers (row 1, same function) |

### Evidence (2026-11-11, branch HEAD `4d9f58b`, 3 independent runs)

The repro harness from the 2026-11-11 verification
(`/tmp/softnix-smoke.LTIcHO/harness/issues_repro.py`, multi-line case) was run
again against a fresh debug build of this branch. It uses 7 realistic Windows
events (5 multi-line, 2 single-line). Agent A sends them over RFC 5424 to a
plain-Python TCP and UDP sink (standing in for a third-party SIEM) and to
agent B's TCP and UDP inputs. Every run gave identical results:

| Path | Multi-line events intact | Notes |
| --- | --- | --- |
| A → SIEM, TCP newline | **0/5** | 31 frames for 7 events, 24 of them without a header |
| A → SIEM, UDP | **5/5** | 7 datagrams: the sender is correct |
| A → agent B, TCP | **0/5** | 18 orphan fragment events per run |
| A → agent B, UDP | **0/5** | 18 orphan fragment events per run (row 2) |

The 4624 event on the SIEM's TCP stream: the first frame has the header
and the first line, and the next 10 frames are the remaining lines, without
a header (`'\r'`, `'Subject:\r'`, `'\tSecurity ID:\t\tNULL SID\r'`, …).

Confounder: 3 of the 7 events have a provider name with a space
(`Service Control Manager` ×2: 7045 multi-line and 7036 single-line;
`Application Error`: 1000 multi-line). This branch is based on `main`,
which does not have the provider-name header fix
(`develop_fix_bug_windows-provider-name`), so the space in APP-NAME breaks
agent B's RFC 5424 parse: `application` becomes `Service` or `Application`,
and the rest of the header leaks into `message`. That is why 1 of the 2
single-line events is not intact on agent B. The bug is unrelated to this issue,
but on agent B it also hides 2 of the 5 multi-line events (see the
prototype results below).

## Impact

High. The security-relevant lines of 4624/4625 (account, domain, source
address, logon type) arrive as header-less fragments that a SIEM cannot tie
back to their event, so detections keyed on those event IDs do not see
them. `framing: newline` is the default, so every TCP/TLS deployment that
uses `rfc5424`, `rfc3164` or `raw` is affected.

## Goals

1. With `framing: newline`, every event is **exactly one frame** on the
   wire, whatever its content, for any receiver.
2. The agent's UDP input treats **one datagram as one event**.
3. **Byte-identical** output for everything that cannot contain CR/LF
   today: single-line events, `format: json`, `framing: octet_counting`,
   and UDP sending.
4. Common field extraction on Windows messages, such as
   `Account Name:\s+(\S+)`, keeps working on the newline wire.

## Non-goals

- Octet-counting on the agent's TCP/TLS input: the octet-counting input fix
  (`2026-11-11-tcp-input-octet-counting.md`).
- Changing the default framing or the default format.
- Tabs. They do not break any framing, and RFC 5424 MSG may contain them.
- CR/LF in header fields (HOSTNAME, APP-NAME, TAG). That is header
  sanitization, handled by the provider-name fix.

## Design

### Part 1 (sender): one frame per event under newline framing

In `frame_batch`'s `Framing::Newline` arm, before appending the trailing
`\n`, rewrite every line break inside the formatted line: each `\r\n`
pair, and each lone `\r` or `\n`. This is the **only** place that writes
newline-framed output, so it covers TCP, TLS and stdout together. It
covers the MSG and the RFC 5424 SD values (including `data_*` values that
now carry CR/LF because of the `EventData` entity fix), since both are
part of the formatted line. Lines without CR/LF take a fast path and stay byte-identical with no
extra allocation (Goal 3). `format: json` never contains a raw CR/LF, so
this is a no-op for it. `Framing::OctetCounting` and the UDP path do not go
through this arm, so they are not touched.

**What the line break becomes is open question 1.** The candidates, applied
to the real 4624 message from the evidence run (203 bytes originally):

| | Option | Wire text (start) | Bytes | `Account Name:\s+(\S+)` | `Account Domain:\s+(\S+)` | Reversible? |
| --- | --- | --- | --- | --- | --- | --- |
| **B** | **one space per line break** *(recommended)* | `…logged on.  Subject: ⇥Security ID:⇥⇥NULL SID  New Logon: …` | 193 | `alice` ✅ | `CORP` ✅ | No |
| A | rsyslog-style octal, `\r`→`#015`, `\n`→`#012` | `…logged on.#015#012#015#012Subject:#015#012⇥Security ID:…` | 263 | `alice#015#012` ❌ | `CORP#015#012#015#012Network` ❌ | Only partly: a literal `#012` in the text is ambiguous |
| C | backslash escape, `\r`→`\r`, `\n`→`\n` as text | `…logged on.\r\n\r\nSubject:\r\n⇥Security ID:…` | 223 | `alice\r\n` ❌ | `CORP\r\n\r\nNetwork` ❌ | No: Windows paths such as `C:\new` become ambiguous |
| D | change nothing; document `octet_counting` / `json` | (still split) | 203 | n/a: the event is split | n/a | n/a |

(⇥ = tab, kept as it is in every option. The regex results were produced
by running the patterns on each variant of the real message.)

Why **B** is recommended:

- It is the only option that keeps simple field extraction correct (Goal 4).
  A and C glue the escape onto the value (`alice#015#012`), which corrupts
  exactly the fields detections use.
- The text stays readable and searchable. It is shorter, never longer.
- What is lost (the line structure) remains available to anyone who needs
  it: `format: json` keeps CR/LF escaped inside JSON, and
  `framing: octet_counting` carries the message unchanged to receivers that
  support it (rsyslog `imtcp`, syslog-ng, and the agent itself after the octet-counting input fix).

When A would be better: if existing SIEM parsers already expect rsyslog's
`#012` convention (for example, Windows logs that used to arrive through an
rsyslog relay with control-character escaping on). That is a deployment
fact only the owner can confirm.

D leaves the default configuration broken, so it is not recommended as the
only change. Its documentation half is part of Part 3 whichever option is
chosen.

### Part 2 (receiver): one UDP datagram is one event

In `run_udp` (`src/inputs/syslog.rs:200-207`), replace the
`for line in text.lines()` loop with a single event per datagram:
`text.trim()`, skip it if empty, otherwise `make_event` once. Embedded
CR/LF stays in `Event.message`, exactly as the sender sent it. This
follows RFC 5426 §3.1 ("Each syslog UDP datagram MUST contain only one
syslog message"). Behaviour for single-line datagrams, including a
trailing `\n`, does not change, because `trim()` removes the trailing line
break just as the per-line `trim()` did.

### Part 3: documentation

- `docs/CONFIGURATION.md:382` and `docs/CONFIGURATION.th.md:381` (the
  `framing` row): state that with `newline`, line breaks inside an event
  are written as one space each (option B), and that `octet_counting` (or
  `format: json`) carries multi-line messages unchanged. Also correct
  "(TCP/TLS)": `framing` applies to `stdout` too, because both share
  `frame_batch`.
- `docs/CONFIGURATION.md:170` and `CONFIGURATION.th.md:169` ("TCP/TLS
  syslog input uses newline framing only"): add that a multi-line message
  arriving on TCP/TLS is split, and point to the octet-counting input fix. Also add that UDP keeps
  one datagram as one event.

## Testing

Unit tests (all cross-platform):

| Test | Location | Asserts | Before the fix |
| --- | --- | --- | --- |
| `newline_framing_keeps_multiline_event_in_one_frame` | `src/outputs/stdout.rs` (new `mod tests`) | `frame_batch` on an event whose message has `\r\n`, a lone `\n` and a lone `\r`: the payload has **exactly one** `\n` (the terminator), and the line breaks became spaces | fails: 3 `\n` (the one from `\r\n`, the lone `\n`, and the terminator) |
| `newline_framing_rewrites_breaks_in_sd_values` | same | an event with `fields.data_X = "a\r\nb"` under `rfc5424`: one frame, `data_X="a b"` | fails |
| `newline_framing_single_line_is_byte_identical` | same | a single-line event's payload equals `format_event(..) + "\n"` | passes (guard) |
| `octet_counting_is_unchanged` | same | a multi-line event under `OctetCounting`: `"<len> <line>"` with the CR/LF intact and `len` the byte length | passes (guard) |
| `json_format_is_unchanged` | same | a multi-line event under `json` + `newline`: equal to `serde_json` output + `\n` | passes (guard) |
| `udp_datagram_is_one_event` | `src/inputs/syslog.rs` tests (next to `udp_receives_rfc3164`) | one datagram with an RFC 5424 line whose MSG has `\r\n`: **one** event, message contains the CR/LF | fails (several events) |
| `udp_trailing_newline_still_one_event` | same | `"<14>… msg\n"`: one event, no empty event | passes (guard) |

End-to-end: re-run the harness's multi-line case (3 runs) with its "intact"
check adapted for option B: compare against the message with CR/LF replaced.
Expected on this branch: SIEM TCP **7 frames for 7 events** and 0
header-less frames, SIEM UDP 5/5, 0 fragment events on agent B, and on agent
B **3/5** multi-line events intact over TCP (replaced message) and UDP
(exact message). The other 2 are the provider-name confounder: each arrives
as **one** event, but with `application` mis-parsed. It becomes 5/5 once the
provider-name fix is merged.

The UDP tests share a new `start_udp()` helper in `src/inputs/syslog.rs`'s
`mod tests`, the same setup as `udp_receives_rfc3164`, so the two new tests
don't repeat it.

### Prototype results (2026-11-11)

Prototype in a throw-away worktree at `4d9f58b`. The code is the Design
above. `frame_batch` gained a `single_line(&str) -> Cow<str>` helper that
borrows when there is no CR/LF.

| Check | Result |
| --- | --- |
| The 7 unit tests before the fix | 3 failed (`…keeps_multiline_event_in_one_frame`: 3 `\n`; `…rewrites_breaks_in_sd_values`: 2 `\n`; `udp_datagram_is_one_event`: got `"line one"`), 4 guards passed |
| After the fix | 9/9 (the 7 new tests + the 2 existing UDP tests) |
| Gate (fmt, clippy `-D warnings`, test `-D warnings`, `+1.98 check`) | clean. 197 lib (190 + 7) + 3 bin + 6 e2e |
| Harness, 3 runs | SIEM TCP **7 frames / 0 header-less** (before: 31 / 24). SIEM UDP 5/5. Fragments on agent B **0** (before: 18 + 18). Agent B multi-line **3/5** TCP and UDP. The 2 misses are the provider-name confounder (`application` = `Service` / `Application`), each one event, not fragments. |
| Field extraction on the SIEM TCP frame of 4624 | `Account Name` = `alice`, `Account Domain` = `CORP`, `Source Network Address` = `10.0.0.15` |

Gate: `cargo fmt --all -- --check`, `RUSTFLAGS="-D warnings" cargo clippy
--all-targets`, `RUSTFLAGS="-D warnings" cargo test --all-targets`,
`RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets`.

## Risks and behaviour changes

1. **The text SIEMs see changes for multi-line events** on newline-framed
   TCP/TLS (and stdout) with `rfc5424`/`rfc3164`/`raw`. Each line break
   becomes the replacement. Parsers that relied on the fragments (unlikely,
   because fragments carry no header) or that expect rsyslog's `#012` will
   need adjusting. Needs a release note.
2. **SD values with line breaks change the same way on that wire** (for
   example `data_*` values that carry `&#13;&#10;`, which the `EventData` entity fix
   now resolves). `format: json` still carries them exactly.
3. **A UDP datagram that contains several LF-separated messages** (a
   non-conforming sender batching messages) becomes one event instead of
   several. RFC 5426 forbids such batching. No sender in this project does
   it, but third-party devices are unknown. See open question 3.
4. **Nothing changes** for `json`, `octet_counting`, UDP sending, or
   single-line events (Goal 3, guarded by tests).

## Rollout

On `develop_fix_bug_known-issues`, as separate commits (spec and plan
first, then):

1. `fix(outputs): keep multi-line events in one frame under newline framing`
   (Part 1 and its tests).
2. `fix(inputs): treat one UDP datagram as one syslog message` (Part 2 and
   its tests).
3. `docs`: CONFIGURATION (en/th) framing notes, and record the fix in the
   issue tracker.

## Out of scope

1. **Octet-counting on the agent's TCP/TLS input** (own spec,
   `2026-11-11-tcp-input-octet-counting.md`). Until
   it lands, agent-to-agent TCP still relies on Part 1.
2. **A config knob for the replacement** (for example
   `newline_replacement: space | octal`). Not proposed for now (open
   question 2).
3. **Collapsing runs of whitespace.** Option B maps each line break to
   exactly one space, so `\r\n\r\n` becomes two spaces. The result is
   predictable and the regex `\s+` handles it.

## Open questions

1. **What should a line break inside an event become under newline
   framing?** Options B (space), A (`#015#012`), C (`\r\n` as text) or D
   (no change, document only).
   Proposed answer: **B**. It is the only option that keeps field
   extraction correct (see the table). Choose A instead only if existing
   SIEM parsers already expect rsyslog's `#012`.
2. **Make it configurable?** Proposed answer: **not now.** Ship one fixed
   behaviour, and add a knob only if a deployment needs the other
   encoding.
3. **UDP: strict one-message-per-datagram, or a heuristic split** (split on
   LF only when the next line starts with `<digits>`)? Proposed answer:
   **strict** (RFC 5426). A heuristic could split a multi-line Windows
   message whose line happens to start with `<`.
4. **Apply Part 1 to `stdout` too?** It shares `frame_batch`. Proposed
   answer: **yes**. Line-based consumers of stdout (container log drivers,
   `| grep`) have the same one-line-per-event expectation.
