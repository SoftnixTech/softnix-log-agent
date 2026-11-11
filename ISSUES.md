# Known issues

The GitHub repository has issues disabled, so this file is the issue
tracker. Each entry has an ID, a status, a symptom, a root cause with
`file:line`, its impact, and fix options. When adding a new entry, use the
next free `SYS-n` ID, add it to the summary table, and update the status
when it is fixed (with the commit that fixes it).

## 2026-11-10 — found during the provider-name fix

Status: **open — recorded only, not fixed**, unless the entry says otherwise.

**Verified 2026-11-11** against commit `f910a8f`. Every entry was
reproduced in 5 out of 5 independent runs with fresh agent processes and
ports, and gave identical results each time. SYS-8 is now confirmed using
the real parser code. The verification also found a new defect (SYS-9) and
corrected the fix options for SYS-7. Full evidence is in `report.html`.

These defects were found while fixing *Windows provider names with spaces
break the RFC 5424 header* (spec:
`docs/superpowers/specs/2026-11-10-syslog-header-sanitization.md`, branch
`develop_fix_bug_windows-provider-name`). **None of them is caused by that
fix, and none is fixed by it.** Each one has a different root cause: the
fix only changes how `src/outputs/format.rs` builds header fields, while
these sit in message framing, the receiver-side parsers, logging or CI.
SYS-3 is the only one that touches the fix's output, and it is not a
regression (see its entry).

How they were found: a mock Windows Event Log run. Event XML for 18 real
providers was mapped to `Event` fields the way `eventlog.rs` does, then sent
through two real agents (A → B), 5 rounds × 38 events, over RFC 5424 and
RFC 3164, TCP and UDP. The harness lives outside the repo, at
`/tmp/softnix-smoke.LTIcHO/harness/winmock.py`. After the fix, the header
on the wire was correct for 190/190 events; the failures below are all
elsewhere.

| ID | Title | Side | Severity | Priority | Affects third-party receivers? |
|---|---|---|---|---|---|
| SYS-1 | Multi-line event messages are split into several events | sender + receiver | **High** | P3 (spec first) | Yes (TCP, newline framing) |
| SYS-2 | RFC 5424 parser ends STRUCTURED-DATA at the wrong `]` when a value contains `[` | receiver | Medium | P4 | No |
| SYS-3 | RFC 3164 parser rejects `TAG[PID]` longer than 48 characters | receiver | Low | P4 | No |
| SYS-4 | Syslog TCP/TLS input does not decode octet-counting framing | receiver | Medium | P3 (with SYS-1) | No |
| SYS-5 | Agent self-logs go to stdout, not stderr | agent | Low | P4 | No |
| SYS-6 | SD-ID uses enterprise number 32473 (reserved for documentation) | sender | Low | P5 | Cosmetic / policy |
| SYS-7 | CI breaks on Rust ≥ 1.99: `fetch_update` is deprecated under `-D warnings` | build | Medium (blocks CI) | **P1** | n/a |
| SYS-8 | Eventlog XML attribute values are not entity-unescaped | input (Windows) | Low | P2 (with SYS-9) | n/a |
| SYS-9 | Eventlog `EventData` values containing XML entities are truncated and split | input (Windows) | **High** | **P2** | Yes (data lost at the source) |
| SYS-10 | CI never builds on the declared MSRV (1.98) | build | Low | P4 | n/a |

See [Fix plan](#fix-plan) at the end of this section for the reasoning, the
PR grouping, and the decisions still needed.

---

### SYS-1 — Multi-line event messages are split into several events

**Status: fixed** in `5693b55` (sender) and `a508a6d` (UDP receiver), branch `develop_fix_bug_known-issues`, not yet merged. Agent-to-agent TCP with `octet_counting` still needs SYS-4.

**Symptom.** Windows renders many event messages with embedded CRLF and
tabs: 4624/4625/4688 (Security), 7045 (Service Control Manager),
Application Error 1000, Sysmon. On the receiver, each line becomes its own
event. Only the first line keeps the syslog header; the rest arrive as
header-less fragments (hostname = the sender's IP, no app, no event_id).

Example from the mock (event 4624, round 1). The receiver's event has only
the first line:

```text
"An account was successfully logged on."
```

…and every remaining line arrives as a separate event:

```text
{"hostname":"127.0.0.1","message":"Service Name:  Contoso Agent", ...}
{"hostname":"127.0.0.1","message":"Service File Name:  \"C:\\Program Files\\Contoso\\agent.exe\" --svc", ...}
```

Mock result: 50/50 multi-line events were split, leaving 38 orphan fragments
per round, on TCP **and** UDP.

**Root cause.**
1. `src/inputs/eventlog.rs` (`format_message`) trims only *trailing*
   `\0`/`\r`/`\n`. Embedded CRLF stays in `Event.message`.
2. `src/outputs/format.rs` puts `ev.message` into the line verbatim, and
   newline framing appends `\n` (`src/outputs/stdout.rs:48`, shared by
   the TCP/TLS syslog sink). One event therefore becomes several lines on
   the wire. Any newline-framed receiver splits it; this is the RFC 6587
   non-transparent-framing limitation.
3. The agent's own receiver also splits:
   - TCP/TLS: `LinesCodec` (`src/inputs/syslog.rs:343`).
   - UDP: each datagram is split with `text.lines()`
     (`src/inputs/syslog.rs:201`), although the sender correctly sends one
     event per datagram (RFC 5426).

**Impact.** The security-relevant details (account, source IP, logon type)
end up in fragments that a SIEM cannot correlate back to the event, so
detections keyed on 4624/4625 do not see them. `framing: newline` is the
default, so every TCP deployment is affected.

**Fix options** (decided 2026-11-11: option B, a space, as described below).
- Sender: on newline framing, escape or replace CR/LF/TAB in MSG, e.g.
  rsyslog-style `#015#012`, `\r\n` → literal `\n`, or replace with a space.
  This changes the text SIEMs see.
- Recommend `framing: octet_counting` for TCP, which depends on SYS-4 for
  agent-to-agent traffic.
- Receiver UDP: treat one datagram as one message (drop the `lines()`
  split, or trim only the trailing newline).

**Fix.** With `framing: newline`, each line break inside an event is
written as one space (`frame_batch`, which covers TCP, TLS and stdout). A
space keeps field extraction such as `Account Name:\s+(\S+)` correct, while
rsyslog-style `#012` breaks it. The agent's UDP input treats one datagram as
one event. `octet_counting` and `format: json` carry multi-line messages
unchanged. Spec:
`docs/superpowers/specs/2026-11-11-sys1-multiline-messages-newline-framing.md`.

---

### SYS-2 — RFC 5424 parser ends STRUCTURED-DATA at the wrong `]` when a value contains `[`

**Symptom.** When an SD PARAM-VALUE contains `[`, the receiver reads the
whole rest of the line as STRUCTURED-DATA and `message` becomes empty.
Per RFC 5424 §6.3.3 only `"`, `\` and `]` must be escaped inside
PARAM-VALUE, so a bare `[` is valid.

Mock example (Microsoft-Windows-Windows Firewall With Advanced Security
2004, rule name `Contoso [TCP 443]`). The line on the wire is valid:

```text
… [softnix@32473 … data_RuleName="Contoso [TCP 443\]" … record_id="1037"] MOCK-1-036 RuleId=… RuleName=Contoso [TCP 443]
```

The receiver produced `message = ""` and
`fields.structured_data = '…record_id="1037"] MOCK-1-036 RuleId=… RuleName=Contoso [TCP 443]'`.
This happened in 6/6 firewall events across the RFC 5424 rounds.

**Root cause.** In `src/pipeline/syslog.rs` (`parse_rfc5424`, the depth
counter starting at line 100), every `[` and `]` is counted, including
those inside a quoted PARAM-VALUE. Only `\x` escapes are skipped. The `[`
inside the value raises the depth to 2, so the closing `]` of the element
brings it back to 1 instead of 0, and the scan runs to the end of the line.

**Impact.** Only when the agent acts as a syslog receiver or relay. It
happens with any sender, including the agent itself, whose SD values
contain `[` (rule names, paths, file names).

**Fix.** Track an "inside quotes" state while scanning: ignore `[`/`]`
inside `"…"`, honour `\"` / `\\` / `\]` escapes there, and count brackets
only outside quotes. Add a regression test using the line above.

---

### SYS-3 — RFC 3164 parser rejects `TAG[PID]` longer than 48 characters

**Symptom.** On the receiver, an RFC 3164 line whose `TAG[PID]` is longer
than 48 characters gets `application = None`, and the whole
`TAG[PID]: msg` ends up in `message`. Mock:
`Microsoft-Windows-Windows_Firewall_With_Advanced_Security[2912]` is 63
characters, and it failed in 4/4 firewall events across the RFC 3164 rounds.

**Root cause.** `src/pipeline/syslog.rs:166` checks
`if !tag.contains(' ') && tag.len() <= 48`, and the length includes the
`[pid]` suffix. The sender deliberately does not cap TAG (plan ruling R-0
in `docs/superpowers/plans/2026-11-10-syslog-header-sanitization.md`), so
the agent's own sender and receiver disagree on the limit.

**Relation to the provider-name fix.** This is not a regression: before the
fix, this name contained spaces and failed the same check anyway. It is
the one remaining gap between the fix's RFC 3164 output and the agent's own
RFC 3164 parser.

**Fix options (owner picks one).**
- Relax the parser so it measures only the name part (before `[`) and
  accepts longer names. The sender stays unchanged.
- Cap the sender's TAG so that `TAG[PID]` stays within 48 characters. This
  truncates long provider names on the RFC 3164 wire, and RFC 3164 has no
  structured data to carry the full name.

Either way, the RFC 3164 note in `docs/CONFIGURATION*.md` must be updated
to match.

---

### SYS-4 — Syslog TCP/TLS input does not decode octet-counting framing

Already recorded in the header spec, under "Out of scope" #1.
`src/inputs/syslog.rs:343` only uses `LinesCodec`. When an agent sends with
`framing: octet_counting`, all events on the connection arrive as one huge
message. Smoke rounds 2 and 5 lost 36/36. This blocks the obvious
workaround for SYS-1 between agents.

**Fix.** Detect RFC 6587 octet-counting (the frame starts with a digit
then SP) per connection, or make it configurable on the input, and decode
`MSG-LEN SP SYSLOG-MSG`.

### SYS-5 — Agent self-logs go to stdout, not stderr

Already recorded in the header spec, under "Out of scope" #2.
`src/main.rs:424` uses `tracing_subscriber::fmt::layer()`, whose writer
defaults to stdout; the comment above it says "stderr". With a
`type: stdout` output, lines such as `WARN web.auth_token was not
configured…` are mixed into the event stream. The mock harness had to
skip them.

**Fix.** `.with_writer(std::io::stderr)` on the fmt layer.

### SYS-6 — SD-ID uses enterprise number 32473 (reserved for documentation)

Already recorded in the header spec, under "Out of scope" #3. RFC 5612
reserves 32473 for documentation examples. A production SD-ID should use
a registered IANA Private Enterprise Number. Changing it is a wire-format
change for SIEM parsers, so it needs an owner decision and a release note.

### SYS-7 — CI breaks on Rust ≥ 1.99: `fetch_update` is deprecated under `-D warnings`

**Status: fixed** in `af3018c` (branch `develop_fix_bug_known-issues`, not yet merged).

`src/engine.rs:251` calls `AtomicU64::fetch_update`, which is deprecated in
favour of `try_update` as of the 1.99 toolchain used locally. CI installs
the current stable toolchain (`dtolnay/rust-toolchain`, stable branch) and
sets `RUSTFLAGS: -D warnings`, so the build fails as soon as CI picks up
1.99. Verified: `RUSTFLAGS="-D warnings" cargo check --all-targets` on
1.99.1 fails with exit 101 at `src/engine.rs:251`.

**Fix.** Replace the call with `AtomicU64::update` (spec:
`docs/superpowers/specs/2026-11-11-sys7-atomic-fetch-update-deprecation.md`).
`try_update` would also work; `update` was chosen because the closure is
infallible. *(Correction: an earlier version
of this entry said the rename would break `rust-version = "1.98"`. That is
wrong.)* In a test crate built with `-D warnings`, 5 runs per toolchain:

| Toolchain | `fetch_update` | `try_update` |
|---|---|---|
| 1.98.1 | builds | **builds** |
| 1.99.1 | fails (deprecated) | builds |

So the rename is safe for the declared MSRV, and no MSRV bump or
`#[allow(deprecated)]` is needed.

Pre-existing; unrelated to the provider-name fix, but it will block that
PR's CI.

### SYS-8 — Eventlog XML attribute values are not entity-unescaped

**Status: fixed** in `cb9586c` (branch `develop_fix_bug_known-issues`, not yet merged).

`src/inputs/eventlog.rs:826` (before the SYS-9 refactor moved the parser to
`src/inputs/eventlog_xml.rs`) reads attribute values with
`String::from_utf8_lossy(&a.value)`, the raw bytes, without
`unescape_value()`.

**Verified** with the real code. `ParsedEvent` and `parse_event_xml`
(`eventlog.rs` lines 798–895) were copied verbatim into a test crate
against `quick-xml` 0.41.0, which runs on macOS. Results, identical in 5/5
runs:

| `<Provider Name='…'>` | `application` produced |
|---|---|
| `Backup &amp; Restore` | `Backup &amp; Restore` |
| `Contoso &quot;Agent&quot;` | `Contoso &quot;Agent&quot;` |
| `O&apos;Brien Tools` | `O&apos;Brien Tools` |

The escaped name is also what `EvtOpenPublisherMetadata` receives, so
message rendering fails for such providers. Low severity: real provider
names rarely contain `&`, `'`, `"`, `<` or `>`.

**Fix.** Use `Attribute::normalized_value(XmlVersion::Implicit1_0)`,
falling back to the raw value on error, and test the cases above.
*(Correction: an earlier version of this entry suggested
`unescape_value()`. That method is deprecated in `quick-xml` 0.41 and
fails the `-D warnings` build.)* Spec:
`docs/superpowers/specs/2026-11-11-sys8-eventlog-xml-attribute-unescape.md`.

---

### SYS-9 — Eventlog `EventData` values containing XML entities are truncated and split

**Status: fixed** in `f6fb143` (refactor `71b954b`, branch `develop_fix_bug_known-issues`, not yet merged).

**Symptom.** Any `<Data>` value that contains an XML entity is cut at the
first entity. The remainder becomes extra, unnamed Data items, and the
escaped characters themselves are lost. Well-formed XML always escapes
`&`, `<` and `>` in text, so command lines, file paths and messages that
contain them are affected. Verified with the real `parse_event_xml`, 5/5
runs. Input:

```text
<Data Name='CommandLine'>cmd.exe /c dir &amp;&amp; echo &quot;done&quot; &gt; out.txt</Data>
```

Result:

```text
data_CommandLine = "cmd.exe /c dir "
(unnamed)        = " echo "
(unnamed)        = "done"
(unnamed)        = " out.txt"
```

Expected: `data_CommandLine = cmd.exe /c dir && echo "done" > out.txt`.
Similarly, `Tom &amp; Jerry` becomes `"Tom "`.

**Root cause.** `quick-xml` 0.41 reports each entity reference as a
separate `Event::GeneralRef`, and splits the surrounding text into
several `Event::Text` events. `parse_event_xml` (`eventlog.rs:851`; line
numbers are from before `71b954b` moved the parser to
`src/inputs/eventlog_xml.rs`) only
handles `Text`, and pushes every text chunk as its own Data item, using
`std::mem::take` on the name for the first chunk only. `GeneralRef`
events fall into `_ => {}` and are dropped. The comment above the `Text`
arm assumes entities arrive inside `Text` and are resolved by
`escape::unescape`; with 0.41 they never are.

**Impact.** High. Sysmon 1 and Security 4688 `CommandLine`, file paths and
URLs lose their tail in `data_*` fields. Those fields are what detections
match on (for example `&&`, `>` redirection, `<` in scripts), and the
values never reach any output intact. When the message DLL is missing,
the fallback message (joined `EventData`) is truncated the same way.

**Fix.** Accumulate the text of the current element across `Text` and
`GeneralRef` events: resolve `amp`, `lt`, `gt`, `quot`, `apos` and
numeric references from `GeneralRef`, and push the Data item once, on
`End`. The parser was first moved to `src/inputs/eventlog_xml.rs`
(`cfg(any(windows, test))`), so its tests run in every CI job and locally,
not only `test-windows`. Spec:
`docs/superpowers/specs/2026-11-11-sys9-eventlog-xml-text-entities.md`.

---

### SYS-10 — CI never builds on the declared MSRV (1.98)

`Cargo.toml:7` declares `rust-version = "1.98"`, but every CI job
(`.github/workflows/ci.yml`: `test-linux`, `test-windows`, `lint`)
installs the latest stable. Nothing checks that the crate still builds on
1.98, so an API newer than the MSRV can merge unnoticed. Found while
writing the SYS-7 spec, where it was checked by hand
(`cargo +1.98 check --all-targets`).

**Fix.** Add an `msrv` job that installs 1.98 and runs
`cargo check --all-targets` (Linux is enough; add Windows if the
`#[cfg(windows)]` code should be covered too).

---

### Fix plan

Agreed 2026-11-11. Ranked by impact, by whether the issue blocks other
work, by effort, and by whether an owner decision is needed first.

| Priority | Issue | Severity | Effort | Owner decision? | Why this position |
|---|---|---|---|---|---|
| **P1** | SYS-7 | Medium | 1 line | No | Blocks CI for every PR, including the provider-name fix waiting to merge. Fixed in `af3018c` (`update`, verified on MSRV 1.98). |
| **P2** | SYS-9 | **High** | Medium | No | Security fields (`CommandLine` for Sysmon and 4688) are lost at the source, whatever the output, and no config works around it. Fixed in `f6fb143`. |
| **P2** | SYS-8 | Low | Small | No | Same parser as SYS-9, so it can be fixed in the same change for almost no extra cost. Fixed in `cb9586c`. |
| **P3** | SYS-1 | **High** | Large | **Yes** | Affects every TCP receiver with newline framing, which is the default. The escaping choice changes what SIEMs see, so it needs a spec. Start the spec in parallel with P1 and P2. Fixed in `5693b55`/`a508a6d` (option B). |
| **P3** | SYS-4 | Medium | Medium | Minor | The agent-to-agent workaround for SYS-1, so design it in the same spec. |
| **P4** | SYS-2 | Medium | Small | No | Only when the agent is a relay, but the whole message is lost. Easy to fix and to test. |
| **P4** | SYS-3 | Low | Small | **Yes** | Choose between relaxing the parser and capping TAG on the sender. Recommended: relax the parser, so no sender data is lost. |
| **P4** | SYS-5 | Low | 1 line | No | Low-risk one-liner that goes in the same PR as SYS-2 and SYS-3. |
| **P4** | SYS-10 | Low | Small (CI) | No | Keeps the declared MSRV honest. Found while fixing SYS-7, where the MSRV had to be checked by hand. |
| **P5** | SYS-6 | Low | Small (code) | **Yes** | Needs a registered IANA PEN, and changes the wire format for every SIEM parser. Ship it in a major release with advance notice. |

**PR grouping.**

1. **PR-A — SYS-7.** Either a small standalone PR, or a commit on
   `develop_fix_bug_windows-provider-name`. It goes first so that CI passes
   and the provider-name fix can merge.
2. **PR-B — SYS-9 + SYS-8** (eventlog parser). The parser's tests now run
   on every platform (`71b954b`).
3. **PR-C — SYS-2 + SYS-3 + SYS-5** (receiver parsers and logging). Three
   small TDD changes. Starts once the owner has chosen the SYS-3 option.
4. **PR-D — SYS-1 + SYS-4** (framing). Spec, then plan, then
   implementation, the same flow as the provider-name fix.
5. **PR-E — SYS-6.** Waits for the owner's PEN decision.

**Owner decisions needed** (these can happen in parallel with PR-A and PR-B):

- **SYS-1:** ~~how to handle CR/LF in MSG on newline framing~~ decided
  2026-11-11: replace each line break with a space (option B).
- **SYS-3:** relax the parser, or cap the sender's TAG.
- **SYS-6:** does the company have an IANA PEN, and when should the SD-ID
  change?

**Blocker for every PR.** The GitHub account `siwacarn` has pull-only access
to `SoftnixTech/softnix-log-agent` (`"push": false`), so no branch can be
pushed yet. This needs write access from an org admin, or an agreed fork
workflow. Note that a fork of this public repo would also be public.
