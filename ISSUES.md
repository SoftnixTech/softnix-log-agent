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

| ID | Title | Side | Severity | Priority | Affects third-party receivers? | Status |
|---|---|---|---|---|---|---|
| SYS-1 | Multi-line event messages are split into several events | sender + receiver | **High** | P3 (spec first) | Yes (TCP, newline framing) | **fixed** (`5693b55`, `a508a6d`) |
| SYS-2 | RFC 5424 parser ends STRUCTURED-DATA at the wrong `]` when a value contains `[` | receiver | Medium | P4 | No | **fixed** (`e755072`) |
| SYS-3 | RFC 3164 parser rejects `TAG[PID]` longer than 48 characters | receiver | Medium (was Low) | P4 | No | spec and plan drafted, option A decided |
| SYS-4 | Syslog TCP/TLS input does not decode octet-counting framing | receiver | Medium | P3 (with SYS-1) | No | **fixed** (`fd90159`, `8de82c5`) |
| SYS-5 | Agent self-logs go to stdout, not stderr | agent | Low | P4 | No | spec and plan drafted |
| SYS-6 | SD-ID uses enterprise number 32473 (reserved for documentation) | sender | Low | P5 | Cosmetic / policy | **won't fix** (owner decision 2026-11-11) |
| SYS-7 | CI breaks on Rust ≥ 1.99: `fetch_update` is deprecated under `-D warnings` | build | Medium (blocks CI) | **P1** | n/a | **fixed** (`af3018c`) |
| SYS-8 | Eventlog XML attribute values are not entity-unescaped | input (Windows) | Low | P2 (with SYS-9) | n/a | **fixed** (`cb9586c`) |
| SYS-9 | Eventlog `EventData` values containing XML entities are truncated and split | input (Windows) | **High** | **P2** | Yes (data lost at the source) | **fixed** (`f6fb143`) |
| SYS-10 | CI never builds on the declared MSRV (1.98) | build | Low | P4 | n/a | spec and plan drafted |

Fixes are on branch `develop_fix_bug_known-issues`, which is based on `main`
and not yet merged. The entries above were found and first verified on the
provider-name branch (`f910a8f`). They were **re-verified on 2026-11-11**
on `develop_fix_bug_known-issues`, 3 runs each: SYS-1 at `4d9f58b` (before
its fix), and SYS-2 to SYS-5 after `a508a6d`. The details are in each
issue's spec under `docs/superpowers/specs/`.

See [Fix plan](#fix-plan) at the end of this section for the reasoning, the
PR grouping, and the decisions still needed.

---

### SYS-1 — Multi-line event messages are split into several events

**Status: fixed** in `5693b55` (sender) and `a508a6d` (UDP receiver), branch `develop_fix_bug_known-issues`, not yet merged. Agent-to-agent TCP with `octet_counting` works since SYS-4 (`fd90159`).

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

**Root cause** (line numbers are from before the fix).
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

**Status: fixed** in `e755072` (branch `develop_fix_bug_known-issues`, not yet merged).

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
only outside quotes. Add a regression test using the line above. If the
scan finds no end of the SD (a malformed line, for example an unterminated
quote), fall back to the previous scan, so that line parses exactly as before.
Spec:
`docs/superpowers/specs/2026-11-11-sys2-rfc5424-sd-bracket-in-value.md`
(re-verified 2026-11-11: 4/4 bug cases, 2/2 controls correct). After the
fix, the harness gives 6/6 correct in 3/3 runs.

---

### SYS-3 — RFC 3164 parser rejects `TAG[PID]` longer than 48 characters

**Status: open, spec and plan drafted. Option A decided 2026-11-11** (relax the parser). #7 in the [Fix plan](#fix-plan).

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

**Fix options** (decided 2026-11-11: the first one, relax the parser).
- Relax the parser so it measures only the name part (before `[`) and
  accepts longer names. The sender stays unchanged.
- Cap the sender's TAG so that `TAG[PID]` stays within 48 characters. This
  truncates long provider names on the RFC 3164 wire, and RFC 3164 has no
  structured data to carry the full name.

Either way, the RFC 3164 note in `docs/CONFIGURATION*.md` must be updated
to match.

**Found 2026-11-11: it also happens without spaces, on `main`.** Real
providers with no spaces exceed 48 once `[PID]` is appended:
`Microsoft-Windows-TerminalServices-LocalSessionManager` (60 with
`[1234]`, RDP logon / logoff events 21/23/24/25) and
`…-RemoteConnectionManager` (64, RDP authentication 1149). The spec
therefore proposes raising the severity to **Medium**, and recommends
relaxing the parser (name and PID each up to 128). Spec:
`docs/superpowers/specs/2026-11-11-sys3-rfc3164-long-tag.md`.

---

### SYS-4 — Syslog TCP/TLS input does not decode octet-counting framing

**Status: fixed** in `fd90159` (decoder) and `8de82c5` (`framing` option), branch `develop_fix_bug_known-issues`, not yet merged.

Already recorded in the header spec, under "Out of scope" #1.
`src/inputs/syslog.rs:344` (`:343` before `a508a6d`) only uses
`LinesCodec`. When an agent sends with `framing: octet_counting`, all
events on the connection arrive as one huge message. Smoke rounds 2 and 5
lost 36/36. Re-verified 2026-11-11: 10 events sent, **0 delivered while the
sender stays connected**, then 1 event of 830 bytes after it closes. This
blocks the obvious workaround for SYS-1 between agents.

Incidental finding: `LinesCodec` also **closes the connection on one
invalid UTF-8 byte** (`InvalidData`), dropping everything still buffered.
UDP decodes lossily and does not have this problem.

**Fix.** Detect RFC 6587 octet-counting per frame (`MSG-LEN SP` followed by
`<` or `{`), add an optional input `framing: auto | newline |
octet_counting`, and decode UTF-8 lossily, as UDP does. Spec:
`docs/superpowers/specs/2026-11-11-sys4-tcp-input-octet-counting.md`.
`auto` does not detect octet-counted `raw` text (no `<` or `{` after the
length); such senders need `framing: octet_counting` on the input.

---

### SYS-5 — Agent self-logs go to stdout, not stderr

**Status: open, spec and plan drafted.** #8 in the [Fix plan](#fix-plan). No owner decision needed.

Already recorded in the header spec, under "Out of scope" #2.
`src/main.rs:424` uses `tracing_subscriber::fmt::layer()`, whose writer
defaults to stdout; the comment above it says "stderr". With a
`type: stdout` output, lines such as `WARN web.auth_token was not
configured…` are mixed into the event stream. The mock harness had to
skip them.

**Fix.** `.with_writer(std::io::stderr)` on the fmt layer.
`docs/OPERATIONS.md:132` already documents stderr. Re-verified 2026-11-11:
stdout had 10 lines (2 events + 8 self-log), and stderr had 0 bytes. Spec:
`docs/superpowers/specs/2026-11-11-sys5-self-logs-to-stderr.md`.

---

### SYS-6 — SD-ID uses enterprise number 32473 (reserved for documentation)

**Status: won't fix (owner decision 2026-11-11).** The company has no IANA PEN, so the SD-ID stays `softnix@32473` and no code changes. Nothing is broken by this: the number is a fixed label that no code reads. Its spec and plan were deleted at the owner's request. If a PEN is obtained later, reopen this entry and write new ones.

Already recorded in the header spec, under "Out of scope" #3. RFC 5612
reserves 32473 for documentation examples. A production SD-ID should use
a registered IANA Private Enterprise Number. Changing it is a wire-format
change for SIEM parsers, so it needs an owner decision and a release note.
The SD-ID is also not documented anywhere. The spec recommended making it
configurable, with an unchanged default, and switching the default once a
PEN exists. That is not being done (see the status above).

---

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

**Status: open, spec and plan drafted.** #9 in the [Fix plan](#fix-plan). It can only be verified on a real CI run, which needs push access.

`Cargo.toml:7` declares `rust-version = "1.98"`, but every CI job
(`.github/workflows/ci.yml`: `test-linux`, `test-windows`, `lint`)
installs the latest stable. Nothing checks that the crate still builds on
1.98, so an API newer than the MSRV can merge unnoticed. Found while
writing the SYS-7 spec, where it was checked by hand
(`cargo +1.98 check --all-targets`).

**Fix.** Add an `msrv` job that installs 1.98 and runs
`cargo check --all-targets` (Linux is enough; add Windows if the
`#[cfg(windows)]` code should be covered too). It reads the version from
`Cargo.toml`, and the pinned `dtolnay/rust-toolchain` SHA accepts a
`toolchain:` input (verified). Spec:
`docs/superpowers/specs/2026-11-11-sys10-ci-msrv-job.md`.

---

### Fix plan

First agreed 2026-11-11 (P1–P5), and **revised the same day** after SYS-7,
SYS-9, SYS-8 and SYS-1 were fixed and specs were drafted for every
remaining issue. Later that day the specs were reviewed and revised,
plans were written for SYS-2, SYS-3, SYS-4, SYS-5 and SYS-10 (under
`docs/superpowers/plans/`), SYS-3 was decided (option A) and SYS-6 was
closed as "won't fix". The order weighs, in turn:

1. **Impact:** data lost or corrupted ranks above cosmetic issues.
2. **Whether an owner decision blocks the work:** unblocked work goes
   first.
3. **Effort and dependencies.**

Every fix goes on one branch, `develop_fix_bug_known-issues` (based on
`main`), at the owner's request. Each issue still gets its own spec, plan
and commits.

**Done** (not yet merged):

| # | Issue | Severity | Fixed in | Spec |
|---|---|---|---|---|
| 1 | SYS-7 | Medium (blocked CI) | `af3018c` | `2026-11-11-sys7-atomic-fetch-update-deprecation.md` |
| 2 | SYS-9 | **High** | `f6fb143` (refactor `71b954b`) | `2026-11-11-sys9-eventlog-xml-text-entities.md` |
| 3 | SYS-8 | Low | `cb9586c` | `2026-11-11-sys8-eventlog-xml-attribute-unescape.md` |
| 4 | SYS-1 | **High** | `5693b55`, `a508a6d` (option B) | `2026-11-11-sys1-multiline-messages-newline-framing.md` |
| 5 | SYS-4 | Medium | `fd90159`, `8de82c5` | `2026-11-11-sys4-tcp-input-octet-counting.md` |
| 6 | SYS-2 | Medium | `e755072` | `2026-11-11-sys2-rfc5424-sd-bracket-in-value.md` |

**Remaining, in the order to do them:**

| # | Issue | Severity | Effort | Blocked by | Why this position |
|---|---|---|---|---|---|
| **7** | **SYS-3** | Medium (proposed; was Low) | Small | nothing (option A decided 2026-11-11) | RDP logon providers lose `application`/`process_id` on RFC 3164, even on `main`. A smaller loss than SYS-2 (the event still arrives, in `message`). |
| **8** | **SYS-5** | Low | 1 line + test | nothing | Corrupts the event stream, but only for `stdout` outputs that are consumed as data. |
| **9** | **SYS-10** | Low | Small (CI) | **push access**, to see it run | A guard, not a fix. Every gate so far has checked 1.98 by hand, so nothing is at risk while it waits. It can only be verified on a real CI run. |
| **10** | **SYS-6** | Low | none | **closed: won't fix** (owner decision 2026-11-11, no PEN) | No breakage today, and the company has no PEN to switch to. Nothing to do unless a PEN is obtained. |

The workflow for each one is the same as for SYS-7/8/9/1: review the spec
with a prototype in a throw-away worktree, write a plan, then implement in
TDD commits, followed by a docs commit that marks the entry fixed here.

**Merge order with the provider-name branch**
(`develop_fix_bug_windows-provider-name`):

- **SYS-7 must merge before, or together with, it.** Otherwise its CI fails
  on Rust ≥ 1.99.
- **SYS-3:** its CONFIGURATION note must say the same thing as the
  provider-name branch's RFC 3164 output note when the two meet.
- **SYS-1's end-to-end check** reaches 5/5 on the agent side only once
  provider names with spaces are sanitized by that fix.

**Review units** (the former PR grouping; useful if the branch is reviewed
in parts):

- **A**: SYS-7.
- **B**: SYS-9 + SYS-8.
- **D**: SYS-1 + SYS-4 (framing).
- **C**: SYS-2 + SYS-3 + SYS-5 (receiver parsers and logging).
- **F**: SYS-10 (CI).
- ~~**E**: SYS-6~~ (closed, won't fix).

**Owner decisions needed:**

- ~~**SYS-3:** relax the parser (A) or cap the sender's TAG (B)~~: decided
  2026-11-11, option A (name and PID ≤ 128). The severity is raised to
  Medium as proposed, unless the owner says otherwise.
- ~~**SYS-6:** PEN, option, timing~~: decided 2026-11-11. The company has
  no IANA PEN. Keep `softnix@32473`, no code change (won't fix).
- *Minor, with proposed answers that are used unless vetoed:* ~~**SYS-4**:
  the detection rule (digits + SP + `<`/`{`), an input `framing` option,
  and lossy UTF-8~~ (used as proposed). **SYS-10**: Linux-only MSRV job.
- ~~**SYS-1:** how to handle CR/LF~~: decided 2026-11-11, option B (a
  space).

**Blocker for every PR.** The GitHub account `siwacarn` has pull-only access
to `SoftnixTech/softnix-log-agent` (`"push": false`), so no branch can be
pushed yet. This needs write access from an org admin, or an agreed fork
workflow. Note that a fork of this public repo would also be public.
