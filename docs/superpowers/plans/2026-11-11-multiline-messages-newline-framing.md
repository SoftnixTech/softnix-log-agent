# Multi-line Messages Under Newline Framing Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking. Execute the tasks in order. Every commit-producing task shows a red run before its fix, and ends with the full gate.

**Goal:** A multi-line event stays one event: one frame on the wire under `framing: newline` (each line break becomes one space, which is option B), and one event per UDP datagram on the agent's receiver.

**Architecture:** Two independent changes. (1) `frame_batch` (`src/outputs/stdout.rs`), the single writer of newline-framed output for TCP, TLS and stdout, passes each formatted line through a new `single_line()` helper. (2) `run_udp` (`src/inputs/syslog.rs`) stops splitting a datagram with `text.lines()`.

**Tech Stack:** Rust 2021, `std::borrow::Cow`, existing tokio test scaffolding.

**Spec:** `docs/superpowers/specs/2026-11-11-multiline-messages-newline-framing.md`

## Global Constraints

- Branch `develop_fix_bug_known-issues`. Starting HEAD is `4d9f58b` plus this plan's docs commit (T0). `rust-version = "1.98"`. The local toolchains are 1.99.1 (with clippy) and 1.98.1 (no clippy, so use `check`).
- **Code changes only in** `src/outputs/stdout.rs` (T1) and `src/inputs/syslog.rs` (T2). Docs: `docs/CONFIGURATION.md`, `docs/CONFIGURATION.th.md` (T3). T4 records the fix in the issue tracker. No config-schema, dependency or wire change other than the one intended.
- **Lib test counts on macOS** (bin 3 and e2e 6 never change): 190 at the start, **195** after T1, **197** after T2.
- **Gate** (after T1 and T2; everything must pass):

  ```bash
  cargo fmt --all -- --check
  RUSTFLAGS="-D warnings" cargo clippy --all-targets
  RUSTFLAGS="-D warnings" cargo test --all-targets
  RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets
  ```

  Do **not** set `CARGO_TARGET_DIR`: the `update::apply` preflight tests look for the binary under `<repo>/target/debug`.
- Stage files **by name**, never `git add -A` (`report.html` stays untracked). Every commit message ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **The prototype has already been done** (2026-11-11, throw-away worktree at `4d9f58b`). The code below is exactly the prototype's code after `cargo fmt`, and it passed every step of this plan: red 3/4, then 9/9, gate 197 lib, harness 7 frames / 0 fragments. The prototype's per-commit patches are kept at `/tmp/multiline/p1-outputs.diff` (T1) and `/tmp/multiline/p2-inputs.diff` (T2) as a cross-check. They are optional: the snippets below are authoritative, so the plan works without `/tmp`.

## Rulings

**R-0: The owner's decisions.** Option B (one space per line break) for open question 1. Open questions 2–4 take the spec's proposed answers: no config knob, strict one message per UDP datagram, and `stdout` is covered too because it shares `frame_batch`. If any of these changes:

| Decision changed | Tasks affected |
| --- | --- |
| Option A (`#015#012`) instead of B | T1: the `single_line` body and the expected strings in the 2 failing tests. T3: the doc wording. The guards are unchanged. |
| Add a config knob | New schema field plus a T1 rework. Needs a spec amendment first. |
| Heuristic UDP split | T2: different implementation and an extra test. Needs a spec amendment first. |
| Exclude `stdout` | T1: the change moves out of `frame_batch` into the TCP/TLS call sites. |

**R-1: Sender and receiver are separate commits.** They are independent: either one alone passes the gate. The receiver change is also the one with a compatibility risk for non-conforming third-party senders (spec risk 3), so it can be reverted on its own.

**R-2: The end-to-end harness is a verification step, not a commit.** It lives outside the repo (`/tmp/softnix-smoke.LTIcHO/harness/issues_repro.py`). The adapted multi-line evaluation is given in T3 step 1.

---

## Dependency graph

```text
T0 C1 spec + plan
T1 C2 fix(outputs): single_line in frame_batch         (red 2 → green, 195)
T2 C3 fix(inputs): one UDP datagram = one event         (red 1 → green, 197)
T3 harness re-run (no commit), then C4 docs CONFIGURATION en/th
T4 record the fix in the issue tracker                  (needs the C2/C3 hashes)
```

---

### Task 0: C1, spec and plan

- [ ] **Step 1:** `git status --short` shows exactly `?? docs/superpowers/plans/2026-11-11-multiline-messages-newline-framing.md`, `?? docs/superpowers/specs/2026-11-11-multiline-messages-newline-framing.md` and `?? report.html`. `git log --oneline -1` is `4d9f58b`.
- [ ] **Step 2:**

  ```bash
  git add docs/superpowers/specs/2026-11-11-multiline-messages-newline-framing.md docs/superpowers/plans/2026-11-11-multiline-messages-newline-framing.md
  git commit -m "docs: spec and plan for multi-line messages under newline framing" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
  ```

---

### Task 1: C2, keep a multi-line event in one frame under newline framing

**File:** `src/outputs/stdout.rs`. It has no `mod tests` today.

- [ ] **Step 1: tests first (red).** Append to the end of the file:

  ```rust

  #[cfg(test)]
  mod tests {
      use super::*;

      fn ev(msg: &str) -> Event {
          let mut e = Event::new("test", "test", msg);
          e.hostname = Some("h".into());
          e.application = Some("app".into());
          e
      }

      fn framed(e: Event, format: OutputFormat, framing: Framing) -> String {
          String::from_utf8(frame_batch(&[e], format, framing)).unwrap()
      }

      // --- Newline framing must keep one event in one frame ---

      #[test]
      fn newline_framing_keeps_multiline_event_in_one_frame() {
          let out = framed(
              ev("line one\r\nline two\nline three\rline four"),
              OutputFormat::Rfc5424,
              Framing::Newline,
          );
          assert_eq!(out.matches('\n').count(), 1, "{out:?}");
          assert!(!out.contains('\r'), "{out:?}");
          assert!(
              out.ends_with("line one line two line three line four\n"),
              "{out:?}"
          );
      }

      #[test]
      fn newline_framing_rewrites_breaks_in_sd_values() {
          let mut e = ev("msg");
          e.fields
              .insert("data_X".into(), serde_json::Value::from("a\r\nb"));
          let out = framed(e, OutputFormat::Rfc5424, Framing::Newline);
          assert_eq!(out.matches('\n').count(), 1, "{out:?}");
          assert!(out.contains(r#"data_X="a b""#), "{out:?}");
      }

      // --- Guards: nothing that cannot contain CR/LF changes ---

      #[test]
      fn newline_framing_single_line_is_byte_identical() {
          let e = ev("one line\twith a tab");
          for format in [
              OutputFormat::Rfc5424,
              OutputFormat::Rfc3164,
              OutputFormat::Raw,
              OutputFormat::Json,
          ] {
              let want = format!("{}\n", format_event(&e, format));
              assert_eq!(framed(e.clone(), format, Framing::Newline), want);
          }
      }

      #[test]
      fn octet_counting_is_unchanged() {
          let e = ev("line one\r\nline two");
          let line = format_event(&e, OutputFormat::Rfc5424);
          assert!(line.contains("\r\n"));
          let want = format!("{} {}", line.len(), line);
          assert_eq!(
              framed(e, OutputFormat::Rfc5424, Framing::OctetCounting),
              want
          );
      }

      #[test]
      fn json_format_is_unchanged() {
          let e = ev("line one\r\nline two");
          let want = format!("{}\n", serde_json::to_string(&e).unwrap());
          assert_eq!(want.matches('\n').count(), 1, "serde must escape CR/LF");
          assert_eq!(framed(e, OutputFormat::Json, Framing::Newline), want);
      }
  }
  ```

  Run `cargo test --lib outputs::stdout::tests`. Expected: **2 failed, 3 passed**.
  - `newline_framing_keeps_multiline_event_in_one_frame` fails with `left: 3, right: 1`.
  - `newline_framing_rewrites_breaks_in_sd_values` fails with `left: 2, right: 1`.

  Any other result means stop.

- [ ] **Step 2: the fix (green).**
  - Add `use std::borrow::Cow;` after `use anyhow::Result;`.
  - In `frame_batch`'s `Framing::Newline` arm, change `payload.extend_from_slice(line.as_bytes());` to `payload.extend_from_slice(single_line(&line).as_bytes());`.
  - Insert this between the end of `frame_batch` and `#[cfg(test)]`:

  ```rust
  /// Newline framing (RFC 6587 §3.4.2) ends a frame at LF, so it cannot carry a
  /// line break inside an event: a multi-line message (a Windows event, or an SD
  /// value with CR/LF) would arrive as several header-less frames. Write
  /// each `\r\n`, lone `\r` and lone `\n` as one space instead. Lines without
  /// CR/LF (and every `json` line, where serde already escapes them) are
  /// returned unchanged, without allocating.
  fn single_line(line: &str) -> Cow<'_, str> {
      if !line.contains(['\r', '\n']) {
          return Cow::Borrowed(line);
      }
      let mut out = String::with_capacity(line.len());
      let mut chars = line.chars().peekable();
      while let Some(c) = chars.next() {
          match c {
              '\r' => {
                  if chars.peek() == Some(&'\n') {
                      chars.next();
                  }
                  out.push(' ');
              }
              '\n' => out.push(' '),
              c => out.push(c),
          }
      }
      Cow::Owned(out)
  }
  ```

  Run `cargo test --lib outputs::stdout::tests`. Expected: **5 passed**.
- [ ] **Step 3: cross-check (optional).** If `/tmp/multiline/p1-outputs.diff` exists, `git diff -- src/outputs/stdout.rs | diff - /tmp/multiline/p1-outputs.diff` should differ only in the `index` line.
- [ ] **Step 4: gate.** The expected lib count is **195**.
- [ ] **Step 5: commit.**

  ```bash
  git add src/outputs/stdout.rs
  git commit -F - <<'EOF'
  fix(outputs): keep multi-line events in one frame under newline framing

  Newline framing (RFC 6587 non-transparent framing) ends a frame at LF,
  but frame_batch wrote each formatted line as-is, so a multi-line Windows
  event (4624/4625/4688, 7045, Sysmon) or an SD value containing CR/LF
  became several frames, all but the first without a syslog header, on
  every newline-framed receiver.

  Write each CRLF, lone CR and lone LF inside the line as one space before
  appending the frame's LF. Covers TCP, TLS and stdout (all share
  frame_batch). Lines without CR/LF, json output, octet_counting and UDP
  are byte-identical. A space keeps common field extraction such as
  "Account Name:\s+(\S+)" working, unlike #012-style escaping.

  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  EOF
  ```

  Record `<C2>`.

---

### Task 2: C3, one UDP datagram is one event

**File:** `src/inputs/syslog.rs`.

- [ ] **Step 1: tests first (red).** In `mod tests`, insert directly **before** `    #[tokio::test]\n    async fn tcp_receives_lines() {`:

  ```rust
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

  ```

  Run `cargo test --lib inputs::syslog::tests::udp_`. Expected: **1 failed** (`udp_datagram_is_one_event`: `left: "line one"`) and **3 passed** (the new trailing-newline guard plus the 2 existing UDP tests).

- [ ] **Step 2: the fix (green).** In `run_udp`, replace the per-line loop:

  ```rust
                              for line in text.lines() {
                                  let line = line.trim();
                                  if line.is_empty() { continue; }
                                  let ev = self.make_event(line, &peer);
                                  metrics.events_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                  status.update_input(&self.cfg.id, |s| s.events += 1);
                                  if tx.send(ev).await.is_err() { return; }
                              }
  ```

  with:

  ```rust
                              // RFC 5426 §3.1: one syslog message per datagram.
                              // Do not split on LF: a multi-line message (a
                              // Windows event) is still one event.
                              let line = text.trim();
                              if line.is_empty() { continue; }
                              let ev = self.make_event(line, &peer);
                              metrics.events_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                              status.update_input(&self.cfg.id, |s| s.events += 1);
                              if tx.send(ev).await.is_err() { return; }
  ```

  This code is inside `tokio::select!`, so rustfmt does not reformat it. Keep the indentation shown. The `continue` now applies to the outer receive loop, the same as the allow-list `continue` a few lines above.
  Run `cargo test --lib inputs::syslog::tests::udp_`. Expected: **4 passed**.
- [ ] **Step 3: cross-check (optional)** against `/tmp/multiline/p2-inputs.diff`, as in T1 step 3.
- [ ] **Step 4: gate.** The expected lib count is **197**.
- [ ] **Step 5: commit.**

  ```bash
  git add src/inputs/syslog.rs
  git commit -F - <<'EOF'
  fix(inputs): treat one UDP datagram as one syslog message

  The UDP input split every datagram on LF, so a multi-line message sent
  correctly as one datagram (RFC 5426: one message per datagram) - such
  as a Windows event forwarded by another agent - became one event per
  line, all but the first without a header.

  Trim the datagram and make it one event; embedded line breaks stay in
  the message. Single-line datagrams, with or without a trailing newline,
  behave as before.

  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  EOF
  ```

  Record `<C3>`.

---

### Task 3: end-to-end check, then C4 docs

- [ ] **Step 1: harness (R-2, no commit).** Build and run 3 rounds into a fresh directory. Running the script directly is fine. Do **not** `import` it: it runs `main()` on import. Set `CASE` to the harness's key for its multi-line case.

  ```bash
  cargo build
  R=$(mktemp -d /tmp/multiline-final.XXXX)
  (cd /tmp/softnix-smoke.LTIcHO/harness && python3 -I issues_repro.py "$OLDPWD/target/debug/softnix-log-agent" "$R" 3 >/dev/null 2>&1)
  CASE='<multi-line case key>'
  python3 -I - "$R" "$CASE" <<'EOF'
  import json, re, sys
  R, C = sys.argv[1], sys.argv[2]
  res = json.load(open(f'{R}/results.json'))['runs'][C]
  B = lambda m: re.sub(r'\r\n|\r|\n', ' ', m)
  for i, r in enumerate(res, 1):
      d = f'{R}/{C}/run-{i}'
      sent = [json.loads(l) for l in open(f'{d}/in/win.jsonl')]
      bev = [json.loads(l) for l in open(f'{d}/b.out') if l.startswith('{')]
      ml = [s for s in sent if '\n' in s['message']]
      def rx(src, tag): return [e for e in bev if e['source'].startswith(src) and tag in e.get('message', '')]
      tcp = sum(1 for s in ml if (m := rx('tcpin:', s['message'].split()[0])) and m[0]['message'] == B(s['message']))
      udp = sum(1 for s in ml if (m := rx('udpin:', s['message'].split()[0])) and m[0]['message'] == s['message'])
      print(f"run {i}: SIEM tcp frames={r['siem_tcp_frames']} headerless={r['siem_tcp_headerless_frames']} "
            f"agent tcp={tcp}/{len(ml)} udp={udp}/{len(ml)} fragments tcp={r['agent_tcp_fragments']} udp={r['agent_udp_fragments']}")
  EOF
  ```

  Expected on every run: `frames=7 headerless=0`, `agent tcp=3/5 udp=3/5`, `fragments tcp=0 udp=0`. The 2 misses on the agent side are the provider-name confounder (spec, Evidence). If the provider-name fix has already been merged into this branch, expect 5/5. If the harness is gone, skip this step and say so in the PR description. The unit tests are the permanent regression net.

- [ ] **Step 2: `docs/CONFIGURATION.md`.** Replace line 170:

  ```text
  > TCP/TLS syslog input uses newline framing only.
  ```

  with:

  ```text
  > TCP/TLS syslog input uses newline framing only, so a message that contains
  > a line break arrives as one event per line. Send multi-line messages to it
  > as single lines (the agent's own syslog output does this; see `framing`
  > below) or over UDP. Octet-counting on this input is a known open
  > issue. The UDP input treats each datagram as one event (RFC 5426),
  > line breaks included.
  ```

  Then replace the `framing` row (line 382):

  ```text
  | `framing` | enum | `newline` | `newline` or `octet_counting` (TCP/TLS). |
  ```

  with:

  ```text
  | `framing` | enum | `newline` | `newline` or `octet_counting` (TCP/TLS and `stdout`). With `newline`, each line break inside an event (CR, LF or CRLF) is written as one space, so every event stays on one line; use `octet_counting` or `format: json` to carry multi-line messages unchanged. |
  ```

- [ ] **Step 3: `docs/CONFIGURATION.th.md`.** Replace line 169 (`> syslog input แบบ TCP/TLS ใช้ newline framing เท่านั้น`) with:

  ```text
  > syslog input แบบ TCP/TLS ใช้ newline framing เท่านั้น ข้อความที่มีการขึ้นบรรทัด
  > จึงถูกแยกเป็นหนึ่ง event ต่อบรรทัด ให้ส่งข้อความหลายบรรทัดมาเป็นบรรทัดเดียว
  > (syslog output ของ agent ทำให้อยู่แล้ว ดู `framing` ด้านล่าง) หรือส่งทาง UDP
  > การรองรับ octet-counting ที่ input นี้ยังเป็นปัญหาที่รอแก้ไข
  > ส่วน syslog input แบบ UDP ถือว่าหนึ่ง datagram คือหนึ่ง event (RFC 5426)
  > รวมการขึ้นบรรทัดในข้อความด้วย
  ```

  Then replace the `framing` row (line 381) with:

  ```text
  | `framing` | enum | `newline` | `newline` หรือ `octet_counting` (TCP/TLS และ `stdout`) เมื่อใช้ `newline` การขึ้นบรรทัดภายใน event (CR, LF หรือ CRLF) จะถูกเขียนเป็นช่องว่างหนึ่งตัว ทุก event จึงอยู่บรรทัดเดียว ถ้าต้องการส่งข้อความหลายบรรทัดแบบไม่เปลี่ยน ให้ใช้ `octet_counting` หรือ `format: json` |
  ```

- [ ] **Step 4:** `git diff --stat` shows only the two CONFIGURATION files. Then:

  ```bash
  git add docs/CONFIGURATION.md docs/CONFIGURATION.th.md
  git commit -m "docs(config): document line-break handling under newline framing" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
  ```

---

### Task 4: record the fix in the issue tracker

- [ ] **Step 1:** Record the fix in the issue tracker: fixed in `<C2>` (sender) and `<C3>` (UDP receiver) with option B, a space per line break, and a link to the spec. Agent-to-agent TCP with `octet_counting` still needs the octet-counting input fix (`2026-11-11-tcp-input-octet-counting.md`).
- [ ] **Step 2: final check.** `git status --short` shows only `?? report.html`. `git diff 4d9f58b --stat` lists the spec and plan, `src/outputs/stdout.rs`, `src/inputs/syslog.rs` and both CONFIGURATION files, and nothing else.

---

### Owner follow-up (not part of these commits)

- **Release note** (the repo has no CHANGELOG, so this goes in the GitHub release text): "Multi-line events (e.g. Windows 4624/4625/4688, 7045) sent with `framing: newline` (the default) now stay one event: line breaks inside the event are written as spaces. Use `framing: octet_counting` or `format: json` to keep them. The UDP syslog input now treats each datagram as one event (RFC 5426)."
- **Push / PR / CI**: blocked on write access (see the `AtomicU64::fetch_update` deprecation plan, `2026-11-11-atomic-fetch-update-deprecation.md`, T4).

## Coverage check against the spec

| Spec item | Where |
| --- | --- |
| Goal 1 (one frame per event under newline) | T1 (`…keeps_multiline_event_in_one_frame`, `…rewrites_breaks_in_sd_values`), T3 step 1 (7 frames / 0 header-less) |
| Goal 2 (one datagram = one event) | T2 (`udp_datagram_is_one_event`), T3 step 1 (agent UDP exact message, 0 fragments) |
| Goal 3 (byte-identical elsewhere) | T1 guards (single-line × 4 formats, octet-counting, json), T2 guard (trailing newline), and the existing UDP tests |
| Goal 4 (field extraction) | spec evidence table. The prototype's harness frame gave `alice` / `CORP` / `10.0.0.15`. |
| Part 3 docs (incl. the "(TCP/TLS)" correction) | T3 steps 2–3 |
| Risks 1–3 (SIEM text changes, SD values, non-conforming UDP senders) | the release note (owner follow-up). Risk 3 can be reverted on its own (R-1). |

## Risks

- **The receiver change (T2) affects third-party senders** that pack several LF-separated messages into one datagram. RFC 5426 forbids that, but if a deployment turns out to depend on it, revert `<C3>` alone and reopen the spec's open question 3.
- **The confounder can hide regressions on agent B.** Until the provider-name fix merges, events from providers with spaces are mis-parsed on agent B no matter what. T3 step 1 therefore expects exactly 3/5 there, and any other count means investigate.
