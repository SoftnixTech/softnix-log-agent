# SYS-4 Octet-Counting on the Syslog TCP/TLS Input Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking. Execute the tasks in order. Every commit-producing task shows a red run before its fix, and ends with the full gate.

**Goal:** The syslog TCP/TLS input decodes RFC 6587 octet-counted frames (one event per frame, delivered while the connection is open, line breaks kept), still accepts newline-terminated lines without any configuration change, and no longer closes a connection on invalid UTF-8.

**Architecture:** One new decoder, `SyslogFrameCodec` (`src/inputs/syslog.rs`), replaces `LinesCodec` in `read_stream`, which serves both TCP and TLS. A new config enum `InputFraming` (`auto` | `newline` | `octet_counting`, `src/config/schema.rs`) selects its mode. `read_stream`'s loop, the idle timeout, the connection cap and `MAX_MSG` are unchanged.

**Tech Stack:** Rust 2021, `tokio_util::codec::Decoder`, `bytes::{Buf, BytesMut}` (both already dependencies), existing tokio test scaffolding.

**Spec:** `docs/superpowers/specs/2026-11-11-sys4-tcp-input-octet-counting.md`

## Global Constraints

- Branch `develop_fix_bug_known-issues`. Starting HEAD is `7abecf9` plus the docs commits of T0. `rust-version = "1.98"`. The local toolchains are stable 1.99.x (with clippy) and 1.98 (no clippy, so use `check`). If `cargo` is not on `PATH`, use `export PATH="$HOME/.cargo/bin:$PATH"`.
- **Code changes only in** `src/config/schema.rs`, `src/inputs/syslog.rs` (T1, T2) and `src/config/mod.rs` (T2, tests only). Docs: `docs/CONFIGURATION.md`, `docs/CONFIGURATION.th.md` (T3) and `ISSUES.md` (T4). No new dependency.
- **Lib test counts on macOS** (bin 3 and e2e 6 never change): 197 at the start, **213** after T1, **215** after T2.
- **Gate** (after T1 and T2; everything must pass):

  ```bash
  cargo fmt --all -- --check
  RUSTFLAGS="-D warnings" cargo clippy --all-targets
  RUSTFLAGS="-D warnings" cargo test --all-targets
  RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets
  ```

  Do **not** set `CARGO_TARGET_DIR`: the `update::apply` preflight tests look for the binary under `<repo>/target/debug`.
- Stage files **by name**, never `git add -A` (`report.html` stays untracked). Every commit message ends with `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`.
- **Prototype status** (2026-11-11, throw-away worktree `/tmp/sys4-proto` at `7abecf9`):
  - **T1 is prototyped.** Its snippets below are the prototype's code after `cargo fmt`. It passed: red 1 (the integration test, see T1 step 1), then 29/29 `inputs::syslog` tests, and the full gate with lib **213**. Its patch is kept at `/tmp/sys4-p1.diff` as an optional cross-check.
  - **T2 is not prototyped.** Its snippets were written but never compiled or run. Treat the first gate of T2 as their verification, and expect small `cargo fmt` differences.
  - The module doc-comment edit in T1 step 2a is not in the prototype either. It is a comment only.

## Rulings

**R-0: The owner's decisions.** The spec's three open questions take their proposed answers, which `ISSUES.md` records as "used unless vetoed": (1) `auto` detects digits + SP + `<`/`{`, (2) the `framing` option is added, (3) invalid UTF-8 is decoded lossily. If one changes:

| Decision changed | Tasks affected |
| --- | --- |
| Detect on "starts with a digit" (rsyslog style) | T1: `octet_header` drops `need_msg_start`. The tests `newline_line_starting_with_digits_stays_a_line`, `partial_header_waits_then_decides` and `explicit_octet_counting_accepts_raw_payload` change. T3 wording. |
| No `framing` option | Drop T2. T1 keeps `InputFraming` private to `src/inputs/syslog.rs`. T3 drops the table row. |
| Keep closing on invalid UTF-8 | T1: `lossy` becomes a fallible conversion, and `invalid_utf8_is_decoded_lossily` inverts. Needs a spec amendment first. |

**R-1: `InputFraming` is defined in T1, and the config field is added in T2.** The spec's rollout says commit 1 has "`auto` as the only behaviour". The codec is simpler to write and test once with all three modes, so T1 adds the enum and the whole codec, with `read_stream` hard-wired to `InputFraming::Auto`. T2 only adds the field and wires it. Behaviour after T1 is exactly "auto only", as the spec asks. A `pub` enum with variants used only in tests raises no dead-code warning, because the crate is a library.

**R-2: The codec skips leading CR/LF in every mode.** The spec says `newline` is "exactly today's `LinesCodec` behaviour". `LinesCodec` yields empty lines and `read_stream` then skips them, so skipping them in the codec gives the same events.

**R-3: The end-to-end harness is a verification step, not a commit.** It lives outside the repo (`/tmp/softnix-smoke.LTIcHO/harness/issues_repro.py`) and `/tmp` can be cleared. If it is gone, skip T3 step 1 and say so in the commit: T1's integration test covers the same behaviour.

---

## Dependency graph

```text
T0 C0 docs: revised fix plan in ISSUES.md (already in the working tree)
   C1 docs: spec + plan
T1 C2 feat(inputs): decode octet-counted frames      (red 1 → green, lib 213)
T2 C3 feat(config): framing option on syslog inputs  (red = does not compile → green, lib 215)
T3 harness re-run (no commit), then C4 docs CONFIGURATION en/th
T4 C5 ISSUES.md: SYS-4 fixed                         (needs the C2/C3 hashes)
```

---

### Task 0: C0 and C1, pending docs

- [ ] **Step 1:** `git status --short` shows ` M ISSUES.md`, the untracked specs and plans for SYS-2/3/4/5/10, and `?? report.html`. `git log --oneline -1` is `7abecf9`.
- [ ] **Step 2:** The `ISSUES.md` change is the tracker update made before this plan: the revised order, specs and plans drafted, SYS-3 decided (option A) and SYS-6 closed as "won't fix". Commit it alone (SYS-6 has no spec or plan any more):

  ```bash
  git add ISSUES.md
  git commit -m "docs: revise the fix plan, decide SYS-3 and close SYS-6" -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

- [ ] **Step 3:**

  ```bash
  git add docs/superpowers/specs/2026-11-11-sys4-tcp-input-octet-counting.md docs/superpowers/plans/2026-11-11-sys4-tcp-input-octet-counting.md
  git commit -m "docs: spec and plan for SYS-4 octet-counting on the syslog TCP input" -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

  The other issues' specs and plans stay untracked. Each is committed by its own plan's T0.

---

### Task 1: C2, decode octet-counted frames

**Files:** `src/config/schema.rs`, `src/inputs/syslog.rs`.

- [ ] **Step 1: the integration test first (red).** In `src/inputs/syslog.rs`'s `mod tests`, insert directly **before** `    #[test]\n    fn make_event_preserves_raw_message_when_enabled() {`:

```rust
    /// SYS-4: octet-counted frames are delivered one event per frame while
    /// the connection is still open, and a line break inside a frame stays.
    #[tokio::test]
    async fn tcp_receives_octet_counted_frames() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let input = SyslogInput::new(&test_cfg(SyslogProtocol::Tcp, 0));
        let (raw_tx, mut rx) = mpsc::channel(16);
        let tx = EventSender::with_budget(raw_tx, 16 * 1024 * 1024);
        let status = Arc::new(StatusRegistry::default());
        status.set_input(InputStatus {
            id: "test".into(),
            ..Default::default()
        });
        let metrics = Arc::new(Metrics::default());
        let cancel = CancellationToken::new();
        tokio::spawn(input.run_tcp(listener, None, tx, status, metrics, cancel.clone()));

        let mut payload = Vec::new();
        for msg in ["first", "line a\r\nline b", "third"] {
            let frame = format!("<165>1 2026-06-10T22:14:15Z h1 app 1 - - {msg}");
            payload.extend_from_slice(format!("{} {frame}", frame.len()).as_bytes());
        }
        use tokio::io::AsyncWriteExt;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(&payload).await.unwrap();
        conn.flush().await.unwrap();

        // `conn` stays open: every event must arrive without waiting for EOF.
        for want in ["first", "line a\r\nline b", "third"] {
            let ev = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                .await
                .expect("an octet-counted frame must be delivered before the sender closes")
                .unwrap();
            assert_eq!(ev.message, want);
            assert_eq!(ev.application.as_deref(), Some("app"));
        }
        drop(conn);
        cancel.cancel();
    }
```

  Run `cargo test --lib tcp_receives_octet`. Expected: **FAILED** on the first `assert_eq!(ev.message, want)`, with `left` being `46 <165>1 … first55 <165>1 … line a`: today's `LinesCodec` only yields at the `\n` inside the second frame.

- [ ] **Step 2a: the enum and the imports.** In `src/config/schema.rs`, insert directly **before** the `#[derive(Debug, Clone, Deserialize, Serialize)]` line of `pub struct SyslogInputConfig`:

```rust
/// How a TCP/TLS syslog input splits the byte stream into messages
/// (RFC 6587). UDP ignores it: one datagram is one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InputFraming {
    /// Detect per frame: `MSG-LEN SP` followed by `<` or `{` is an
    /// octet-counted frame, anything else is a newline-terminated line.
    #[default]
    Auto,
    /// Newline-terminated lines only, with no detection.
    Newline,
    /// Every frame is `MSG-LEN SP MSG`, whatever the message starts with.
    OctetCounting,
}
```

  In `src/inputs/syslog.rs`:
  - Replace the module doc comment's second line `//! parsing and newline framing for stream transports.` with `//! parsing. Stream transports accept newline and octet-counted framing (RFC 6587).`
  - `use crate::config::{parse_ip_net, SyslogInputConfig, SyslogProtocol};` becomes `use crate::config::{parse_ip_net, InputFraming, SyslogInputConfig, SyslogProtocol};`
  - Add `use bytes::{Buf, BytesMut};` after `use anyhow::{Context, Result};`
  - `use tokio_util::codec::{FramedRead, LinesCodec};` becomes `use tokio_util::codec::{Decoder, FramedRead};`

- [ ] **Step 2b: the codec (green).** In `src/inputs/syslog.rs`, insert directly **after** `const MAX_MSG: usize = 64 * 1024;` and its blank line:

```rust
/// Longest MSG-LEN the decoder reads. Six digits cover `MAX_MSG` (65536).
const MAX_LEN_DIGITS: usize = 6;

/// What the start of the buffer says about RFC 6587 octet-counting.
enum OctetHeader {
    /// `MSG-LEN SP` is complete: `header_len` bytes of header, then a
    /// message of `msg_len` bytes.
    Frame { header_len: usize, msg_len: usize },
    /// Still a possible header prefix (such as `12`); more bytes decide.
    Undecided,
    /// Not an octet-counting header.
    No,
}

/// Read `MSG-LEN SP` at the start of `buf` (which must not be empty).
/// MSG-LEN is 1 to `MAX_LEN_DIGITS` ASCII digits with no leading zero. With
/// `need_msg_start`, the byte after the space must also be `<` (a syslog
/// PRI) or `{` (JSON): that is what tells a real header from a plain-text
/// line that happens to begin with a number, such as `200 OK`.
fn octet_header(buf: &[u8], need_msg_start: bool) -> OctetHeader {
    let digits = buf
        .iter()
        .take(MAX_LEN_DIGITS + 1)
        .take_while(|b| b.is_ascii_digit())
        .count();
    if digits == 0 || digits > MAX_LEN_DIGITS || buf[0] == b'0' {
        return OctetHeader::No;
    }
    match buf.get(digits) {
        None => return OctetHeader::Undecided,
        Some(b' ') => {}
        Some(_) => return OctetHeader::No,
    }
    if need_msg_start {
        match buf.get(digits + 1) {
            None => return OctetHeader::Undecided,
            Some(b'<' | b'{') => {}
            Some(_) => return OctetHeader::No,
        }
    }
    let msg_len = buf[..digits]
        .iter()
        .fold(0usize, |n, d| n * 10 + usize::from(d - b'0'));
    OctetHeader::Frame {
        header_len: digits + 1,
        msg_len,
    }
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn too_long(len: usize, max: usize) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("syslog frame of {len} bytes exceeds the {max}-byte limit"),
    )
}

/// Frame decoder for the TCP/TLS input (RFC 6587): octet-counted frames
/// (`MSG-LEN SP MSG`, §3.4.1) and newline-terminated lines (§3.4.2), detected
/// per frame in `auto` mode so both can share one connection.
///
/// Unlike `LinesCodec`, which this replaces, invalid UTF-8 is decoded lossily
/// (as the UDP path does) instead of ending the connection, so one
/// legacy-encoded byte cannot drop everything still buffered behind it.
struct SyslogFrameCodec {
    mode: InputFraming,
    max: usize,
    /// How much of the pending newline frame was already searched for `\n`.
    scanned: usize,
}

impl SyslogFrameCodec {
    fn new(mode: InputFraming, max: usize) -> Self {
        Self {
            mode,
            max,
            scanned: 0,
        }
    }

    fn header(&self, buf: &[u8]) -> OctetHeader {
        match self.mode {
            InputFraming::Newline => OctetHeader::No,
            InputFraming::Auto => octet_header(buf, true),
            InputFraming::OctetCounting => octet_header(buf, false),
        }
    }

    /// One newline-terminated line, without its `\n` and one trailing `\r`.
    /// A line longer than `max` is an error, as with `LinesCodec`.
    fn decode_line(&mut self, buf: &mut BytesMut) -> std::io::Result<Option<String>> {
        let from = self.scanned.min(buf.len());
        match buf[from..].iter().position(|b| *b == b'\n') {
            Some(off) => {
                let end = from + off;
                self.scanned = 0;
                if end > self.max {
                    return Err(too_long(end, self.max));
                }
                let line = buf.split_to(end + 1);
                let line = &line[..end];
                Ok(Some(lossy(line.strip_suffix(b"\r").unwrap_or(line))))
            }
            None if buf.len() > self.max => Err(too_long(buf.len(), self.max)),
            None => {
                self.scanned = buf.len();
                Ok(None)
            }
        }
    }
}

impl Decoder for SyslogFrameCodec {
    type Item = String;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> std::io::Result<Option<String>> {
        // Between frames, skip CR/LF: an empty line, or the LF some senders
        // add after an octet-counted frame.
        if self.scanned == 0 {
            let skip = buf
                .iter()
                .take_while(|b| matches!(**b, b'\r' | b'\n'))
                .count();
            buf.advance(skip);
        }
        if buf.is_empty() {
            return Ok(None);
        }
        match self.header(buf) {
            OctetHeader::Frame {
                header_len,
                msg_len,
            } => {
                if msg_len > self.max {
                    return Err(too_long(msg_len, self.max));
                }
                let total = header_len + msg_len;
                if buf.len() < total {
                    buf.reserve(total - buf.len());
                    return Ok(None);
                }
                buf.advance(header_len);
                Ok(Some(lossy(&buf.split_to(msg_len))))
            }
            OctetHeader::Undecided => Ok(None),
            OctetHeader::No if self.mode == InputFraming::OctetCounting => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed octet-counting header (expected `MSG-LEN SP`)",
                ))
            }
            OctetHeader::No => self.decode_line(buf),
        }
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> std::io::Result<Option<String>> {
        if let Some(frame) = self.decode(buf)? {
            return Ok(Some(frame));
        }
        if buf.is_empty() {
            return Ok(None);
        }
        // What is left is a frame the sender never finished.
        let truncated_octet = match self.header(buf) {
            OctetHeader::Frame { .. } => true,
            OctetHeader::Undecided => self.mode == InputFraming::OctetCounting,
            OctetHeader::No => false,
        };
        self.scanned = 0;
        let rest = buf.split_to(buf.len());
        if truncated_octet {
            // Not a valid message: drop it rather than deliver a partial event.
            tracing::debug!(
                "syslog: dropping a truncated octet-counted frame ({} bytes) at end of stream",
                rest.len()
            );
            return Ok(None);
        }
        // A last line without its `\n` (or a lone header prefix such as
        // `12 `) is delivered, as `LinesCodec` did.
        let line = rest.strip_suffix(b"\r").unwrap_or(&rest);
        Ok(Some(lossy(line)))
    }
}
```

  In `read_stream`, replace `let mut frames = FramedRead::new(stream, LinesCodec::new_with_max_length(MAX_MSG));` with:

```rust
        let mut frames =
            FramedRead::new(stream, SyslogFrameCodec::new(InputFraming::Auto, MAX_MSG));
```

- [ ] **Step 3: the codec unit tests.** In `mod tests`, insert directly **after** the test added in step 1 (before `make_event_preserves_raw_message_when_enabled`):

```rust
    fn codec(mode: InputFraming) -> SyslogFrameCodec {
        SyslogFrameCodec::new(mode, MAX_MSG)
    }

    /// Decode until the codec asks for more bytes.
    fn decode_all(c: &mut SyslogFrameCodec, buf: &mut BytesMut) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(frame) = c.decode(buf).unwrap() {
            out.push(frame);
        }
        out
    }

    #[test]
    fn octet_frames_decode_one_per_frame() {
        let mut buf = BytesMut::from(&b"12 <14>1 a b\r\nc5 <1>xy"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["<14>1 a b\r\nc", "<1>xy"]
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn octet_frame_split_across_reads() {
        let mut c = codec(InputFraming::Auto);
        let mut buf = BytesMut::from(&b"1"[..]);
        assert_eq!(c.decode(&mut buf).unwrap(), None);
        buf.extend_from_slice(b"2 <14>1");
        assert_eq!(c.decode(&mut buf).unwrap(), None);
        buf.extend_from_slice(b" a b\r\nc");
        assert_eq!(
            c.decode(&mut buf).unwrap().as_deref(),
            Some("<14>1 a b\r\nc")
        );
        assert_eq!(c.decode(&mut buf).unwrap(), None);
    }

    #[test]
    fn mixed_frames_on_one_connection() {
        let mut buf = BytesMut::from(&b"<13>line one\n5 <1>xy<13>line two\n"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["<13>line one", "<1>xy", "<13>line two"]
        );
    }

    #[test]
    fn newline_line_starting_with_digits_stays_a_line() {
        let mut buf = BytesMut::from(&b"200 OK fine\n"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["200 OK fine"]
        );
    }

    #[test]
    fn crlf_line_ending_is_stripped() {
        let mut buf = BytesMut::from(&b"<13>dos line\r\n"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["<13>dos line"]
        );
    }

    #[test]
    fn octet_frame_too_long_is_an_error() {
        let mut buf = BytesMut::from(&b"70000 <14>1 x"[..]);
        assert!(codec(InputFraming::Auto).decode(&mut buf).is_err());
    }

    #[test]
    fn invalid_utf8_is_decoded_lossily() {
        let mut buf = BytesMut::from(&b"<13>caf\xff one\n10 <13>caf\xff 2"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["<13>caf\u{fffd} one", "<13>caf\u{fffd} 2"]
        );
    }

    #[test]
    fn explicit_octet_counting_accepts_raw_payload() {
        let mut buf = BytesMut::from(&b"5 hello"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::OctetCounting), &mut buf),
            ["hello"]
        );
        // The same bytes in `auto` are a line: no `<` or `{` after the header.
        let mut buf = BytesMut::from(&b"5 hello\n"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["5 hello"]
        );
    }

    #[test]
    fn explicit_octet_counting_rejects_bad_header() {
        let mut buf = BytesMut::from(&b"hello\n"[..]);
        assert!(codec(InputFraming::OctetCounting).decode(&mut buf).is_err());
    }

    #[test]
    fn explicit_newline_mode_is_linescodec() {
        let mut buf = BytesMut::from(&b"12 <14>1 a b\n"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Newline), &mut buf),
            ["12 <14>1 a b"]
        );
    }

    #[test]
    fn partial_header_waits_then_decides() {
        let mut c = codec(InputFraming::Auto);
        let mut buf = BytesMut::from(&b"12"[..]);
        assert_eq!(c.decode(&mut buf).unwrap(), None);
        buf.extend_from_slice(b" ");
        assert_eq!(c.decode(&mut buf).unwrap(), None);
        buf.extend_from_slice(b"OK\n");
        assert_eq!(c.decode(&mut buf).unwrap().as_deref(), Some("12 OK"));
    }

    #[test]
    fn trailing_lf_after_octet_frame_is_skipped() {
        let mut buf = BytesMut::from(&b"5 <1>xy\n5 <1>zz"[..]);
        assert_eq!(
            decode_all(&mut codec(InputFraming::Auto), &mut buf),
            ["<1>xy", "<1>zz"]
        );
    }

    #[test]
    fn newline_line_too_long_is_an_error() {
        let mut c = codec(InputFraming::Auto);
        // Exactly MAX_MSG bytes with no `\n` yet may still grow into a line...
        let mut buf = BytesMut::from(&vec![b'x'; MAX_MSG][..]);
        assert_eq!(c.decode(&mut buf).unwrap(), None);
        // ...one more byte may not.
        buf.extend_from_slice(b"x");
        assert!(c.decode(&mut buf).is_err());
    }

    #[test]
    fn eof_drops_incomplete_octet_frame() {
        let mut buf = BytesMut::from(&b"12 <14>1 a"[..]);
        assert_eq!(
            codec(InputFraming::Auto).decode_eof(&mut buf).unwrap(),
            None
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn eof_returns_pending_line_and_undecided_prefix() {
        let mut c = codec(InputFraming::Auto);
        let mut buf = BytesMut::from(&b"last line"[..]);
        assert_eq!(
            c.decode_eof(&mut buf).unwrap().as_deref(),
            Some("last line")
        );
        assert_eq!(c.decode_eof(&mut buf).unwrap(), None);

        let mut buf = BytesMut::from(&b"12 "[..]);
        assert_eq!(c.decode_eof(&mut buf).unwrap().as_deref(), Some("12 "));
    }
```

- [ ] **Step 4:** `cargo test --lib inputs::syslog` gives **29 passed** (13 before, +1 integration, +15 codec).
- [ ] **Step 5: cross-check (optional).** If `/tmp/sys4-p1.diff` exists, `git diff -- src/config/schema.rs src/inputs/syslog.rs | diff - /tmp/sys4-p1.diff` should differ only in the `index` lines and the module doc comment.
- [ ] **Step 6: gate.** The expected lib count is **213**.
- [ ] **Step 7: commit.**

  ```bash
  git add src/config/schema.rs src/inputs/syslog.rs
  git commit -m "feat(inputs): decode octet-counted syslog frames on TCP/TLS" -m "The TCP/TLS input only understood newline framing, so a sender using RFC 6587 octet-counting (the agent's own framing: octet_counting included) delivered nothing until it closed, and then one corrupt event (SYS-4).

SyslogFrameCodec replaces LinesCodec. It detects each frame: MSG-LEN SP followed by '<' or '{' is an octet-counted frame, anything else is a newline-terminated line. Invalid UTF-8 is now decoded lossily, as on UDP, instead of closing the connection." -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

---

### Task 2: C3, the `framing` option

**Files:** `src/config/schema.rs`, `src/inputs/syslog.rs`, `src/config/mod.rs` (tests). **Not prototyped**, see Global Constraints.

- [ ] **Step 1: tests first (red).** In `src/inputs/syslog.rs`'s `mod tests`, in `test_cfg`, add `framing: InputFraming::Auto,` after `format: SyslogFormat::Auto,`. Then insert directly **before** `    fn codec(mode: InputFraming) -> SyslogFrameCodec {`:

```rust
    /// SYS-4: `framing: octet_counting` on the input carries payloads that
    /// `auto` cannot detect, because they do not start with `<` or `{` (the
    /// agent's own `format: raw` output is one).
    #[tokio::test]
    async fn tcp_explicit_octet_counting_receives_raw_payloads() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut cfg = test_cfg(SyslogProtocol::Tcp, 0);
        cfg.framing = InputFraming::OctetCounting;
        cfg.format = SyslogFormat::Raw;
        let input = SyslogInput::new(&cfg);
        let (raw_tx, mut rx) = mpsc::channel(16);
        let tx = EventSender::with_budget(raw_tx, 16 * 1024 * 1024);
        let status = Arc::new(StatusRegistry::default());
        status.set_input(InputStatus {
            id: "test".into(),
            ..Default::default()
        });
        let metrics = Arc::new(Metrics::default());
        let cancel = CancellationToken::new();
        tokio::spawn(input.run_tcp(listener, None, tx, status, metrics, cancel.clone()));

        use tokio::io::AsyncWriteExt;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"5 hello9 two\nlines").await.unwrap();
        conn.flush().await.unwrap();

        for want in ["hello", "two\nlines"] {
            let ev = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                .await
                .expect("a raw octet-counted frame must be delivered before the sender closes")
                .unwrap();
            assert_eq!(ev.message, want);
        }
        drop(conn);
        cancel.cancel();
    }
```

  In `src/config/mod.rs`'s `mod tests`, insert directly **after** the closing `}` of `syslog_input_defaults_for_new_knobs`:

```rust

    /// SYS-4: `framing` on a syslog input defaults to `auto`, accepts the
    /// three documented values, and rejects anything else at load time.
    #[test]
    fn syslog_input_framing_option() {
        let (cfg, _w) = parse(SAMPLE).unwrap();
        assert_eq!(cfg.inputs.syslog[0].framing, InputFraming::Auto);

        let yaml = |framing: &str| {
            format!(
                "inputs:\n  syslog:\n    - id: in\n      protocol: tcp\n      port: 5514\n      framing: {framing}\noutputs:\n  - id: console\n    type: stdout\n"
            )
        };
        for (value, want) in [
            ("auto", InputFraming::Auto),
            ("newline", InputFraming::Newline),
            ("octet_counting", InputFraming::OctetCounting),
        ] {
            let (cfg, _w) = parse(&yaml(value)).unwrap();
            assert_eq!(cfg.inputs.syslog[0].framing, want, "framing: {value}");
        }
        assert!(parse(&yaml("lines")).is_err());
    }
```

  Run `cargo test --lib framing`. Expected: **does not compile** (`no field framing on type SyslogInputConfig`). That is the red run. `InputFraming` reaches `src/config/mod.rs`'s tests through `use super::*` (`pub use schema::*`).

- [ ] **Step 2: the field and the wiring (green).** In `src/config/schema.rs`, in `SyslogInputConfig`, insert after `pub format: SyslogFormat,`:

```rust
    /// TCP/TLS only (a UDP datagram is always one message): how the byte
    /// stream is split into messages. The default, `auto`, accepts both
    /// newline-terminated lines and RFC 6587 octet-counted frames.
    #[serde(default)]
    pub framing: InputFraming,
```

  In `src/inputs/syslog.rs`'s `read_stream`, change `SyslogFrameCodec::new(InputFraming::Auto, MAX_MSG)` to `SyslogFrameCodec::new(self.cfg.framing, MAX_MSG)`.

- [ ] **Step 3:** `grep -rn "SyslogInputConfig {" src tests` shows only `schema.rs` (the definition) and the two helpers in `src/inputs/syslog.rs` (`test_cfg`, and `test_cfg_keep_raw`, which uses `..test_cfg(..)`). No other literal needs the field.
- [ ] **Step 4: gate.** The expected lib count is **215**. `parse_syslog_into`'s `Raw` arm does nothing (checked at `7abecf9`), so `message` stays the frame as received and the integration test's second message is `two\nlines`.
- [ ] **Step 5: commit.**

  ```bash
  git add src/config/schema.rs src/inputs/syslog.rs src/config/mod.rs
  git commit -m "feat(config): add framing option to syslog inputs" -m "inputs.syslog[].framing: auto (default) | newline | octet_counting, for TCP/TLS. newline turns per-frame detection off. octet_counting accepts any payload, which auto cannot detect when it does not start with '<' or '{' (octet-counted raw text)." -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

---

### Task 3: end-to-end check, then C4 docs

- [ ] **Step 1: harness (R-3, no commit).** Run the script directly. Do **not** `import` it: it runs `main()` on import.

  ```bash
  cargo build
  mkdir -p /tmp/sys4-runs
  python3 /tmp/softnix-smoke.LTIcHO/harness/issues_repro.py "$PWD/target/debug/softnix-log-agent" /tmp/sys4-runs 3
  python3 -c 'import json; [print(r) for r in json.load(open("/tmp/sys4-runs/results.json"))["runs"]["SYS-4"]]'
  ```

  Expected in each of the 3 runs: `siem_frames_decoded: 10`, `agent_events_while_sender_connected: 10` (was 0), `agent_events_after_sender_closed: 10` (was 1), `agent_first_event_message_len` well under 100 (was 830) and `raw_events: 10`. The script also runs the other issues' cases. Ignore them here.

- [ ] **Step 2: `docs/CONFIGURATION.md`.** In the `inputs.syslog` table, insert after the `format` row:

  ```markdown
  | `framing` | enum | `auto` | TCP/TLS only (ignored for UDP). `auto`, `newline` or `octet_counting`. `auto` detects each frame: digits, a space, then `<` or `{` is an RFC 6587 octet-counted frame (`MSG-LEN SP MSG`), and anything else is a newline-terminated line. `newline` turns detection off. `octet_counting` requires every frame to be `MSG-LEN SP MSG` whatever the message starts with, and closes the connection on a malformed header. A frame longer than 64 KiB closes the connection. Invalid UTF-8 is replaced with U+FFFD and does not close the connection. |
  ```

  Replace the blockquote that starts `> TCP/TLS syslog input uses newline framing only` (6 lines) with:

  ```markdown
  > The TCP/TLS syslog input accepts both RFC 6587 framings, detected per
  > frame (`framing: auto`): newline-terminated lines and octet-counted
  > frames. An octet-counted frame is one event with its line breaks kept, so
  > a sender using `framing: octet_counting` (the agent's own syslog output
  > included) delivers multi-line messages unchanged. With newline framing, a
  > message that contains a line break still arrives as one event per line.
  > The agent's own output avoids that by writing each line break as a space
  > (see `framing` under `outputs`). `auto` recognises an octet-counted frame
  > by the `<` or `{` after its length, so a sender of octet-counted `raw`
  > text needs `framing: octet_counting` on this input. The UDP input treats
  > each datagram as one event (RFC 5426), line breaks included.
  ```

- [ ] **Step 3: `docs/CONFIGURATION.th.md`.** Insert after the `format` row:

  ```markdown
  | `framing` | enum | `auto` | เฉพาะ TCP/TLS (UDP ไม่ใช้ค่านี้) เลือกได้ `auto`, `newline` หรือ `octet_counting` — `auto` ตรวจทีละ frame: ตัวเลข ตามด้วยช่องว่าง แล้วตามด้วย `<` หรือ `{` คือ frame แบบ octet-counting ตาม RFC 6587 (`MSG-LEN SP MSG`) นอกนั้นถือเป็นบรรทัดที่จบด้วย newline — `newline` ปิดการตรวจ — `octet_counting` บังคับให้ทุก frame เป็น `MSG-LEN SP MSG` ไม่ว่าข้อความจะขึ้นต้นด้วยอะไร และปิด connection เมื่อ header ผิดรูป — frame ที่ยาวเกิน 64 KiB จะปิด connection — UTF-8 ที่ไม่ถูกต้องจะถูกแทนด้วย U+FFFD โดยไม่ปิด connection |
  ```

  Replace the blockquote that starts `> syslog input แบบ TCP/TLS ใช้ newline framing เท่านั้น` (6 lines) with:

  ```markdown
  > syslog input แบบ TCP/TLS รับ framing ของ RFC 6587 ได้ทั้งสองแบบ โดยตรวจ
  > ทีละ frame (`framing: auto`): บรรทัดที่จบด้วย newline และ frame แบบ
  > octet-counting — frame แบบ octet-counting หนึ่ง frame คือหนึ่ง event และ
  > คงการขึ้นบรรทัดไว้ ผู้ส่งที่ใช้ `framing: octet_counting` (รวมถึง syslog
  > output ของ agent เอง) จึงส่งข้อความหลายบรรทัดมาได้โดยไม่ถูกเปลี่ยน — ถ้าใช้
  > newline framing ข้อความที่มีการขึ้นบรรทัดจะยังถูกแยกเป็นหนึ่ง event ต่อ
  > บรรทัด ซึ่ง output ของ agent เลี่ยงโดยเขียนการขึ้นบรรทัดเป็นช่องว่าง
  > (ดู `framing` ในหัวข้อ `outputs`) — `auto` รู้จัก frame แบบ octet-counting
  > จาก `<` หรือ `{` ที่ตามหลังความยาว ผู้ส่งข้อความ `raw` แบบ octet-counting
  > จึงต้องตั้ง `framing: octet_counting` ที่ input นี้ — ส่วน syslog input แบบ
  > UDP ถือว่าหนึ่ง datagram คือหนึ่ง event (RFC 5426) รวมการขึ้นบรรทัดด้วย
  ```

- [ ] **Step 4:** `git diff --stat` shows only the two CONFIGURATION files. Then:

  ```bash
  git add docs/CONFIGURATION.md docs/CONFIGURATION.th.md
  git commit -m "docs(config): document framing on syslog inputs" -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

---

### Task 4: C5, mark SYS-4 fixed in `ISSUES.md`

- [ ] **Step 1:** In the summary table, set SYS-4's status to `**fixed** (<C2>, <C3>)`, with the two hashes in backticks.
- [ ] **Step 2:** Replace the SYS-4 entry's status line with: **Status: fixed** in `<C2>` (decoder) and `<C3>` (`framing` option), branch `develop_fix_bug_known-issues`, not yet merged. After the entry's **Fix.** paragraph add one sentence: "`auto` does not detect octet-counted `raw` text (no `<` or `{` after the length); such senders need `framing: octet_counting` on the input."
- [ ] **Step 3:** In the SYS-1 entry's status line, replace "Agent-to-agent TCP with `octet_counting` still needs SYS-4." with "Agent-to-agent TCP with `octet_counting` works since SYS-4 (`<C2>`)."
- [ ] **Step 4:** In the Fix plan, move the SYS-4 row from **Remaining** to **Done** as row 5 (issue, severity Medium, the two hashes, the spec file name). In **Owner decisions needed**, strike the SYS-4 part of the "Minor" bullet and add "used as proposed".
- [ ] **Step 5:** `git diff ISSUES.md` touches only those places. Then:

  ```bash
  git add ISSUES.md
  git commit -m "docs: mark SYS-4 fixed" -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

- [ ] **Step 6: final check.** `git diff 7abecf9 --stat` lists, for this plan, the SYS-4 spec and plan, `src/config/schema.rs`, `src/config/mod.rs`, `src/inputs/syslog.rs`, both CONFIGURATION files and `ISSUES.md`. `git worktree list` may still show `/tmp/sys4-proto`. Removing it (`git worktree remove --force /tmp/sys4-proto`) is the owner's call.

---

### Owner follow-up (not part of these commits)

- **Release note** (the repo has no CHANGELOG, so this goes in the GitHub release text): "The syslog TCP/TLS input now accepts RFC 6587 octet-counted frames as well as newline-terminated lines, detected per frame. New option `inputs.syslog[].framing` (`auto` | `newline` | `octet_counting`). Invalid UTF-8 on TCP/TLS is now replaced with U+FFFD instead of closing the connection."
- **Push / PR / CI**: blocked on write access (see the SYS-7 plan, T4).

## Coverage check against the spec

| Spec item | Where |
| --- | --- |
| Goal 1 (one event per octet frame, while connected, CR/LF kept) | T1 `tcp_receives_octet_counted_frames`, `octet_frames_decode_one_per_frame`, `octet_frame_split_across_reads`. T3 step 1 (10 while connected). |
| Goal 2 (no config change for newline senders) | the existing `tcp_receives_lines`, `tcp_closes_idle_connections_…`, T1 `crlf_line_ending_is_stripped`, T2 default `auto` |
| Goal 3 (mixed frames on one connection) | T1 `mixed_frames_on_one_connection`, `trailing_lf_after_octet_frame_is_skipped` |
| Goal 4 (same limits) | T1 `octet_frame_too_long_is_an_error`, `newline_line_too_long_is_an_error` |
| Undecided header prefix | T1 `partial_header_waits_then_decides`, `eof_returns_pending_line_and_undecided_prefix` |
| `decode_eof` (Risk 3) | T1 `eof_drops_incomplete_octet_frame`, `eof_returns_pending_line_and_undecided_prefix` |
| Lossy UTF-8 (Risk 2) | T1 `invalid_utf8_is_decoded_lossily` |
| Part 2 (`framing` option) | T1 `explicit_newline_mode_is_linescodec`, `explicit_octet_counting_accepts_raw_payload`, `explicit_octet_counting_rejects_bad_header`. T2 both tests. |
| Part 3 docs, including the `raw` limit (Risk 4) | T3 steps 2–3 |
| Risk 1 (a text line that looks like a header) | documented in T3 (`newline` turns detection off). No test: it is the accepted behaviour. |

## Risks

- **T2 is unverified code.** If it fails to compile or a test fails for a reason other than a typo, stop and re-read the spec's Part 2 rather than patching around it.
- **`cargo fmt` may reflow T2's snippets.** Run `cargo fmt --all` before the gate, and commit what it produces.
- **The harness can disappear with `/tmp`** (R-3).
