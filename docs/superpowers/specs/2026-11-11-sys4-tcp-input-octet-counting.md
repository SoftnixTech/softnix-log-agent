# SYS-4: Syslog TCP/TLS input does not decode octet-counting framing — design spec

Status: **draft — owner review needed** (open question 1 is the "minor"
decision recorded in `ISSUES.md`). Nothing is implemented yet.
Issue: SYS-4 in `ISSUES.md` (Medium, P3).
Related: SYS-1 (fixed in `5693b55`/`a508a6d`). Its spec names
`framing: octet_counting` as the way to carry multi-line messages
unchanged, and that path does not work agent-to-agent until this is fixed.
Branch: `develop_fix_bug_known-issues`.

## Problem

`read_stream` (`src/inputs/syslog.rs:335`) serves both the TCP and the TLS
listener, and decodes every connection with
`FramedRead::new(stream, LinesCodec::new_with_max_length(MAX_MSG))`
(`:344`). It understands only RFC 6587 §3.4.2 non-transparent (newline)
framing. A sender using RFC 6587 §3.4.1 octet-counting (`MSG-LEN SP
SYSLOG-MSG`, with no terminator), such as the agent's own output with
`framing: octet_counting` (`src/outputs/stdout.rs`, `frame_batch`), or
rsyslog and syslog-ng configured for octet-counted TCP, never sends a `\n`.
So:

1. **Nothing is delivered while the connection is open.** `LinesCodec`
   keeps buffering, waiting for a newline.
2. When the sender closes, `decode_eof` hands over **the whole stream as one
   event**, with the length prefixes inside it.
3. Past `MAX_MSG` (64 KiB) of buffered data, `LinesCodec` returns
   `MaxLineLengthExceeded`, and `read_stream` closes the connection.

The input has no option to select a framing. `SyslogInputConfig`
(`src/config/schema.rs:135`) has none, and `docs/CONFIGURATION.md:170`
says "newline framing only".

### Incidental finding: one invalid UTF-8 byte closes the connection

`LinesCodec` returns `io::ErrorKind::InvalidData` for a line that is not
valid UTF-8 (`tokio-util` 0.7.19, `lines_codec.rs:95-97`), and `read_stream`
turns any codec error into the end of the connection
(`Ok(Some(Err(e))) => return Err(e.into())`). A single legacy-encoded byte
(for example Windows-1252 text from an old device) therefore drops the TCP
connection, together with everything still buffered on it. The UDP path
decodes with `String::from_utf8_lossy` and never has this problem. This
spec replaces the codec, so it has to pick a behaviour. See Design and open
question 3.

### Evidence (2026-11-11, branch HEAD after `a508a6d`, 3 independent runs)

The repro harness (`/tmp/softnix-smoke.LTIcHO/harness/issues_repro.py`,
SYS-4 case): agent A sends 10 single-line events with `protocol: tcp,
framing: octet_counting` to a plain-Python sink and to agent B's TCP input.
Every run gave identical results:

| Receiver | Result |
| --- | --- |
| Python sink (an octet-counting decoder) | **10/10** frames decoded: the sender is correct |
| Agent B, while A is connected | **0 events** |
| Agent B, after A closes | **1 event**, 830 bytes: `80 <14>1 2026-11-11T05:02:51.685Z WIN-SRV01 EventLog 0 - - S4R1E0 single line event80 <14>1 …` |

## Impact

Medium. Only the agent's own TCP/TLS **input** is affected. Third-party
receivers that support octet-counting decode the agent's output correctly.
But this blocks the agent-to-agent (relay) use of octet-counting, which is
the only way to carry multi-line messages *unchanged* over TCP (SYS-1).
While the sender stays connected, events are also delayed without limit
and then lost into one blob.

## Goals

1. The TCP/TLS input decodes RFC 6587 octet-counted frames: one event per
   frame, delivered as soon as the frame is complete, with embedded CR/LF
   kept.
2. **No configuration change is needed**: existing newline-framed senders
   behave exactly as before.
3. Octet-counted and newline frames can be mixed on one connection (each
   frame is detected on its own, as rsyslog's `imtcp` does).
4. The same limits as today: a frame longer than `MAX_MSG` closes the
   connection, and the idle timeout and connection cap are unchanged.

## Non-goals

- The output side: `framing: octet_counting` is already correct.
- UDP: datagrams carry no framing (SYS-1 Part 2).
- Changing `MAX_MSG` or the idle and handshake timeouts.

## Design

### Part 1: a framing-aware decoder

Replace `LinesCodec` in `read_stream` with a new `SyslogFrameCodec` (a
`tokio_util::codec::Decoder`, `Item = String`) in `src/inputs/syslog.rs`.
For each frame, at the current buffer position:

1. **Skip leading `\r`/`\n`.** Some octet-counting senders add a trailing
   LF. An empty line in newline mode was already skipped by `read_stream`.
2. **Octet-counted** when the buffer starts with `MSG-LEN SP` and the next
   byte looks like the start of a message. `MSG-LEN` is 1–6 ASCII digits
   with no leading zero, so its value can be at most `MAX_MSG` (65536). The
   next byte must be `<` (a syslog PRI) or `{` (JSON). The `<`/`{` check is
   what separates a real header from a plain-text line that happens to
   begin with a number, such as `200 OK …` from a `format: raw` sender
   (open question 1).
   - Wait until `MSG-LEN` bytes after the space have arrived, then return
     exactly those bytes. Nothing is stripped, so CR/LF inside stays.
   - If `MSG-LEN > MAX_MSG`, return an error, which closes the connection
     (Goal 4).
   - **Undecided.** While the buffer holds only a possible header prefix
     (1–6 digits with no leading zero, optionally followed by the space,
     and nothing after it), the codec cannot tell yet. It returns `None`
     and waits for the next byte. The wait is bounded: the first byte that
     breaks the pattern (a 7th digit, a non-digit other than the space, or
     a byte after the space that is not `<`/`{`) makes it a newline frame.
3. **Otherwise, a newline frame**, exactly as `LinesCodec` does today: up to
   `\n`, with one trailing `\r` removed, and `MaxLineLengthExceeded`
   semantics above `MAX_MSG`.
4. **`decode_eof`:** a pending newline line is returned, as `LinesCodec`
   does. A pending, **incomplete** octet-counted frame is dropped with a
   `debug!` log. A truncated frame is not a valid message. An
   **undecided** remainder (such as `12` or `12 `) is returned as a
   newline line, which is what `LinesCodec` does with it today. In
   explicit `octet_counting` mode there are no newline lines, so such a
   remainder is a truncated frame and is dropped as well.

Decoding uses `String::from_utf8_lossy`, the same as the UDP path, instead of
failing (open question 3). `read_stream` keeps its loop. Only the codec it
builds changes. It still `trim()`s and skips empty frames, so the CR/LF
*inside* an octet-counted message survives: `trim()` removes only leading
and trailing whitespace.

### Part 2: optional explicit framing on the input

Add `framing` to `SyslogInputConfig`, with the values `auto` (the default),
`newline` and `octet_counting`.

| Value | Behaviour |
| --- | --- |
| `auto` (default) | Per-frame detection as in Part 1 |
| `newline` | Exactly today's `LinesCodec` behaviour, except that invalid UTF-8 is decoded lossily. An escape hatch if `auto` ever misdetects. |
| `octet_counting` | Every frame must be `MSG-LEN SP MSG`. The `<`/`{` check is skipped, so `format: raw` payloads work. A malformed header closes the connection. |

The field is ignored for `protocol: udp`, as `max_connections` is. Config
validation is unchanged: it is a plain enum with a default, and
`deny_unknown_fields` still applies.

`SyslogInputConfig` is built as a struct literal in one place, the
`test_cfg` helper in `src/inputs/syslog.rs`'s tests (every other test goes
through YAML). It gains the new field in the same commit, or the tests do
not compile.

### Part 3: documentation

- `docs/CONFIGURATION.md:170` and `docs/CONFIGURATION.th.md:169`: replace
  the SYS-1 note "uses newline framing only … tracked as SYS-4" with the
  new behaviour. Both framings are accepted (auto-detected per frame), and
  octet-counting keeps multi-line messages intact.
- Add the `framing` row to the `inputs.syslog` table (en/th).
- State the one combination `auto` cannot detect: an octet-counted sender
  whose payload does not start with `<` or `{`. The agent itself does this
  with `format: raw` + `framing: octet_counting`. The receiving input must
  then set `framing: octet_counting`.

## Testing

Unit tests on the codec, fed through a `BytesMut` (`Decoder::decode`
directly, deterministic, no sockets):

| Test | Input | Asserts | Before |
| --- | --- | --- | --- |
| `octet_frames_decode_one_per_frame` | `"12 <14>1 a b\r\nc"` + `"5 <1>xy"` | 2 items, exact bytes, CR/LF kept | n/a (new codec) |
| `octet_frame_split_across_reads` | the header and the body in 3 chunks | `None` until complete, then the item | |
| `mixed_frames_on_one_connection` | newline line, then an octet frame, then a newline line | 3 items in order | |
| `newline_line_starting_with_digits_stays_a_line` | `"200 OK fine\n"` (raw text) | one newline item `"200 OK fine"` | |
| `octet_frame_too_long_is_an_error` | `"70000 <…"` | `Err` | |
| `invalid_utf8_is_decoded_lossily` | a line with `0xff` | an item containing `U+FFFD`, no error | `LinesCodec`: `Err` |
| `explicit_octet_counting_accepts_raw_payload` | `octet_counting` mode, `"5 hello"` | `"hello"` | |
| `explicit_newline_mode_is_linescodec` | `newline` mode, `"12 <14>…\n"` | one line item including the `12 ` | |
| `explicit_octet_counting_rejects_bad_header` | `octet_counting` mode, `"hello\n"` | `Err` | |
| `partial_header_waits_then_decides` | `"12"`, then `" "`, then `"OK\n"` | `None`, `None`, then one newline item `"12 OK"` | |
| `trailing_lf_after_octet_frame_is_skipped` | `"5 <1>xy\n5 <1>zz"` | 2 items, `"<1>xy"` and `"<1>zz"`, no empty item | |
| `newline_line_too_long_is_an_error` | more than `MAX_MSG` bytes with no `\n` | `Err` | `LinesCodec`: `Err` |
| `eof_drops_incomplete_octet_frame` | `decode_eof` on `"12 <14>1 a"` | `None`, no item, no error | |
| `eof_returns_pending_line_and_undecided_prefix` | `decode_eof` on `"last line"`, and on `"12 "` | the item `"last line"`; the item `"12 "` | `LinesCodec`: the same |

Integration (`src/inputs/syslog.rs` tests, next to `tcp_receives_lines`):

- `tcp_receives_octet_counted_frames`: write 3 octet-counted RFC 5424
  frames, one with `\r\n` in MSG, and **keep the connection open**. All 3
  events arrive before the connection is closed (Goal 1), and the
  multi-line message keeps its inner `\r\n` byte for byte. (`read_stream`
  still `trim()`s leading and trailing whitespace of every frame, as it
  does today.) On today's code this fails: no event arrives before close.
- `tcp_receives_lines` (existing) stays green, which guards Goal 2.

End-to-end: the harness's SYS-4 case (3 runs). Expected: agent B gets
**10 events while A is connected**, 0 after close, and each one equals the
sent line. In addition, the SYS-1 case with agent A's TCP output switched to
`framing: octet_counting` gives agent B the **exact** multi-line messages
(5/5, minus the provider-name confounder described in the SYS-1 spec).

Gate: fmt, clippy `-D warnings`, test `-D warnings`, `+1.98 check`.

## Risks and behaviour changes

1. **A plain-text line that looks exactly like an octet header followed by
   `<` or `{`** (for example `12 <b>bold</b>` from a raw-text sender) would
   be read as a 12-byte frame. This needs digits, a space and `<`/`{` at the
   very start of a line, which is not expected from syslog or JSON senders.
   `framing: newline` turns detection off.
2. **Invalid UTF-8 no longer closes the connection.** It is decoded
   lossily, as on UDP. This is strictly more delivery, but it is a
   behaviour change, so it is listed here.
3. **A truncated octet frame at EOF is dropped**, not delivered as a partial
   event. Today the whole stream is delivered as one corrupt event in that
   case.
4. **`auto` does not detect octet-counted `raw` payloads** (no `<` or `{`
   after the header). Such a connection behaves as it does today: nothing
   is delivered until it closes. The fix is `framing: octet_counting` on
   the input, and Part 3 documents it.

## Rollout

On `develop_fix_bug_known-issues`, as separate commits after the spec and
plan:

1. `feat(inputs): decode octet-counted syslog frames on TCP/TLS` (Part 1,
   with `auto` as the only behaviour, plus the codec and integration tests).
2. `feat(config): add framing option to syslog inputs` (Part 2 and its
   tests).
3. `docs`: CONFIGURATION en/th, and mark SYS-4 fixed in `ISSUES.md`.

## Open questions

1. **How is octet-counting detected in `auto` mode?** Proposed answer:
   digits + SP + `<` or `{` (Part 1, step 2). The alternative is rsyslog's
   simpler "starts with a digit", which also catches octet-counted raw
   payloads, but misreads raw lines such as `200 OK`.
2. **Add the `framing` option (Part 2) now, or only `auto`?** Proposed
   answer: **add it**. It is cheap, and it gives an escape hatch for both
   kinds of misdetection, as well as for octet-counted `raw`.
3. **Invalid UTF-8: decode lossily, or keep closing the connection?**
   Proposed answer: **lossy**, the same as UDP. Closing the connection loses
   every event still in flight because of one bad byte.
