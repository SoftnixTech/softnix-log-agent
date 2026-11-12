# Eventlog `EventData` values containing XML entities are truncated and split — design spec

Status: **implemented for trial, not committed** (2026-11-11). The owner
asked for the proposed answers to the open questions to be implemented
first, so the fix can be tested. V1–V5 pass on macOS. V6 (Windows CI) is
still pending.
Implementation plan:
`docs/superpowers/plans/2026-11-11-eventlog-xml-text-entities.md`.
Related: attribute values that are not entity-unescaped (the attribute fix)
have their own spec,
`docs/superpowers/specs/2026-11-11-eventlog-xml-attribute-unescape.md`.
It is a separate defect in a separate part of the same parser. It relies on
Part 2 of this spec (the move to a cross-platform module) for its tests,
but not on Part 1.

## Problem

`parse_event_xml` (`src/inputs/eventlog.rs:813` before this change) turns
the XML from `EvtRender` into a `ParsedEvent`. `build_event` (`:705`) maps
it to an `Event`, including the `data_*` fields and the fallback message
built from the joined EventData.

`quick-xml` 0.41 reports each entity or character reference (`&amp;`,
`&#13;`) as its own `Event::GeneralRef`, and splits the text around it into
separate `Event::Text` events. The parser:

- handles only `Text` (`:851`), and pushes **every** chunk as a separate
  Data item. Only the first chunk gets the `Name`, because of
  `std::mem::take(&mut cur_data_name)` at `:871`.
- drops `GeneralRef` in `_ => {}` (`:891`), so the escaped characters
  themselves are lost.
- skips chunks that are whitespace only (`:867`), so the spaces between two
  entities are lost too.

The comment at `:852-860` assumes entities arrive inside `Text` and are
resolved by `escape::unescape`. With 0.41 they never arrive there.

### Evidence (2026-11-11, `quick-xml` 0.41.0, macOS)

`ParsedEvent` and `parse_event_xml` were copied verbatim from
`eventlog.rs:798-895` into a scratch crate and compared with the design
below. Later, the same cases ran as unit tests against the real code
(V1).

| Input (inside `<EventData>`) | Current result | With this fix |
| --- | --- | --- |
| `<Data Name='CommandLine'>cmd.exe /c dir &amp;&amp; echo &quot;done&quot; &gt; out.txt</Data>` | `("CommandLine","cmd.exe /c dir ")`, `("", " echo ")`, `("","done")`, `("", " out.txt")` | `("CommandLine", "cmd.exe /c dir && echo \"done\" > out.txt")` |
| `<Data Name='Who'>Tom &amp; Jerry</Data>` | `("Who","Tom ")`, `("", " Jerry")` | `("Who","Tom & Jerry")` |
| `<Data Name='X'>a&amp; &amp;b</Data>` | `("X","a")`, `("","b")`: the `&`s **and** the space are gone | `("X","a& &b")` |
| `<Data Name='X'>&lt;</Data>` (value is only an entity) | **no item at all** | `("X","<")` |
| `<Data Name='X'>line1&#13;&#10;line2 &#x41;&#66;</Data>` | `("X","line1")`, `("","line2 ")` | `("X","line1\r\nline2 AB")` |
| `<Data>first</Data><Data>second &amp; third</Data>` | 3 unnamed items | 2 unnamed items, the second one intact |
| `<Data Name='X'>a &foo; b</Data>` (unknown entity) | `("X","a ")`, `("", " b")` | `("X","a &foo; b")` |
| `<Computer>a&amp;b</Computer>` (System field) | `computer = "b"`: the last chunk wins | `computer = "a&b"` |
| `<Keywords>&#x30;x10</Keywords>` (System field) | `keywords = "x10"` | `keywords = "0x10"` |

Cases that **must not change**, and do not change with this fix: the full
`SAMPLE` event from the existing test; empty, self-closing and
whitespace-only Data elements, which still produce no item; leading and
trailing whitespace in a value (`"  alice "`); and CDATA, which is dropped
before and after.

## Impact

High. `data_CommandLine` for Sysmon 1 and Security 4688, file paths, URLs
and script blocks lose everything after the first `&`, `<`, `>`, `"` or
`'`. Those are exactly the characters detections match on (`&&`, `>`
redirection, `<script`). The loss happens at the input, so every output
(JSON, RFC 5424 SD, RFC 3164) gets the truncated value, and no config works
around it.

## Goals

1. Each Data element produces **exactly one** item, whose value is the
   element's full text with predefined entities (`amp`, `lt`, `gt`, `quot`,
   `apos`) and numeric character references (`&#NN;`, `&#xHH;`) resolved.
2. The same applies to the System text fields the parser reads (`EventID`,
   `Level`, `Computer`, `EventRecordID`, `Keywords`).
3. Output for element text without references is **identical** to today's.
4. The parser is unit-tested in every CI job and locally on macOS, not only
   in `test-windows`.
5. No deprecated `quick-xml` API, so it builds under `-D warnings` on
   1.98 and 1.99.

## Non-goals

- Attribute values: the attribute fix.
- No change to `build_event`, `format_message`, the subscription and
  bookmark logic, or the `Event` shape.
- No CR/LF handling for the wire: that belongs to the fix for multi-line
  messages split by newline framing
  (`2026-11-11-multiline-messages-newline-framing.md`).
- No CDATA, `UserData` or DTD-defined entities (see
  [Out of scope](#out-of-scope)).

## Design

### Part 1: build up element text across `Text` and `GeneralRef`

Replace the per-chunk handling with a buffer for the current element's text:

- **`Start(e)`**: as today, read the attributes. Then set `cur = name` and
  **clear** the buffer.
- **`Empty(e)`**: as today, read the attributes. Clear the buffer and
  `cur`. A self-closing element has no text and no `End` event.
- **`Text(t)`**: append `t.decode()` to the buffer, **without** trimming or
  skipping whitespace. The `escape::unescape` call and its comment go away,
  because in 0.41 `Text` never contains references.
- **`GeneralRef(r)`**: append its value:
  - a character reference (`r.resolve_char_ref()` returns `Ok(Some(c))`):
    push `c`;
  - a named reference: `quick_xml::escape::resolve_predefined_entity(name)`
    returns `Some(v)`: push `v`;
  - anything else (an unknown entity, an invalid character reference such as
    `&#0;`): push the literal `&name;`, so no data is lost silently.
- **`End(e)`**: if `e` closes `cur` **and** the buffer is not
  whitespace-only, assign the value once, using exactly today's rules: a
  Data item inside EventData takes the name from `cur_data_name`, otherwise
  the System field match. Then, as today, leave EventData if `e` is
  EventData, and clear `cur` and the buffer.

The whitespace-only check moves from "each chunk" to "the whole value", so
whitespace between references is kept, and values that are really empty
are still skipped (Goal 3).

### Part 2: move the parser into a module that compiles on every platform

The whole of `eventlog.rs` is `#[cfg(windows)]` (`src/inputs/mod.rs:1`),
and `quick-xml` is a Windows-only dependency (`Cargo.toml:52-54`), so the
parser's tests used to run only in CI's `test-windows` job. The parser is
pure string processing with no Windows API, so:

- `ParsedEvent` and `parse_event_xml`, plus their test, move to
  `src/inputs/eventlog_xml.rs`. They become `pub(super)` (visible only
  inside `inputs`), and `eventlog.rs` imports them with
  `use super::eventlog_xml::parse_event_xml;`.
- `src/inputs/mod.rs`: `#[cfg(any(windows, test))] mod eventlog_xml;`.
- `Cargo.toml`: add `quick-xml = "0.41"` to `[dev-dependencies]` too. The
  Windows target dependency stays, so release builds for Linux and macOS
  still do **not** include `quick-xml` or the parser. The version is the
  same, so `Cargo.lock` does not change.
- `ParsedEvent` gets `#[cfg_attr(not(windows), allow(dead_code))]`. On
  non-Windows test builds only the tests read its fields, so any field the
  tests don't read would hit `dead_code` and fail `-D warnings`. This was
  verified in the scratch crate. The attribute stops a future field from
  breaking Linux CI.

A side benefit is that the parser now also goes through clippy in the
`lint` job (Linux). This part is done first, as a pure move with no logic
change.

## Testing

All tests live in `eventlog_xml.rs`'s `mod tests`, so they run on Linux,
macOS and Windows.

The **failing tests**: each one fails before Part 1.

| Test | Input | Asserts |
| --- | --- | --- |
| `data_value_with_entities_is_one_item` | the `CommandLine` line from the Evidence table, plus `Tom &amp; Jerry` | each is one item with the full value |
| `data_value_keeps_whitespace_between_refs` | `a&amp; &amp;b` | `"a& &b"` |
| `data_value_that_is_only_an_entity_is_kept` | `&lt;` | `[("X","<")]` |
| `numeric_char_refs_are_resolved` | `line1&#13;&#10;line2 &#x41;&#66;` | `"line1\r\nline2 AB"` |
| `unnamed_data_with_entity_stays_one_item` | `<Data>first</Data><Data>second &amp; third</Data>` | 2 items |
| `unknown_entity_is_kept_literally` | `a &foo; b`, and the invalid character reference `a&#0;b` | `"a &foo; b"`, `"a&#0;b"` (the second was checked in the scratch crate; before the fix it splits into `("Z","a")`, `("","b")`) |
| `system_text_fields_resolve_entities` | `<Computer>a&amp;b</Computer>`, `<Keywords>&#x30;x10</Keywords>` | `"a&b"`, `"0x10"` |

The **byte-identical guards**: they pass before and after the change.

| Test | Asserts |
| --- | --- |
| `parses_system_and_eventdata` (moved; `Keywords` added to `SAMPLE`) | every `SAMPLE` field, including `keywords` |
| `empty_and_whitespace_only_data_are_skipped` | empty, self-closing and whitespace-only Data produce no item, and the next item is unaffected |
| `data_value_whitespace_is_preserved` | `"  alice "` stays as it is |

### Verification matrix

| # | Command | Where | Expected | Trial result |
| --- | --- | --- | --- | --- |
| V1 | `cargo test --lib eventlog_xml` before Part 1 | macOS | the 7 new tests fail, the 3 guards pass | as expected |
| V2 | `RUSTFLAGS="-D warnings" cargo test --all-targets` | macOS, 1.99.1 | all pass | 189 lib + 3 bin + 6 e2e pass |
| V3 | `RUSTFLAGS="-D warnings" cargo clippy --all-targets`, `cargo fmt --all -- --check` | macOS, 1.99.1 | clean | clean |
| V4 | `RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets` | macOS, 1.98.1 | passes | passes |
| V5 | `cargo tree -e normal \| grep -c quick-xml`, `git diff Cargo.lock` | macOS | `0`, no diff | `0`, no diff |
| V6 | CI `test-windows` (test + clippy) | Windows | passes. This is the only gate that compiles `eventlog.rs` with the new import. | **pending** (no Windows toolchain locally) |

Independence from the attribute fix: with its change reverted and only this
fix applied, 10/12 parser tests pass. The 2 that fail are the attribute
fix's tests.

## Risks and behaviour changes

1. **`data_*` values are complete.** This is the fix itself. Detections that
   used to miss will now match.
2. **The extra unnamed Data items disappear.** The fallback message (the
   joined EventData, used when the message DLL is missing) changes from
   `CommandLine=cmd.exe /c dir   echo  done  out.txt` to the real command
   line.
3. **Values can now contain CR/LF that come from `&#13;&#10;`.** Before,
   such values were truncated at the reference. A literal CRLF in element
   text already passes through today, so this adds a new path into the
   newline-framing bug (an event split on newline framing), not a new kind
   of problem. SD values are escaped by `sd_escape` (`format.rs:83`) for
   `"`, `\` and `]`, but not for newlines. The newline-framing fix remains
   the place to handle that.
4. **An unknown entity is kept literally** (`&foo;`). `EvtRender` emits no
   DTD, so in practice this cannot happen. The rule is defensive.

## Rollout

On `develop_fix_bug_known-issues`, after the `AtomicU64::fetch_update`
deprecation fix (`0f67852`, `af3018c`, `cf5bc5a`):

1. `refactor(eventlog): move XML parser to a cross-platform module`
   (Part 2: a pure move. `parses_system_and_eventdata` and `SAMPLE` are
   byte-identical to the originals in `eventlog.rs`.)
2. `fix(eventlog): resolve XML entities in EventData text` (Part 1, the 7
   failing tests, the 2 new guards, and `Keywords` added to `SAMPLE` and
   `parses_system_and_eventdata`). This fixes the bug.
3. The attribute fix's commit follows (see its spec).
4. `docs`: record the fix in the issue tracker, and correct the proposed
   fix there: the tests are cross-platform, not `#[cfg(windows)]`.

## Out of scope

1. **CDATA sections** in Data (`Event::CData`) are dropped before and after.
   `EvtRender` does not emit CDATA for EventData. Record it as a new issue
   if a real event shows up with it.
2. **`UserData` events** produce no `data_*` fields before and after.
3. **CR/LF on the wire**: the newline-framing fix.
4. **Attribute values**: the attribute fix.

## Open questions (resolved: the owner adopted the proposed answers for trial on 2026-11-11)

1. Move the parser to a cross-platform module (Part 2)? **Yes.**
2. Unknown or invalid references? **Keep them literally.**
3. Should `&#13;&#10;` become real CR/LF? **Yes.** Handle the wire
   representation in the newline-framing fix.
4. Branch? **`develop_fix_bug_known-issues`**, with the
   `fetch_update` deprecation commits restored.
