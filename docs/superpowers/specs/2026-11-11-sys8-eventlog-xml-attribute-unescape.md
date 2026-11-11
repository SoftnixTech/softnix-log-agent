# SYS-8: Eventlog XML attribute values are not entity-unescaped — design spec

Status: **implemented for trial, not committed** (2026-11-11). V1–V4 pass
on macOS. V5 (Windows CI) is still pending.
Issue: SYS-8 in `ISSUES.md` (Low, P2).
Implementation plan:
`docs/superpowers/plans/2026-11-11-sys8-eventlog-xml-attribute-unescape.md`
(runs after the SYS-9 plan).
Related: SYS-9 (element text),
`docs/superpowers/specs/2026-11-11-sys9-eventlog-xml-text-entities.md`.
The two are separate defects in separate parts of the same parser. This fix
touches only the attribute closure. It uses SYS-9's Part 2 (the parser now
lives in `src/inputs/eventlog_xml.rs`, testable on every platform), but not
SYS-9's Part 1.

## Problem

The `attr` closure in `parse_event_xml` (`src/inputs/eventlog.rs:826`
before the SYS-9 move) returns `String::from_utf8_lossy(&a.value)`, the raw
attribute bytes. The attributes the parser reads are therefore never
unescaped:

| Attribute | Maps to |
| --- | --- |
| `Provider Name` | `Event.application`, and the publisher passed to `EvtOpenPublisherMetadata` (`format_message`) |
| `Data Name` | the key of a `data_*` field |
| `TimeCreated SystemTime` | `Event.timestamp` |
| `Execution ProcessID` | `Event.process_id` |

### Evidence (2026-11-11, `quick-xml` 0.41.0, macOS)

| `<Provider Name='…'>` | Current `application` | With this fix |
| --- | --- | --- |
| `Backup &amp; Restore` | `Backup &amp; Restore` | `Backup & Restore` |
| `Contoso &quot;Agent&quot;` | `Contoso &quot;Agent&quot;` | `Contoso "Agent"` |
| `O&apos;Brien Tools` | `O&apos;Brien Tools` | `O'Brien Tools` |
| `Tab&#9;Name` | `Tab&#9;Name` | `Tab<TAB>Name` |

`<Data Name='A&amp;B'>v</Data>` produces the key `A&amp;B` today. With
this fix it is `A&B`.

### A trap in the fix that `ISSUES.md` proposes

`ISSUES.md` suggests `a.unescape_value()`. In `quick-xml` 0.41 that method
is **deprecated** ("use `Self::normalized_value()`"). Verified: a test build
with `RUSTFLAGS="-D warnings"` fails with
`use of deprecated method … Attribute::unescape_value`. Using it would break
CI's `test-windows` job, the same class of failure as SYS-7.

## Impact

Low. Real provider names, Data names, timestamps and PIDs rarely contain
`&`, `'`, `"`, `<` or `>`. When one does, `application` and the `data_*`
key carry the escaped text, and `EvtOpenPublisherMetadata` is asked for a
publisher that does not exist, so the message falls back to the joined
EventData instead of the rendered text.

## Goals

1. The four attribute values above have predefined entities and character
   references resolved.
2. Output for attribute values without references is **identical** to
   today's.
3. No deprecated `quick-xml` API.
4. An attribute that was `Some(…)` before the fix never becomes `None`
   because of it.

## Non-goals

- Element text: SYS-9.
- Every other part of the parser and `build_event`.

## Design

In the `attr` closure, replace `String::from_utf8_lossy(&a.value)` with
`a.normalized_value(quick_xml::XmlVersion::Implicit1_0)`. That method is
not deprecated, resolves the predefined entities through
`resolve_predefined_entity`, and resolves character references. If it
returns an error (a malformed reference), fall back to the current raw
`from_utf8_lossy` value (Goal 4).

`normalized_value` also applies standard XML attribute-value
normalization: a *literal* tab, CR or LF inside an attribute becomes a
space, while a character reference such as `&#9;` still becomes a real
tab. This is what any conforming XML parser does. `EvtRender` does not put
literal whitespace control characters inside these attributes, so this is
not expected to change any real value.

## Testing

In `src/inputs/eventlog_xml.rs`'s `mod tests`, so they run on every
platform. Both fail before the change.

| Test | Input | Asserts |
| --- | --- | --- |
| `provider_name_is_unescaped` | the four names above | `Backup & Restore`, `Contoso "Agent"`, `O'Brien Tools`, a tab |
| `data_name_attribute_is_unescaped` | `<Data Name='A&amp;B'>v</Data>` | `[("A&B","v")]` |

The guards pass before and after the change:

| Test | Asserts |
| --- | --- |
| `parses_system_and_eventdata` (existing) | its `Provider Name`, `SystemTime`, `ProcessID` and `Data Name` values have no references and must not change |
| `malformed_attribute_reference_keeps_raw_value` (added in the plan review) | `Provider Name='a&foo;b'`, `'a&#0;b'` and `'a&b'` keep their raw value. `normalized_value` returns `Err` for all three, so this exercises the Goal 4 fallback. Checked in the scratch crate: old and new code give the same result. |

### Verification matrix

| # | Command | Where | Expected | Trial result |
| --- | --- | --- | --- | --- |
| V1 | `cargo test --lib eventlog_xml` before the change | macOS | the 2 SYS-8 tests fail | as expected |
| V2 | `RUSTFLAGS="-D warnings" cargo test --all-targets` | macOS, 1.99.1 | all pass | passes (together with SYS-9) |
| V3 | `RUSTFLAGS="-D warnings" cargo clippy --all-targets`, `cargo fmt --all -- --check` | macOS, 1.99.1 | clean, with no deprecation warning | clean |
| V4 | `RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets` | macOS, 1.98.1 | passes | passes |
| V5 | CI `test-windows` | Windows | passes | **pending** |

Independence from SYS-9: with only SYS-9's fix applied (this change
reverted), exactly the 2 SYS-8 tests fail, and the other 10 pass.

## Behaviour changes

1. **`application` is unescaped** for provider names containing
   references. This changes the JSON field, the RFC 5424 APP-NAME and the
   RFC 3164 TAG. On this branch (based on `main`), `format.rs:14`/`:23`
   still write `application` into the header **verbatim**, with no
   sanitizing. Header sanitization comes with the provider-name fix on
   `develop_fix_bug_windows-provider-name`, which has not merged yet. For
   the named entities this is harmless: `& " ' < >` are printable ASCII,
   valid in APP-NAME, and the escaped forms already contained any spaces
   the name had. See risk 5 for character references.
2. **`EvtOpenPublisherMetadata` finds these publishers**, so their
   messages render properly instead of falling back to the joined
   EventData.
3. **`data_*` keys are unescaped** (`data_A&B` instead of `data_A&amp;B`).
4. **Literal whitespace control characters in attributes become spaces**
   (XML normalization). This is not expected in `EvtRender` output.
5. **A `Data Name` that unescapes to `"`, `]`, `=` or a space now drops out
   of the RFC 5424 SD.** `rfc5424_structured_data` (`format.rs:46-53`)
   skips any key that is not a valid SD-NAME. `Name='a&quot;b'` used to be
   emitted as the (valid) param `data_a&quot;b`. Now the key is
   `data_a"b`, which is skipped on the RFC 5424 wire but still present in
   JSON output. Data names like this are not expected in real events, and
   the wire output stays valid.
6. **A character reference that resolves to whitespace in `Provider Name`
   (`&#9;`, `&#32;`) now puts that whitespace into the RFC 5424 / 3164
   header on this branch.** That breaks the header for that event, exactly
   like a provider name with a literal space does today on `main` (the
   original provider-name bug). Before this fix, the reference stayed as
   printable `&#9;`. It is fixed once the provider-name branch merges,
   because it sanitizes the header. No real provider names like this are
   known.

## Rollout

On `develop_fix_bug_known-issues`, right after SYS-9's commits:

1. `fix(eventlog): unescape XML attribute values` (the `attr` closure and
   the 2 tests). This fixes SYS-8.
2. `docs`: mark SYS-8 fixed in `ISSUES.md`, and correct its **Fix** text:
   `normalized_value`, not the deprecated `unescape_value`.

## Open questions

None blocking. The fallback on error (Goal 4) and the normalization note
follow standard XML behaviour. Behaviour changes 5 and 6 were found in the
2026-11-11 review. Both are edge cases with no known real-world occurrence,
and 6 goes away once the provider-name fix merges. They are recorded so the
owner can veto them.
