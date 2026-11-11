# Syslog Header Sanitization Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking. Execute tasks in order; the tree compiles and the full suite passes after every task.

**Goal:** Make every RFC 5424 (and RFC 3164) line the agent emits carry a spec-valid header, whatever the value of `hostname` / `application` / `process_id`. The trigger is Windows provider names with spaces, such as `Service Control Manager`. The original value stays recoverable, and output for already-valid values does not change by a single byte.

**Architecture:** A pure helper, `sanitize_token` (and its RFC 5424 wrapper `header_token`), turns any string into a valid header token, or the NILVALUE `-`. It returns `Cow::Borrowed` when the input is already valid. `format_event` applies the helper to each free-form header field at the moment the wire line is built. When a value had to change, the original goes into the existing `[softnix@32473 …]` SD element. `Event` itself is never modified, so JSON output, `when:` conditions, routing and transforms keep seeing the original provider name.

**Tech Stack:** Rust 2021, `std::borrow::Cow`, `rand` 0.8 (already a regular dependency) for the seeded property test.

**Spec:** `docs/superpowers/specs/2026-11-10-syslog-header-sanitization.md`

## Global Constraints

- `rust-version = "1.98"`. The local toolchain is 1.99.1.
- **Only `src/outputs/format.rs` changes in code** (plus docs in Task 4). No changes to `Event`, inputs, the parsers, config schema, the on-disk queue or the state format.
- No new dependencies.
- Every task ends with `cargo test --all-targets`, `cargo clippy --all-targets` (no new warnings; CI sets `RUSTFLAGS: -D warnings`) and `cargo fmt --all -- --check`, all clean.
- **Baseline test count:** 176 lib + 3 bin + 6 e2e + 0 doc = **185**. Each task states the new expected count.
- New tests are appended at the **end** of `mod tests` in `src/outputs/format.rs`, just before its closing brace.
- Commit messages use the repo's conventional prefix, `fix(format): …` (docs: `docs(format): …`). Each ends with the `Co-Authored-By` trailer required by the session.
- `src/inputs/eventlog.rs` is `#[cfg(windows)]` and is **not touched**. The CI `test-windows` job (tests + clippy on `windows-latest`) is the Windows compile gate. Local `cargo check --target x86_64-pc-windows-gnu` needs a mingw C toolchain for `ring`, so it is optional.

## Rulings (decisions this plan makes where the spec leaves room)

**R-0: Open questions are assumed to take the spec's proposed answers.** The replacement character is `_`. The original value is emitted only when the value was altered. The RFC 3164 TAG is not capped at 32. Part B ships in the same patch. If the owner decides otherwise, the affected tasks are:

| Decision changed | Tasks affected |
|---|---|
| Replacement character | T1 (table), T2 and T3 (expected strings), T4 (docs) |
| Always emit the original | T2 (`rfc5424_header_field` condition, the byte-identical test is dropped) |
| Cap TAG at 32 | T3 (`usize::MAX` becomes `32`, extra test row) |
| Part B as a follow-up | Drop T3; the T4 3164 doc wording goes with it |

**R-1: An already-valid input is never changed.** This includes inputs made only of `_` (`"___"`). Spec step 5 (`_`-only → `-`) applies only to values that the earlier steps changed. Goal 3 (byte-identical output) takes precedence.

**R-2: An empty original is not preserved.** `Some("")` becomes `-` in the header, and no `application=""` parameter is added, because there is nothing to recover. Whitespace-only originals (such as `" "`) *are* preserved, because they differ from empty.

**R-3: A collision is checked against what `ev.fields` would actually emit.** The preserved-original parameter is skipped only if the same key in `ev.fields` would itself produce a parameter (non-null). A `null` field of the same name does not suppress the preserved original.

**R-4: The RFC 3164 PID is sanitized like the TAG.** Characters `[`, `]` and `:` are replaced and the length is capped at 128. The spec's Part B names HOSTNAME and TAG; the PID sits inside the TAG's brackets (`{tag}[{pid}]:`), so it has the same failure mode. This is a small extension of the spec and is called out here so the reviewer can veto it.

**R-5: RFC 3164 uses `-` as a literal tag.** When the TAG sanitizes to nothing, `-` is emitted, consistent with RFC 5424. RFC 3164 has no NILVALUE, so a 3164 receiver will see `application="-"`. This is acceptable because the case needs a fully non-ASCII or whitespace-only provider name.

**R-6: The smoke harness stays out of the repo.** It lives at `/tmp/softnix-smoke.LTIcHO/harness/smoke.py`. The Rust tests from T1–T3 are the permanent regression net, and the harness is a one-off acceptance check (T5).

**R-7: The property loop and round-trip tests belong to T2, not a separate task.** Written before the fix, they fail on the current formatter (bad header token; `application == Some("Service")`). That gives a real red-then-green cycle without having to check out an older formatter afterwards.

---

## Dependency graph and ordering

```text
T1 sanitize_token / header_token (pure helper)
 ├── T2 RFC 5424 header + preserved-original SD + property/round-trip tests
 └── T3 RFC 3164 HOSTNAME / TAG / PID            (uses T1 and T2's test helper `fixed_event`)
T4 docs                                          (after T2 + T3)
T5 verification: smoke re-run + full gate        (after T1–T4)
T6 manual Windows check + release note           (owner, before release)
```

Execution order: **T1 → T2 → T3 → T4 → T5 → T6.**

---

### Task 1: the `sanitize_token` / `header_token` helper

**Files:**
- Modify: `src/outputs/format.rs`. Add `use std::borrow::Cow;` to the imports (lines 1-3). Add the constants and the two functions directly after `sd_escape` (ends around line 92). Append new tests to the end of `mod tests`.

**Interfaces:**
- Produces (private to the module):
  - `const HOSTNAME_MAX: usize = 255; const APP_NAME_MAX: usize = 48; const PROCID_MAX: usize = 128;`
  - `fn header_token(raw: &str, max: usize) -> Cow<'_, str>`
  - `fn sanitize_token<'a>(raw: &'a str, max: usize, extra: &[char]) -> Cow<'a, str>`
- Nothing outside the tests calls them yet. To keep a plain `cargo build` free of `dead_code` warnings, put `#[cfg_attr(not(test), allow(dead_code))]` on the two functions and the three constants. **T2 removes these attributes** once real callers exist.

- [ ] **Step 1: Write the failing tests.** Append to `mod tests`:

```rust
    #[test]
    fn header_token_table() {
        // Spec "Expected APP-NAME values" table, row for row.
        let a48 = "A".repeat(48);
        let b48 = "B".repeat(48);
        let b49 = "B".repeat(49);
        let cases: &[(&str, &str)] = &[
            ("Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Security-Auditing"),
            ("Service Control Manager", "Service_Control_Manager"),
            ("Application Error", "Application_Error"),
            (
                "Microsoft-Windows-User Profiles Service",
                "Microsoft-Windows-User_Profiles_Service",
            ),
            (
                "Microsoft-Windows-Windows Firewall With Advanced Security",
                "Microsoft-Windows-Windows_Firewall_With_Advanced",
            ),
            (" LeadingSpace", "LeadingSpace"),
            ("TrailingSpace ", "TrailingSpace"),
            ("Double  Space", "Double_Space"),
            ("Tab\tSeparated", "Tab_Separated"),
            ("ระบบ บันทึก", "-"),
            (&a48, &a48),
            (&b49, &b48),
            ("", "-"),
            ("-", "-"),
            ("Odd\"Name]x", "Odd\"Name]x"),
        ];
        for (input, want) in cases {
            assert_eq!(header_token(input, APP_NAME_MAX), *want, "input {input:?}");
        }
    }

    #[test]
    fn header_token_borrows_valid_input_unchanged() {
        // Goal 3: valid values come back as the same borrowed slice, which is
        // what lets format_event detect "unchanged" and stay byte-identical.
        // Plan R-1: a value made only of '_' is valid and stays as-is.
        for s in ["nginx", "Microsoft-Windows-Kernel-General", "-", "___", "Odd\"Name]x"] {
            assert!(
                matches!(header_token(s, APP_NAME_MAX), Cow::Borrowed(b) if b == s),
                "{s:?}"
            );
        }
    }

    #[test]
    fn sanitize_token_extra_chars_and_caps() {
        let delims = ['[', ']', ':'];
        assert_eq!(sanitize_token("Foo:Bar[1]", usize::MAX, &delims), "Foo_Bar_1_");
        assert_eq!(sanitize_token("ok", usize::MAX, &delims), "ok");
        // A run of replaced chars collapses; pre-existing '_' are kept.
        assert_eq!(header_token("a \t\n b", APP_NAME_MAX), "a_b");
        assert_eq!(header_token("a_ b", APP_NAME_MAX), "a__b");
        // A changed value that sanitizes to only '_' becomes NILVALUE.
        assert_eq!(header_token("_ _", APP_NAME_MAX), "-");
        // Non-ASCII runs collapse too; valid PRINTUSASCII ('"', ']') is kept.
        assert_eq!(header_token("ระบบ \"x\" ]", APP_NAME_MAX), "_\"x\"_]");
        // Truncation is by octets; the result is ASCII, so never mid-char.
        assert_eq!(header_token(&"x".repeat(300), HOSTNAME_MAX).len(), 255);
        assert_eq!(header_token(&"7".repeat(200), PROCID_MAX).len(), 128);
    }
```

- [ ] **Step 2: Run them and confirm they fail.** `cargo test --lib outputs::format` should fail to compile with `cannot find function 'header_token'` (and likewise `sanitize_token`, `APP_NAME_MAX`, …). That compile failure is the red state.

- [ ] **Step 3: Implement.** Add `use std::borrow::Cow;` at the top, and after `sd_escape`:

```rust
/// RFC 5424 §6 header field limits, in octets.
#[cfg_attr(not(test), allow(dead_code))]
const HOSTNAME_MAX: usize = 255;
#[cfg_attr(not(test), allow(dead_code))]
const APP_NAME_MAX: usize = 48;
#[cfg_attr(not(test), allow(dead_code))]
const PROCID_MAX: usize = 128;

/// Make `raw` a valid RFC 5424 header token (PRINTUSASCII = %d33-126, at most
/// `max` octets) or the NILVALUE "-". Returns `Cow::Borrowed(raw)` when `raw`
/// is already valid, so valid values reach the wire byte-identical.
///
/// Windows provider names such as "Service Control Manager" contain spaces;
/// interpolated verbatim they shift every following header field (see
/// docs/superpowers/specs/2026-11-10-syslog-header-sanitization.md).
#[cfg_attr(not(test), allow(dead_code))]
fn header_token(raw: &str, max: usize) -> Cow<'_, str> {
    sanitize_token(raw, max, &[])
}

/// `header_token`, plus `extra` characters that must also be replaced (the
/// RFC 3164 TAG uses '[', ']' and ':' as PID / CONTENT delimiters).
///
/// Order: trim -> replace each run of disallowed chars with one '_' -> cap at
/// `max` octets -> empty or only '_' left => "-". An input that is already
/// valid is returned untouched, even if it is all '_' (plan R-1).
#[cfg_attr(not(test), allow(dead_code))]
fn sanitize_token<'a>(raw: &'a str, max: usize, extra: &[char]) -> Cow<'a, str> {
    let allowed = |c: char| ('\x21'..='\x7e').contains(&c) && !extra.contains(&c);
    if !raw.is_empty() && raw.len() <= max && raw.chars().all(allowed) {
        return Cow::Borrowed(raw);
    }
    let trimmed = raw.trim();
    let mut out = String::with_capacity(trimmed.len().min(max));
    let mut last_replaced = false;
    for c in trimmed.chars() {
        if out.len() >= max {
            break;
        }
        if allowed(c) {
            out.push(c);
            last_replaced = false;
        } else if !last_replaced {
            out.push('_');
            last_replaced = true;
        }
    }
    // Every pushed char is ASCII, so `out.len()` counts characters too.
    debug_assert!(out.len() <= max && out.is_ascii());
    if out.bytes().all(|b| b == b'_') {
        // Also covers the empty case: nothing meaningful survived.
        return Cow::Borrowed("-");
    }
    Cow::Owned(out)
}
```

- [ ] **Step 4: Run the tests and confirm they pass.** `cargo test --lib outputs::format` should show every test passing.

- [ ] **Step 5: Run the gate.** `cargo test --all-targets` should report **188** (179 lib + 3 + 6 + 0). Run `cargo clippy --all-targets` and `cargo fmt --all -- --check`; both must be clean. Run `cargo build` and confirm no `dead_code` warning.

- [ ] **Step 6: Commit.** `fix(format): add header_token helper for RFC 5424 header fields`

---

### Task 2: sanitize the RFC 5424 header and preserve the original value

**Files:**
- Modify: `src/outputs/format.rs`. Change the `OutputFormat::Rfc5424` arm of `format_event` (lines 10-18) and `rfc5424_structured_data` (lines 36-64). Add the new helpers `rfc5424_header_field` and `push_sd_param`. Remove the `cfg_attr(... dead_code)` attributes from T1. Append the new tests and test helpers.

**Interfaces:**
- Consumes: T1's `header_token`, `HOSTNAME_MAX`, `APP_NAME_MAX`, `PROCID_MAX`; the existing `value_to_param(&Value) -> Option<String>` and `sd_escape(&str) -> String`. Tests also use `crate::pipeline::parse_syslog_into(&mut Event, &str, SyslogFormat)` (re-exported at `src/pipeline/mod.rs:15`), `crate::config::SyslogFormat`, and `rand::{rngs::StdRng, Rng, SeedableRng}` (rand 0.8).
- Produces:
  - `fn rfc5424_header_field<'a>(value: Option<&'a str>, max: usize, default: &'static str, param: &'static str, preserved: &mut Vec<(&'static str, &'a str)>) -> Cow<'a, str>`
  - `fn rfc5424_structured_data(ev: &Event, preserved: &[(&str, &str)]) -> String`. This is a signature change; the only caller is the `Rfc5424` arm (verify with `grep -rn rfc5424_structured_data src`).
  - `fn push_sd_param(params: &mut String, name: &str, value: &str)`
  - Test-only: `fn fixed_event(app: Option<&str>, msg: &str) -> Event`, `fn sd_len(s: &str) -> Option<usize>`, `fn strict_rfc5424(line: &str) -> (String, String, String, String)`.
  - `format_event`'s public signature does not change.

- [ ] **Step 1: Pin the current bytes before touching anything.** Append this helper and test, then run them against the **unmodified** formatter. The test must pass now; that is the point of this step.

```rust
    fn fixed_event(app: Option<&str>, msg: &str) -> Event {
        let mut ev = Event::new("s", "eventlog", msg);
        ev.timestamp = chrono::DateTime::parse_from_rfc3339("2026-11-10T08:58:07.110Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        ev.hostname = Some("WIN-SRV01".into());
        ev.application = app.map(str::to_string);
        ev.process_id = Some("4321".into());
        ev.severity = Some(6);
        ev.fields.insert("channel".into(), serde_json::Value::from("System"));
        ev.fields.insert("event_id".into(), serde_json::Value::from(7036));
        ev
    }

    #[test]
    fn rfc5424_valid_values_are_byte_identical() {
        // Goal 3. These strings are what the pre-fix formatter produces; they
        // must not change. ev.fields is a BTreeMap, so params are key-sorted.
        for app in [
            "Microsoft-Windows-Security-Auditing",
            "Microsoft-Windows-Kernel-General",
            "Microsoft-Windows-Sysmon",
            "EventLog",
            "VSS",
        ] {
            let line = format_event(&fixed_event(Some(app), "msg"), OutputFormat::Rfc5424);
            assert_eq!(
                line,
                format!(
                    "<14>1 2026-11-10T08:58:07.110Z WIN-SRV01 {app} 4321 - \
                     [softnix@32473 channel=\"System\" event_id=\"7036\"] msg"
                )
            );
        }
        let line = format_event(&fixed_event(None, "msg"), OutputFormat::Rfc5424);
        assert!(line.contains(" WIN-SRV01 softnix-log-agent 4321 - ["), "{line}");
    }
```

      Running `cargo test --lib rfc5424_valid_values_are_byte_identical` should **pass**. If it fails, the expected literal is wrong, not the code: fix the literal to match the current output before continuing.

- [ ] **Step 2: Write the failing tests.** Append:

```rust
    #[test]
    fn rfc5424_sanitizes_provider_with_spaces() {
        let ev = fixed_event(
            Some("Service Control Manager"),
            "The service entered the running state.",
        );
        assert_eq!(
            format_event(&ev, OutputFormat::Rfc5424),
            "<14>1 2026-11-10T08:58:07.110Z WIN-SRV01 Service_Control_Manager 4321 - \
             [softnix@32473 application=\"Service Control Manager\" channel=\"System\" \
             event_id=\"7036\"] The service entered the running state."
        );
    }

    #[test]
    fn rfc5424_preserved_param_creates_sd_element() {
        // No custom fields: the SD would have been "-"; the preserved original
        // must still get an element.
        let mut ev = Event::new("s", "eventlog", "msg");
        ev.application = Some("Application Error".into());
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert!(
            line.ends_with(
                " - Application_Error - - [softnix@32473 application=\"Application Error\"] msg"
            ),
            "{line}"
        );
    }

    #[test]
    fn rfc5424_preserved_param_is_escaped_and_utf8() {
        let mut ev = fixed_event(Some("ระบบ \"x\" ]"), "msg");
        ev.fields.clear();
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert!(line.contains(" WIN-SRV01 _\"x\"_] 4321 - "), "{line}");
        assert!(line.contains(r#"[softnix@32473 application="ระบบ \"x\" \]"] msg"#), "{line}");
    }

    #[test]
    fn rfc5424_preserved_param_yields_to_existing_field() {
        // Plan R-3: an emitted field with the same name wins; exactly one param.
        let mut ev = fixed_event(Some("Service Control Manager"), "msg");
        ev.fields.insert("application".into(), serde_json::Value::from("from-field"));
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert_eq!(line.matches("application=").count(), 1, "{line}");
        assert!(line.contains("application=\"from-field\""), "{line}");
        // ...but a null field (which emits nothing) does not suppress it.
        ev.fields.insert("application".into(), serde_json::Value::Null);
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert_eq!(line.matches("application=").count(), 1, "{line}");
        assert!(line.contains("application=\"Service Control Manager\""), "{line}");
    }

    #[test]
    fn rfc5424_sanitizes_hostname_and_procid() {
        let mut ev = fixed_event(Some("VSS"), "msg");
        ev.hostname = Some("my host".into());
        ev.process_id = Some("12 34".into());
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert!(
            line.contains(
                " my_host VSS 12_34 - [softnix@32473 hostname=\"my host\" \
                 process_id=\"12 34\" channel="
            ),
            "{line}"
        );
    }

    #[test]
    fn rfc5424_empty_application_is_nilvalue_without_param() {
        // Plan R-2: Some("") -> "-" and nothing to preserve.
        let line = format_event(&fixed_event(Some(""), "msg"), OutputFormat::Rfc5424);
        assert!(line.contains(" WIN-SRV01 - 4321 - [softnix@32473 channel="), "{line}");
        assert!(!line.contains("application="), "{line}");
    }

    /// Byte length of a well-formed RFC 5424 STRUCTURED-DATA at the start of
    /// `s` (NILVALUE or 1*SD-ELEMENT), or None if malformed.
    fn sd_len(s: &str) -> Option<usize> {
        if s.starts_with('-') {
            return Some(1);
        }
        let b = s.as_bytes();
        let sd_name = |i: &mut usize| -> bool {
            let start = *i;
            while *i < b.len()
                && (0x21..=0x7e).contains(&b[*i])
                && !matches!(b[*i], b'=' | b' ' | b']' | b'"')
            {
                *i += 1;
            }
            (1..=32).contains(&(*i - start))
        };
        if b.first() != Some(&b'[') {
            return None;
        }
        let mut i = 0;
        while b.get(i) == Some(&b'[') {
            i += 1;
            if !sd_name(&mut i) {
                return None;
            }
            while b.get(i) == Some(&b' ') {
                i += 1;
                if !sd_name(&mut i) || b.get(i) != Some(&b'=') || b.get(i + 1) != Some(&b'"') {
                    return None;
                }
                i += 2;
                loop {
                    match *b.get(i)? {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b']' => return None, // must be escaped inside PARAM-VALUE
                        _ => i += 1,
                    }
                }
            }
            if b.get(i) != Some(&b']') {
                return None;
            }
            i += 1;
        }
        Some(i)
    }

    /// Strict RFC 5424 §6 header check; returns (HOSTNAME, APP-NAME, PROCID, MSG).
    fn strict_rfc5424(line: &str) -> (String, String, String, String) {
        let rest = line.strip_prefix('<').unwrap_or_else(|| panic!("{line:?}"));
        let (pri, rest) = rest.split_once(">1 ").unwrap_or_else(|| panic!("{line:?}"));
        assert!(
            !pri.is_empty() && pri.len() <= 3 && pri.bytes().all(|c| c.is_ascii_digit()),
            "{line:?}"
        );
        let mut parts = rest.splitn(6, ' ');
        let mut next = || parts.next().unwrap_or_else(|| panic!("short header: {line:?}"));
        let (_ts, host, app, procid, msgid, tail) = (next(), next(), next(), next(), next(), next());
        for (tok, max) in [(host, 255), (app, 48), (procid, 128), (msgid, 32)] {
            assert!(
                tok == "-"
                    || (!tok.is_empty()
                        && tok.len() <= max
                        && tok.bytes().all(|c| (0x21..=0x7e).contains(&c))),
                "bad header token {tok:?} in {line:?}"
            );
        }
        let n = sd_len(tail).unwrap_or_else(|| panic!("malformed SD in {line:?}"));
        let msg = tail[n..]
            .strip_prefix(' ')
            .unwrap_or_else(|| panic!("no SP before MSG: {line:?}"));
        (host.into(), app.into(), procid.into(), msg.into())
    }

    #[test]
    fn rfc5424_header_is_valid_for_any_input() {
        use rand::{rngs::StdRng, Rng, SeedableRng};
        const ALPHABET: &[char] = &[
            'a', 'Z', '0', '-', '_', '.', '"', ']', '[', '\\', '=', ':', ' ', '\t', '\n', '\r',
            '\u{0}', '\u{7f}', '\u{a0}', '\u{3000}', 'ร', 'ะ', 'บ', '中', '文', 'é', '🙂',
        ];
        let random_string = |rng: &mut StdRng| -> String {
            let len = rng.gen_range(0..=80);
            (0..len).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())]).collect()
        };
        let mut rng = StdRng::seed_from_u64(0x5EED_5424);
        for _ in 0..2000 {
            let app = random_string(&mut rng);
            let host = random_string(&mut rng);
            let pid = random_string(&mut rng);
            let mut ev = fixed_event(Some(&app), "msg");
            ev.hostname = Some(host.clone());
            ev.process_id = Some(pid.clone());
            let line = format_event(&ev, OutputFormat::Rfc5424);
            let (h, a, p, msg) = strict_rfc5424(&line);
            assert_eq!(a, header_token(&app, APP_NAME_MAX), "{line:?}");
            assert_eq!(h, header_token(&host, HOSTNAME_MAX), "{line:?}");
            assert_eq!(p, header_token(&pid, PROCID_MAX), "{line:?}");
            assert_eq!(msg, "msg", "{line:?}");
        }
    }

    #[test]
    fn rfc5424_round_trips_through_our_parser() {
        use crate::config::SyslogFormat;
        for app in [
            "Service Control Manager",
            "Application Error",
            "Microsoft-Windows-Windows Firewall With Advanced Security",
            "Tab\tSeparated",
            "ระบบ บันทึก",
            "Microsoft-Windows-Security-Auditing",
        ] {
            let line = format_event(&fixed_event(Some(app), "the message"), OutputFormat::Rfc5424);
            let mut back = Event::new("rx", "syslog", "");
            crate::pipeline::parse_syslog_into(&mut back, &line, SyslogFormat::Rfc5424);
            let want = header_token(app, APP_NAME_MAX);
            let want = (want != "-").then(|| want.into_owned());
            assert_eq!(back.application, want, "{line:?}");
            assert_eq!(back.process_id.as_deref(), Some("4321"), "{line:?}");
            assert_eq!(back.hostname.as_deref(), Some("WIN-SRV01"), "{line:?}");
            assert_eq!(back.message, "the message", "{line:?}");
        }
    }
```

- [ ] **Step 3: Run them and confirm they fail.** `cargo test --lib outputs::format` should show:
  - `rfc5424_sanitizes_provider_with_spaces` fails: the line contains `Service Control Manager` verbatim.
  - The four `rfc5424_preserved_param_*` / `…hostname_and_procid` tests fail: no `application=` / `hostname=` param, and the raw value is in the header.
  - `rfc5424_empty_application_is_nilvalue_without_param` fails: the header has `WIN-SRV01  4321`, two spaces.
  - `rfc5424_header_is_valid_for_any_input` panics with `bad header token` or `malformed SD`.
  - `rfc5424_round_trips_through_our_parser` fails on `Service Control Manager` with `left: Some("Service")`.
  - `rfc5424_valid_values_are_byte_identical` and the three original `rfc5424_*` tests **still pass**.

      Record the round-trip and property-loop failure messages in the commit body; they are the evidence that these tests catch the bug.

- [ ] **Step 4: Implement.** Replace the `Rfc5424` arm:

```rust
        OutputFormat::Rfc5424 => {
            let pri = pri_of(ev);
            let ts = ev.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true);
            // Originals of header values that had to be sanitized; re-emitted
            // as SD-PARAMs so nothing is lost. Empty (no allocation) unless
            // something changed.
            let mut preserved = Vec::new();
            let host = rfc5424_header_field(
                ev.hostname.as_deref(),
                HOSTNAME_MAX,
                "-",
                "hostname",
                &mut preserved,
            );
            let app = rfc5424_header_field(
                ev.application.as_deref(),
                APP_NAME_MAX,
                "softnix-log-agent",
                "application",
                &mut preserved,
            );
            let pid = rfc5424_header_field(
                ev.process_id.as_deref(),
                PROCID_MAX,
                "-",
                "process_id",
                &mut preserved,
            );
            let sd = rfc5424_structured_data(ev, &preserved);
            format!("<{pri}>1 {ts} {host} {app} {pid} - {sd} {}", ev.message)
        }
```

      Add the helpers, and rework `rfc5424_structured_data`. Its existing field loop is kept as-is, apart from the four `params.push*` lines, which become one `push_sd_param` call:

```rust
/// Sanitize one RFC 5424 header field. `None` renders as `default`; a value
/// that had to change (and was not empty, plan R-2) is recorded in
/// `preserved` under the SD-PARAM name `param`.
fn rfc5424_header_field<'a>(
    value: Option<&'a str>,
    max: usize,
    default: &'static str,
    param: &'static str,
    preserved: &mut Vec<(&'static str, &'a str)>,
) -> Cow<'a, str> {
    let Some(raw) = value else {
        return Cow::Borrowed(default);
    };
    let token = header_token(raw, max);
    if token != raw && !raw.is_empty() {
        preserved.push((param, raw));
    }
    token
}

fn rfc5424_structured_data(ev: &Event, preserved: &[(&str, &str)]) -> String {
    let mut params = String::new();
    for (name, original) in preserved {
        // Plan R-3: a field of the same name that would itself be emitted
        // wins, so a PARAM-NAME never appears twice.
        if ev.fields.get(*name).and_then(value_to_param).is_some() {
            continue;
        }
        push_sd_param(&mut params, name, original);
    }
    for (key, val) in &ev.fields {
        // ... existing `structured_data` skip, value_to_param, and
        // PARAM-NAME validity check, unchanged ...
        push_sd_param(&mut params, key, &value);
    }
    if params.is_empty() {
        "-".to_string()
    } else {
        format!("[softnix@32473{params}]")
    }
}

fn push_sd_param(params: &mut String, name: &str, value: &str) {
    params.push(' ');
    params.push_str(name);
    params.push_str("=\"");
    params.push_str(&sd_escape(value));
    params.push('"');
}
```

      Remove the `#[cfg_attr(not(test), allow(dead_code))]` attributes added in T1.

- [ ] **Step 5: Run the tests and confirm they pass.** `cargo test --lib outputs::format` should be all green.

      If the property loop finds a counterexample, the fix is incomplete. **Do not weaken the test.** Copy the failing input from the panic message into the T1 table with its correct expected token, and fix `sanitize_token`.

- [ ] **Step 6: Run the gate.** `cargo test --all-targets` should report **197** (188 lib + 3 + 6 + 0). The property loop should take well under 1 s in debug; if not, lower it to 1,000 iterations and say why in the commit. Clippy and fmt must be clean, and `cargo build` must show no `dead_code` warning.

- [ ] **Step 7: Commit.** `fix(format): sanitize RFC 5424 HOSTNAME/APP-NAME/PROCID, keep originals in SD`

---

### Task 3: RFC 3164 HOSTNAME / TAG / PID (spec Part B)

**Files:**
- Modify: `src/outputs/format.rs`. Change the `OutputFormat::Rfc3164` arm of `format_event`, and add the constant `RFC3164_TAG_DELIMS` next to the T1 constants. Append the tests.

**Interfaces:**
- Consumes: T1's `sanitize_token`, `header_token`, `HOSTNAME_MAX`, `PROCID_MAX`; T2's test helper `fixed_event`; `crate::pipeline::parse_syslog_into` with `SyslogFormat::Rfc3164`.
- Produces: `const RFC3164_TAG_DELIMS: &[char] = &['[', ']', ':'];`

- [ ] **Step 1: Write the failing tests.** Append:

```rust
    #[test]
    fn rfc3164_sanitizes_tag_pid_and_host() {
        let mut ev = fixed_event(Some("Service Control Manager"), "msg");
        let line = format_event(&ev, OutputFormat::Rfc3164);
        assert!(line.ends_with(" WIN-SRV01 Service_Control_Manager[4321]: msg"), "{line}");

        ev.application = Some("Foo:Bar[x]".into()); // delimiters inside TAG
        ev.process_id = Some("12]34".into()); // plan R-4
        ev.hostname = Some("my host".into());
        let line = format_event(&ev, OutputFormat::Rfc3164);
        assert!(line.ends_with(" my_host Foo_Bar_x_[12_34]: msg"), "{line}");

        // Not capped at 32 (spec open question 3, plan R-0).
        ev.application = Some("Microsoft-Windows-Security-Auditing".into());
        ev.process_id = None;
        let line = format_event(&ev, OutputFormat::Rfc3164);
        assert!(line.ends_with(" Microsoft-Windows-Security-Auditing: msg"), "{line}");
    }

    #[test]
    fn rfc3164_round_trips_through_our_parser() {
        use crate::config::SyslogFormat;
        let ev = fixed_event(Some("Service Control Manager"), "the message");
        let line = format_event(&ev, OutputFormat::Rfc3164);
        let mut back = Event::new("rx", "syslog", "");
        crate::pipeline::parse_syslog_into(&mut back, &line, SyslogFormat::Rfc3164);
        assert_eq!(back.hostname.as_deref(), Some("WIN-SRV01"), "{line:?}");
        assert_eq!(back.application.as_deref(), Some("Service_Control_Manager"), "{line:?}");
        assert_eq!(back.process_id.as_deref(), Some("4321"), "{line:?}");
        assert_eq!(back.message, "the message", "{line:?}");
    }

    #[test]
    fn rfc3164_valid_values_are_byte_identical() {
        // Same pinning idea as the RFC 5424 test: valid names do not change.
        let line = format_event(&fixed_event(Some("EventLog"), "msg"), OutputFormat::Rfc3164);
        assert_eq!(line, "<14>Nov 10 08:58:07 WIN-SRV01 EventLog[4321]: msg");
    }
```

- [ ] **Step 2: Run them and confirm they fail.** `cargo test --lib outputs::format` should fail the first two tests:
  - The line contains `Service Control Manager[4321]`.
  - The parser leaves `application = None` and puts the whole remainder in `message`, because `parse_rfc3164` rejects tags containing a space (`src/pipeline/syslog.rs`, `if !tag.contains(' ') && tag.len() <= 48`).

      `rfc3164_valid_values_are_byte_identical` passes, which confirms the PRI and timestamp assumptions.

- [ ] **Step 3: Implement.** Add next to the T1 constants:

```rust
/// Characters that delimit PID and CONTENT in an RFC 3164 `TAG[PID]:`, so
/// they must not appear inside either.
const RFC3164_TAG_DELIMS: &[char] = &['[', ']', ':'];
```

      Replace the `Rfc3164` arm:

```rust
        OutputFormat::Rfc3164 => {
            let pri = pri_of(ev);
            let ts = ev.timestamp.format("%b %e %H:%M:%S");
            let host = ev
                .hostname
                .as_deref()
                .map_or(Cow::Borrowed("-"), |h| header_token(h, HOSTNAME_MAX));
            // RFC 3164 has no structured data: the original value cannot be
            // kept on this wire (documented; use rfc5424 or json for that).
            // TAG length is deliberately not capped (plan R-0).
            let tag = ev.application.as_deref().map_or(Cow::Borrowed("softnix"), |a| {
                sanitize_token(a, usize::MAX, RFC3164_TAG_DELIMS)
            });
            match ev.process_id.as_deref() {
                Some(pid) => {
                    let pid = sanitize_token(pid, PROCID_MAX, RFC3164_TAG_DELIMS);
                    format!("<{pri}>{ts} {host} {tag}[{pid}]: {}", ev.message)
                }
                None => format!("<{pri}>{ts} {host} {tag}: {}", ev.message),
            }
        }
```

- [ ] **Step 4: Run the tests and confirm they pass.** Every test in `outputs::format` should pass, including the existing `rfc3164_format`.

- [ ] **Step 5: Run the gate.** `cargo test --all-targets` should report **200** (191 lib + 3 + 6 + 0), plus clippy and fmt clean.

- [ ] **Step 6: Commit.** `fix(format): sanitize RFC 3164 HOSTNAME/TAG/PID`

---

### Task 4: documentation

**Files:**
- Modify: `docs/CONFIGURATION.md`. Change the `inputs.eventlog` "Mapped event fields" bullet (around line 203) and the "Notes on formats/transports" list (around line 409).
- Modify: `docs/CONFIGURATION.th.md`. Make the same two places match (around lines 202 and 408).
- Modify: `docs/INSTALL-WINDOWS.md`. Add a bullet after "Messages" (around line 107).
- Modify: `docs/superpowers/specs/2026-11-10-syslog-header-sanitization.md`. Once the owner has answered the open questions, set the status line to approved and record the answers.

- [ ] **Step 1: `CONFIGURATION.md`, formats notes.** Add after the `rfc5424 output emits enrichment…` bullet:

```markdown
- Header fields are made wire-safe: in `rfc5424` and `rfc3164` output, any
  character outside printable ASCII (spaces, tabs, non-ASCII) in `hostname`,
  `application` or `process_id` is replaced by `_` (a run collapses to one),
  and values are capped at the RFC limits (APP-NAME 48, HOSTNAME 255,
  PROCID 128). Example: provider `Service Control Manager` is sent as
  APP-NAME `Service_Control_Manager`. In `rfc5424` the original value is kept
  in the STRUCTURED-DATA element (`application="Service Control Manager"`,
  likewise `hostname` / `process_id`); `rfc3164` has no place for it. Values
  that are already valid are sent unchanged. `json` output, `when:`
  conditions and routing always see the original value.
```

- [ ] **Step 2: `CONFIGURATION.md`, eventlog mapping.** Append to the "Mapped event fields" bullet: ``Provider names containing spaces are sanitized on the syslog wire only — see *Notes on formats/transports*.``

- [ ] **Step 3: `CONFIGURATION.th.md`.** Add the same passage in Thai after the `output rfc5424 แนบ field enrich/custom…` bullet:

```markdown
- field ใน header ถูกทำให้ปลอดภัยสำหรับ wire: ใน output `rfc5424` และ `rfc3164`
  อักขระที่ไม่ใช่ ASCII ที่พิมพ์ได้ (เว้นวรรค, tab, อักขระที่ไม่ใช่ ASCII) ใน
  `hostname`, `application` หรือ `process_id` จะถูกแทนด้วย `_` (ติดกันหลายตัว
  เหลือตัวเดียว) และตัดความยาวตามที่ RFC กำหนด (APP-NAME 48, HOSTNAME 255,
  PROCID 128) เช่น provider `Service Control Manager` ถูกส่งเป็น APP-NAME
  `Service_Control_Manager` ใน `rfc5424` ค่าเดิมถูกเก็บไว้ใน STRUCTURED-DATA
  (`application="Service Control Manager"` และ `hostname` / `process_id`
  แบบเดียวกัน) ส่วน `rfc3164` ไม่มีที่เก็บ ค่าที่ถูกต้องอยู่แล้วส่งออกไปตามเดิม
  output `json`, เงื่อนไข `when:` และ routing เห็นค่าเดิมเสมอ
```

      For the mapping bullet: ``ชื่อ provider ที่มีเว้นวรรคจะถูกแปลงเฉพาะบน syslog wire — ดูหมายเหตุเรื่อง format/transport``

- [ ] **Step 4: `INSTALL-WINDOWS.md`.** Add after the "Messages" bullet:

```markdown
- **Provider names with spaces** (e.g. `Service Control Manager`, `Application Error`) are sent over syslog as `Service_Control_Manager` / `Application_Error`, because RFC 5424 forbids spaces in APP-NAME. The exact name is kept in the structured data as `application="…"` (rfc5424 only) — see [CONFIGURATION.md](CONFIGURATION.md#outputs).
```

      Before committing, check that the anchor exists: `grep -n '^## .*outputs' docs/CONFIGURATION.md`. If the heading is spelled differently, fix the anchor.

- [ ] **Step 5: Check.** Run `cargo test --all-targets` and confirm 200 (docs-only change; this confirms nothing else moved).

- [ ] **Step 6: Commit.** `docs(format): document syslog header sanitization`

---

### Task 5: verification — smoke re-run and full gate

**Files:** none in the repo. Uses `/tmp/softnix-smoke.LTIcHO/harness/smoke.py` (plan R-6). If `/tmp` has been cleaned, rebuild the harness from the spec's "Evidence" section: two agents; file input with `parser: json`; stdout `rfc5424` plus a syslog forward; 6 rounds over TCP-newline / TCP-octet-counting / UDP × receiver `rfc5424` / `auto`; 36 cases per round.

- [ ] **Step 1: Point the harness's expectation at the sanitized value.** Add this Python twin of `sanitize_token`:

```python
def tok(raw, mx, extra=()):
    ok = lambda c: 33 <= ord(c) <= 126 and c not in extra
    if raw and len(raw.encode()) <= mx and all(ok(c) for c in raw):
        return raw
    out, rep = [], False
    for c in raw.strip():
        if len(out) >= mx:
            break
        if ok(c):
            out.append(c); rep = False
        elif not rep:
            out.append("_"); rep = True
    s = "".join(out)
    return "-" if set(s) <= {"_"} else s
```

      Then, with `want = tok(name, 48)`:
  - `wire_app_ok` becomes `p["app"] == want`.
  - `rx_ok` checks `r.get("application") == (None if want == "-" else want)`; the pid and message checks are unchanged.
  - Add `wire_orig_ok`: when `want != name and name != ""`, the wire line contains `application="<name with \ " ] escaped>"`.

- [ ] **Step 2: Build and run.** Run `cargo build`, then `python3 -I /tmp/softnix-smoke.LTIcHO/harness/smoke.py target/debug/softnix-log-agent "$(mktemp -d)" 6`. Expected, using the same aggregation as the investigation:
  - Strict ABNF valid: **216/216**.
  - APP-NAME equals `tok(name)`: **216/216**.
  - Original preserved wherever it changed: **all** such rows.
  - On newline transports (rounds 1, 3, 4, 6), the receiver's `application`, `process_id` and `message` all match: **144/144**.
  - Octet-counting rounds 2 and 5 still fail on the **receiver** side. This is expected: the input does not decode octet-counting (spec "Out of scope" #1), so it is not a regression. Their **wire** lines must still be 72/72 ABNF-valid.

      Any miss outside the receiver side of rounds 2 and 5 is a bug. Add that exact input to the T1 table and go back to T1.

- [ ] **Step 3: Full gate.** Run `cargo test --all-targets` (200), `cargo clippy --all-targets`, `cargo fmt --all -- --check` and `cargo build --release`. Run `cargo check --target x86_64-pc-windows-gnu` only if a mingw toolchain is installed (`brew install mingw-w64`); otherwise CI's `test-windows` job is the gate.

- [ ] **Step 4:** Paste the Step 2 numbers into the PR description.

---

### Task 6: manual Windows check and release note (owner, before tagging)

- [ ] **Step 1:** Run the patched build on a real Windows host. Configure an `eventlog` input on `System` and a `syslog` output (rfc5424, tcp, newline framing) pointing at a test receiver. A second agent with a `syslog` input and `stdout` json output is enough as the receiver.
- [ ] **Step 2:** Run `Restart-Service Spooler`, which produces 7036 events from `Service Control Manager`. On the receiver, confirm:
  - `APP-NAME=Service_Control_Manager`
  - PROCID equal to the real pid
  - an SD containing `application="Service Control Manager"`
  - the rendered message intact
- [ ] **Step 3:** Raise an `Application Error` (1000) event, for example by crashing a test process. Confirm `Application_Error` in the header and the original in the SD.
- [ ] **Step 4: Release note** (patch version, 0.1.x):

```markdown
### Fixed
- Syslog output (rfc5424/rfc3164): Windows Event Log provider names that
  contain spaces (e.g. `Service Control Manager`, `Application Error`) no
  longer produce malformed headers. They are now sent as
  `Service_Control_Manager`; the exact name is kept in STRUCTURED-DATA as
  `application="Service Control Manager"` (rfc5424).
  **Action:** SIEM rules that matched the previously corrupted values
  (e.g. APP-NAME `Service` / `Application`) must be updated.
```

---

## Coverage check against the spec

| Spec item | Where it is covered |
|---|---|
| Header token rule (trim, replace, collapse, cap, `_`-only → `-`) | T1 implementation, `header_token_table`, `sanitize_token_extra_chars_and_caps` |
| Expected APP-NAME table | T1 `header_token_table`, row for row |
| HOSTNAME 255 / PROCID 128 | T1 caps test, T2 `rfc5424_sanitizes_hostname_and_procid`, T2 property loop |
| Original preserved in SD, only when altered | T2 `…sanitizes_provider_with_spaces`, `…creates_sd_element`, `…escaped_and_utf8` |
| Collision with `ev.fields` | T2 `rfc5424_preserved_param_yields_to_existing_field` (plus R-3) |
| Goal 3: byte-identical for valid values | T2 Step 1, pinned before the change; T3 `rfc3164_valid_values_are_byte_identical` |
| Unit test 5 (property loop, about 2,000 strings) | T2 `rfc5424_header_is_valid_for_any_input` |
| Unit test 6 (round-trip through own parser) | T2 `rfc5424_round_trips_through_our_parser` |
| Unit test 7 / Part B, RFC 3164 | T3 |
| Event / JSON / conditions untouched (non-goal) | Structural: only `format.rs` changes, and no `Event` field is written anywhere in the diff |
| Docs (CONFIGURATION ×2, INSTALL-WINDOWS) | T4 |
| Smoke re-run 216/216, 144/144 | T5 |
| Manual Windows check, release note | T6 |
| Out-of-scope items (octet-counting input, stdout self-logs, PEN 32473) | Not addressed; T5 notes the octet-counting receiver rounds are expected to still fail |

## Risks and known trade-offs

- **SIEM rules keyed on the corrupted values break.** This is intended, and it is called out in the release note (T6 Step 4).
- **RFC 3164 loses the original name.** This is documented (T4), and there is no fix within the 3164 format.
- **The NILVALUE `-` hides fully non-ASCII names in the header.** The original is still in the RFC 5424 SD, but not on the 3164 wire (R-5).
- **Hot-path cost:** valid values take the borrowed fast path, which is one `chars().all(..)` scan per header field, and the `preserved` `Vec` does not allocate unless something changed.
- **R-4 extends the spec** (the RFC 3164 PID is sanitized). The reviewer should explicitly accept or reject it.
