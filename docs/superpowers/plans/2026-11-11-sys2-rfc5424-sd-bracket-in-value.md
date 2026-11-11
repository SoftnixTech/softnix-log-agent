# SYS-2 RFC 5424 STRUCTURED-DATA End Detection Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking. Execute the tasks in order. The commit-producing task shows a red run before its fix, and ends with the full gate.

**Goal:** `parse_rfc5424` finds the end of STRUCTURED-DATA by the RFC 5424 grammar, so a `[` (or an escaped `"` followed by `]`) inside a quoted PARAM-VALUE no longer empties `message`. A line for which the grammar scan finds no end parses exactly as it does today.

**Architecture:** The inline bracket-depth loop in `parse_rfc5424` (`src/pipeline/syslog.rs:93-112`) moves into two private functions: `sd_end_by_grammar` (new, quote-aware, returns `None` when it finds no end) and `sd_end_by_brackets` (today's loop, unchanged, used as the fallback). `sd_end` combines them.

**Tech Stack:** Rust 2021, no new dependency.

**Spec:** `docs/superpowers/specs/2026-11-11-sys2-rfc5424-sd-bracket-in-value.md`

## Global Constraints

- Branch `develop_fix_bug_known-issues`, after the SYS-4 plan (order #6 in `ISSUES.md`'s Fix plan). `rust-version = "1.98"`. If `cargo` is not on `PATH`, use `export PATH="$HOME/.cargo/bin:$PATH"`.
- **Code changes only in** `src/pipeline/syslog.rs`. Docs: `ISSUES.md` (T2). No config, dependency or wire change.
- **Lib test count:** **+10** over the count before T1 (225 if SYS-4 is done first, which leaves 215).
- **Gate** (after T1):

  ```bash
  cargo fmt --all -- --check
  RUSTFLAGS="-D warnings" cargo clippy --all-targets
  RUSTFLAGS="-D warnings" cargo test --all-targets
  RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets
  ```

  Do **not** set `CARGO_TARGET_DIR`.
- Stage files **by name**, never `git add -A`. Every commit message ends with `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`.
- **Not prototyped.** At the owner's request no source was touched while writing this plan, so the snippets below have never been compiled. T1 step 1's red run and step 3's gate are their verification. Expect small `cargo fmt` differences. The expected results in T1 were traced by hand against the code at `7abecf9`.

## Rulings

**R-0: No owner decision.** The spec has no open question.

**R-1: Fallback on "no end found".** The spec (as revised 2026-11-11) falls back to the old scan whenever the grammar scan reaches the end of the line without finding the end of the SD, not only when it ends inside quotes. `sd_end_by_grammar` therefore returns `Option<usize>`.

**R-2: The old scan is kept verbatim** as `sd_end_by_brackets`, including its `\` handling outside quotes. It is only reached for lines that are not valid RFC 5424, and Goal 3 requires those to parse as today.

---

## Dependency graph

```text
T0 C1 docs: spec + plan
T1 C2 fix(pipeline): SD end by the grammar   (red 4 → green, +10 tests)
   harness re-run (no commit)
T2 C3 ISSUES.md: SYS-2 fixed                 (needs the C2 hash)
```

---

### Task 0: C1, spec and plan

- [ ] **Step 1:**

  ```bash
  git add docs/superpowers/specs/2026-11-11-sys2-rfc5424-sd-bracket-in-value.md docs/superpowers/plans/2026-11-11-sys2-rfc5424-sd-bracket-in-value.md
  git commit -m "docs: spec and plan for SYS-2 RFC 5424 structured-data end detection" -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

---

### Task 1: C2, end STRUCTURED-DATA by the grammar

**File:** `src/pipeline/syslog.rs`.

- [ ] **Step 1: tests first (red).** In `mod tests`, insert directly **before** `    #[test]\n    fn rfc3164_thai_body_does_not_panic() {`:

```rust
    /// Parse an RFC 5424 line whose STRUCTURED-DATA and MSG are `tail`.
    /// Returns the `structured_data` field and `message`.
    fn parse_sd(tail: &str) -> (Option<String>, String) {
        let mut ev = Event::new("net", "syslog", "");
        let line = format!("<165>1 2026-06-10T22:14:15Z h1 app 1 ID47 {tail}");
        assert!(parse_rfc5424(&mut ev, &line));
        let sd = ev
            .fields
            .get("structured_data")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        (sd, ev.message)
    }

    fn assert_sd(tail: &str, sd: &str, message: &str) {
        let (got_sd, got_message) = parse_sd(tail);
        assert_eq!(got_sd.as_deref(), Some(sd), "structured_data of {tail:?}");
        assert_eq!(got_message, message, "message of {tail:?}");
    }

    // SYS-2: `[` inside a quoted PARAM-VALUE is valid (RFC 5424 §6.3.3) and
    // must not be counted as an SD-ELEMENT bracket.
    #[test]
    fn sd_value_with_open_bracket_keeps_message() {
        assert_sd(
            r#"[ex@32473 k="open [ only"] hello"#,
            r#"[ex@32473 k="open [ only"]"#,
            "hello",
        );
    }

    #[test]
    fn sd_value_with_escaped_close_and_open_bracket() {
        assert_sd(
            r#"[ex@32473 rule="Contoso [TCP 443\]"] hello"#,
            r#"[ex@32473 rule="Contoso [TCP 443\]"]"#,
            "hello",
        );
    }

    #[test]
    fn sd_value_bracket_in_first_of_two_elements() {
        assert_sd(
            r#"[a@32473 k="x [y\]"][b@32473 z="1"] hello"#,
            r#"[a@32473 k="x [y\]"][b@32473 z="1"]"#,
            "hello",
        );
    }

    #[test]
    fn sd_escaped_quote_before_bracket_in_value() {
        assert_sd(
            r#"[ex@32473 k="a\"]b"] hello"#,
            r#"[ex@32473 k="a\"]b"]"#,
            "hello",
        );
    }

    #[test]
    fn sd_plain_and_escaped_close_unchanged() {
        assert_sd(
            r#"[ex@32473 k="plain"] hello"#,
            r#"[ex@32473 k="plain"]"#,
            "hello",
        );
        assert_sd(
            r#"[ex@32473 k="a\]b"] hello"#,
            r#"[ex@32473 k="a\]b"]"#,
            "hello",
        );
    }

    #[test]
    fn sd_escaped_backslash_before_closing_quote() {
        assert_sd(
            r#"[ex@32473 k="a\\"] hello"#,
            r#"[ex@32473 k="a\\"]"#,
            "hello",
        );
    }

    /// Malformed SD (an unterminated quote): parsed as before SYS-2.
    #[test]
    fn sd_unterminated_quote_falls_back_to_old_scan() {
        assert_sd(
            r#"[ex@32473 k="never closed] hello"#,
            r#"[ex@32473 k="never closed]"#,
            "hello",
        );
    }

    /// Malformed SD whose stray quote pairs up with a quote in MSG: the
    /// grammar scan ends outside quotes without finding an end, and the old
    /// scan decides.
    #[test]
    fn sd_stray_quotes_fall_back_to_old_scan() {
        assert_sd(
            r#"[ex@32473 k="5" screen"] it's ""#,
            r#"[ex@32473 k="5" screen"]"#,
            r#"it's ""#,
        );
    }

    #[test]
    fn sd_without_message_unchanged() {
        assert_sd(r#"[ex@32473 k="v"]"#, r#"[ex@32473 k="v"]"#, "");
    }

    #[test]
    fn sd_nilvalue_unchanged() {
        assert_eq!(parse_sd("- hello"), (None, "hello".to_string()));
    }
```

  Run `cargo test --lib pipeline::syslog::tests::sd_`. Expected: **4 failed, 6 passed**. The failures are `sd_value_with_open_bracket_keeps_message`, `sd_value_with_escaped_close_and_open_bracket`, `sd_value_bracket_in_first_of_two_elements` (all three: `message` is empty and `structured_data` is the whole tail) and `sd_escaped_quote_before_bracket_in_value` (`structured_data` ends at `a\"]`). If `sd_stray_quotes_fall_back_to_old_scan` does not compile because of the raw-string delimiters, write its strings with `r##"…"##`.

- [ ] **Step 2: the fix (green).** In `parse_rfc5424`, replace the whole `else if tail.starts_with('[') { … }` arm (from `} else if tail.starts_with('[') {` up to and including its `m.trim_start()` line) with:

```rust
    } else if tail.starts_with('[') {
        // find end of (possibly multiple) SD elements
        let (sd, m) = tail.split_at(sd_end(tail));
        ev.fields
            .insert("structured_data".to_string(), Value::String(sd.to_string()));
        m.trim_start()
```

  Insert directly **after** the closing `}` of `parse_rfc5424` (before the `/// RFC3164:` doc comment):

```rust

/// Byte index just past the last SD-ELEMENT of `tail`, which starts with `[`.
/// The index always follows an ASCII `]` (or is `tail.len()`), so it is a
/// char boundary.
fn sd_end(tail: &str) -> usize {
    sd_end_by_grammar(tail).unwrap_or_else(|| sd_end_by_brackets(tail))
}

/// The RFC 5424 §6.3 grammar: `[` and `]` delimit SD-ELEMENTs only outside a
/// quoted PARAM-VALUE, and inside quotes `\` escapes the next byte (`\"`,
/// `\\`, `\]`). Returns `None` when the line ends before the SD does, which
/// means the SD is malformed (for example an unterminated quote).
fn sd_end_by_grammar(tail: &str) -> Option<usize> {
    let bytes = tail.as_bytes();
    let mut depth = 0usize;
    let mut in_quotes = false;
    let mut i = 0;
    while i < bytes.len() {
        match (in_quotes, bytes[i]) {
            (true, b'\\') => i += 1, // skip the escaped byte
            (true, b'"') => in_quotes = false,
            (false, b'"') => in_quotes = true,
            (false, b'[') => depth += 1,
            (false, b']') => {
                depth = depth.saturating_sub(1);
                if depth == 0 && bytes.get(i + 1) != Some(&b'[') {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The scan used before SYS-2: every `[` and `]` counts, quoted or not. Kept
/// for malformed SD only, so such a line parses exactly as it always has.
/// Returns `tail.len()` when it finds no end either.
fn sd_end_by_brackets(tail: &str) -> usize {
    let bytes = tail.as_bytes();
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => depth += 1,
            b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 && (i + 1 >= bytes.len() || bytes[i + 1] != b'[') {
                    return i + 1;
                }
            }
            b'\\' => i += 1, // skip escaped char
            _ => {}
        }
        i += 1;
    }
    tail.len()
}
```

  `cargo test --lib pipeline::syslog` is all green, including the existing `rfc5424_parses`.

- [ ] **Step 3: gate.** Lib count is **+10**.
- [ ] **Step 4: harness (no commit).** If `/tmp/softnix-smoke.LTIcHO/harness/issues_repro.py` still exists:

  ```bash
  cargo build && mkdir -p /tmp/sys2-runs
  python3 /tmp/softnix-smoke.LTIcHO/harness/issues_repro.py "$PWD/target/debug/softnix-log-agent" /tmp/sys2-runs 3
  python3 -c 'import json; [print(r) for r in json.load(open("/tmp/sys2-runs/results.json"))["runs"]["SYS-2"]]'
  ```

  Expected: all 6 cases correct in each of the 3 runs (it was 2/6). If the harness is gone, skip this step and say so in the commit body.

- [ ] **Step 5: commit.**

  ```bash
  git add src/pipeline/syslog.rs
  git commit -m "fix(pipeline): end RFC 5424 STRUCTURED-DATA by the grammar, not raw brackets" -m "parse_rfc5424 counted every '[' and ']', including those inside a quoted PARAM-VALUE. A valid value such as rule=\"Contoso [TCP 443\\]\" raised the depth, the scan ran to the end of the line, and message became empty (SYS-2).

Brackets now count only outside quotes, and '\\' escapes only inside them. When that scan finds no end (malformed SD), the previous scan decides, so such lines parse as before." -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

---

### Task 2: C3, mark SYS-2 fixed in `ISSUES.md`

- [ ] **Step 1:** In the summary table, set SYS-2's status to **fixed** with the `<C2>` hash.
- [ ] **Step 2:** Replace the SYS-2 entry's status line with: **Status: fixed** in `<C2>` (branch `develop_fix_bug_known-issues`, not yet merged). In its **Fix.** paragraph, change "If the scan ends inside an unterminated quote, fall back to today's scan" to "If the scan finds no end of the SD, fall back to the previous scan".
- [ ] **Step 3:** In the Fix plan, move the SYS-2 row from **Remaining** to **Done** (issue, severity Medium, the hash, the spec file name).
- [ ] **Step 4:**

  ```bash
  git add ISSUES.md
  git commit -m "docs: mark SYS-2 fixed" -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

---

## Coverage check against the spec

| Spec item | Where |
| --- | --- |
| Goal 1 (grammar) | `sd_value_with_open_bracket_keeps_message`, `sd_value_with_escaped_close_and_open_bracket`, `sd_value_bracket_in_first_of_two_elements`, `sd_escaped_quote_before_bracket_in_value` |
| Goal 2 (valid lines identical) | `sd_plain_and_escaped_close_unchanged`, `sd_escaped_backslash_before_closing_quote`, `sd_without_message_unchanged`, `sd_nilvalue_unchanged`, the existing `rfc5424_parses` |
| Goal 3 (malformed no worse, no panic) | `sd_unterminated_quote_falls_back_to_old_scan`, `sd_stray_quotes_fall_back_to_old_scan`, the existing `no_panic_on_any_multibyte_offset` |
| End-to-end | T1 step 4 |

## Risks

- **Unverified snippets** (see Global Constraints). If a guard test (one expected to pass before the fix) fails in the red run, the hand trace was wrong: stop and re-check that case against the current code before going on.
- **A malformed SD for which the grammar scan does find an end** is split differently from before, for example an unescaped `]` inside a value no longer ends the SD early. The spec accepts this as an improvement.
