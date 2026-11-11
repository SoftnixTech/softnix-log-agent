# SYS-8 Eventlog XML Attribute Unescape Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking. Execute the tasks in order. Run this plan **after** the SYS-9 plan, on the same branch.

**Goal:** Resolve entity and character references in the attribute values `parse_event_xml` reads (`Provider Name`, `Data Name`, `TimeCreated SystemTime`, `Execution ProcessID`), using a `quick-xml` API that is not deprecated.

**Architecture:** One closure changes, the `attr` closure in `src/inputs/eventlog_xml.rs`. `String::from_utf8_lossy(&a.value)` becomes `a.normalized_value(XmlVersion::Implicit1_0)`, falling back to the raw value on error.

**Tech Stack:** Rust 2021, `quick-xml` 0.41 `Attribute::normalized_value`. **Not** `unescape_value`, which is deprecated and fails `-D warnings`.

**Spec:** `docs/superpowers/specs/2026-11-11-sys8-eventlog-xml-attribute-unescape.md`
**Prerequisite:** `docs/superpowers/plans/2026-11-11-sys9-eventlog-xml-text-entities.md` must have completed (commits C0–C4). That plan moves the parser into `src/inputs/eventlog_xml.rs`. This plan uses its gate, its `/tmp/sys89/stages.py` and its `$FINAL` snapshot.

## Global Constraints

- Starting point: HEAD is the SYS-9 plan's C4 (`docs: mark SYS-9 fixed`), and `src/inputs/eventlog_xml.rs` holds the C3 state, with no `normalized_value` or `XmlVersion` in it.
- **Lib test count:** 187 before this plan, **190** after it: the 2 SYS-8 tests, plus the fallback guard added in T1 step 3.
- The gate is the same four commands as in the SYS-9 plan (fmt, clippy `-D warnings`, test `-D warnings`, `+1.98 check`).
- Only `src/inputs/eventlog_xml.rs` changes in code. Docs: this spec and plan, and `ISSUES.md`.
- Commit trailer and staging rules are the same as in the SYS-9 plan.

## Rulings

**R-0: The final file is the target.** After T1 step 2 the working file must be byte-identical to `$FINAL` (`/tmp/sys89/final_eventlog_xml.rs`, saved in SYS-9 T0). The snippets below are the same code, written out so this plan still works if `/tmp/sys89` is gone. Apply them by hand in that case.

**R-1: The red state is shown first.** As in SYS-9, nothing is committed until the 2 SYS-8 tests have been seen failing against the old closure.

**R-2: The fallback gets a guard test.** It was found in the plan review (2026-11-11, scratch crate): an unknown entity (`a&foo;b`), an invalid character reference (`a&#0;b`) or a bare `&` (`a&b`) in an attribute makes `normalized_value` return `Err`, so the closure's raw-value fallback can be reached. In all three cases the old and new code both return the raw value. The guard pins this behaviour (spec Goal 4). It is not in `$FINAL`, so it is added after the `cp` (T1 step 3).

---

### Task 0: C5, spec and plan

- [ ] **Step 1:** `git status --short` lists the SYS-8 spec and plan as untracked, and `report.html` as untracked. Nothing else is modified.
- [ ] **Step 2:**

  ```bash
  git add docs/superpowers/specs/2026-11-11-sys8-eventlog-xml-attribute-unescape.md docs/superpowers/plans/2026-11-11-sys8-eventlog-xml-attribute-unescape.md
  git commit -m "docs: spec and plan for SYS-8 eventlog XML attribute unescape" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
  ```

---

### Task 1: C6, unescape attribute values

**Files:** `src/inputs/eventlog_xml.rs` only.

- [ ] **Step 1: red.** `python3 -I /tmp/sys89/stages.py c6-red $FINAL src/inputs/eventlog_xml.rs`. This adds the two SYS-8 tests, but leaves the old closure in place. Then run `cargo test --lib eventlog_xml`. Expected: **2 failed, 10 passed**. The failures must be exactly `provider_name_is_unescaped` and `data_name_attribute_is_unescaped`.

  If `/tmp/sys89` is gone, add the tests by hand instead. Insert this section directly before `    // --- Guards:` in `mod tests`:

  ```rust
      // --- SYS-8: attribute values must be unescaped ---

      #[test]
      fn provider_name_is_unescaped() {
          for (raw, want) in [
              ("Backup &amp; Restore", "Backup & Restore"),
              ("Contoso &quot;Agent&quot;", "Contoso \"Agent\""),
              ("O&apos;Brien Tools", "O'Brien Tools"),
              ("Tab&#9;Name", "Tab\tName"),
          ] {
              let p = parse_event_xml(&format!(
                  "<Event><System><Provider Name='{raw}'/></System></Event>"
              ));
              assert_eq!(p.provider, want, "Provider Name='{raw}'");
          }
      }

      #[test]
      fn data_name_attribute_is_unescaped() {
          assert_eq!(
              data_of("<Data Name='A&amp;B'>v</Data>"),
              vec![pair("A&B", "v")]
          );
      }

  ```

- [ ] **Step 2: green.** `cp $FINAL src/inputs/eventlog_xml.rs`. If `/tmp/sys89` is gone, make the two edits by hand: add `    use quick_xml::XmlVersion;` after `    use quick_xml::reader::Reader;` in `parse_event_xml`, then replace the `attr` closure with:

  ```rust
      // Attribute values with references resolved (SYS-8). `normalized_value`,
      // not the deprecated `unescape_value` (which fails `-D warnings`). On a
      // malformed reference fall back to the raw value, so a bad attribute
      // never turns into `None`.
      let attr = |e: &quick_xml::events::BytesStart, name: &[u8]| -> Option<String> {
          e.attributes().flatten().find_map(|a| {
              if a.key.as_ref() == name {
                  Some(match a.normalized_value(XmlVersion::Implicit1_0) {
                      Ok(v) => v.into_owned(),
                      Err(_) => String::from_utf8_lossy(&a.value).into_owned(),
                  })
              } else {
                  None
              }
          })
      };
  ```

  Then `cargo test --lib eventlog_xml`. Expected: **12 passed**.

- [ ] **Step 3: fallback guard (R-2).** Insert directly after `data_name_attribute_is_unescaped`, inside the SYS-8 section:

  ```rust
      #[test]
      fn malformed_attribute_reference_keeps_raw_value() {
          // `normalized_value` returns Err for these; the fallback keeps the
          // raw attribute instead of dropping it (spec Goal 4). Same result
          // as before the fix.
          for raw in ["a&foo;b", "a&#0;b", "a&b"] {
              let p = parse_event_xml(&format!(
                  "<Event><System><Provider Name='{raw}'/></System></Event>"
              ));
              assert_eq!(p.provider, raw, "Provider Name='{raw}'");
          }
      }
  ```

  Then run `cargo test --lib eventlog_xml`. Expected: **13 passed**. This guard is a behaviour pin, not a red test: the old closure returns the same raw values. That was checked in the scratch crate during the plan review (R-2), so it needs no red step.

- [ ] **Step 4: verify the scope.** `git diff HEAD -- src/inputs/eventlog_xml.rs` shows only three changes: the `XmlVersion` import, the closure (with its comment), and the SYS-8 test section (3 tests). `grep -c "unescape_value(" src/inputs/eventlog_xml.rs` must print `0`, because only the comment mentions it, without `(`.
- [ ] **Step 5: gate.** The expected lib count is **190**, with clippy clean and no deprecation warning.
- [ ] **Step 6: commit.**

  ```bash
  git add src/inputs/eventlog_xml.rs
  git commit -F - <<'EOF'
  fix(eventlog): unescape XML attribute values

  parse_event_xml read attribute values as raw bytes, so Provider Name,
  Data Name, SystemTime and ProcessID kept &amp; / &quot; / &apos; /
  &#9; literally: "Backup &amp; Restore" reached Event.application and
  EvtOpenPublisherMetadata escaped, so its messages could not render.

  Use Attribute::normalized_value (standard XML attribute-value
  normalization, predefined entities and character references resolved),
  falling back to the raw value on a malformed reference. Not
  unescape_value: it is deprecated in quick-xml 0.41 and fails
  -D warnings.

  Fixes SYS-8.

  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  EOF
  ```

  Record `<C6>`.

---

### Task 2: C7, mark SYS-8 fixed in `ISSUES.md`

- [ ] **Step 1:** Under the SYS-8 heading add:
  `**Status: fixed** in \`<C6>\` (branch \`develop_fix_bug_known-issues\`, not yet merged).`
- [ ] **Step 2:** In the first paragraph, after `src/inputs/eventlog.rs:826`, add "(before the SYS-9 refactor moved the parser to `src/inputs/eventlog_xml.rs`)".
- [ ] **Step 3:** Replace the **Fix.** paragraph ("Use `a.unescape_value()` (or decode and then `quick_xml::escape::unescape`) and add a unit test with the cases above.") with:

  > **Fix.** Use `Attribute::normalized_value(XmlVersion::Implicit1_0)`, falling back to the raw value on error, and test the cases above. *(Correction: an earlier version of this entry suggested `unescape_value()`. That method is deprecated in `quick-xml` 0.41 and fails the `-D warnings` build.)* Spec: `docs/superpowers/specs/2026-11-11-sys8-eventlog-xml-attribute-unescape.md`.

- [ ] **Step 4:** In the Fix plan's P2 SYS-8 row, append " Fixed in `<C6>`."
- [ ] **Step 5:** `git diff ISSUES.md` touches only the SYS-8 entry and its P2 row. Then:

  ```bash
  git add ISSUES.md
  git commit -m "docs: mark SYS-8 fixed; correct its fix text" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
  ```

- [ ] **Step 6: final check.** `git status --short` shows only `?? report.html`. Then compare the whole series with the trial: `git diff cf5bc5a --stat` lists `Cargo.toml`, `ISSUES.md`, the SYS-7 plan, the four SYS-8/SYS-9 docs, and `src/inputs/{eventlog.rs,eventlog_xml.rs,mod.rs}`, and nothing else.

---

### Task 3: push, PR, CI (owner, blocked)

This is the same as the SYS-7 plan's T4 (`git push -u origin develop_fix_bug_known-issues`, once there is write access). For SYS-8 and SYS-9, its step 3 is the one gate that matters: `test-windows` must compile `eventlog.rs` with the new import (SYS-9 spec V6, SYS-8 spec V5).

---

## Coverage check against the spec

| Spec item | Where |
| --- | --- |
| Goal 1 (the four attributes unescaped) | T1 steps 1–2 (`provider_name_is_unescaped`, `data_name_attribute_is_unescaped`) |
| Goal 2 (no change without references) | the existing `parses_system_and_eventdata` stays green (T1 gate) |
| Goal 3 (no deprecated API) | T1 step 4 (no `unescape_value(`), T1 gate (clippy `-D warnings`) |
| Goal 4 (never `None` because of the fix) | T1 step 3 (`malformed_attribute_reference_keeps_raw_value`) |
| Behaviour changes 5–6 (SD key drop, whitespace in the header on `main`) | recorded in the spec for the owner to accept. No code here. |
| ISSUES.md correction (`unescape_value` deprecated) | T2 step 3 |
| V5 (Windows CI) | T3 |

## Risks

- **Behaviour change 6** (a `&#9;` in `Provider Name` becomes a tab in the header) holds only until the provider-name fix merges. If the provider-name branch is abandoned, record it as a new issue.
- **No local Windows build.** This plan touches only the cross-platform module, so local tests cover it fully. The Windows risk is the SYS-9 import, covered by CI.
