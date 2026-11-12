# RFC 5424 parser ends STRUCTURED-DATA at the wrong `]` when a value contains `[` — design spec

Status: **draft — owner review** (no decision is needed; the fix is the
standard grammar). Nothing is implemented yet.
Branch: `develop_fix_bug_known-issues`.

## Problem

`parse_rfc5424` (`src/pipeline/syslog.rs:55`) finds the end of
STRUCTURED-DATA with a bracket depth counter (`:93-112`):

```rust
match bytes[i] {
    b'[' => depth += 1,
    b']' => { depth = depth.saturating_sub(1);
              if depth == 0 && (next is not '[') { idx = i + 1; break; } }
    b'\\' => i += 1, // skip escaped char
    _ => {}
}
```

It counts **every** `[` and `]`, including those inside a quoted
PARAM-VALUE. RFC 5424 §6.3.3 requires only `"`, `\` and `]` to be escaped
inside PARAM-VALUE, so a bare `[` there is valid. The agent's own
`sd_escape` (`src/outputs/format.rs:83`) correctly leaves it unescaped. A
`[` inside a value raises the depth to 2. The element's closing `]` then
brings it back only to 1, the scan runs to the end of the line, the whole
rest of the line becomes `fields.structured_data`, and **`message` becomes
empty**.

### Evidence (2026-11-11, branch HEAD after `a508a6d`, 3 independent runs)

The harness (`/tmp/softnix-smoke.LTIcHO/harness/issues_repro.py`, the
STRUCTURED-DATA case) sends 6 RFC 5424 lines to agent B's TCP input. Every run gave
identical results:

| Case | SD | `message` | Correct? |
| --- | --- | --- | --- |
| control-plain | `[ex@32473 k="plain value"]` | `hello from …` | ✅ |
| escaped-close-only | `[ex@32473 k="a\]b"]` | `hello from …` | ✅ |
| firewall-rule | `[ex@32473 rule="Contoso [TCP 443\]"]` | **empty** | ❌ |
| office-file | `[ex@32473 file="Q3 [draft\].xlsx"]` | **empty** | ❌ |
| open-bracket-only | `[ex@32473 k="open [ only"]` | **empty** | ❌ |
| two-elements | `[a@32473 k="x [y\]"][b@32473 z="1"]` | **empty** | ❌ |

The original mock found the same thing on the agent's own output: 6/6
Windows Firewall 2004 events whose rule name contained `[`.

## Impact

Medium. Only when the agent is a syslog receiver or relay, but then the
**whole message is lost** (it is moved into `structured_data`), for any
sender whose SD values contain `[`: rule names, file names, paths. That
includes another agent.

## Goals

1. The end of STRUCTURED-DATA is found by the RFC 5424 grammar: brackets
   count only **outside** quoted PARAM-VALUEs, and inside quotes `\"`, `\\`
   and `\]` are escapes.
2. Every line that parses correctly today parses **identically** (the
   controls, multiple SD elements, `-` NILVALUE SD, an SD with no message).
3. A malformed SD (for example an unterminated quote) behaves no worse than
   today. It parses exactly as it does today, through the fallback in
   Design, and the parser never panics.

## Non-goals

- Parsing SD into fields. `structured_data` stays the raw string, as today.
- Validating SD-ID or PARAM-NAME syntax.
- RFC 3164 parsing (the RFC 3164 parser rejecting a long `TAG[PID]`,
  `2026-11-11-rfc3164-long-tag.md`).

## Design

Replace the scan loop with a two-state scanner over bytes. This is safe
on UTF-8: every byte it looks at is ASCII, and ASCII bytes never occur
inside a multi-byte sequence. The split index always lands right after a
`]`, so it is a char boundary.

```text
outside quotes:  '"' → enter quotes
                 '[' → depth += 1
                 ']' → depth -= 1 (saturating); if depth == 0 and the next
                       byte is not '[' → end of SD (idx = i + 1)
inside quotes:   '\' → skip the next byte (covers \" \\ \] and any other)
                 '"' → leave quotes
                 anything else, including '[' and ']' → ignored
```

**Fallback for malformed SD.** If the scan reaches the end of the line
**without finding the end of the SD** (the loop never breaks), the SD is
not valid RFC 5424. Re-run today's bracket-only scan and use its result,
so a malformed line parses exactly as it does today (Goal 3). The rule is
"no end found", not "still inside quotes", because quotes in MSG are
scanned too once the SD's own quotes are unbalanced:

- `[ex@32473 k="never closed] hello` ends **inside** quotes. Today the `]`
  ends the SD and `message == "hello"`.
- `[ex@32473 k="5" screen"] it's "` has an even number of quotes, so it
  ends **outside** quotes, at depth 1, with no end found. Today
  `message == "it's \""`. A fallback keyed on "inside quotes" would miss
  this line and empty its message.

A valid SD never reaches the fallback: its last `]` always breaks the
loop, including when no MSG follows. If the old scan finds no end either,
the result is what it is today (the whole tail is `structured_data`).

The one behaviour change outside quotes: `\` is no longer an escape there.
RFC 5424 defines escapes only inside PARAM-VALUE, and an SD-NAME cannot
contain `\` anyway, so no correctly formed line is affected. Everything
after the loop (the `split_at(idx)`, the `structured_data` field, the
trimmed message, the BOM strip) stays as it is.

## Testing

Unit tests in `src/pipeline/syslog.rs`'s `mod tests`:

| Test | Line (SD part) | Asserts | Before the fix |
| --- | --- | --- | --- |
| `sd_value_with_open_bracket_keeps_message` | `[ex@32473 k="open [ only"]` | `message == "hello"`, `structured_data` equals the SD | fails: message empty |
| `sd_value_with_escaped_close_and_open_bracket` | `[ex@32473 rule="Contoso [TCP 443\]"]` | the same | fails |
| `sd_value_bracket_in_first_of_two_elements` | `[a@32473 k="x [y\]"][b@32473 z="1"]` | the SD covers both elements, `message == "hello"` | fails |
| `sd_plain_and_escaped_close_unchanged` | `[ex@32473 k="plain"]`, `[ex@32473 k="a\]b"]` | as today | passes (guard) |
| `sd_escaped_backslash_before_closing_quote` | `[ex@32473 k="a\\"]` | the SD ends after `"]`, `message == "hello"` | passes (guard) |
| `sd_unterminated_quote_falls_back_to_old_scan` | `[ex@32473 k="never closed] hello` | the same as today: `structured_data == "[ex@32473 k=\"never closed]"`, `message == "hello"`, no panic | passes (guard). It would **fail** without the fallback. |
| `sd_stray_quotes_fall_back_to_old_scan` | `[ex@32473 k="5" screen"] it's "` | the same as today: `structured_data == "[ex@32473 k=\"5\" screen\"]"`, `message == "it's \""` | passes (guard). It would **fail** with a fallback keyed only on "inside quotes". |
| `sd_escaped_quote_before_bracket_in_value` | `[ex@32473 k="a\"]b"]` | `structured_data` equals the whole SD, `message == "hello"` | fails: today the SD ends at `a\"]` and `message == "b\"] hello"` |
| `sd_without_message_unchanged` | `[ex@32473 k="v"]` at the end of the line | `structured_data` equals the SD, `message == ""` | passes (guard) |
| `sd_nilvalue_unchanged` | `-` | `message == "hello"`, no `structured_data` | passes (guard) |

The existing RFC 5424 test (`rfc5424_parses`, `[exampleSDID@32473
iut="3"]`) stays green.

End-to-end: the harness's STRUCTURED-DATA case. Expected: 6/6 correct, 3 runs.

Gate: fmt, clippy `-D warnings`, test `-D warnings`, `+1.98 check`.

## Risks

- **Malformed SD.** Whenever the new scan finds no end, the old scan
  decides, so the result is identical (the two `…_fall_back_to_old_scan`
  tests). A malformed SD for which the new scan *does* find an end is
  split by the new rules, which are the only ones RFC 5424 defines. For
  example, an unescaped `]` inside a value (`k="a]b"`) no longer ends the
  SD early, which is an improvement.

## Rollout

On `develop_fix_bug_known-issues`, after the spec and plan:

1. `fix(pipeline): end RFC 5424 STRUCTURED-DATA by the grammar, not raw brackets`
   (the scanner and its tests).
2. `docs`: record the fix in the issue tracker.

## Open questions

None. The grammar fixes the behaviour. (This fix may ship in one PR with
the long RFC 3164 tag fix and the self-logs-to-stderr fix, but each has its
own spec and commits.)
