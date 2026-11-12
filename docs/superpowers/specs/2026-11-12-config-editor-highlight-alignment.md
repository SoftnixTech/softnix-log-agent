# Web GUI config editor: the highlight layer drifts from the text near the end of the file — design spec

Status: **implemented, not committed** (2026-11-12): both changes are in
the working tree, and V1–V6 and V9 pass. V7 (real Windows) and V8
(Firefox, Safari) are still open. Branch
`develop_fix_bug_config-editor-highlight` (from `develop` @ `94fab19`, the
merge of PR #5; `src/ui.html` there is the same as at `879d30f`).
Implementation plan:
`docs/superpowers/plans/2026-11-12-config-editor-highlight-alignment.md`.

Reported from the field on 2026-11-12: softnix-log-agent v0.1.6 on
Windows 10, Web GUI at `http://127.0.0.1:8080`, Configuration tab, with
the `agent.yaml` the installer writes (it ends with a newline). A 17.5 s
screen recording shows typed text and a selection landing one line away
from where the text is drawn. Reproduced on v0.1.7 and on `develop` @
`879d30f` the same day (see [Evidence](#evidence)).

## Problem

The Configuration tab edits the YAML in a transparent `<textarea>` drawn
over a syntax-coloured `<pre>` (`src/ui.html:146-157`, `442-443`). The user
sees the `<pre>`, but types into the `<textarea>`. Near the end of a file
that ends with `\n`, the two layers are one line apart:

- clicking an empty line puts the caret, and the typed characters, on the
  next line;
- a drag selection shows two copies of the text, one line apart;
- with Windows scrollbars and one line wide enough to scroll sideways, the
  gap grows to about two lines down and 17 px across.

The saved file is always what the `<textarea>` holds, so nothing is
corrupted by the editor itself. The risk is that an operator edits a line
other than the one they see, in a security product's config.
**Severity: Medium.**

Almost every real config is affected: YAML files normally end with a
newline, the installer's `agent.yaml` does, and pressing Enter at the end
of any file creates the condition.

## Root cause

`renderCfgHighlight` and `syncCfgHlScroll` (`src/ui.html:489-500`) copy
the text into the `<pre>` and copy the `<textarea>`'s `scrollTop` and
`scrollLeft` onto it:

```js
function renderCfgHighlight(){
  const code=$("#cfghlcode"),cfg=$("#cfg");
  if(!code||!cfg)return;
  code.innerHTML=highlightYaml(cfg.value);
  syncCfgHlScroll();
}
function syncCfgHlScroll(){
  const hl=$("#cfghl"),cfg=$("#cfg");
  if(!hl||!cfg)return;
  hl.scrollTop=cfg.scrollTop;
  hl.scrollLeft=cfg.scrollLeft;
}
```

A browser clamps `scrollTop` and `scrollLeft` to an element's own scroll
range. The overlay therefore follows the textarea only while both have the
same scroll range. Two things make the overlay's range smaller:

1. **The trailing newline.** A `<textarea>` gives the text after the last
   `\n` (empty) its own line. A `<pre>` makes no line box for a final `\n`.
   The overlay is one line (13 px × 1.55 = 20.15 px) shorter. When the
   textarea is scrolled into its last 20 px, the overlay is already at its
   maximum `scrollTop` and stops, one line behind.
2. **Scrollbars that take space.** `#cfg` has `overflow:auto` and
   `wrap="off"`. `#cfghl` has `overflow:hidden`, so it never shows
   scrollbars. On Windows (classic scrollbars, 17 px), a vertical scrollbar
   makes the textarea's visible width 17 px narrower, and a horizontal one
   makes its visible height 17 px lower. Each makes the textarea's scroll
   range 17 px larger than the overlay's on that axis. macOS overlay
   scrollbars take no space, which is why this part does not show there.

Both causes are in the code that `e99d443` (2026-09-09, "redesign the web
GUI") added, so every release since v0.1.6 has them.

## Evidence

Measured in Chrome on macOS (agent built from `f1e945d`, whose
`src/ui.html` is identical to `879d30f`), with a 52-line config and a
1200 × 800 window, using the measurement script in the plan (Task 1). For
each case the script scrolls to the top, the middle and the bottom-right
corner, and reports the largest offset between where the overlay draws the
first character of the last non-empty line and where the textarea draws
it. "Classic" means 17 px scrollbars forced on `#cfg` with
`::-webkit-scrollbar`, to match Windows. The fixed variants were measured
by patching the two functions in the live page.

| Content | Scrollbars | Current code | A only | B only | A + B |
| --- | --- | --- | --- | --- | --- |
| ends with `\n` | overlay (macOS) | **20 px** down | 0 | 0 | 0 |
| ends with `\n`, one long line | overlay (macOS) | **20 px** down | 0 | 0 | 0 |
| no trailing `\n` | overlay (macOS) | 0 | 0 | 0 | 0 |
| ends with `\n` | classic (Windows) | **20 px** down | 0 | 0 | 0 |
| ends with `\n`, one long line | classic (Windows) | **37 px** down, **17 px** across | **17 px** down, **17 px** across | 0 | 0 |
| no trailing `\n` | classic (Windows) | 0 | 0 | 0 | 0 |

(A and B are the two changes in [Design](#design).)

Raw heights for the first row: textarea `scrollHeight` 1091 px and overlay
1071 px; at the bottom the textarea's `scrollTop` is 613 and the overlay's
593. A file ending in three newlines gives 1132 and 1112 px, so the gap is
always one line and does not grow. A screenshot with the textarea text
made visible shows it one line above the coloured text.

`git show v0.1.6:src/ui.html` has the same two functions (lines 492 and
498), which matches the field report.

## Goals

1. Over the whole scroll range, the overlay draws every character where
   the textarea draws it (offset 0 px on both axes), whether or not the
   value ends with `\n`, and with overlay or classic scrollbars.
2. Typing, pasting, Enter at the end of the file, resizing the textarea
   (`resize:vertical`) and the "Discard changes" reload keep that true.
3. No change to the colours, the tokenizer (`highlightYaml*`), the saved
   content or the API.

## Non-goals

- No new editor component or library. The page is one self-contained file
  served by the agent (`include_str!("ui.html")`, `src/web.rs:22`) and must
  work offline.
- No change to the YAML tokenizer.
- No browser test infrastructure in CI. The owner decided not to add
  Playwright (see [Open questions](#open-questions), question 1).

## Design

Two small changes in `src/ui.html`. B is required, A is recommended (see
the end of this section).

**A: give the overlay the same line count as the textarea.** When the
value ends with `\n`, add one more `\n` to the overlay, so the `<pre>` also
has the empty last line:

```js
function renderCfgHighlight(){
  const code=$("#cfghlcode"),cfg=$("#cfg");
  if(!code||!cfg)return;
  // A <pre> makes no line box for a final "\n", but the textarea shows the
  // empty line after it. Add one so both have the same number of lines.
  code.innerHTML=highlightYaml(cfg.value)+(cfg.value.endsWith("\n")?"\n":"");
  syncCfgHlScroll();
}
```

**B: move the overlay instead of scrolling it.** Shift the `<code>`
element by the textarea's scroll offsets with a CSS transform. A transform
is not clamped to a scroll range, so the overlay follows the textarea even
when the textarea's range is larger because of its scrollbars:

```js
function syncCfgHlScroll(){
  const hl=$("#cfghl"),code=$("#cfghlcode"),cfg=$("#cfg");
  if(!hl||!code||!cfg)return;
  // Shift the overlay, don't scroll it: its scroll range is clamped, and it
  // is smaller than the textarea's whenever the textarea's scrollbars take
  // space (Windows). Keep the <pre> itself at 0 in case anything scrolled it.
  hl.scrollTop=0; hl.scrollLeft=0;
  code.style.transform=`translate(${-cfg.scrollLeft}px,${-cfg.scrollTop}px)`;
}
```

The `<pre>` keeps `overflow:hidden`, so it still clips the shifted text at
its padding edge, the same edge where the textarea clips. Setting the
`<pre>`'s own scroll back to 0 is defensive: nothing should scroll an
`aria-hidden`, `pointer-events:none` element, but if something did (for
example find-in-page), B would otherwise add that offset.

**B is the fix; A is a cheap extra.** B alone gives 0 px in every
measured case: the overlay's missing last line is empty, so nothing is
drawn there, and the `input` handler re-renders as soon as text is typed
on it. A is still recommended, because it makes the two layers the same
height again. Then nothing that ever reads the overlay's size or scroll
range, now or after a later change, sees a different answer from the
textarea's. A alone is not enough: it leaves the 17 px gaps on Windows
(table above).

### Rejected alternatives

- **A only.** Fixes macOS and Windows files that have no long lines, but
  leaves 17 px on each axis when Windows scrollbars show (measured).
- **Give the overlay real scrollbars** (`overflow:scroll` on `#cfghl`, the
  same size as the textarea's) so the ranges match. The scrollbars would
  have to match exactly per browser and OS, and they would show under the
  textarea. More fragile than B.
- **Hide the textarea's scrollbars** and scroll through the overlay. Makes
  the overlay interactive and changes how the editor handles input.
- **Replace the overlay with an editor library.** Out of scope (Non-goals).

## Testing

The repo has no test for `src/ui.html`, and CI has no browser. The
measurement needs real layout, so it cannot run as a Rust or DOM-only test.
Verification is a scripted browser check, run by hand against an agent
built from the branch. The plan has the script.

### Verification matrix

| # | Check | Browser | Expected | Result (2026-11-12) |
| --- | --- | --- | --- | --- |
| V1 | Before the fix: reproduce the rows of the [Evidence](#evidence) table with the current code | Chrome, macOS | same numbers as the table | **pass**: see the table |
| V2 | After the fix: all 6 content × scrollbar cases, at the bottom-right | Chrome, macOS (overlay and forced classic scrollbars) | 0 px on both axes | **pass**: 6/6 at 0 px |
| V3 | Offset 0 at the top, the middle and the bottom while scrolling with the wheel | Chrome, macOS | 0 px | **pass**: every 5 px, all 53 lines, 278 positions, worst 0 px |
| V4 | Press Enter at the end of a file without a trailing `\n`, then type on the new line | Chrome, macOS | caret and colour on the same line | **pass**: real key presses, line 52, 0 px |
| V5 | Resize the textarea with its handle, then scroll to the bottom | Chrome, macOS | 0 px | **pass**: 636 / 320 / 436 px, 0 px |
| V6 | Empty config; one-line config without `\n` | Chrome, macOS | 0 px, no error in the console | **pass**: no error |
| V7 | V2, V4 and V5 with native scrollbars | Chrome or Edge, real Windows 10/11 | 0 px; the field report's steps no longer reproduce | open: needs a Windows machine |
| V8 | V2 and V4 | Firefox and Safari, macOS | 0 px | open: Firefox not installed; Safari needs Remote Automation or a manual run |
| V9 | `cargo fmt --check`, `RUSTFLAGS="-D warnings" cargo clippy --all-targets`, `cargo test --all-targets` | local | pass (the file is `include_str!`'d, so a rebuild is needed) | **pass**: 258 tests |

V2–V6 and V9 were first run in a temporary worktree on `879d30f`, then
run again on the branch's base `94fab19` with a fresh release build, with
the same results. The re-run also typed on the empty last line of a file
that ends with `\n`, as in the field report (caret and text on line 53,
0 px), and checked that a drag selection over the last lines shows one copy
of the text.

V7 needs a real Windows machine. If none is available before merge, the
forced classic scrollbars in V2 are the stand-in, and V7 is done on the
first Windows install of the build.

## Rollout

1. One `fix(ui): …` commit with both changes in `src/ui.html`.
2. One `docs: …` commit with this spec and its plan.
3. PR into `develop`. Merge only after CI is green on the head being
   merged.
4. Record the result in the issue tracker.

## Open questions

1. **Add an automated browser check?** For example a Playwright script in
   a separate, optional workflow. **Decided by the owner on 2026-11-12:
   no, do not add Playwright.** It would be the repo's first browser test,
   and it would add a Node toolchain to a Rust repo for a two-function
   change. Verification stays the scripted check in the plan, run by hand.
   Revisit if the GUI gets more client-side logic.
2. **Backport to a v0.1.x patch release?** Operators on v0.1.6 and v0.1.7
   have the bug today. Proposed answer: ship it with the next release from
   `develop`. It is a client-side change and carries no risk to the data
   path.
