# Config Editor Highlight Alignment — Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking. Execute the tasks in order. Tasks marked `[x]` were done before this plan was written (2026-11-12) and are recorded for traceability.

**Goal:** Keep the Web GUI config editor's syntax-highlight overlay exactly on top of the text the user types into, over the whole scroll range, whether or not the file ends with a newline, and with Windows scrollbars that take space.

**Architecture:** No architectural change. Two functions in `src/ui.html` change: `syncCfgHlScroll` moves the overlay with a CSS transform instead of copying `scrollTop`/`scrollLeft` (B, the fix), and `renderCfgHighlight` gives the overlay the empty last line that the textarea has (A, recommended extra).

**Tech Stack:** Plain JavaScript and CSS in the single-file UI `src/ui.html`, served by the agent through `include_str!` (`src/web.rs:22`). Rust 2021 only for the rebuild and the gate.

**Spec:** `docs/superpowers/specs/2026-11-12-config-editor-highlight-alignment.md`

## Global Constraints

- Work in the main checkout, branch `develop_fix_bug_config-editor-highlight`, based on `develop` @ `94fab19` (merge of PR #5). Tasks 2–5 were first done in a temporary worktree on `879d30f`; the uncommitted changes were moved onto the new branch unchanged (`src/ui.html` is identical at both commits).
- **Only `src/ui.html` changes in code.** No change to the tokenizer (`highlightYaml*`), the CSS colours, the markup, or any Rust file.
- `ISSUES.md` is untracked on `develop` since PR #5. It is the live tracker: update it, never stage it.
- `src/ui.html` is compiled into the binary, so every UI change needs `cargo build` before a browser check.
- Local toolchains: `stable` = 1.99.1 (with clippy), `1.98` = 1.98.1. Both live in `~/.cargo/bin`, which may need adding to `PATH`.
- Commit messages use the repo's prefixes (`fix(ui): …`, `docs: …`) and end with the `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` trailer. Commit only when the owner asks.

## Rulings

**R-1: B is the fix, A is kept.** The spec's Design section explains why. B alone measures 0 px in every case. A makes the two layers the same height again.

**R-2: No automated browser test.** Decided by the owner on 2026-11-12: do not add Playwright (the spec's open question 1). Verification is the scripted check in Task 1, run by hand.

**R-3: Classic scrollbars are tested two ways on macOS.** The script forces them with `::-webkit-scrollbar` (Chrome and Safari). For a check closer to Windows, and for Firefox, set *System Settings → Appearance → Show scroll bars → Always*, which gives every browser scrollbars that take space.

---

## Dependency graph

```text
T1 reproduce + measurement script        [x]
 └── T2 fix B: transform-based sync       [x]
      └── T3 fix A: trailing-newline line  [x]
           └── T4 rebuild + Rust gate (V9)  [x]
                └── T5 Chrome checks (V2–V6)   [x] (step 6 waits for the owner)
                     ├── T6 Firefox + Safari (V8)   pending
                     └── T7 real Windows (V7)   owner / tester
                          └── T8 commits, PR, tracker   owner approval
```

---

### Task 1: reproduce and write the measurement script [x]

Done 2026-11-12 on an agent built from `f1e945d` (same `src/ui.html` as `879d30f`). Results are in the spec's Evidence table.

- [x] **Step 1: test config.** A config long enough to scroll, ending with a newline, with the web GUI on a spare port:

  ```bash
  D=/tmp/sx-gui; mkdir -p "$D"
  python3 - "$D" <<'EOF'
  import sys
  d = sys.argv[1]
  lines = ["# GUI alignment check: this file ends with a newline",
           f"agent: {{ data_dir: {d}/data, log_level: info }}",
           "web:", "  enabled: true", "  bind: 127.0.0.1", "  port: 28080",
           "  auth_token: gui-check-token-0123456789", "inputs:", "  syslog:"]
  lines += [f"    - {{ id: udp{i:02d}, protocol: udp, bind: 127.0.0.1, port: {26000 + i} }}  # input {i}"
            for i in range(40)]
  lines += ["outputs:", "  - { id: out, type: stdout, format: json }", "# LAST LINE"]
  open(f"{d}/agent.yaml", "w").write("\n".join(lines) + "\n")
  EOF
  ./target/release/softnix-log-agent run --config /tmp/sx-gui/agent.yaml
  ```

  Open `http://127.0.0.1:28080/#token=gui-check-token-0123456789` in a 1200 × 800 window and click **Configuration**.

- [x] **Step 2: measurement script.** Paste into the DevTools console on the Configuration tab (wrap it as `(<script>)()` there). It changes the textarea in memory only, restores it, and saves nothing. `0px` on both axes everywhere means aligned.

  ```js
  async () => {
    const c = document.getElementById("cfg"), code = document.getElementById("cfghlcode");
    if (!c || !code) return "open the Configuration tab first";
    const tick = () => new Promise(r => setTimeout(r, 60));
    const orig = c.value;
    const cs = getComputedStyle(c), lh = parseFloat(cs.lineHeight);
    const padT = parseFloat(cs.paddingTop), padL = parseFloat(cs.paddingLeft);
    const bT = parseFloat(cs.borderTopWidth), bL = parseFloat(cs.borderLeftWidth);
    const style = document.createElement("style");
    document.head.appendChild(style);
    // 17 px scrollbars that take space, as on Windows (Chrome/Safari only).
    const CLASSIC = "#cfg::-webkit-scrollbar{width:17px;height:17px;background:#444}" +
                    "#cfg::-webkit-scrollbar-thumb{background:#999}";
    // Overlay position of the first non-blank character of the last non-empty
    // line, minus the textarea position of the same character.
    function offset() {
      const lines = c.value.split("\n");
      let n = lines.length - 1;
      while (n > 0 && !lines[n].trim()) n--;
      const col = lines[n].length - lines[n].trimStart().length;
      const text = code.textContent;
      let idx = 0;
      for (let i = 0; i < n; i++) idx = text.indexOf("\n", idx) + 1;
      idx += col;
      const w = document.createTreeWalker(code, NodeFilter.SHOW_TEXT);
      const r = document.createRange();
      let node, acc = 0;
      while ((node = w.nextNode())) {
        if (acc + node.length > idx) { r.setStart(node, idx - acc); r.setEnd(node, idx - acc + 1); break; }
        acc += node.length;
      }
      const g = r.getBoundingClientRect(), box = c.getBoundingClientRect();
      const lineTop = box.top + bT + padT + n * lh - c.scrollTop;
      const left = box.left + bL + padL + col * g.width - c.scrollLeft;
      return { dy: Math.round(g.top - lineTop - (lh - g.height) / 2), dx: Math.round(g.left - left) };
    }
    const base = orig.replace(/\n+$/, "");
    const firstNl = base.indexOf("\n");
    const withLong = base.slice(0, firstNl) + "\n# " + "long line ".repeat(30) + base.slice(firstNl);
    const contents = {
      "ends with \\n": base + "\n",
      "ends with \\n, one long line": withLong + "\n",
      "no trailing \\n": base,
    };
    const out = {};
    for (const [sb, css] of [["overlay", ""], ["classic 17px", CLASSIC]]) {
      style.textContent = css;
      await tick();
      for (const [name, value] of Object.entries(contents)) {
        c.value = value;
        renderCfgHighlight();
        let dy = 0, dx = 0;
        for (const [top, left] of [[0, 0], [0.5, 0], [1e6, 1e6]]) { // top, middle, bottom-right
          c.scrollTop = top < 1 ? top * (c.scrollHeight - c.clientHeight) : top;
          c.scrollLeft = left;
          c.dispatchEvent(new Event("scroll"));
          await tick();
          const m = offset();
          if (Math.abs(m.dy) > Math.abs(dy)) dy = m.dy;
          if (Math.abs(m.dx) > Math.abs(dx)) dx = m.dx;
        }
        out[`${sb} | ${name}`] = `dy=${dy}px dx=${dx}px`;
      }
    }
    style.remove();
    c.value = orig;
    renderCfgHighlight();
    c.scrollTop = 0; c.scrollLeft = 0;
    c.dispatchEvent(new Event("scroll"));
    return out;
  }
  ```

- [x] **Step 3: baseline (V1).** On the current code the script returns:

  | Case | Result |
  | --- | --- |
  | overlay, ends with `\n` | `dy=20px dx=0px` |
  | overlay, ends with `\n`, one long line | `dy=20px dx=0px` |
  | overlay, no trailing `\n` | `dy=0px dx=0px` |
  | classic, ends with `\n` | `dy=20px dx=0px` |
  | classic, ends with `\n`, one long line | `dy=37px dx=17px` |
  | classic, no trailing `\n` | `dy=0px dx=0px` |

  The fixed variants were also measured by patching the two functions in the live page: B alone and A + B give `0px` in all 6 cases, and A alone leaves `dy=17px dx=17px` in the classic long-line case.

### Task 2: fix B — move the overlay with a transform [x]

**Files:** `src/ui.html`, `syncCfgHlScroll` (lines 495-500).

- [x] **Step 1:** Replace the function (done 2026-11-12, uncommitted):

  ```diff
   function syncCfgHlScroll(){
  -  const hl=$("#cfghl"),cfg=$("#cfg");
  -  if(!hl||!cfg)return;
  -  hl.scrollTop=cfg.scrollTop;
  -  hl.scrollLeft=cfg.scrollLeft;
  +  const hl=$("#cfghl"),code=$("#cfghlcode"),cfg=$("#cfg");
  +  if(!hl||!code||!cfg)return;
  +  // Shift the overlay, don't scroll it: its scroll range is clamped, and it
  +  // is smaller than the textarea's whenever the textarea's scrollbars take
  +  // space (Windows). Keep the <pre> itself at 0 in case anything scrolled it.
  +  hl.scrollTop=0; hl.scrollLeft=0;
  +  code.style.transform=`translate(${-cfg.scrollLeft}px,${-cfg.scrollTop}px)`;
   }
  ```

- [x] **Step 2:** Check that nothing else reads or sets `#cfghl`'s scroll position:

  ```bash
  grep -n 'cfghl' src/ui.html
  ```

  Expected: only the CSS (lines 148, 155, 157), the markup (line 443), `renderCfgHighlight` and `syncCfgHlScroll`. Result: as expected (`scrollTop`/`scrollLeft` appear only in `syncCfgHlScroll`).

### Task 3: fix A — give the overlay the empty last line [x]

**Files:** `src/ui.html`, `renderCfgHighlight` (lines 489-494).

- [x] **Step 1:** (done 2026-11-12, uncommitted)

  ```diff
   function renderCfgHighlight(){
     const code=$("#cfghlcode"),cfg=$("#cfg");
     if(!code||!cfg)return;
  -  code.innerHTML=highlightYaml(cfg.value);
  +  // A <pre> makes no line box for a final "\n", but the textarea shows the
  +  // empty line after it. Add one so both have the same number of lines.
  +  code.innerHTML=highlightYaml(cfg.value)+(cfg.value.endsWith("\n")?"\n":"");
     syncCfgHlScroll();
   }
  ```

  The added `"\n"` is a constant, so it does not change the escaping guarantee in the tokenizer's comment ("Raw text is always escaped before it can reach innerHTML").

### Task 4: rebuild and run the Rust gate (V9) [x]

- [x] **Step 1:** All passed on 2026-11-12 (in the temporary worktree on `879d30f`): fmt, clippy, **258** tests (248 lib + 3 bin + 6 e2e + 1 `self_logs_on_stderr`), release build.

  ```bash
  cargo fmt --all -- --check
  RUSTFLAGS="-D warnings" cargo clippy --all-targets
  RUSTFLAGS="-D warnings" cargo test --all-targets      # 258 passed on macOS
  cargo build --release
  ```

  Re-run on the new base `94fab19` (2026-11-12): fmt, clippy, **258** tests (248 + 3 + 6 + 1) and the release build all pass.

  The test count must match `develop` (258 on macOS). No Rust code changes, so any difference is unrelated and must be explained before going on.

### Task 5: Chrome checks on macOS (V2–V6) [x] except step 6

Run against the release build from Task 4 with the Task 1 config.

- [x] **Step 1 (V2):** Run the Task 1 script. Expected: `dy=0px dx=0px` in all 6 cases. Result: all 6 `dy=0px dx=0px`; the page was first checked to serve the new functions.
- [x] **Step 2 (V3):** Scroll slowly from the top to the bottom with the mouse wheel, with the textarea text made visible (`#cfg{color:rgba(255,0,0,.6)}` added in DevTools). Expected: the red text stays exactly on the coloured text the whole way. Remove the style afterwards. Result: also checked by script, with the long-line config, every 5 px from top to bottom (scrollLeft moved in step) and the first glyph of all 53 lines at each position: 137 positions with overlay scrollbars, 141 with classic, worst offset 0 px on both axes. Screenshot with the red text at the bottom: no double text.
- [x] **Step 3 (V4):** Delete the last newline, click at the end of `# LAST LINE`, press Enter, and type `abc`. Expected: the caret and `abc` are drawn on the same new line, and the overlay colours it. Click **Discard changes** afterwards. Result: with real key presses (Enter, then `abc: 123`), caret line = typed line = 52, offset 0, `abc` has `tok-key`; Discard changes restored the server copy and the file on disk was not written.
- [x] **Step 4 (V5):** Drag the textarea's resize handle to make it 200 px taller, then shorter than the original, and run the script again each time. Expected: `0px` everywhere. Result: heights 636 / 320 / 436 px, the overlay matched the textarea each time, offset 0.
- [x] **Step 5 (V6):** In the textarea, select all and delete (empty value), then type one line without Enter. Expected: no console error, and the line is coloured in place. Click **Discard changes** afterwards. Result: empty, one line without `\n` and one line with `\n` all give offset 0, no page error, no console message.
- [x] **Re-run on `94fab19` (2026-11-12),** release build from the new base, the page first checked to serve the new functions: V2 all 6 cases `dy=0px dx=0px`; V3 sweep 137 positions (overlay) and 141 (classic) × 53 lines, worst 0 px; V4 with real keys, both after deleting the last `\n` (caret line = typed line = 52) and typing on the empty last line of a file that ends with `\n`, as in the field report (caret line = typed line = 53, overlay height = textarea scrollHeight = 1112 px), both 0 px and `tok-key`, and a drag selection over the last lines shows one copy of the text; V5 heights 636 / 316 / 436 px, 0 px; V6 empty, one line with and without `\n`, 0 px. No console message; Discard changes left the file on disk unchanged (same SHA-1).
- [ ] **Step 6:** Repeat Steps 1–3 with *Show scroll bars → Always* (R-3). **Not done:** it changes a system-wide macOS setting, so it waits for the owner. The CSS-forced classic scrollbars in Steps 1–2 cover the same geometry.

### Task 6: Firefox and Safari on macOS (V8)

- [ ] **Step 1:** Safari: Task 5 Steps 1 and 3. **Pending:** driving Safari needs *Allow Remote Automation* (`safaridriver --enable`, sudo), or a manual run. The script's classic case works in Safari (`::-webkit-scrollbar`).
- [ ] **Step 2:** Firefox: Task 5 Steps 1 and 3. **Pending:** Firefox is not installed on the test machine. Firefox ignores `::-webkit-scrollbar`, so its "classic" rows repeat the overlay case. Run once more with *Show scroll bars → Always* (R-3) for real space-taking scrollbars.
- [ ] **Step 3:** Record any non-zero offset in the spec's Verification matrix before going on.

### Task 7: real Windows (V7) — owner or tester

- [ ] **Step 1:** Build or download the branch's Windows binary (`cargo build --release --target x86_64-pc-windows-msvc`, or the CI artifact if there is one), run it with a config that ends with a newline and has at least one line wider than the editor, and open the Configuration tab in Chrome or Edge.
- [ ] **Step 2:** Run the Task 1 script. Expected: `0px` everywhere. Its "classic" rows double as the native case here, because Windows scrollbars already take space.
- [ ] **Step 3:** Repeat the field report's steps (click an empty line near the end and type; drag-select the last lines). Expected: characters appear where clicked, and the selection shows one copy of the text.
- [ ] **Step 4:** If no Windows machine is available before merge, write that in the PR and do this on the first Windows install of the build (spec, Testing).

### Task 8: commits, PR and tracker — owner approval

- [ ] **Step 1:** Commit `src/ui.html` alone: `fix(ui): keep the config editor highlight aligned with the text`.
- [ ] **Step 2:** Commit the spec and this plan: `docs: spec and plan for the config editor highlight alignment fix`. Fill in the results of Tasks 5–7 first.
- [ ] **Step 3:** Push the branch and open a PR into `develop`. Before merging, check that the PR's latest green CI run is for its current head (`gh pr view <n> --json headRefOid,statusCheckRollup`), and that the branch is up to date with `develop`.
- [x] **Step 4:** ~~Rebase onto `develop` after PR #5 merges.~~ Not needed: PR #5 merged (`94fab19`) before anything was committed, so the branch was recreated from that `develop` and the changes reapplied. Re-run Task 4 on the new base before committing.
- [ ] **Step 5:** Record the result in the issue tracker (the untracked `ISSUES.md` in the main checkout), with links to the spec and this plan.

---

## Coverage check against the spec

| Spec item | Where |
| --- | --- |
| Goal 1: 0 px on both axes, any trailing newline, both scrollbar styles | T2, T3, T5 step 1, T6, T7 |
| Goal 2: typing, Enter at the end, resize, Discard changes | T5 steps 2–5 |
| Goal 3: no change to colours, tokenizer, saved content or API | Global Constraints, T4 |
| Design A | T3 |
| Design B | T2 |
| V1 | T1 step 3 |
| V2–V6 | T5 |
| V7 | T7 |
| V8 | T6 |
| V9 | T4 |
| Rollout 1–4 | T8 |
| Open question 1 (no browser test) | R-2 |
