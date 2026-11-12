# Restore the `fetch_update` Fix After Merge `e541e78` — Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking. Execute the tasks in order. Tasks marked `[x]` were done before this plan was written (2026-11-12) and are recorded for traceability.

**Goal:** Make `develop` compile under `-D warnings` again, by restoring the `AtomicU64::update` call of the `fetch_update` deprecation fix that merge `e541e78` turned into a bare `try_update(…)` with an unused `Result`. Then get the fix merged with CI green on the head that is merged.

**Architecture:** No architectural change. One call site in `ChannelBudget::release` (`src/engine.rs:239-255`) returns to the `af3018c` form.

**Tech Stack:** Rust 2021, `std::sync::atomic::AtomicU64::update` (stable on 1.98 and 1.99, verified in the `fetch_update` deprecation spec).

**Spec:** `docs/superpowers/specs/2026-11-12-restore-atomic-update-after-merge.md`

## Global Constraints

- `rust-version = "1.98"`. Local toolchains: `stable` = 1.99.1 (with clippy), `1.98` = 1.98.1 (no clippy, so the MSRV is checked with `cargo check`). Both live in `~/.cargo/bin`, which may need adding to `PATH`.
- **Only `src/engine.rs` changes in code.**
- Baseline after the fix (`bfc3af2`, macOS): **258** tests pass (248 lib + 3 bin + 6 e2e + 1 `self_logs_on_stderr`). Windows CI runs 247 lib tests, because some lib tests are `#[cfg(unix)]` and others `#[cfg(windows)]`.
- Commit messages use the repo's prefixes (`fix(engine): …`, `docs: …`) and end with the `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` trailer.
- zsh note for scripts: write `"${c}:src/engine.rs"`, not `"$c:src/…"`. zsh reads `$c:s…` as a substitution modifier.

## Rulings

**R-1: Revert to `update`, not `let _ = try_update`.** This is the decision of the `fetch_update` deprecation fix (its spec, Option A). The spec's Design section explains why.

**R-2: Branch `develop_fix_bug`, PR #4 into `develop`.** It already exists and carries the fix.

**R-3: No new test.** The defect is a compile error. The clamp is already pinned by `channel_budget_release_saturates_at_zero` (added by the `fetch_update` fix).

---

## Dependency graph

```text
T1 reproduce on 9d08455            [x]
 └── T2 revert to update + gate     [x] 0e1f135
      └── T3 tracker: mark fixed    [x] bfc3af2
           └── T4 merge-integrity review    [x] (this plan)
                └── T5 PR #4 CI green       [x] run 43136148376
                     └── T6 merge PR #4, check develop push run   [x] 879d30f, run 43141090497
                          └── T7 tracker: final status + wording     [x] updated 2026-11-12, not committed yet
```

---

### Task 1: reproduce [x]

- [x] **Step 1:** In a clean worktree at `9d08455`: `RUSTFLAGS="-D warnings" cargo clippy --all-targets`. Result: **fails**, `error: unused std::result::Result that must be used --> src/engine.rs:249:9`, for `lib` and `lib test`. Re-checked 2026-11-12.
- [x] **Step 2:** Find the cause: `git show --remerge-diff e541e78`, and print lines 249–253 at `d4df550`, `db15f72`, `50f62f3` and `e541e78` (table in the spec's Root cause).

### Task 2: revert to `update` [x] — `0e1f135`

**Files:** `src/engine.rs` (`ChannelBudget::release`).

- [x] **Step 1:** Comment at line 242: `via \`try_update\`` → `via \`update\``.
- [x] **Step 2:** Lines 251–252:

  ```diff
  -            .try_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
  -                Some(cur.saturating_sub(EventSender::event_bytes(ev)))
  +            .update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
  +                cur.saturating_sub(EventSender::event_bytes(ev))
  ```

- [x] **Step 3: gate.** All passed (re-run 2026-11-12 at `bfc3af2`):

  ```bash
  cargo fmt --all -- --check
  RUSTFLAGS="-D warnings" cargo clippy --all-targets
  RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets
  RUSTFLAGS="-D warnings" cargo test --all-targets      # 258 passed
  cargo audit
  ```

- [x] **Step 4:** Commit `fix(engine): restore the … AtomicU64::update call lost in merge e541e78`.

### Task 3: record the fix in the issue tracker [x] — `bfc3af2`

- [x] Marked the issue fixed in the issue tracker, and noted that the `fetch_update` fix holds again.

### Task 4: merge-integrity review [x]

Checks that the fix is complete and that the merge lost nothing else.

- [x] **Step 1:** `git diff db15f72 HEAD -- src/engine.rs` is empty.
- [x] **Step 2:** `git show --remerge-diff --format= e541e78` lists only `src/engine.rs` as conflicted.
- [x] **Step 3:** `git log --oneline d4df550..50f62f3 -- src/engine.rs` shows only `7bb53e6` (the provider-name side's `fetch_update` fix), so nothing from that side is missing.
- [x] **Step 4:** `grep -rn "fetch_update\|try_update" src tests` finds only the doc comment at `src/engine.rs:936`.

### Task 5: CI on PR #4 [x]

- [x] Run 43136148376 on `bfc3af2`: `lint`, `msrv`, `test-linux`, `test-windows` and `audit` all pass.

### Task 6: merge PR #4 (owner) [x]

- [x] **Step 1:** The PR's latest CI run was for its current head (`bfc3af2`, run 43136148376), all checks `SUCCESS`.
- [x] **Step 2:** `develop` had not moved: it was still `9d08455`, the parent of `0e1f135` and the first parent of the merge `879d30f`. No update was needed.
- [x] **Step 3:** Merged at 2026-11-12T02:23:38Z as `879d30f`. The `push` run on `develop` (43141090497) is green on every job.

For future merges, keep steps 1–2 as a checklist: the head SHA in `gh pr view <n> --json headRefOid,statusCheckRollup` must match the green run, and the branch must be up to date with its base. That is the step that was skipped for PR #3.

### Task 7: record the final status in the issue tracker [x]

Done 2026-11-12.

- [x] **Step 1:** Recorded in the issue tracker that the fix merged by PR #4 at `879d30f`, with CI green on the PR (run 43136148376) and on `develop` (run 43141090497), together with the corrected root cause and links to the spec and plan.
- [ ] **Step 2:** Commit `docs: spec and plan for the merge fix; update its status after CI`. **Not done: the owner asked not to commit yet.**

---

## Coverage check against the spec

| Spec item | Where |
| --- | --- |
| Goal 1: clippy passes on stable | T2 step 3, T5 |
| Goal 2: MSRV builds | T2 step 3, T5 (`msrv` job) |
| Goal 3: behaviour unchanged | T2 step 3 (saturation test in the suite) |
| Goal 4: the `update` decision holds everywhere | T2, T4 step 4, T7 |
| V1–V10 | T1, T2 step 3, T4, T5 |
| Rollout 3: merge with CI green on the merged head | T6 |
| Rollout 4 and the stale text | T7 |
| Open question 1 (branch protection) | owner, outside this plan |

## Risks

- **The same mix can happen again.** Any merge between branches that fixed the same lines in different ways can give a mix that compiles on neither side. Mitigation: after resolving a conflict, run the T2 step 3 gate before committing the merge, and rely on branch protection (spec open question 1).
- **Stable keeps moving.** A later stable release may add a new lint. The `msrv` job (`docs/superpowers/specs/2026-11-11-ci-msrv-job.md`) covers only the lower bound.
