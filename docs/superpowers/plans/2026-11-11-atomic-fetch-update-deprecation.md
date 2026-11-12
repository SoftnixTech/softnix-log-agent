# `fetch_update` Deprecation Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking. Execute the tasks in order.

**Goal:** Get CI green again on Rust ≥ 1.99. To do that, replace the one deprecated `AtomicU64::fetch_update` call (`src/engine.rs:251`) with `AtomicU64::update`, keep the MSRV at 1.98, and leave `ChannelBudget::release` behaving exactly as it does today.

**Architecture:** There is no architectural change. One call site switches to the std API that replaces it, the comment that names the method is updated, and a new unit test pins the saturating clamp that the call exists to provide.

**Tech Stack:** Rust 2021 and `std::sync::atomic::AtomicU64::update`, which is stable on both 1.98.1 and 1.99.1 (verified in the spec).

**Spec:** `docs/superpowers/specs/2026-11-11-atomic-fetch-update-deprecation.md`

## Global Constraints

- `rust-version = "1.98"`. Toolchains installed locally: `stable` = 1.99.1 (with clippy) and `1.98` = 1.98.1 (**no clippy**, so MSRV is checked with `cargo check`).
- **Only `src/engine.rs` changes in code.** No dependency, config, wire-format or CI change.
- **Baseline test count** on the fix branch (cut from `main` = `d4df550`, 1.99.1, without `-D warnings`): 176 lib + 3 bin + 6 e2e + 0 doc = **185**, all passing. After Task 2 the count is **186** (177 lib). (`develop_fix_bug_windows-provider-name` has 191 lib, because it carries 15 extra tests of its own; `src/engine.rs` is identical on both branches.)
- Before Task 2, `RUSTFLAGS="-D warnings"` builds **fail** on 1.99.1. That failure is the defect. So Task 1 runs its tests *without* `-D warnings`, and from Task 2 on every gate uses `-D warnings`, as CI does.
- Commit messages use the repo's conventional prefix (`fix(engine): …`, `docs: …`). Each one ends with the `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` trailer.
- `src/inputs/eventlog.rs` (`#[cfg(windows)]`) is not touched. The CI `test-windows` job is the only Windows gate (spec V5).

## Rulings (decisions this plan makes where the spec leaves room)

**R-0: Open questions take the spec's proposed answers.** Option A (`update`), a standalone branch (open question 2a), and the missing CI MSRV check recorded as a follow-up issue (open question 3; out-of-scope item 2 is not recorded). If the owner decides otherwise:

| Decision changed | Tasks affected |
| --- | --- |
| Option B (`try_update`) | T2 step 2 uses the Option B snippet from the spec, and the comment says `try_update`. In T3, the tracker records `try_update` as the fix. |
| Commit on `develop_fix_bug_windows-provider-name` instead | T0: skip creating the branch; commit the docs on the current branch. Everything else stays the same. |
| No follow-up issue for the CI MSRV check | T3: skip step 2. |

**R-1: The branch is cut from `main`.** `main` and `develop` are the same commit (`d4df550`), so the tree is identical either way. The PR target is chosen when the PR is opened (T4).

**R-2: The spec and plan travel with the fix.** This follows the provider-name precedent (`70fe4a6 docs: spec and plan …`), so the reviewer of the PR sees why the change was made. `report.html` stays untracked: it is verification output, not project documentation.

**R-3: The issue-tracker update is its own commit (T3).** It goes in a separate `docs:` commit, so if the owner wants it landed separately, that one commit can be dropped from the PR without touching the fix.

**R-4: Test and fix share one commit (T1 + T2).** The spec's Rollout section says one commit. The new test is a behaviour pin that passes before and after the change, not a red test, so a test-only commit would add no signal. There is also a practical reason: before the fix, no commit can pass the CI gate anyway.

---

## Dependency graph and ordering

```text
T0 branch + docs commit
T1 saturation test (pins current behaviour, + mutation check)
 └── T2 replace fetch_update → update, full gate, commit   (T1 + T2 = one commit, R-4)
      └── T3 issue tracker: fix recorded, MSRV follow-up   (needs T2's hash)
           └── T4 push + PR + CI (blocked on write access)   (owner)
```

---

### Task 0: branch and docs commit

**Files:** `docs/superpowers/specs/2026-11-11-atomic-fetch-update-deprecation.md`, `docs/superpowers/plans/2026-11-11-atomic-fetch-update-deprecation.md` (both untracked today).

- [ ] **Step 1:** Check that the tree has no tracked changes: `git status --porcelain` shows only `??` lines (the local issue-tracker file, `report.html`, the two docs files).
- [ ] **Step 2:** `git switch -c develop_fix_bug_known-issues main`. Untracked files carry over.
- [ ] **Step 3:** Confirm that the new branch still has the defect: `grep -n fetch_update src/engine.rs` shows lines 242 and 251.
- [ ] **Step 4:** Commit only the two docs files:

  ```bash
  git add docs/superpowers/specs/2026-11-11-atomic-fetch-update-deprecation.md \
          docs/superpowers/plans/2026-11-11-atomic-fetch-update-deprecation.md
  git commit -m "docs: spec and plan for the fetch_update deprecation" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
  ```

---

### Task 1: pin the saturating clamp

**Files:** `src/engine.rs`, `mod tests`. Insert the test directly after `channel_bytes_gauge_tracks_admitted_and_drained_events` (currently ending at line 932), so the two gauge tests sit together.

- [ ] **Step 1:** Add the test:

  ```rust
      /// `ChannelBudget::release` must clamp `agent_channel_bytes` at 0, not
      /// wrap, when it releases more bytes than the gauge currently holds.
      /// Pins the behaviour across the `fetch_update` → `update`
      /// replacement; plain `fetch_sub` would wrap to ~u64::MAX here.
      #[test]
      fn channel_budget_release_saturates_at_zero() {
          let (tx, _rx) = mpsc::channel::<Event>(8);
          let metrics = Arc::new(Metrics::default());
          let sender = EventSender::with_budget(tx, 1024 * 1024).with_metrics(metrics.clone());
          let budget = sender.channel_budget();
          let ev = Event::new("s", "t", &"x".repeat(2048));

          // Gauge below the event's size: clamp to 0, not u64::MAX - 1047.
          metrics.channel_bytes.store(1000, Ordering::Relaxed);
          budget.release(&ev, &metrics);
          assert_eq!(
              metrics.channel_bytes.load(Ordering::Relaxed),
              0,
              "release of 2048 bytes from a 1000-byte gauge must saturate at 0"
          );

          // Gauge already at 0: stays at 0, not u64::MAX - 2047.
          budget.release(&ev, &metrics);
          assert_eq!(
              metrics.channel_bytes.load(Ordering::Relaxed),
              0,
              "release from an empty gauge must stay at 0"
          );
      }
  ```

  No new imports are needed: `mod tests` already has `use super::*;` (which brings in `mpsc`, `Arc`, `Metrics`, `Event`, `EventSender`) and `use std::sync::atomic::Ordering;` (line 703).

- [ ] **Step 2:** Run it on the **unchanged** call, without `-D warnings` (see Global Constraints):
  `cargo test --lib channel_budget_release_saturates_at_zero`. Expected: **1 passed** (one deprecation warning is printed, which is expected).
- [ ] **Step 3: mutation check.** This proves the test can actually fail. Temporarily replace the body of `ChannelBudget::release`'s gauge update with
  `metrics.channel_bytes.fetch_sub(EventSender::event_bytes(ev), Ordering::Relaxed);`
  and run the same command. Expected: **FAILED**, with left = `18446744073709550568` (`u64::MAX - 1047`). Then **revert** the mutation, and check that `git diff src/engine.rs` shows only the added test.

No commit (R-4).

---

### Task 2: replace `fetch_update` with `update`

**Files:** `src/engine.rs`, `ChannelBudget::release` (lines 239–254).

- [ ] **Step 1:** Change the first line of the comment (line 242):

  ```diff
  -        // `saturating_sub` (via `fetch_update`, since `AtomicU64` has no
  +        // `saturating_sub` (via `update`, since `AtomicU64` has no
  ```

  Lines 243–247 stay as they are.

- [ ] **Step 2:** Replace the call (lines 249–253):

  ```diff
  -        let _ = metrics
  -            .channel_bytes
  -            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
  -                Some(cur.saturating_sub(EventSender::event_bytes(ev)))
  -            });
  +        metrics
  +            .channel_bytes
  +            .update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
  +                cur.saturating_sub(EventSender::event_bytes(ev))
  +            });
  ```

  `update` returns the previous value and is not `#[must_use]` (verified in the spec: there is no `unused_must_use` and no clippy lint on 1.98.1 or 1.99.1), so the bare statement is fine.

- [ ] **Step 3:** `grep -n "fetch_update" src/engine.rs` returns only the new test's doc comment (from T1), which names the replacement on purpose. There must be no call and no mention in `ChannelBudget::release`.
- [ ] **Step 4: full gate** (spec V1–V4). Every command must pass:

  ```bash
  cargo fmt --all -- --check                                    # V3
  RUSTFLAGS="-D warnings" cargo clippy --all-targets            # V1 — failed before this task
  RUSTFLAGS="-D warnings" cargo test --all-targets              # V2 — expect 177 lib + 3 bin + 6 e2e = 186
  RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets       # V4 — MSRV
  ```

  If `fmt --check` fails, run `cargo fmt --all` and re-run the gate. If V4 fails, stop: the spec's MSRV evidence is wrong, and the decision goes back to the owner (switch to Option B or bump the MSRV).

- [ ] **Step 5:** `git diff --stat` shows only `src/engine.rs`. Commit:

  ```bash
  git add src/engine.rs
  git commit -m "fix(engine): replace deprecated AtomicU64::fetch_update" -m "Rust 1.99 deprecates fetch_update (renamed to try_update). CI builds
  with RUSTFLAGS=-D warnings on the latest stable, so the deprecation broke
  every CI job. Use AtomicU64::update instead: the closure can never fail,
  so the Option wrapper and the discarded Result go away. Stable on the
  1.98 MSRV, so no MSRV change. A new test pins the saturating clamp the
  call exists for.

  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
  ```

  Record the short hash. T3 needs it.

---

### Task 3: record the fix in the issue tracker

**Files:** the issue tracker only (its own commit, R-3). Let `<HASH>` be the T2 commit's short hash.

- [ ] **Step 1:** Record the issue as fixed in `<HASH>`, and note that the fix uses `update`, not the `try_update` rename the bug report proposed.
- [ ] **Step 2:** Record the missing CI MSRV check as a follow-up issue (spec out-of-scope item 1).
- [ ] **Step 3:** Commit the tracker change on its own, with a `docs:` prefix.

---

### Task 4: push, PR and CI (owner, blocked)

- [ ] **Step 1:** Get write access to `SoftnixTech/softnix-log-agent` (the account currently has `"push": false`), or agree on a fork workflow. A fork of this public repo is public.
- [ ] **Step 2:** `git push -u origin develop_fix_bug_known-issues` (the branch got this name on 2026-11-11, when it was renamed so it can carry the fixes for other known issues too), then open the PR against the base the owner picks (`main` or `develop`, R-1). The PR body ends with the Claude Code attribution line.
- [ ] **Step 3 (spec V5):** All of `test-linux`, `test-windows` and `lint` must be green. If `test-windows` fails on a *different* deprecation in `#[cfg(windows)]` code, that is a new issue (record it in the issue tracker), not part of this PR, unless it is just as trivial.
- [ ] **Step 4:** After merge, rebase `develop_fix_bug_windows-provider-name` onto the updated base so its CI picks up the fix. Then record in the issue tracker that the fix merged in #<PR>.

---

## Coverage check against the spec

| Spec item | Where |
| --- | --- |
| Goal 1: clippy + tests pass on 1.99.1 with `-D warnings` | T2 step 4 (V1, V2) |
| Goal 2: builds on MSRV 1.98 | T2 step 4 (V4) |
| Goal 3: behaviour unchanged, clamp at 0 | T1 (test + mutation check), T2 step 4 (existing gauge test in V2) |
| Goal 4: smallest possible diff | T2 step 5 (`git diff --stat`: one file) |
| Design: Option A + comment update | T2 steps 1–2 |
| Testing: existing test kept, new saturation test | T1, T2 step 4 |
| V3 fmt | T2 step 4 |
| V5 Windows CI | T4 step 3 |
| Rollout: fix commit + separate issue-tracker status commit | T2 step 5, T3 |
| Out-of-scope item 1 → follow-up issue | T3 step 2 |
| Open questions | R-0, R-1 |

## Risks and known trade-offs

- **Stable may move again before merge.** If CI already runs a newer stable (1.100+) by the time the PR opens, it may surface another new lint or deprecation. T4 step 3 catches this; spec out-of-scope item 2 is the long-term answer.
- **Windows-only code is not compiled locally.** The grep shows no `fetch_update` in `eventlog.rs`, but other 1.99 deprecations there would show up only in CI (T4 step 3).
- **The mutation check is manual.** T1 step 3 must be reverted by hand. The `git diff` check at the end of that step is the guard.
- **Everything stops at T4** until write access exists. T0–T3 are local commits that can be pushed as-is later.
