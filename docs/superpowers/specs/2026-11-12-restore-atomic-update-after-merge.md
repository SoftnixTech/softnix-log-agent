# Merge `e541e78` broke the `fetch_update` fix, so `develop` does not compile under `-D warnings` — design spec

Status: **fixed and merged.** `0e1f135` (branch `develop_fix_bug`) merged
into `develop` through PR #4 at 2026-11-12T02:23:38Z (`879d30f`). CI is
green on the PR (run 43136148376) and on the `develop` push (run
43141090497, all jobs).
Implementation plan:
`docs/superpowers/plans/2026-11-12-restore-atomic-update-after-merge.md`.

This spec was written **after** the fix, on 2026-11-12. It records the
design and the evidence, and the review of the fix against both. Every claim
below was re-checked on 2026-11-12 at `bfc3af2`.

Related: the `AtomicU64::fetch_update` deprecation on Rust 1.99
(`docs/superpowers/specs/2026-11-11-atomic-fetch-update-deprecation.md`),
whose fix this issue restores.

## Problem

Every CI job that builds the crate fails on `develop` @ `9d08455` (run
42997642297): `lint`, `msrv`, `test-linux` and `test-windows`.

```text
error: unused `std::result::Result` that must be used
   --> src/engine.rs:249:9
```

Nothing on `develop` can pass CI, and nothing can be confirmed on CI
(the CI MSRV job, the flaky backed-up-destination e2e test fix) until
this is fixed.

## Root cause

The `fetch_update` deprecation was fixed twice, once on each branch, and the two fixes differ:

| Commit | Branch | Line 249 | Lines 251–252 |
| --- | --- | --- | --- |
| `d4df550` (merge base) | `main` | `let _ = metrics` | `.fetch_update(…, \|cur\| { Some(cur.saturating_sub(…)) })` |
| `db15f72` (`af3018c`) | `develop_fix_bug_known-issues` | `metrics` | `.update(…, \|cur\| { cur.saturating_sub(…) })` |
| `50f62f3` (`7bb53e6`) | `develop` (provider-name, PR #2) | `let _ = metrics` | `.try_update(…, \|cur\| { Some(cur.saturating_sub(…)) })` |
| `e541e78` (merge) | `develop_fix_bug_known-issues` | `metrics` | `.try_update(…, \|cur\| { Some(cur.saturating_sub(…)) })` |

The merge produced a mix of the two sides, and no person removed the
`let _ =` by hand:

1. **Line 249 merged automatically.** Only the known-issues side changed it
   (`let _ = metrics` → `metrics`), so git took that side without a
   conflict.
2. **Lines 251–252 conflicted**, because both sides changed them. `git show
   --remerge-diff e541e78` shows the conflict was resolved with the
   provider-name side (`try_update` + `Some(…)`). The comment at line 242 was
   resolved the same way.

`update` returns `u64` and is not `#[must_use]`, so a bare statement is
fine. `try_update` returns `Result<u64, u64>`, which is `#[must_use]`, so
without `let _ =` the result is unused. `-D warnings` (`ci.yml`) makes
that an error.

### Why CI did not stop it

PR #3 (`develop_fix_bug_known-issues` → `develop`) was **merged at
09:43:59Z, before CI ran on its final head**. The merge commit `e541e78`
was pushed to the PR branch, and its CI run (42997702133) started at
09:44:27Z, 28 s after the merge, and failed. The previous head, `db15f72`,
had a green run (42995554353), so the PR showed green checks from a head
that was no longer the one being merged. `develop` has no branch
protection that requires the checks of the current head.

## Goals

1. `develop` compiles and passes `RUSTFLAGS="-D warnings" cargo clippy
   --all-targets` on stable (1.99.1) again.
2. The MSRV (1.98) still builds.
3. `ChannelBudget::release` behaves as before: lower the gauge by
   `event_bytes(ev)` and clamp at 0.
4. The decision of the `fetch_update` fix (`update`, not `try_update`)
   holds in the code, the comment and the issue tracker.

## Non-goals

- No other change to `ChannelBudget` or the gauge.
- No change to CI. Branch protection is an owner decision (see
  [Open questions](#open-questions)).

## Design

Go back to the form of the original `fetch_update` fix (`af3018c`), the
option that its spec chose:

```rust
// src/engine.rs:242
// `saturating_sub` (via `update`, since `AtomicU64` has no
// ...
metrics
    .channel_bytes
    .update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
        cur.saturating_sub(EventSender::event_bytes(ev))
    });
```

Rejected alternative: put `let _ =` back in front of `try_update`. That
also compiles. But it brings back the `Option` and the discarded `Result`
that the original fix removed on purpose, and leaves the code different
from that fix's spec, plan and issue-tracker entry.

## Testing

As with the original `fetch_update` fix, the failing check is the build itself, so there is no
runtime test to turn from red to green. The behaviour is pinned by tests
that already exist:

- `channel_budget_release_saturates_at_zero` (`src/engine.rs:939`, added
  by the `fetch_update` fix) pins the clamp at 0.
- `channel_bytes_gauge_tracks_admitted_and_drained_events` pins the
  normal path.

### Verification matrix

| # | Check | Where | Result (2026-11-12) |
| --- | --- | --- | --- |
| V1 | `RUSTFLAGS="-D warnings" cargo clippy --all-targets` on `9d08455` (red) | local, 1.99.1, clean worktree | **fails**, 1 error at `src/engine.rs:249:9`, for `lib` and `lib test` |
| V2 | Same on `bfc3af2` (green) | local, 1.99.1 | passes |
| V3 | `cargo fmt --all -- --check` | local | passes |
| V4 | `RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets` | local, 1.98.1 | passes |
| V5 | `RUSTFLAGS="-D warnings" cargo test --all-targets` | local, macOS | **258 passed** (248 lib + 3 bin + 6 e2e + 1 `self_logs_on_stderr`) |
| V6 | `grep -rn "fetch_update\|try_update" src tests` | local | only the doc comment of the saturation test (`src/engine.rs:936`), no call |
| V7 | `git diff db15f72 bfc3af2 -- src/engine.rs` | local | **empty**: `engine.rs` is byte-identical to the known-issues side |
| V8 | `git show --remerge-diff e541e78` | local | `src/engine.rs` is the only conflicted file, so the merge lost nothing else |
| V9 | `git diff d4df550 50f62f3 -- src/engine.rs` | local | the provider-name side changed only the `fetch_update` lines (`7bb53e6`), so taking the known-issues side for the whole file drops nothing from it |
| V10 | CI on `bfc3af2` (PR #4) | run 43136148376 | **all 5 jobs pass**: `lint`, `msrv`, `test-linux`, `test-windows`, `audit` |
| V11 | CI on `develop` after the merge (`879d30f`, push) | run 43141090497 | **all jobs pass** |

## Review of the implementation (`0e1f135`)

**Correct.** The diff is the 3-line revert to the `af3018c` form described
above, and the file now matches the known-issues side exactly (V7). Nothing
else from either side was lost in the merge (V8, V9). CI passes on Linux,
Windows and the MSRV, on the PR and on `develop` after the merge (V10,
V11).

One correction to the original bug report: it says the merge "dropped `let
_ =`". More exactly, git merged line 249 automatically from the
known-issues side, and the conflict on lines 251–252 was resolved with the
provider-name side. Neither half is wrong on its own; together they do not
compile. Merges between these branches can repeat this, so it is worth
recording.

**Stale text found during the review** (issue tracker, 2026-11-12):

- This issue's status said "pending CI: not pushed yet". `0e1f135` was merged into
  `develop` in PR #4 (`879d30f`) with CI green.
- The tracker's "Blocker for every PR" (no push access) no longer
  holds: PRs #2, #3 and #4 are merged.

## Rollout

1. `0e1f135 fix(engine): restore the … AtomicU64::update call lost in
   merge e541e78`: done.
2. `bfc3af2` (the `docs:` commit that marks this issue fixed): done.
3. Merge PR #4 into `develop` after its CI is green on the head being
   merged, then confirm the `push` run on `develop`: **done**
   (`879d30f`, run 43141090497).
4. Record the final status in the issue tracker, with the corrected
   root-cause wording and a link to this spec.

## Open questions

1. **Protect `develop` and `main`?** Require the `lint`, `msrv`,
   `test-linux` and `test-windows` checks, and require the branch to be
   up to date before merging. That stops a PR from merging on the green
   checks of an older head. Proposed answer: **yes**. This needs an org
   admin and is not a code change.
2. **Record the process gap as its own issue?** Proposed answer: no. It is
   recorded here and in this issue's root cause. Open a new issue only if
   the owner declines question 1.
