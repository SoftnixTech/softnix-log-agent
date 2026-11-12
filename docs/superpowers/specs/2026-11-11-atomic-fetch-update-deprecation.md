# `AtomicU64::fetch_update` deprecation breaks CI on Rust ≥ 1.99 — design spec

Status: **draft — waiting for owner review** (see [Open questions](#open-questions)).
Implementation plan:
`docs/superpowers/plans/2026-11-11-atomic-fetch-update-deprecation.md`.
It assumes the proposed answer to every open question.

Reviewed 2026-11-11: every claim was re-checked against commit `f910a8f`.
Changes made: a must-use check for `update`, the 1.98 baseline, the
`develop` base branch, the stale fix text in the bug report, and a stronger
saturation test.

## Problem

`ChannelBudget::release` (`src/engine.rs:239`) lowers the
`agent_channel_bytes` gauge with a saturating subtraction built on
`AtomicU64::fetch_update`:

```rust
// src/engine.rs:249-253
let _ = metrics
    .channel_bytes
    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
        Some(cur.saturating_sub(EventSender::event_bytes(ev)))
    });
```

Rust 1.99 deprecates `fetch_update` ("renamed to `try_update` for
consistency"). CI sets `RUSTFLAGS: -D warnings` (`.github/workflows/ci.yml:9`)
and installs the toolchain with `dtolnay/rust-toolchain` from its *stable
branch* (`ci.yml:16`, `:24`, `:38`). The SHA pin fixes the action's code, not
the Rust version, so every run installs the stable release of that day. As
soon as CI gets 1.99, the deprecation warning becomes an error, and the
`test-linux`, `test-windows` and `lint` jobs all fail. Every open PR is
blocked, including the provider-name fix on
`develop_fix_bug_windows-provider-name`.

`release.yml` uses the same toolchain action (`release.yml:49`, `:90`). It
does not set `-D warnings`, so release builds still succeed and only print
the warning.

### Evidence (2026-11-11, commit `f910a8f`)

| Check | Toolchain | Result |
| --- | --- | --- |
| `RUSTFLAGS="-D warnings" cargo clippy --all-targets` (the CI command) | 1.99.1 | **fails**: exactly one error, `src/engine.rs:251`, for both the `lib` and `lib test` targets |
| `RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets` on the unchanged code | 1.98.1 | passes (10.5 s). V4 therefore starts from a clean baseline. |
| `grep fetch_update` over `src/`, `tests/`, `benches/`, `examples/`, `build.rs` | n/a | one call site (`engine.rs:251`) plus one mention in the comment at `engine.rs:242` |
| Test program using `try_update` and `update` on `AtomicU64`, built with `-D warnings` | 1.98.1 | builds, gives correct results |
| Same program | 1.99.1 | builds, gives correct results |
| Statement `a.update(…);` with its return value dropped (no `let _ =`), `-D warnings` | 1.98.1 (`cargo run`) and 1.99.1 (`cargo clippy --all-targets` and `cargo run`) | builds, no `unused_must_use` and no clippy lint. Option A can be a bare statement. |

Output of the test program on both toolchains:
`try_update=Ok(5) a=0 update_old=5 b=3`. That is the old value, then a
value saturated at 0 (5 − 9), then 5 − 2 = 3.

So both replacement APIs are stable on the declared MSRV
(`rust-version = "1.98"`, `Cargo.toml:7`), and neither one needs an MSRV
bump or `#[allow(deprecated)]`.

## Goals

1. `RUSTFLAGS="-D warnings" cargo clippy --all-targets` and
   `cargo test --all-targets` pass on Rust 1.99.1.
2. The crate still builds with `-D warnings` on Rust 1.98, the declared MSRV.
3. The behaviour of `ChannelBudget::release` does not change: the gauge is
   lowered by `event_bytes(ev)` and clamps at 0 instead of wrapping.
4. The diff is as small as possible, so it can merge ahead of every other PR.

## Non-goals

- No other change to `ChannelBudget`, `EventSender` or the gauge accounting.
- No change to CI toolchain selection (see [Out of scope](#out-of-scope)).
- No version bump or release-note entry. Nothing visible to users changes.

## Design

Replace the deprecated call with one of the std APIs that replace it.
Both have the same argument order as `fetch_update`
(`set_order, fetch_order, f`), and both are a CAS loop that gives the same
result as today's code.

### Option A — `update` (recommended)

```rust
metrics
    .channel_bytes
    .update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
        cur.saturating_sub(EventSender::event_bytes(ev))
    });
```

`update` takes `FnMut(u64) -> u64` and returns the previous value. The
closure here can never fail, so this states the intent directly. The
`Some(..)` wrapper goes away, and so does the `let _ =` that today throws
away a `Result` that can only ever be `Ok`.

### Option B — `try_update` (plain rename)

```rust
let _ = metrics
    .channel_bytes
    .try_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
        Some(cur.saturating_sub(EventSender::event_bytes(ev)))
    });
```

This renames the method and nothing else. It is the fix the original bug
report proposed. It has the smallest diff, but keeps the `Option` and the discarded
`Result` that the code does not need.

Both options are verified on 1.98.1 and 1.99.1. This spec recommends A.
If the owner prefers the smallest possible diff, B is just as correct.

### Comment update

The comment at `src/engine.rs:242` reads
"`saturating_sub` (via `fetch_update`, since `AtomicU64` has no built-in
fetch-saturating-sub)". Change it to name the method actually used.
The rest of the comment, which explains why the clamp is kept, stays as it
is.

## Testing

The failing check for this defect is the build itself: on 1.99 with
`-D warnings` the crate does not compile. There is no runtime behaviour to
turn from red to green. The test work is therefore about making sure the
rename does not change behaviour.

1. **Existing test, kept:**
   `channel_bytes_gauge_tracks_admitted_and_drained_events`
   (`src/engine.rs:920`) covers the normal path: admit 2048 bytes, release,
   gauge = 0.
2. **New test:** `channel_budget_release_saturates_at_zero`, a plain
   `#[test]` in the same `tests` module. It releases a 2048-byte event twice:
   first with the gauge at 1000, which is less than the event's size, and
   then with the gauge at 0. Both times it asserts that the gauge is `0`. A
   wrapping subtraction would leave `u64::MAX - 1047` and
   `u64::MAX - 2047`. No test covers
   the clamp today, and the clamp is the one behaviour that a careless
   replacement (say, plain `fetch_sub`) would silently break. The test passes
   before and after the change. It exists to pin the behaviour, not to
   reproduce the bug.

### Verification matrix

| # | Command | Toolchain | Expected |
| --- | --- | --- | --- |
| V1 | `RUSTFLAGS="-D warnings" cargo clippy --all-targets` | 1.99.1 | passes (failed before the fix) |
| V2 | `RUSTFLAGS="-D warnings" cargo test --all-targets` | 1.99.1 | all tests pass, including the new one |
| V3 | `cargo fmt --all -- --check` | 1.99.1 | passes |
| V4 | `RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets` | 1.98.1 | passes, so the MSRV still holds. This is `check`, not `clippy`, because the local 1.98 toolchain has no clippy component. |
| V5 | CI `test-windows` job | stable on CI | passes. This cannot be run locally: `src/inputs/eventlog.rs` only compiles on Windows, so a deprecation that only Windows code hits would show up only here. The grep above found no `fetch_update` there. |

## Rollout

One commit, for example
`fix(engine): replace deprecated AtomicU64::fetch_update`, containing the
code change, the comment update and the new test. A follow-up commit marks
the issue as fixed in the issue tracker, names the fixing commit, and, if
Option A is chosen, corrects the proposed fix text in the bug report. That text currently says
"Rename the call to `try_update`", which would no longer match the code. The
status update goes in a separate commit because it has to quote the hash of
the first one.

Where the commit goes depends on open question 2.

## Out of scope

Recorded here so they are not lost. None of them blocks this fix.

1. **CI does not check the MSRV.** All three CI jobs install the latest
   stable, so nothing checks `rust-version = "1.98"`. V4 checks it by hand
   for this change only. A `msrv` job (`cargo +1.98 check --all-targets`)
   would catch an API that is too new before it merges. Suggested as a new
   issue (now `docs/superpowers/specs/2026-11-11-ci-msrv-job.md`).
2. **Floating stable plus `-D warnings`.** Any future stable release can
   deprecate something else and break CI in the same way, with no change to
   this repo. The options are to pin CI to a fixed toolchain and bump it on
   purpose, to add a scheduled CI run on stable that warns early, or to
   accept the risk. That decision belongs to the owner and needs its own
   issue.

## Open questions

1. **Which API: `update` (A) or `try_update` (B)?**
   Proposed answer: **A**. It is equally verified and states the intent more
   clearly.
2. **Where does the commit go?**
   - (a) A standalone branch (for example `develop_fix_bug_known-issues`)
     with its own PR. This keeps the provider-name PR focused. The
     provider-name branch then rebases once that PR merges. Base: `main` and `develop` both point at
     `d4df550` today, and CI runs on pushes to both, so either base gives the
     same tree. The owner picks the PR target.
   - (b) An extra commit on `develop_fix_bug_windows-provider-name`. Fewer
     PRs, but it mixes an unrelated fix into that PR.

   Proposed answer: **(a)**. Either way, nothing can be pushed until the
   account has write access to `SoftnixTech/softnix-log-agent`.
3. **Should out-of-scope items 1 and 2 be recorded as issues now?**
   Proposed answer: record item 1 as a follow-up issue (the missing CI MSRV
   check). Record item 2 only if the owner wants to track it.
