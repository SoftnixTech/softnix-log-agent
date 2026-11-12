# Reliable and Guarding Backed-Up-Destination e2e Test — Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking. Execute the tasks in order. Tasks marked `[x]` were done before this plan was written (2026-11-12) and are recorded for traceability.

**Goal:** Make `a_backed_up_destination_does_not_stop_its_peers` (`tests/e2e.rs:338`) pass reliably on every CI platform, and fail when per-destination fan-out blocks on a full destination (the C-3 bug).

**Architecture:** Test-only change. No product code changes.

**Tech Stack:** Rust 2021, tokio (`#[tokio::test]`, current-thread runtime), UDP/TCP loopback sockets, `engine.shared.queues` / `metrics` / `router_shed` from the public engine API.

**Spec:** `docs/superpowers/specs/2026-11-12-e2e-backed-up-destination-test.md`

## Global Constraints

- **Only `tests/e2e.rs` changes.** If the test seems to need a product change, stop. That is a new issue, not this one.
- The mutation used to prove the test is a guard: in `route_event` (`src/engine.rs`, the `if force_deliver {` line, currently 651), change it to `if true || force_deliver {`. Every fan-out then uses blocking `tx.send`, as before the C-3 fix. **Use a throw-away worktree** and revert with `git checkout -- src/engine.rs`.
- Local toolchain: `~/.cargo/bin` (may need adding to `PATH`). The e2e tests do not run under Docker/Wine (SIGTRAP), so Windows is checked on CI only.
- Commit messages use `test(e2e): …` / `docs: …` and end with the `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` trailer.

## Rulings

**R-1: Keep the pass bar at 25 of 50 markers.** The fix is about making the conditions right, not about loosening the assertion.

**R-2: Count what the agent received, not what was sent** (`events_received`). UDP loss on the way in would otherwise make the top-up look full when it is not.

**R-3: The test must fail at its final assertion under the mutation.** A precondition failure under the mutation would mean the test is checking the wrong thing.

---

## Dependency graph

```text
T1 reproduce: old test passes under the mutation   [x]
 └── T2 implement D1–D4                              [x] 170d99f
      └── T3 local gate: 5/5 pass, 3/3 fail mutated  [x] (re-run 2026-11-12)
           └── T4 Windows CI                         [x] 3/3 pass; owner closed at 3/3 (2026-11-12)
                └── T5 issue tracker                 [x] updated 2026-11-12, not committed yet
T6 follow-ups (optional, with burst-shedding work)   [ ]
```

---

### Task 1: reproduce [x]

- [x] **Step 1:** Read the failing run 42992580077 (`de96813`, `test-windows`): `healthy destination only got 0/50 marker events`, 18.8 s.
- [x] **Step 2:** Apply the mutation and run the **old** test. Result: **passes**. The old test is not a guard. Re-checked 2026-11-12 with the `170d99f~1` test: 2/2 pass, 0.32–0.40 s.

### Task 2: implement D1–D4 [x] — `170d99f`

**Files:** `tests/e2e.rs`.

- [x] **D1** (lines 423–438): spawn a task that loops on `sink.recv_from`, ignores errors, and counts datagrams containing `MARKER` into an `AtomicUsize`. Abort it before `engine.stop()`.
- [x] **D2** (lines 470–515): fill until `stuck_q.is_full()` and `stuck_q.len()` has not changed for 1 s (30 s deadline). Assert `wedged`.
- [x] **D3** (lines 526–553): send small `topup` events until `events_received` has risen by `4096 + 1024` (15 s deadline). Assert it.
- [x] **D4** (lines 571–612): wait until `events_received` is stable for 200 ms (5 s max), record `router_shed["healthy"]`, send 50 markers 10 ms apart, wait up to 10 s for `MARKERS / 2`, and report the shed delta and `is_full()` in the failure message.

### Task 3: local gate [x]

Re-run 2026-11-12 at `bfc3af2`, macOS:

- [x] **Step 1:** `for i in 1 2 3 4 5; do cargo test --test e2e a_backed_up_destination_does_not_stop_its_peers; done`. Result: **5/5 pass**, 10.87–10.96 s.
- [x] **Step 2:** In a throw-away worktree, apply the mutation and run 3 times. Result: **3/3 fail** at the final assertion: `0/50 … healthy router shed 0 … stuck still full: true`, about 21 s each. Revert, then `git status --porcelain` is empty.
- [x] **Step 3:** `RUSTFLAGS="-D warnings" cargo clippy --all-targets` and `cargo test --all-targets`. Result: clean, 258 passed.

### Task 4: Windows CI [x]

- [x] **Step 1:** `test-windows` passed, e2e 6/6, in every run where the test ran: 42995554353 (`db15f72`), 43136148376 (`bfc3af2`), 43141090497 (`879d30f`, `develop` push). Two other runs contain the fix but did not compile (merge `e541e78` broke the `fetch_update` fix) and are not counted.
- [x] **Step 2:** ~~Get **5 consecutive** green `test-windows` runs~~. **The owner accepted 3/3 and closed the issue on 2026-11-12** (spec open question 1). The commands below are kept for reruns if needed. Either re-run the job on the latest `develop` run:

  ```bash
  JOB=$(gh run view 43141090497 --json jobs --jq '.jobs[]|select(.name=="test-windows")|.databaseId')
  gh run rerun 43141090497 --job "$JOB"   # repeat after each finishes
  ```

  or count the next `develop` push runs. If the owner accepts 3/3, mark this step done with that note. For each run, record its ID and the test's line from
  `gh run view <run> --log --job <job> | grep a_backed_up_destination`.
- [ ] **Step 3:** If any run fails, keep its log. The failure message's `healthy router shed` and `stuck still full` values tell the cases apart. Shed > 0 means the markers were shed by `try_send` for "healthy" (settle too short). `stuck still full: false` means the wedge was lost. Precondition messages mean the fill or top-up did not finish in time on that runner. Reopen the issue with that data.

### Task 5: record the result in the issue tracker [x]

Done 2026-11-12.

- [x] **Step 1:** Recorded the fix in the issue tracker as closed by the owner after Windows CI 3/3 (42995554353, 43136148376, 43141090497). The old "Passing runs took 4–5 s" wording now says it was the old test.
- [ ] **Step 2:** Commit `docs: backed-up-destination test spec and plan; record Windows CI result`. **Not done: the owner asked not to commit yet.**

### Task 6: follow-ups (optional, with the burst-shedding work) [ ]

- [ ] **Step 1:** Remove the hand copy of `ROUTER_CAPACITY` in `TOP_UP` (spec review point 3). Either expose the constant to tests, or assert during the top-up that `router_shed["stuck"]` rose, which proves the router channel was full.
- [ ] **Step 2:** In the work on the burst-shedding problem (events shed on a burst under `full_policy: block`), re-run T3 steps 1–2 (pass and mutation) after its routing change, not just the normal suite.
- [ ] **Step 3:** After the slow-stop problem (`Engine::stop` waits 8 s on a wedged TCP output) is fixed, check that this test's run time drops from about 11 s to about 3 s.

---

## Coverage check against the spec

| Spec item | Where |
| --- | --- |
| Goal 1: reliable on every platform | T3 step 1 (macOS), T4 (Windows), CI `test-linux` |
| Goal 2: fails on a blocking fan-out | T1 step 2 (old: no), T3 step 2 (new: yes) |
| Goal 3: diagnostic failure message | T2 D4, T4 step 3 |
| D1–D4 | T2 |
| V1–V7 | T3, T4 |
| Review points 1, 5 | T4 step 2, T5 step 1 |
| Review points 2, 3, 4 | T6 |
| Open questions 1, 2 | T4 step 2, T6 |

## Risks

- **CI runner speed.** The 30 s fill, 15 s top-up and 5 s settle deadlines assume a runner that is not starved. A slow runner fails with a precondition message, which shows that the runner was slow, not that the product is broken.
- **Windows is only checked on CI.** Neither the macOS runs nor the Docker/Wine setup tells us anything about the Windows UDP buffer behaviour that caused the flake.
- **The mutation check is manual.** It must be done in a throw-away worktree and reverted. T3 step 2 ends with `git status --porcelain`.
