# e2e isolation test is flaky on Windows and did not guard the bug it names — design spec

Status: **closed — fixed** in `170d99f` (test only), merged into `develop`
(PR #3, then PR #4 → `879d30f`). On Windows CI the test passed in **3 of 3**
runs where it ran (see V5). The owner closed the issue on 2026-11-12 at 3/3,
instead of the 5 in a row proposed below.
Implementation plan:
`docs/superpowers/plans/2026-11-12-e2e-backed-up-destination-test.md`.

This spec was written **after** the fix, on 2026-11-12. It records the
design and the evidence, and the review of the fix against both. Every
local claim below was re-checked on 2026-11-12 at `bfc3af2` on macOS
(Apple silicon, Rust 1.99.1).

## Problem

`a_backed_up_destination_does_not_stop_its_peers` (`tests/e2e.rs:338`)
guards the C-3 fix: per-destination fan-out in `route_event`
(`src/engine.rs`) uses `try_send`, so a destination whose `block`-policy
disk queue is full sheds its own events and does not stall the others.

The test had two defects:

1. **Flaky on Windows.** It failed on `test-windows` in run 42992580077
   (`de96813`) with `healthy destination only got 0/50 marker events`, and
   passed in the two runs before. Passing runs took 4–5 s. The failing run
   took 18.8 s: about 8.5 s to fill, then the full 10 s marker wait with
   nothing arriving.
2. **Not a guard.** With the pre-fix blocking `tx.send` put back in
   `route_event`, the old test **still passed** (0.3–0.4 s, 2/2 runs,
   re-checked 2026-11-12). So it would not have caught C-3 coming back.

## Root cause (test only; the product code is correct)

1. **The sink was read too late.** The test read the "healthy" UDP sink
   only after sending the markers. "healthy" also forwards every 8 KiB
   filler, so the sink's kernel receive buffer was already full, and the
   kernel dropped the markers before `recv_from` ran. Windows' small default
   UDP receive buffer makes this lose every marker.
2. **The markers went out in one burst** while the agent's input socket
   buffer and the "healthy" router channel were still full of filler.
3. **One `is_full()` reading did not mean "stuck" was stalled.** The
   "stuck" worker keeps draining into loopback TCP buffers, which autotune
   to several MiB, so its queue dips below the cap and the router un-parks.
   A blocking fan-out only stalls once the 4096-event router channel
   (`ROUTER_CAPACITY`, `src/engine.rs:53`) is also full. The old test never
   filled it, which is why it passed with the bug.

## Goals

1. The test passes reliably on Linux, macOS and Windows with the current
   (`try_send`) code.
2. The test fails, for the reason it names, when `route_event` blocks on a
   full destination.
3. When it fails, the message says enough to tell a real stall from test
   noise.

## Non-goals

- No change to product code. `route_event`, the router and `DiskQueue` stay
  as they are.
- The slow-stop problem (`Engine::stop` waits 8 s on a wedged TCP output)
  is not fixed here, though this test hits it (see the review).
- The burst-shedding problem (shedding under a burst while the disk queue
  has room) is not fixed here.

## Design

Four changes, all in the test (`tests/e2e.rs`):

| # | Change | Lines | Fixes |
| --- | --- | --- | --- |
| D1 | A background task drains the healthy sink for the whole test and counts `MARKER` datagrams. It keeps reading past a transient error (e.g. a Windows `WSAECONNRESET`). | 423–438 | cause 1 |
| D2 | "Wedged" precondition: keep sending filler until the stuck queue `is_full()` **and** its `len()` has not changed for 1 s, so its worker is parked in `write_all`. Assert this, with a 30 s deadline. | 470–515 | cause 3 |
| D3 | Top-up: push `4096 + 1024` small events, counted by the agent's `events_received`, not by what was sent. With a blocking fan-out the pipeline stalls after about 4096 and the 8192-event input channel takes the rest, so the target is reached either way. Assert it, with a 15 s deadline. | 526–553 | cause 3 |
| D4 | Settle, then pace: wait until `events_received` stops moving (at most 5 s), then send the 50 markers 10 ms apart. The failure message includes the "healthy" `router_shed` delta during the marker phase and whether "stuck" is still full. | 571–612 | cause 2, goal 3 |

The pass condition is unchanged: at least `MARKERS / 2` (25 of 50) markers
reach the healthy sink within 10 s.

## Verification matrix

| # | Check | Where | Result |
| --- | --- | --- | --- |
| V1 | New test, current code, 5 runs | macOS, 2026-11-12 | **5/5 pass**, 10.87–10.96 s each |
| V2 | New test, `route_event` forced to blocking `send` (`if true \|\| force_deliver {`), 3 runs | macOS, 2026-11-12 | **3/3 fail** after about 21 s with `healthy destination only got 0/50 … (healthy router shed 0 …; stuck still full: true)`. They fail at the final assertion, not at a precondition, so the test catches the stall itself. |
| V3 | Old test (`170d99f~1`), same blocking mutation, 2 runs | macOS, 2026-11-12 | **2/2 pass** (0.32–0.40 s). This confirms defect 2. |
| V4 | Full suite `RUSTFLAGS="-D warnings" cargo test --all-targets` | macOS, 2026-11-12 | 258 passed; e2e 6/6 |
| V5 | CI `test-windows`, every run that contains `170d99f` | runs 42995554353 (`db15f72`, PR #3), 43136148376 (`bfc3af2`, PR #4), 43141090497 (`879d30f`, `develop` push) | **3/3 pass**; e2e 6/6 each time, about 11–12 s for the binary. Runs 42997702133 (`e541e78`) and 42997642297 (`9d08455`) also contain the fix but failed to compile (merge `e541e78` broke the `fetch_update` fix, see `2026-11-12-restore-atomic-update-after-merge.md`), so the test did not run there. They are not counted. |
| V6 | CI `test-linux` | the same three runs | pass |
| V7 | Docker/Wine retest | 2026-11-11 | not usable: `tests/e2e.rs` aborts with SIGTRAP under Rosetta and QEMU before any assertion |

## Review of the implementation (`170d99f`)

**Correct, and now a real guard.** V1 and V2 together show the test passes
on the fix and fails on the bug, for the reason in its name. V3 shows the
old test did neither. The four changes match the three causes one to one.
Every Windows CI run that reached the test since the fix has passed (V5,
3/3).

Points found in the review, none blocking:

1. **Three Windows passes are good, but not yet proof of "not flaky".**
   Before the fix the test failed in 1 of 3 Windows runs. At that rate, 3
   passes in a row would still happen by chance about 30% of the time
   ((2/3)^3). See [Remaining work](#remaining-work).
2. **Most of the run time is the slow-stop problem.** Each run takes about
   10.9 s on macOS. About 8 s of that is `engine.stop()` waiting out its
   per-task timeout on the wedged "stuck" worker (measured as 8.0 s in this
   test). When the slow-stop problem is fixed this test should drop to about
   3 s. That is a free check for that fix.
3. **`TOP_UP` copies `ROUTER_CAPACITY` by hand.** `4096` in the test
   (line 526) is `ROUTER_CAPACITY` (`src/engine.rs:53`), which is private.
   If the capacity grows, the top-up no longer fills the router channel, and
   the test quietly goes back to not being a guard. V2 is the only thing that
   would show it. A follow-up could expose the constant to tests, or make
   the test check `router_shed["stuck"]` rose during the top-up.
4. **The burst-shedding fix will change the code this test guards.** Every
   fix option for the burst-shedding problem changes when `route_event` sheds. The test's comments
   ("Under the fix … 'stuck' sheds them") and its premise (a full, wedged
   queue) still hold under the proposed fix ("shed only when the disk queue
   is actually full"). But the burst-shedding work must re-run V1 and V2, not just
   the normal suite.
5. **Wording in the original bug report.** "Passing runs took 4–5 s" describes the
   old test on Windows CI. The new test takes about 11 s locally and 12 s
   for the e2e binary on Windows CI.

## Remaining work

1. ~~Get 2 more Windows passes, for 5 consecutive.~~ Not needed: the
   owner accepted 3/3 (open question 1).
2. ~~Record the result in the issue tracker (plan T5).~~ Done 2026-11-12, including point 5.
3. Optional: point 3 of the review, with the burst-shedding work. If the
   test ever fails on Windows again, reopen the issue with the failure message (plan T4
   step 3).

## Open questions

1. ~~**Is 5 consecutive Windows passes the right bar to close the issue?**~~
   **Decided 2026-11-12: close at 3/3** (owner). Original proposal: 5. The old flake rate was about 1 in 3, so 5 passes
   in a row would happen by chance with that rate only about 13% of the
   time ((2/3)^5), against about 30% for the 3 passes seen so far. The
   owner may accept 3/3 instead, given the root cause is understood and
   the mutation check (V2) passes.
2. **Do point 3 (the `ROUTER_CAPACITY` coupling) now, or leave it for the
   burst-shedding work, which touches the same code?** Proposed answer:
   with the burst-shedding work.
