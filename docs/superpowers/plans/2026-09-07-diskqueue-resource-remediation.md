# DiskQueue Resource Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix findings R-1 through R-5 of the DiskQueue resource analysis: un-wedge the queue after a transient segment-create failure, bound `peek_batch` by bytes, get the cursor `fsync`s and the batch reads out from under the queue mutex and off the tokio runtime, and stop deep-cloning the event body on every condition evaluation.

**Architecture:** `DiskQueue` stays a synchronous, `std::sync::Mutex`-guarded, single-producer/single-consumer on-disk queue with an unchanged file format; the changes shrink what happens *inside* the lock (serialize the cursor under it, `fsync` outside it; buffer segment appends through a `BufWriter`) and move the batch-granularity calls (`peek_batch`, `ack`) onto `tokio::task::spawn_blocking` at the two `OutputWorker::run` call sites. The per-event `push` stays on the router's async task by deliberate ruling (see Ruling R2-A). The condition DSL gains a borrowing accessor (`Event::get_str`) with an exact fallback to the existing owned-`Value` path, so behaviour is bit-identical while the hot `when: {field: message, op: contains}` case allocates nothing.

**Tech Stack:** Rust 2021 / Tokio / std::sync::Mutex-guarded DiskQueue

**Spec:** docs/superpowers/specs/2026-09-07-diskqueue-resource-analysis.md

## Global Constraints

- Rust edition 2021, `rust-version = "1.98"`; the toolchain is 1.98.1 (`cargo 1.98.1`, `rustc 1.98.1`).
- `panic = "abort"` stays in the release profile (`Cargo.toml:64`) — fixes must remove panics, never rely on unwinding.
- No change to the on-disk queue format: segment layout stays `[u32 len][u32 crc][payload]`, `HEADER = 8` (`src/buffer.rs:23`), `cursor.json` shape unchanged (`struct Cursor { seg: u64, off: u64 }`, `src/buffer.rs:25-29`). An agent built from this plan must read queues written by 0.1.1.
- No new dependencies (neither `[dependencies]` nor `[dev-dependencies]`).
- Every task ends with `cargo test --all-targets`, `cargo clippy --all-targets` (no new warnings — CI runs `RUSTFLAGS: -D warnings`), and `cargo fmt --all -- --check` all clean.
- Baseline test count on macOS/Linux: 110 unit + 0 (bin) + 6 e2e = 116 tests. Each task states the new expected count.
- `src/inputs/eventlog.rs` is `#[cfg(windows)]`; none of these tasks touch it. If one does, its only local compile check is `cargo zigbuild --release --target x86_64-pc-windows-gnu` and clippy cannot be run on it locally at all.
- Commit message prefix = the finding id, e.g. `fix(R-3): ...`.
- `full_policy: block` remains the shipped default; nothing here changes queue policy semantics.
- New tests are appended at the **end** of each existing `mod tests` block (immediately before its closing brace) so the line numbers quoted by later tasks stay valid.
- `tempfile` is already a `[dev-dependencies]` entry; temp dirs are made with `tempfile::tempdir()`, matching every existing test in `src/buffer.rs`.

---

## Dependency graph and ordering

```
T1 (R-3 buffer)  ──┐
T2 (R-3 engine)    │   independent of T1
T3 (R-4 peek_batch)├── T3 must land before T6 (T6's spawn_blocking closure calls the 2-arg peek_batch)
T4 (R-4 validate)  │   independent
T5 (R-1 ack)       │   depends on T3 (its tests call the 2-arg peek_batch)
T6 (R-2 BufWriter) ┘   depends on T1 (rewrites the same roll_segment body) and T3 (signature)
T7 (R-5 get_str)  ──┬── independent of T1..T6
T8 (R-5 condition)  │   depends on T7 (uses Event::get_str)
T9 (R-5 mask)      ─┘   depends on T7 (uses Event::get_str)
```

Execution order: **T1 → T2 → T3 → T4 → T5 → T6 → T7 → T8 → T9.** The tree compiles and the full suite passes after every task, not just at the end. Only T3 changes a public signature, and it updates all 16 call sites in the same commit.

**Ruling (task cut for R-1/R-2):** R-1 and R-2 are kept as two adjacent tasks (T5, T6) rather than one, split along the finding boundary so the commit prefixes stay unambiguous. T5 is entirely about the cursor write (`ack` + its two call sites); T6 is entirely about the segment writer and the batch read (`Inner::writer` type + a three-site flush audit + the two `peek_batch` call sites). They have different verification strategies — T5's is a durability/ordering property provable with a two-thread test, T6's is a read-visibility property provable by a single red assertion on `oldest_age_secs` — and mixing them produces one diff that spans both without either test pinning the whole thing. Both are needed for the finding pair to be closed; neither is useful to ship alone, so they are adjacent.

**Ruling R2-A (`push` stays on the async runtime):** the spec's R-2 fix #2 says to move `push`/`peek_batch`/`ack` into `spawn_blocking`. This plan moves only `peek_batch` and `ack`, and deliberately leaves `queue.push(&ev)` (`src/engine.rs:484`) and `queue.push_blocking(&ev, &cancel)` (`src/engine.rs:476`) on the router task. Reasons:
1. Granularity: `run_router` dispatches **one event per iteration**. A `spawn_blocking` per event costs a task allocation plus a blocking-pool handoff and two thread wakeups per event, at up to 10k events/s per destination. Since every one of those blocking tasks then contends on the *same* `DiskQueue` mutex, the blocking pool (default max 512 threads) would only become a thread-shaped queue in front of a lock that already serializes them.
2. `push_blocking` is `async` and owns a `tokio::select!` over `space_notify` / `sleep(250ms)` / `cancel.cancelled()` (`src/buffer.rs:214-227`) that the drain arm of `run_pipeline` depends on for prompt shutdown (`src/engine.rs:529-556`). It cannot be moved into a blocking closure without re-designing cancellation; wrapping only its inner `self.push(ev)?` reintroduces problem (1) once per loop iteration.
3. After T5 and T6 land, the work `push` does under the lock is `crc32fast::hash` + a `memcpy` into an 8 KiB `BufWriter` buffer, with a real `write(2)` only every ~8 KiB and **no `fsync` anywhere** — microseconds, not the 5-10 ms `fsync` that R-1 identified as the actual contention. `serde_json::to_vec(ev)` already happens *before* the lock (`src/buffer.rs:155`).
4. `run_router` is one task per destination whose only job is pushing; briefly blocking it does not starve other destinations (they each have their own router task). The harm R-2 describes is holding the *shared* mutex while blocked on I/O, which T5 and T6 remove.
Alternative considered and rejected: batch N events inside `run_router` and dispatch one `spawn_blocking` per batch. Rejected as out of scope — it changes `push_blocking`'s full-policy and cancellation semantics and the `run_pipeline` drain contract, i.e. a redesign rather than a fix.

**Ruling R2-B (`peek_batch`'s flush stays best-effort):** `peek_batch` keeps `w.flush().ok()` (`src/buffer.rs:233-235`) rather than propagating the error. Once `writer` is a `BufWriter`, a failing flush means some appended records are not yet on disk — but there may still be megabytes of readable records already on disk, and returning `Err` would make the worker sleep 1 s and read *nothing*, i.e. stop draining the queue exactly when the disk is in trouble. Reader-always-makes-progress is the invariant this file is built on (see the doc comments at `src/buffer.rs:515-524` and `src/outputs/worker.rs:91-97`). The swallow is documented in code.

**Ruling R1-A (segment unlink stays under the lock):** `ack`'s `std::fs::remove_file` loop (`src/buffer.rs:295-302`) stays inside the critical section. It is an `unlink(2)` with no `fsync`, it only runs when a segment is fully consumed (every ~8 MB, not every batch), and moving it out would require snapshotting paths and re-acquiring the lock to fix up `inner.bytes`/`inner.segments`. Only the `write_atomic` (two `fsync`s, the thing R-1 measured) moves out.

**Ruling R3-A (rate-limit counter type):** `route_event` uses `Arc<AtomicU64>` for its shed counter (`src/engine.rs:638`) because that counter is *also* read by `/metrics` through `EngineShared::router_shed`. `run_router`'s queue-write-error counter has no external reader and lives in a single-task loop, so it is a plain local `u64` with the identical `n % 100 == 1` throttle. The throttle predicate is extracted as a pure function so it is unit-testable without a wedged disk, matching the pattern established by commit e61a811 ("extract fix decisions into pure, unit-tested helpers").

**Ruling R4-A (`stdout::frame_batch` is not modified):** the spec lists `src/outputs/stdout.rs:41-57`'s second full copy under R-4's *Where*, but its suggested fix does not touch it. `frame_batch(events, ..)` (`src/outputs/stdout.rs:41`) builds a `Vec<u8>` proportional to the batch it is handed, so bounding `peek_batch` to `PEEK_MAX_BYTES` transitively bounds `frame_batch`'s payload to ~8 MiB + one record instead of ~200 MB. No change to `stdout.rs`.

**Ruling R5-A (`mask` is in scope):** the spec lists `src/pipeline/transform.rs:143-146`'s triple copy under R-5. It is included (T9) because the change is one match arm, keeps an exact fallback to the current owned-`Value` path for non-string fields, and `mask` on `message` is precisely the config the spec names as the trigger.

**Ruling TDD-A (two tasks have no red test):** T5's cursor-write-outside-the-lock change and T6's `BufWriter` change are, at the level of the public API, refactors. Where no red test exists, the plan says so and states the truthful expected result of the verification run instead of inventing a failure. T6 still gets a genuine red-then-green cycle by ordering the type change before the flush audit (the `oldest_age_secs` assertion fails in between). T5's tests are stated as regression nets that pass before and after; their job is to fail if the lock scoping is done wrong.

---

### Task 1: R-3 — create the next segment before advancing the write cursor

**Files:**
- Modify: `src/buffer.rs` — `push`'s lazy writer open, lines 180-185; `roll_segment`, lines 423-433; new tests appended at the end of `mod tests`, before the closing brace at line 792.

**Interfaces:**
- Consumes: `DiskQueue::open(base_dir: &std::path::Path, id: &str, cfg: &BufferConfig) -> Result<Arc<Self>>` (`src/buffer.rs:73`); `DiskQueue::push(&self, ev: &Event) -> Result<PushOutcome>` (`src/buffer.rs:154`); `DiskQueue::len(&self) -> u64` (`src/buffer.rs:318`); `Event::new(source: &str, source_type: &str, raw: &str) -> Self` (`src/event.rs:36`); `BufferConfig { dir: Option<PathBuf>, max_size_mb: u64, segment_size_mb: u64, full_policy: FullPolicy }` (`src/config/schema.rs:425-437`); the test helpers `fn cfg(max_mb: u64, policy: FullPolicy) -> BufferConfig` (`src/buffer.rs:560`) and `fn ev(n: usize) -> Event` (`src/buffer.rs:569`), which set `segment_size_mb: 1`.
- Produces: no signature changes. `fn roll_segment(inner: &mut Inner) -> Result<()>` keeps its signature; the append open inside `push` gains `.create(true)` and an error context.

- [ ] **Step 1: Write the two failing tests.**
      Append to the end of `mod tests` in `src/buffer.rs`, immediately before the module's closing brace (currently line 792):

```rust
    /// R-3: `roll_segment` used to increment `write_seg` *before* the fallible
    /// `File::create`, so one transient failure at a segment boundary left the
    /// write cursor pointing at a segment file that nothing would ever create.
    /// Every later `push` then returned `NotFound` forever, even after the
    /// original fault cleared, and `run_router` turned into a per-event
    /// `format!` + mutex loop while silently dropping every event.
    #[test]
    #[cfg(unix)]
    fn a_transient_segment_create_failure_does_not_wedge_the_queue() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(64, FullPolicy::Block)).unwrap();
        let qdir = dir.path().join("d1");
        // `cfg()` sets segment_size_mb: 1. Five ~205 KB records leave seg 0 at
        // ~1_025_670 bytes, just under the 1 MiB rollover threshold, so the
        // sixth push is the one that rolls.
        let big = "y".repeat(200 * 1024);
        for _ in 0..5 {
            assert!(matches!(
                q.push(&Event::new("t", "raw", &big)).unwrap(),
                PushOutcome::Stored { .. }
            ));
        }

        // Make the queue directory unwritable so the rollover's File::create
        // fails. Writes to the already-open segment fd are unaffected.
        let orig = std::fs::metadata(&qdir).unwrap().permissions();
        let mut ro = orig.clone();
        ro.set_mode(0o500);
        std::fs::set_permissions(&qdir, ro).unwrap();

        // Directory permissions are not enforced for uid 0; in a container that
        // runs tests as root there is nothing to reproduce.
        let probe = qdir.join(".probe");
        if std::fs::File::create(&probe).is_ok() {
            std::fs::remove_file(&probe).ok();
            std::fs::set_permissions(&qdir, orig).unwrap();
            eprintln!("skipping: directory permissions are not enforced for this user");
            return;
        }

        let boundary = q.push(&Event::new("t", "raw", &big));
        // Restore before asserting so a failure cannot leave an undeletable dir.
        std::fs::set_permissions(&qdir, orig).unwrap();
        assert!(
            boundary.is_err(),
            "the rollover must fail while the queue directory is read-only"
        );

        // The transient fault has cleared: pushes must work again.
        assert!(
            matches!(
                q.push(&Event::new("t", "raw", &big)).unwrap(),
                PushOutcome::Stored { .. }
            ),
            "queue stayed wedged after the fault cleared"
        );
        // 5 + the boundary push (whose write succeeded; only the roll failed)
        // + the recovery push.
        assert_eq!(q.len(), 7);
        let mut segs: Vec<String> = std::fs::read_dir(&qdir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".seg"))
            .collect();
        segs.sort();
        assert_eq!(
            segs,
            vec![
                "00000000000000000000.seg".to_string(),
                "00000000000000000001.seg".to_string()
            ],
            "recovery must roll into the next segment, not skip one"
        );
    }

    /// R-3, upgrade path: a queue already wedged by 0.1.1 has a write segment
    /// index whose file does not exist. `OpenOptions::append(true)` without
    /// `.create(true)` returns NotFound for that forever, so the append open
    /// must be self-healing or upgrading the agent does not un-wedge the queue.
    #[test]
    fn a_queue_whose_write_segment_file_is_missing_recreates_it() {
        let dir = tempfile::tempdir().unwrap();
        let qdir = dir.path().join("d1");
        {
            let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
            q.push(&ev(0)).unwrap();
        }
        // Reproduce the 0.1.1 wedge exactly: write_seg points at segment 1,
        // whose file is gone.
        std::fs::File::create(qdir.join("00000000000000000001.seg")).unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
        std::fs::remove_file(qdir.join("00000000000000000001.seg")).unwrap();

        assert!(
            matches!(q.push(&ev(1)).unwrap(), PushOutcome::Stored { .. }),
            "push must recreate the missing write segment instead of failing"
        );
        assert!(qdir.join("00000000000000000001.seg").exists());
        assert_eq!(q.len(), 2);
    }
```

- [ ] **Step 2: Run the tests and confirm both fail.**
      `cargo test --lib buffer::tests::a_transient_segment_create_failure_does_not_wedge_the_queue buffer::tests::a_queue_whose_write_segment_file_is_missing_recreates_it`
      Expected failure, both tests, both a panic on `Result::unwrap()`:
      - `a_transient_segment_create_failure_does_not_wedge_the_queue`: `called Result::unwrap() on an Err value: No such file or directory (os error 2)` at the recovery `q.push(...).unwrap()`. The boundary push already advanced `write_seg` to 1 without creating `00000000000000000001.seg`, so the recovery push's `OpenOptions::new().append(true).open(...)` returns `NotFound`.
      - `a_queue_whose_write_segment_file_is_missing_recreates_it`: `called Result::unwrap() on an Err value: No such file or directory (os error 2)` at `q.push(&ev(1)).unwrap()`, for the same missing-`.create(true)` reason.

- [ ] **Step 3: Make the lazy writer open self-healing.**
      In `src/buffer.rs`, replace lines 180-185:

```rust
        if inner.writer.is_none() {
            let f = OpenOptions::new()
                .append(true)
                .open(seg_path(&inner.dir, inner.write_seg))?;
            inner.writer = Some(f);
        }
```

      with:

```rust
        if inner.writer.is_none() {
            let path = seg_path(&inner.dir, inner.write_seg);
            // `.create(true)` is deliberate belt-and-braces for R-3: if the
            // write segment's file is missing for any reason — including a
            // queue left wedged by an older build, which advanced `write_seg`
            // before the fallible `File::create` — `append(true)` alone
            // returns NotFound from every push forever. Recreating it costs
            // nothing in the normal case (the file exists) and turns a
            // permanent wedge into a self-healing gap.
            let f = OpenOptions::new()
                .append(true)
                .create(true)
                .open(&path)
                .with_context(|| format!("cannot open queue segment {}", path.display()))?;
            inner.writer = Some(f);
        }
```

- [ ] **Step 4: Reorder `roll_segment` so state is mutated only after the fallible call.**
      In `src/buffer.rs`, replace lines 423-433:

```rust
fn roll_segment(inner: &mut Inner) -> Result<()> {
    if let Some(w) = inner.writer.take() {
        drop(w);
    }
    inner.write_seg += 1;
    inner.write_off = 0;
    File::create(seg_path(&inner.dir, inner.write_seg))?;
    let seg = inner.write_seg;
    inner.segments.insert(seg);
    Ok(())
}
```

      with:

```rust
/// Advance the write cursor to a fresh segment.
///
/// Every fallible step happens **before** any state is mutated: the old code
/// incremented `write_seg` first, so a single transient `File::create` failure
/// (EMFILE, inode exhaustion, a momentarily unwritable queue directory, an
/// antivirus lock on Windows) left the write cursor pointing at a file that
/// nothing would ever create, and every subsequent `push` failed forever. On
/// failure here the caller's state is untouched, so the next `push` reopens
/// the current segment and appends to it as normal.
fn roll_segment(inner: &mut Inner) -> Result<()> {
    if let Some(w) = inner.writer.take() {
        drop(w);
    }
    let next = inner.write_seg + 1;
    let path = seg_path(&inner.dir, next);
    File::create(&path)
        .with_context(|| format!("cannot create queue segment {}", path.display()))?;
    inner.write_seg = next;
    inner.write_off = 0;
    inner.segments.insert(next);
    Ok(())
}
```

- [ ] **Step 5: Run the tests and confirm they pass.**
      `cargo test --lib buffer::` — expected: all `buffer::tests` pass, including the two new ones. Then `cargo test --all-targets` — expected `112 passed` for the lib target (110 baseline + 2), `0` for the bin target, `6` e2e; **118 total**.
      Then `cargo clippy --all-targets` — expected: clean, no new warnings. Then `cargo fmt --all -- --check` — expected: clean.

- [ ] **Step 6: Commit.**

```
fix(R-3): create the next segment before advancing the write cursor

roll_segment incremented inner.write_seg and zeroed inner.write_off before
calling File::create, so one transient failure at a segment boundary
(EMFILE, inode exhaustion, a momentarily unwritable queue directory, an
antivirus lock on Windows) left the write cursor pointing at a segment file
that nothing would ever create. Because the lazy append open used
OpenOptions::append(true) without .create(true), every subsequent push then
returned NotFound forever — even after the original fault cleared — turning
run_router into a per-event format! + mutex loop that silently dropped
every event while /healthz still reported ok (is_full() looks at `bytes`,
which never grows).

Do the fallible work first: create the next segment file, and only then
move write_seg/write_off/segments. On failure the queue's state is
untouched, so the next push reopens the current segment and appends.

Independently, add .create(true) to the append open. That is the upgrade
path: a queue already wedged by 0.1.1 has a write segment index whose file
does not exist, and without .create(true) installing a fixed agent does not
un-wedge it.

Two tests: a unix-only reproduction that chmods the queue directory to 0500
across a segment boundary, restores it, and asserts the next push succeeds
(it returned NotFound forever before); and a cross-platform test that
constructs the already-wedged on-disk state directly and asserts push
recreates the missing segment file.
```

---

### Task 2: R-3 — rate-limit `run_router`'s queue-write error path

**Files:**
- Modify: `src/engine.rs` — add a module-level constant and pure helper next to `ROUTER_CAPACITY` (after line 50); `run_router`, lines 466-503 (the `Err(e)` arm is lines 498-500); new test appended at the end of `mod tests` (module starts at line 654, ends at the last line of the file, line 1018).

**Interfaces:**
- Consumes: `Metrics::record_error(&self, msg: impl Into<String>)` (`src/metrics.rs:24`), which increments `self.errors` **and** overwrites `self.last_error`; the public fields `Metrics::errors: AtomicU64` and `Metrics::events_dropped: AtomicU64` (`src/metrics.rs:11-16`); the throttle idiom at `src/engine.rs:638-645` (`let n = shed.fetch_add(1, Ordering::Relaxed) + 1; if n % 100 == 1 { tracing::warn!(..) }`).
- Produces: `const WRITE_ERROR_LOG_EVERY: u64 = 100;` and `fn should_log_write_error(n: u64) -> bool` (private to `src/engine.rs`).

- [ ] **Step 1: Write the failing test.**
      Append to the end of `mod tests` in `src/engine.rs`, immediately before the module's closing brace:

```rust
    /// R-3: a failing queue hits `run_router`'s Err arm once per event, and
    /// `Metrics::record_error` allocates a String and takes a mutex each time.
    /// The throttle is a pure function so it can be pinned without a wedged
    /// disk; it must match the every-100th cadence `route_event` already uses
    /// for its shed log.
    #[test]
    fn queue_write_errors_are_logged_every_hundredth_occurrence() {
        assert!(
            should_log_write_error(1),
            "the first failure must always produce a message"
        );
        for n in 2..=100 {
            assert!(!should_log_write_error(n), "occurrence {n} must be silent");
        }
        assert!(should_log_write_error(101));
        assert!(!should_log_write_error(102));
        assert_eq!(
            (1..=1000).filter(|&n| should_log_write_error(n)).count(),
            10,
            "1000 failures must produce exactly 10 messages"
        );
    }
```

- [ ] **Step 2: Run the test and confirm it fails.**
      `cargo test --lib engine::tests::queue_write_errors_are_logged_every_hundredth_occurrence`
      Expected failure: a compile error, `error[E0425]: cannot find function should_log_write_error in this scope`, reported at each of the five call sites in the new test.

- [ ] **Step 3: Add the constant and the pure helper.**
      In `src/engine.rs`, insert after line 50 (`const ROUTER_CAPACITY: usize = 4096;`):

```rust
/// How often `run_router` may materialise a queue-write error message.
///
/// A queue that cannot be written fails for *every* event, and
/// `Metrics::record_error` allocates a `String` and takes a
/// `Mutex<Option<String>>` on each call — at full input rate that is the hot
/// loop R-3 describes. Only every hundredth occurrence gets a message; the
/// `errors` counter is still bumped for every one, so `/metrics` does not
/// under-report. Same cadence as `route_event`'s shed log.
const WRITE_ERROR_LOG_EVERY: u64 = 100;

/// True when the `n`-th (1-based) queue-write failure should produce a
/// message rather than just a counter bump. Pure, so the throttle is testable
/// without a wedged disk.
fn should_log_write_error(n: u64) -> bool {
    n % WRITE_ERROR_LOG_EVERY == 1
}
```

- [ ] **Step 4: Apply the throttle in `run_router`.**
      In `src/engine.rs`, replace line 474 (`    while let Some(ev) = rx.recv().await {`) with:

```rust
    // Consecutive queue-write failures, for the message throttle below. A
    // plain local counter, not the `Arc<AtomicU64>` `route_event` uses for
    // its shed count: that one is also read by /metrics through
    // EngineShared::router_shed, while this one has no reader outside this
    // single-task loop.
    let mut write_errors: u64 = 0;

    while let Some(ev) = rx.recv().await {
```

      and replace lines 498-500:

```rust
            Err(e) => {
                metrics.record_error(format!("queue {} write: {e}", out.id));
            }
```

      with:

```rust
            Err(e) => {
                // The event is gone: it reached neither the queue nor any
                // counter before, so a wedged queue lost traffic completely
                // silently while /healthz still reported ok.
                metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                write_errors += 1;
                if should_log_write_error(write_errors) {
                    metrics.record_error(format!(
                        "queue {} write: {e} (occurrence {write_errors}; logged every {WRITE_ERROR_LOG_EVERY}th)"
                    ));
                } else {
                    // record_error bumps `errors` itself; keep the counter
                    // exact on the throttled path too.
                    metrics.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
```

- [ ] **Step 5: Run and confirm.**
      `cargo test --lib engine::` — expected: all `engine::tests` pass including the new one. `cargo test --all-targets` — expected **119 total** (113 lib + 0 bin + 6 e2e).
      `cargo clippy --all-targets` — expected clean. `cargo fmt --all -- --check` — expected clean.

- [ ] **Step 6: Commit.**

```
fix(R-3): rate-limit run_router's queue-write error path and count the loss

When a destination's queue cannot be written, run_router hit
metrics.record_error() once per event — a String allocation plus a
Mutex<Option<String>> acquire at full input rate — while the events
themselves were neither queued nor counted anywhere, so the loss was
invisible on the Overview page and /healthz still reported ok.

Throttle the message to every 100th consecutive failure, the same cadence
route_event already applies to its per-destination shed log, and keep the
`errors` counter exact by bumping it directly on the throttled path
(record_error increments it itself on the logged path). Count each failed
push in events_dropped so the loss is visible: the event has reached
neither the queue nor any other counter by that point. This can over-count
by one when a push's write succeeded and only its rollover failed, which is
a far better trade than under-counting by one per event for the duration of
an outage.

The throttle predicate is a pure function with a unit test, so the cadence
is pinned without needing a wedged disk.
```

---

### Task 3: R-4 — bound `peek_batch` by bytes as well as by count

**Files:**
- Modify: `src/buffer.rs` — `peek_batch`, lines 229-279; every call in `mod tests` (14 sites: lines 584, 589, 599, 602, 615, 621, 662, 675, 707, 714, 735, 745, 778, 788), plus a new `TEST_PEEK_BYTES` const and two new tests appended at the end of `mod tests`. Task 1's two new tests do not call `peek_batch`, so those 14 line numbers are still current.
- Modify: `src/outputs/worker.rs` — add `PEEK_MAX_BYTES` next to `UNHEALTHY_AFTER` (line 10); the two calls at lines 90 and 169.

**Interfaces:**
- Consumes: `RecordRead::Ok { payload: Vec<u8>, rec_len: u64 }` (`src/buffer.rs:502-506`); `read_record(f: &mut File, max_believable_len: u64) -> Result<RecordRead>` (`src/buffer.rs:525`); `RetryConfig { initial_backoff_ms: u64, max_backoff_ms: u64, batch_size: usize }` (`src/config/schema.rs:484-492`).
- Produces: `pub fn peek_batch(&self, max: usize, max_bytes: usize) -> Result<Vec<Event>>` — replaces `pub fn peek_batch(&self, max: usize) -> Result<Vec<Event>>`. This is the signature every later task uses.
  `const PEEK_MAX_BYTES: usize = 8 * 1024 * 1024;` in `src/outputs/worker.rs`.
- Invariant produced: **`peek_batch` returns at least one event whenever at least one decodable record is readable from the peek position and `max >= 1`, regardless of `max_bytes`.** A single record larger than `max_bytes` is therefore returned on its own and can never wedge the reader.
- Byte-accounting rule: the accumulator counts `rec_len`, i.e. **on-disk record bytes** (`HEADER + payload.len()`), the same quantity `push` adds to `inner.bytes`. A record is refused when `peeked_bytes + rec_len > max_bytes` **and** `out` is not empty; a refused record does not advance `off`, so the next call re-reads it.

- [ ] **Step 1: Write the failing tests.**
      Append to the end of `mod tests` in `src/buffer.rs`, immediately before the module's closing brace. Add the shared constant at the **top** of the module, immediately after `use crate::event::Event;` (line 558):

```rust
    /// A byte budget large enough never to bind in tests that are exercising
    /// something other than the budget itself.
    const TEST_PEEK_BYTES: usize = 64 * 1024 * 1024;
```

      and the two tests at the end of the module:

```rust
    /// R-4: `peek_batch` was bounded by event count only, so with the default
    /// batch_size 200 and file-input events up to 4 MiB each, a batch could
    /// reach ~200 MB in RAM (and `frame_batch` another ~200 MB alongside it)
    /// against an advertised ~12 MB footprint.
    #[test]
    fn peek_batch_stops_at_the_byte_budget() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(64, FullPolicy::Block)).unwrap();
        let big = "b".repeat(64 * 1024);
        for i in 0..10 {
            assert!(matches!(
                q.push(&Event::new("t", "raw", &format!("{i}{big}"))).unwrap(),
                PushOutcome::Stored { .. }
            ));
        }

        // Each record is ~65.7 KB on disk: a 65_537-byte body, ~180 bytes of
        // JSON envelope (two rfc3339 timestamps, source, source_type,
        // collector_version; every Option field is skipped when None) and the
        // 8-byte header. With a 150_000-byte budget two fit (~131.4 KB) and
        // the third does not (~197.1 KB), leaving ~18 KB
        // of margin on the accept side and ~47 KB on the reject side, so the
        // exact count below does not depend on the envelope's exact size.
        const BUDGET: usize = 150_000;
        let first = q.peek_batch(10, BUDGET).unwrap();
        assert!(
            !first.is_empty() && first.len() < 10,
            "byte budget must bind before the count budget, got {}",
            first.len()
        );
        assert_eq!(first.len(), 2, "two ~66 KB records fit in 150 000 bytes");
        assert!(first[0].message.starts_with('0'));
        assert!(first[1].message.starts_with('1'));

        // The refused record is not consumed: the next call starts there, so
        // nothing is lost and nothing is skipped.
        let second = q.peek_batch(10, BUDGET).unwrap();
        assert_eq!(second.len(), 2);
        assert!(second[0].message.starts_with('2'));

        // Draining with a generous budget still yields the rest in order.
        let rest = q.peek_batch(100, TEST_PEEK_BYTES).unwrap();
        assert_eq!(rest.len(), 6);
        assert!(rest[0].message.starts_with('4'));
        assert!(rest[5].message.starts_with('9'));
    }

    /// R-4 invariant: the budget must never produce an empty batch when a
    /// record is readable. An oversized record that was refused forever would
    /// pin the peek offset and spin the output worker's empty-batch floor at
    /// 10 Hz for the life of the process.
    #[test]
    fn peek_batch_always_returns_one_record_even_when_it_exceeds_the_budget() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(64, FullPolicy::Block)).unwrap();
        let huge = "z".repeat(2 * 1024 * 1024);
        q.push(&Event::new("t", "raw", &huge)).unwrap();
        q.push(&ev(1)).unwrap();

        let batch = q.peek_batch(10, 1024).unwrap();
        assert_eq!(
            batch.len(),
            1,
            "a record larger than max_bytes must still be returned, alone"
        );
        assert_eq!(batch[0].message, huge);

        // And the offset advanced past it, so the reader makes progress.
        q.ack(1).unwrap();
        let next = q.peek_batch(10, 1024).unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].message, "event number 1");
    }
```

- [ ] **Step 2: Run the tests and confirm they fail.**
      `cargo test --lib buffer::tests::peek_batch_stops_at_the_byte_budget buffer::tests::peek_batch_always_returns_one_record_even_when_it_exceeds_the_budget`
      Expected failure: a compile error, `error[E0061]: this method takes 1 argument but 2 arguments were supplied`, pointing at `q.peek_batch(10, BUDGET)` and every other two-argument call in the new tests, with the note `method peek_batch defined here` at `src/buffer.rs:230`.

- [ ] **Step 3: Add the byte budget to `peek_batch`.**
      In `src/buffer.rs`, replace lines 229-279 with:

```rust
    /// Read up to `max` events, and at most `max_bytes` of on-disk record
    /// bytes, from the in-memory peek position.
    ///
    /// `max` alone is not a memory bound: event bodies are capped per event
    /// (1 MiB per line, up to a 4 MiB unterminated read from a file input) but
    /// not per batch, so a count-only limit let the default `batch_size: 200`
    /// materialise ~200 MB of `Event`s in one call — and the output sink then
    /// builds a second, equally large wire payload from it while the batch is
    /// still alive.
    ///
    /// `max_bytes` counts `rec_len` (`HEADER + payload`), the same quantity
    /// `push` adds to `inner.bytes`. A record that would take the running
    /// total over the budget is left unconsumed for the next call.
    ///
    /// Invariant: **at least one event is returned whenever one is readable**
    /// (for `max >= 1`), whatever `max_bytes` is. A single record bigger than
    /// the budget is returned on its own rather than refused forever, which
    /// would pin the peek offset and spin the worker's empty-batch floor.
    pub fn peek_batch(&self, max: usize, max_bytes: usize) -> Result<Vec<Event>> {
        let mut inner = self.inner.lock().unwrap();
        // Make appended-but-buffered data visible to the reader.
        if let Some(w) = inner.writer.as_mut() {
            w.flush().ok();
        }
        let mut out = Vec::new();
        let mut peeked_bytes: usize = 0;
        // Set when the byte budget refuses a record, so both loops unwind
        // without advancing `pos` past a record that was not consumed.
        let mut budget_hit = false;
        let mut pos = inner.peek;
        let segs: Vec<u64> = inner.segments.range(pos.seg..).copied().collect();
        for seg in segs {
            if out.len() >= max || budget_hit {
                break;
            }
            let start = if seg == pos.seg { pos.off } else { 0 };
            let path = seg_path(&inner.dir, seg);
            let mut f = File::open(&path)?;
            // Bound the length check on the file's actual size, not the
            // configured segment size — a legitimate record can exceed
            // `segment_size_mb` (see `read_record`'s doc comment).
            let file_len = f.metadata()?.len();
            f.seek(SeekFrom::Start(start))?;
            let mut off = start;
            loop {
                if out.len() >= max {
                    break;
                }
                match read_record(&mut f, file_len)? {
                    RecordRead::Ok { payload, rec_len } => {
                        // Stop before taking a record that would push the
                        // batch over the byte budget — but never return an
                        // empty batch just because the next record is
                        // oversized, or the peek offset would never advance.
                        if !out.is_empty()
                            && peeked_bytes.saturating_add(rec_len as usize) > max_bytes
                        {
                            budget_hit = true;
                            break;
                        }
                        off += rec_len;
                        peeked_bytes = peeked_bytes.saturating_add(rec_len as usize);
                        match serde_json::from_slice::<Event>(&payload) {
                            Ok(ev) => out.push(ev),
                            Err(e) => {
                                self.corrupt.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(queue = %self.id, "skipping undecodable queue record: {e}");
                            }
                        }
                    }
                    RecordRead::Corrupt { skip } => {
                        off += skip;
                        self.corrupt.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(queue = %self.id, skip, "skipping CRC-failed queue record");
                    }
                    RecordRead::Eof => break,
                }
            }
            pos = Cursor { seg, off };
        }
        inner.peek = pos;
        Ok(out)
    }
```

- [ ] **Step 4: Update all 14 existing `peek_batch` calls in `src/buffer.rs`'s `mod tests`.**
      Every one keeps its current `max` and gains `TEST_PEEK_BYTES`:
      - line 584: `let batch = q.peek_batch(4, TEST_PEEK_BYTES).unwrap();`
      - line 589: `let batch = q.peek_batch(100, TEST_PEEK_BYTES).unwrap();`
      - line 599: `let b1 = q.peek_batch(10, TEST_PEEK_BYTES).unwrap();`
      - line 602: `let b2 = q.peek_batch(10, TEST_PEEK_BYTES).unwrap();`
      - line 615: `q.peek_batch(2, TEST_PEEK_BYTES).unwrap();`
      - line 621: `let batch = q.peek_batch(10, TEST_PEEK_BYTES).unwrap();`
      - line 662: `let batch = q.peek_batch(5, TEST_PEEK_BYTES).unwrap();`
      - line 675: `let batch = q.peek_batch(100, TEST_PEEK_BYTES).unwrap();`
      - line 707: `let batch = q.peek_batch(10, TEST_PEEK_BYTES).unwrap();`
      - line 714: `assert!(q.peek_batch(10, TEST_PEEK_BYTES).unwrap().is_empty());`
      - line 735: `let batch = q.peek_batch(10, TEST_PEEK_BYTES).unwrap();`
      - line 745: `assert!(q.peek_batch(10, TEST_PEEK_BYTES).unwrap().is_empty());`
      - line 778: `let batch = q.peek_batch(10, TEST_PEEK_BYTES).unwrap();`
      - line 788: `q2.peek_batch(10, TEST_PEEK_BYTES).unwrap().is_empty(),`
      Verify with `grep -n "peek_batch(" src/buffer.rs` — every hit must have two arguments except the definition.

- [ ] **Step 5: Update the two `peek_batch` calls in `src/outputs/worker.rs`.**
      Insert after line 10 (`const UNHEALTHY_AFTER: u64 = 3;`):

```rust
/// Per-batch byte budget handed to `DiskQueue::peek_batch`.
///
/// `retry.batch_size` bounds a batch by event *count*, which is not a memory
/// bound: a file input can emit events up to 4 MiB each, so the default 200
/// events could materialise ~200 MB of `Event`s here plus a second, equally
/// large wire payload in `frame_batch`. 8 MiB is comfortably above any
/// realistic batch of syslog-sized events and two orders of magnitude below
/// the worst case it removes.
const PEEK_MAX_BYTES: usize = 8 * 1024 * 1024;
```

      Replace line 90:

```rust
            let batch = match self.queue.peek_batch(self.retry.batch_size) {
```

      with:

```rust
            let batch = match self.queue.peek_batch(self.retry.batch_size, PEEK_MAX_BYTES) {
```

      Replace line 169:

```rust
        if let Ok(batch) = self.queue.peek_batch(self.retry.batch_size) {
```

      with:

```rust
        if let Ok(batch) = self
            .queue
            .peek_batch(self.retry.batch_size, PEEK_MAX_BYTES)
        {
```

- [ ] **Step 6: Run and confirm.**
      `cargo test --all-targets` — expected **121 total** (115 lib + 0 bin + 6 e2e), all passing. In particular `buffer::tests::peek_batch_returns_a_record_larger_than_the_configured_segment_size` (which pushes a 2 MiB record and peeks with `TEST_PEEK_BYTES`) and `outputs::tests::a_custom_sink_receives_every_queued_event` must still pass, and the e2e `a_backed_up_destination_does_not_stop_its_peers` must still pass (its queue cap is 2 MiB, well under the 8 MiB budget, so the budget never binds there).
      `cargo clippy --all-targets` — expected clean. `cargo fmt --all -- --check` — expected clean.

- [ ] **Step 7: Commit.**

```
fix(R-4): bound peek_batch by bytes as well as by event count

peek_batch(max) bounded a batch by event count only. Event bodies are
capped per event but not per batch — src/inputs/file.rs allows a 1 MiB line
and can emit an unterminated line up to the 4 MiB read budget — so the
default retry.batch_size: 200 could materialise ~200 MB of Events in one
call, with frame_batch building a second, equally large Vec<u8> alongside it
while the batch is still alive. The CHANNEL_BYTES semaphore does not cover
any of this: it gates the input->pipeline channel, and this memory is
allocated downstream of the disk queue.

peek_batch now takes max_bytes and accumulates rec_len (HEADER + payload,
the same quantity push adds to inner.bytes), refusing a record that would
take the batch over budget without advancing the peek offset past it. The
output worker passes 8 MiB.

The invariant that matters: at least one event is always returned when one
is readable, so a single record larger than the budget is returned on its
own instead of being refused forever — which would pin the peek offset and
spin the worker's empty-batch floor at 10 Hz for the life of the process.
Both properties are tested.

Signature change only; the on-disk format is untouched.
```

---

### Task 4: R-4 — put an upper bound on `retry.batch_size`

**Files:**
- Modify: `src/config/validate.rs` — the retry check at lines 220-222; new test appended at the end of `mod tests` (module starts at line 337).

**Interfaces:**
- Consumes: `parse(yaml: &str)` re-exported as `crate::config::parse` and used by every existing test in this module (`src/config/validate.rs:339`); `bail!` from `anyhow` (already imported, `src/config/validate.rs:5`); `RetryConfig::batch_size: usize` (`src/config/schema.rs:491`).
- Produces: no signature changes; one additional `bail!` branch inside `pub fn validate(cfg: &Config) -> Result<Vec<String>>` (`src/config/validate.rs:11`).

- [ ] **Step 1: Write the failing test.**
      Append to the end of `mod tests` in `src/config/validate.rs`, immediately before the module's closing brace:

```rust
    /// R-4: `retry.batch_size` had a lower bound but no upper bound, so
    /// `100000` was accepted and would OOM the agent on its first flush
    /// (peek_batch's byte budget caps one batch's bytes, but nothing capped
    /// the Vec<Event> length itself).
    #[test]
    fn rejects_an_absurd_batch_size() {
        let yaml = r#"
inputs:
  syslog:
    - id: rsyslog
      protocol: udp
      port: 5514
outputs:
  - id: console
    type: stdout
    retry:
      batch_size: 100000
"#;
        let err = parse(yaml).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("console"), "expected output id in error: {msg}");
        assert!(
            msg.contains("batch_size"),
            "expected field name in error: {msg}"
        );
    }

    #[test]
    fn accepts_a_batch_size_at_the_upper_bound() {
        let yaml = r#"
inputs:
  syslog:
    - id: rsyslog
      protocol: udp
      port: 5514
outputs:
  - id: console
    type: stdout
    retry:
      batch_size: 10000
"#;
        let (cfg, _w) = parse(yaml).unwrap();
        assert_eq!(cfg.outputs[0].retry.batch_size, 10_000);
    }
```

- [ ] **Step 2: Run the tests and confirm the first fails.**
      `cargo test --lib config::validate::tests::rejects_an_absurd_batch_size config::validate::tests::accepts_a_batch_size_at_the_upper_bound`
      Expected: `accepts_a_batch_size_at_the_upper_bound` passes (10000 is already accepted); `rejects_an_absurd_batch_size` fails with `called Result::unwrap_err() on an Ok value: (Config { .. }, [])` — validation currently accepts `batch_size: 100000`.

- [ ] **Step 3: Add the upper bound.**
      In `src/config/validate.rs`, replace lines 220-222:

```rust
        if o.retry.batch_size == 0 {
            bail!("outputs[{}]: retry.batch_size must be >= 1", o.id);
        }
```

      with:

```rust
        if o.retry.batch_size == 0 {
            bail!("outputs[{}]: retry.batch_size must be >= 1", o.id);
        }
        // Upper bound, R-4: batch_size is an event count, and a batch's
        // Vec<Event> plus the wire payload built from it both live in RAM at
        // once. peek_batch's byte budget caps the bytes read per batch, but
        // nothing caps the number of Events, so an absurd value still means
        // an absurd allocation. 10_000 is 50x the default.
        if o.retry.batch_size > 10_000 {
            bail!(
                "outputs[{}]: retry.batch_size must be <= 10000 (got {})",
                o.id,
                o.retry.batch_size
            );
        }
```

- [ ] **Step 4: Run and confirm.**
      `cargo test --lib config::` — expected: all pass, including both new tests. `cargo test --all-targets` — expected **123 total** (117 lib + 0 bin + 6 e2e).
      `cargo clippy --all-targets` — expected clean. `cargo fmt --all -- --check` — expected clean.

- [ ] **Step 5: Commit.**

```
fix(R-4): reject retry.batch_size above 10000

The only retry validation was batch_size == 0, so retry.batch_size: 100000
was accepted and would OOM the agent on its first flush. peek_batch's new
byte budget caps the bytes read per batch, but nothing caps the length of
the Vec<Event> itself, and the sink then builds a wire payload from it while
the batch is still alive.

10_000 is 50x the default of 200 and far above any batch size that improves
throughput for either sink in this codebase. Tests cover both the rejection
and the boundary value.
```

---

### Task 5: R-1 — persist the queue cursor outside the queue mutex, and off the runtime

**Files:**
- Modify: `src/buffer.rs` — `ack`, lines 281-310; two new tests appended at the end of `mod tests`.
- Modify: `src/outputs/worker.rs` — the ack in the main loop, lines 121-123; the shutdown-flush ack, line 175.

**Interfaces:**
- Consumes: `crate::fsutil::write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()>` (`src/fsutil.rs:12`), which does `write_all` + `f.sync_all()` + `rename` + a directory `sync_all()`; `DiskQueue::peek_batch(&self, max: usize, max_bytes: usize) -> Result<Vec<Event>>` (from Task 3); `tokio::task::spawn_blocking`.
- Produces: `pub fn ack(&self, acked_events: u64) -> Result<()>` — unchanged signature, changed lock scope. `DiskQueue` is `Send + Sync` (its only interior mutability is `Mutex<Inner>`, two `Notify`s and two `AtomicU64`s), and `anyhow::Error` is `Send + Sync + 'static`, so `move || q.ack(n)` is a valid `spawn_blocking` closure with `Arc<DiskQueue>` moved in.
- **Ruling TDD-A applies:** the lock-scope change has no observable API delta, so the two tests below are regression nets that pass before and after. Their job is to fail if the refactor loses or reorders cursor state. This is stated truthfully in Step 2 rather than dressed up as a red test.

- [ ] **Step 1: Write the tests.**
      Append to the end of `mod tests` in `src/buffer.rs`, immediately before the module's closing brace:

```rust
    /// R-1: `ack` serialises the cursor under the queue mutex but does
    /// `write_atomic`'s two fsyncs outside it, so the router's `push` is no
    /// longer blocked for ~5-10 ms per fsync. The contract must not move: the
    /// cursor is single-consumer (only the output worker's loop calls
    /// `ack`/`reset_peek`, never concurrently with itself), so every pushed
    /// event must still be peeked exactly once, in order, and an acked event
    /// must never be replayed after a reopen.
    #[test]
    fn ack_is_durable_under_concurrent_pushes() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();

        let seen = std::thread::scope(|s| {
            let writer = s.spawn(|| {
                for i in 0..200 {
                    assert!(matches!(
                        q.push(&ev(i)).unwrap(),
                        PushOutcome::Stored { .. }
                    ));
                }
            });
            let reader = s.spawn(|| {
                let mut seen: Vec<String> = Vec::new();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
                while seen.len() < 200 && std::time::Instant::now() < deadline {
                    let batch = q.peek_batch(10, TEST_PEEK_BYTES).unwrap();
                    if batch.is_empty() {
                        std::thread::yield_now();
                        continue;
                    }
                    let n = batch.len() as u64;
                    seen.extend(batch.into_iter().map(|e| e.message));
                    q.ack(n).unwrap();
                }
                seen
            });
            writer.join().unwrap();
            reader.join().unwrap()
        });

        assert_eq!(
            seen.len(),
            200,
            "every pushed event must be peeked exactly once"
        );
        for (i, msg) in seen.iter().enumerate() {
            assert_eq!(msg, &format!("event number {i}"), "order broken at {i}");
        }
        assert_eq!(q.len(), 0);

        drop(q);
        let q2 = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
        assert!(
            q2.peek_batch(1000, TEST_PEEK_BYTES).unwrap().is_empty(),
            "acked events replayed after reopen: the cursor write outside the \
             lock did not persist"
        );
    }

    /// R-1/R-2: the output worker calls both of these from
    /// `tokio::task::spawn_blocking`, which requires `Arc<DiskQueue>` to be
    /// `Send + 'static` and both return types to be `Send`. Pin that so a
    /// later change to `Inner` cannot silently break the call sites.
    #[tokio::test]
    async fn peek_batch_and_ack_are_callable_from_the_blocking_pool() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
        for i in 0..4 {
            q.push(&ev(i)).unwrap();
        }

        let qc = Arc::clone(&q);
        let batch = tokio::task::spawn_blocking(move || qc.peek_batch(10, TEST_PEEK_BYTES))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(batch.len(), 4);

        let qc = Arc::clone(&q);
        let n = batch.len() as u64;
        tokio::task::spawn_blocking(move || qc.ack(n))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(q.len(), 0);
    }
```

- [ ] **Step 2: Run the tests and record the result.**
      `cargo test --lib buffer::tests::ack_is_durable_under_concurrent_pushes buffer::tests::peek_batch_and_ack_are_callable_from_the_blocking_pool`
      Expected result: **both PASS on the unmodified tree.** This is deliberate and is Ruling TDD-A: moving `write_atomic` out of the critical section changes no observable behaviour, and `DiskQueue` is already `Send + Sync`, so no test can be red beforehand. These are regression nets — record the pass, then proceed. Step 5 re-runs them after the change; a mis-scoped cursor write shows up as `acked events replayed after reopen`, and a broken ordering shows up as `order broken at N`.

- [ ] **Step 3: Move the cursor write out of the critical section.**
      In `src/buffer.rs`, replace lines 281-310:

```rust
    /// Confirm delivery of everything peeked so far; persists the cursor and
    /// removes fully-consumed segments.
    pub fn ack(&self, acked_events: u64) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.cursor = inner.peek;
        inner.count = inner.count.saturating_sub(acked_events);

        // Delete segments wholly behind the cursor (never the write segment).
        let done: Vec<u64> = inner
            .segments
            .range(..inner.cursor.seg)
            .copied()
            .filter(|&s| s != inner.write_seg)
            .collect();
        for seg in done {
            let path = seg_path(&inner.dir, seg);
            if let Ok(md) = std::fs::metadata(&path) {
                inner.bytes = inner.bytes.saturating_sub(md.len());
            }
            std::fs::remove_file(&path).ok();
            inner.segments.remove(&seg);
        }

        let cursor_path = inner.dir.join("cursor.json");
        crate::fsutil::write_atomic(&cursor_path, &serde_json::to_vec(&inner.cursor)?)
            .with_context(|| format!("cannot persist queue cursor {}", cursor_path.display()))?;
        drop(inner);
        self.space_notify.notify_waiters();
        Ok(())
    }
```

      with:

```rust
    /// Confirm delivery of everything peeked so far; persists the cursor and
    /// removes fully-consumed segments.
    ///
    /// The cursor is *serialised* under the queue mutex but *written* outside
    /// it. `write_atomic` does two `fsync`s (the temp file, then the parent
    /// directory), and at the default `retry.batch_size: 200` and a few
    /// thousand events/s that is ~100 fsyncs/s with the mutex held — on a
    /// consumer SSD, 50-100% of wall-clock time. `run_router`'s `push` takes
    /// the same mutex, so that, not "brief lock contention", is what
    /// `ROUTER_CAPACITY` and the `router_shed` counter were absorbing.
    ///
    /// Releasing the lock across the write is safe because the cursor is
    /// single-consumer: only `OutputWorker::run`'s loop calls `ack` and
    /// `reset_peek`, and never concurrently with itself. The one other writer
    /// of `inner.cursor` is `drop_oldest_segment`, which can only move it
    /// *forward* past segments it has just deleted; a cursor persisted from
    /// before such a move points at a deleted segment, which `open()` already
    /// clamps to the next surviving one (see the clamp at the top of `open`).
    /// The unlink loop stays inside the lock: it is `unlink(2)` with no fsync
    /// and only runs when a whole segment has been consumed.
    pub fn ack(&self, acked_events: u64) -> Result<()> {
        let (cursor_path, bytes) = {
            let mut inner = self.inner.lock().unwrap();
            inner.cursor = inner.peek;
            inner.count = inner.count.saturating_sub(acked_events);

            // Delete segments wholly behind the cursor (never the write segment).
            let done: Vec<u64> = inner
                .segments
                .range(..inner.cursor.seg)
                .copied()
                .filter(|&s| s != inner.write_seg)
                .collect();
            for seg in done {
                let path = seg_path(&inner.dir, seg);
                if let Ok(md) = std::fs::metadata(&path) {
                    inner.bytes = inner.bytes.saturating_sub(md.len());
                }
                std::fs::remove_file(&path).ok();
                inner.segments.remove(&seg);
            }

            let cursor_path = inner.dir.join("cursor.json");
            let bytes = serde_json::to_vec(&inner.cursor)?;
            (cursor_path, bytes)
        };
        // Lock released: the two fsyncs below no longer block `push`.
        crate::fsutil::write_atomic(&cursor_path, &bytes)
            .with_context(|| format!("cannot persist queue cursor {}", cursor_path.display()))?;
        self.space_notify.notify_waiters();
        Ok(())
    }
```

- [ ] **Step 4: Call `ack` from the blocking pool in both worker call sites.**
      In `src/outputs/worker.rs`, replace lines 121-123:

```rust
                    if let Err(e) = self.queue.ack(n as u64) {
                        metrics.record_error(format!("output {id}: queue ack: {e}"));
                    }
```

      with:

```rust
                    // R-1: `ack` fsyncs the cursor twice. Do it on the
                    // blocking pool instead of parking one of the runtime's
                    // two worker threads inside fsync.
                    let q = std::sync::Arc::clone(&self.queue);
                    let acked = n as u64;
                    match tokio::task::spawn_blocking(move || q.ack(acked)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            metrics.record_error(format!("output {id}: queue ack: {e}"));
                        }
                        Err(e) => {
                            metrics.record_error(format!("output {id}: queue ack task: {e}"));
                        }
                    }
```

      and replace line 175:

```rust
                    let _ = self.queue.ack(n as u64);
```

      with:

```rust
                    let q = std::sync::Arc::clone(&self.queue);
                    let acked = n as u64;
                    let _ = tokio::task::spawn_blocking(move || q.ack(acked)).await;
```

- [ ] **Step 5: Run and confirm.**
      `cargo test --all-targets` — expected **125 total** (119 lib + 0 bin + 6 e2e), all passing. `buffer::tests::ack_is_durable_under_concurrent_pushes` and `buffer::tests::cursor_is_written_atomically_and_survives_reopen` must both still pass (the latter also asserts no `cursor.json.tmp` survives an ack, which pins that the write still goes through `write_atomic`). `outputs::tests::a_custom_sink_receives_every_queued_event` and the e2e `syslog_in_queue_survives_restart` must still pass — they exercise the new `spawn_blocking` ack path end to end.
      `cargo clippy --all-targets` — expected clean. `cargo fmt --all -- --check` — expected clean.

- [ ] **Step 6: Commit.**

```
fix(R-1): fsync the queue cursor outside the queue mutex and off the runtime

DiskQueue::ack held inner across fsutil::write_atomic, which does two
fsyncs (the temp file, then the parent directory). At the default
retry.batch_size: 200 and a few thousand events/s that is ~100 fsyncs/s
with the queue mutex held — on a consumer SSD, 50-100% of wall-clock time.
run_router's push takes the same mutex, on the same 2-worker runtime, so
this is the real cause of the "brief lock contention" that ROUTER_CAPACITY
and the router_shed counter were built to absorb. It is not brief.

Serialise the cursor under the lock, release it, then write. Safe because
the cursor is single-consumer: only OutputWorker::run's loop calls
ack/reset_peek, never concurrently with itself, and the only other writer
of inner.cursor (drop_oldest_segment) can only move it forward past
segments it just deleted, which open()'s existing clamp already handles.
The unlink loop stays under the lock: unlink(2) has no fsync and only runs
when a whole segment has been consumed.

Both worker call sites now go through tokio::task::spawn_blocking, so no
runtime worker thread parks inside fsync. Not push: see the R-2 commit for
why the per-event path stays on the router task.

A two-thread test asserts every pushed event is peeked exactly once in
order under concurrent push/ack, and that a reopen replays nothing that was
acked — which is what a mis-scoped cursor write would break. A second test
pins that peek_batch and ack stay callable from the blocking pool.
```

---

### Task 6: R-2 — buffer segment appends and read batches off the runtime

**Files:**
- Modify: `src/buffer.rs` — the `use std::io::{...}` line 16; `Inner::writer`, line 36; `DiskQueue::open`'s `Inner` construction, line 137 (`writer: None` — unchanged text, listed because its type changes); `push`'s writer open (as rewritten by Task 1, lines ~180-196) and its `write_all` error path (lines ~186-199 pre-Task-1 numbering, ~191-210 after Task 1); `roll_segment` (as rewritten by Task 1); `oldest_age_secs`, lines 370-393; one new test appended at the end of `mod tests`.
- Modify: `src/outputs/worker.rs` — the main-loop `peek_batch` (as rewritten by Task 3, lines ~99-113) and the shutdown-flush `peek_batch` (as rewritten by Task 3, lines ~178-181).

**Interfaces:**
- Consumes: `std::io::BufWriter<File>` — `BufWriter::new(inner: W) -> BufWriter<W>` (8 KiB default capacity), `BufWriter::flush(&mut self) -> io::Result<()>` via `Write`, and `BufWriter::into_parts(self) -> (W, Result<Vec<u8>, WriterPanicked>)`, which **does not flush** (verified empirically: after `write_all(b"hello")` then `into_parts`, the file length is 0 and the 5 buffered bytes come back in the `Ok` variant). `into_parts` is stable since Rust 1.56, well inside the 1.98 MSRV. Writes larger than the buffer capacity bypass the buffer, so a 2 MiB record is still one `write(2)`.
- Produces: `writer: Option<BufWriter<File>>` in `Inner`. No public signature changes.
- **Ruling TDD-A / red-green ordering:** the type change comes first and is *deliberately* left incomplete, so the new `oldest_age_secs` test is genuinely red between Step 3 and Step 5.

- [ ] **Step 1: Write the test.**
      Append to the end of `mod tests` in `src/buffer.rs`, immediately before the module's closing brace:

```rust
    /// R-2: `inner.writer` is a `BufWriter`, so up to 8 KiB of appended
    /// records can be sitting in memory rather than in the segment file. Every
    /// reader that opens the *write* segment by path must flush first.
    /// `oldest_age_secs` backs `/api/buffer`'s "oldest_event_age_seconds",
    /// which the GUI polls every 3 s; reporting null for a queue that
    /// demonstrably holds an event is a regression.
    #[test]
    fn oldest_age_secs_sees_a_freshly_pushed_event() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
        assert!(q.oldest_age_secs().is_none(), "empty queue has no oldest");
        q.push(&ev(0)).unwrap();
        assert_eq!(q.len(), 1);
        let age = q.oldest_age_secs();
        assert!(
            age.is_some(),
            "oldest_age_secs must flush the write buffer before reading the segment"
        );
        assert!(age.unwrap() >= 0, "age must not be negative: {age:?}");
    }
```

- [ ] **Step 2: Run the test and confirm it passes for now.**
      `cargo test --lib buffer::tests::oldest_age_secs_sees_a_freshly_pushed_event` — expected: **PASSES**, because `writer` is still an unbuffered `File` and every `write_all` reaches the file immediately. Step 4 is the step that makes it red.

- [ ] **Step 3: Change `Inner::writer` to a `BufWriter<File>` and fix the writer lifecycle.**
      In `src/buffer.rs`, replace line 16:

```rust
use std::io::{Read, Seek, SeekFrom, Write};
```

      with:

```rust
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
```

      Replace line 36:

```rust
    writer: Option<File>,
```

      with:

```rust
    /// Buffered so `push` does not issue one `write(2)` per event on the
    /// runtime while holding the queue mutex; 8 KiB (the `BufWriter::new`
    /// default) collapses ~40 syslog-sized records into one syscall. Every
    /// reader that opens the write segment by path flushes this first:
    /// `peek_batch` and `oldest_age_secs`. `roll_segment` flushes explicitly
    /// rather than relying on `Drop`, which swallows the error.
    writer: Option<BufWriter<File>>,
```

      In `push`, wrap the newly opened file (the `inner.writer = Some(f);` line inside the block Task 1 rewrote):

```rust
            inner.writer = Some(BufWriter::new(f));
```

      In `push`'s `write_all` error path, replace the two lines

```rust
            inner.writer = None;
            roll_segment(&mut inner)?;
```

      with:

```rust
            // Discard the buffer *without* flushing: `real_len` above is the
            // truth about what reached the file, and `BufWriter::drop` would
            // otherwise retry the failed write behind our back and append
            // bytes after we have re-based `write_off`. `into_parts` is the
            // only way to drop a BufWriter without flushing it.
            if let Some(w) = inner.writer.take() {
                let _ = w.into_parts();
            }
            roll_segment(&mut inner)?;
```

      In `roll_segment` (as rewritten by Task 1), replace

```rust
    if let Some(w) = inner.writer.take() {
        drop(w);
    }
```

      with:

```rust
    // Flush explicitly. A dropped `BufWriter` also flushes, but swallows the
    // error — which would silently discard every record still buffered for
    // the segment we are leaving while `write_off`, `bytes` and `count` go on
    // claiming they exist.
    if let Some(mut w) = inner.writer.take() {
        if let Err(e) = w.flush() {
            // Do not let the implicit Drop retry this flush and partially
            // succeed after we stop tracking it: discard the buffer and
            // re-base the write offset on what actually reached the file. The
            // segment index is left alone, so the next `push` reopens this
            // same segment and appends to it.
            let _ = w.into_parts();
            let path = seg_path(&inner.dir, inner.write_seg);
            inner.write_off = std::fs::metadata(&path)
                .map(|m| m.len())
                .unwrap_or(inner.write_off);
            return Err(anyhow::Error::new(e)
                .context(format!("cannot flush queue segment {}", path.display())));
        }
    }
```

- [ ] **Step 4: Run the test and confirm it now fails.**
      `cargo test --lib buffer::tests::oldest_age_secs_sees_a_freshly_pushed_event`
      Expected failure: `assertion failed: age.is_some()` with the message `oldest_age_secs must flush the write buffer before reading the segment`. The pushed record is still in the 8 KiB buffer, so `oldest_age_secs`'s `f.metadata()?.len()` is 0, `read_record`'s header `read_exact` returns `UnexpectedEof` → `RecordRead::Eof`, the segment loop finds nothing, and the function returns `None`.

- [ ] **Step 5: Flush in `oldest_age_secs`.**
      In `src/buffer.rs`, replace lines 371-376:

```rust
    pub fn oldest_age_secs(&self) -> Option<i64> {
        let inner = self.inner.lock().unwrap();
        if inner.count == 0 {
            return None;
        }
        let segs: Vec<u64> = inner.segments.range(inner.cursor.seg..).copied().collect();
```

      with:

```rust
    pub fn oldest_age_secs(&self) -> Option<i64> {
        let mut inner = self.inner.lock().unwrap();
        if inner.count == 0 {
            return None;
        }
        // Same read-visibility contract as `peek_batch`: this opens the write
        // segment by path, so anything still in the writer's 8 KiB buffer has
        // to be flushed first or a queue holding exactly one small event
        // reports no oldest event at all.
        if let Some(w) = inner.writer.as_mut() {
            w.flush().ok();
        }
        let segs: Vec<u64> = inner.segments.range(inner.cursor.seg..).copied().collect();
```

      Flush audit — these are all the readers of a segment file by path, and all of them are now covered:
      - `peek_batch` — already flushes (`w.flush().ok()`, kept best-effort per Ruling R2-B).
      - `oldest_age_secs` — flushes as of this step.
      - `open()`'s `scan_segment` and `set_len` repair — runs before any writer exists (`writer: None` is set in the same `Inner` literal), nothing to flush.
      - `drop_oldest_segment`'s `scan_segment` — only ever scans a segment that is not the write segment; when the oldest *is* the write segment it calls `roll_segment` first, which flushes and clears the writer.
      - `ack`'s `std::fs::metadata` loop — only segments strictly behind `cursor.seg`, never the write segment.
      - `push`'s error-path `std::fs::metadata` — deliberately reads the *unflushed* length; that is the point of the `into_parts` discard above.
      - `len`/`bytes`/`is_full`/`wait_data` — in-memory only.
      No caller outside `src/buffer.rs` opens a segment file: `seg_path` is a private free function (`src/buffer.rs:419`) and `Inner.dir` is a private field, so no other module can name a segment path at all. (The only other `.seg` grep hit under `src/` is the substring inside `cfg.buffer.segment_size_mb` in `src/config/validate.rs`.)

- [ ] **Step 6: Call `peek_batch` from the blocking pool in both worker call sites.**
      In `src/outputs/worker.rs`, replace the main-loop peek (as rewritten by Task 3):

```rust
            let batch = match self.queue.peek_batch(self.retry.batch_size, PEEK_MAX_BYTES) {
                // wait_data can report "data available" while peek_batch returns
                // nothing (all remaining records were skipped as corrupt). Without
                // a floor this becomes a tight loop that pins a core forever.
                Ok(b) if b.is_empty() => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Ok(b) => b,
                Err(e) => {
                    metrics.record_error(format!("output {id}: queue read: {e}"));
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };
```

      with:

```rust
            // R-2: peek_batch does File::open + metadata + seek + N read_exact
            // + N serde_json::from_slice under the queue mutex. One dispatch
            // per batch keeps that off the runtime's two worker threads.
            let q = std::sync::Arc::clone(&self.queue);
            let max = self.retry.batch_size;
            let peeked =
                tokio::task::spawn_blocking(move || q.peek_batch(max, PEEK_MAX_BYTES)).await;
            let batch = match peeked {
                // wait_data can report "data available" while peek_batch returns
                // nothing (all remaining records were skipped as corrupt). Without
                // a floor this becomes a tight loop that pins a core forever.
                Ok(Ok(b)) if b.is_empty() => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Ok(Ok(b)) => b,
                Ok(Err(e)) => {
                    metrics.record_error(format!("output {id}: queue read: {e}"));
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                Err(e) => {
                    metrics.record_error(format!("output {id}: queue read task: {e}"));
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };
```

      and replace the shutdown-flush peek (as rewritten by Task 3):

```rust
        if let Ok(batch) = self
            .queue
            .peek_batch(self.retry.batch_size, PEEK_MAX_BYTES)
        {
```

      with:

```rust
        let q = std::sync::Arc::clone(&self.queue);
        let max = self.retry.batch_size;
        let final_peek = tokio::task::spawn_blocking(move || q.peek_batch(max, PEEK_MAX_BYTES)).await;
        if let Ok(Ok(batch)) = final_peek {
```

- [ ] **Step 7: Run and confirm.**
      `cargo test --lib buffer::tests::oldest_age_secs_sees_a_freshly_pushed_event` — expected: passes.
      `cargo test --all-targets` — expected **126 total** (120 lib + 0 bin + 6 e2e), all passing. Specifically:
      - `buffer::tests::segment_rollover` pins that records buffered before a roll are readable after it.
      - `buffer::tests::peek_batch_returns_a_record_larger_than_the_configured_segment_size` pins that a 2 MiB record still round-trips through the `BufWriter`.
      - `buffer::tests::a_transient_segment_create_failure_does_not_wedge_the_queue` (Task 1) pins that a rollover whose `File::create` fails still leaves a usable queue now that the flush happens first.
      - `outputs::tests::a_custom_sink_receives_every_queued_event` and all six e2e tests pin the two new `spawn_blocking` call sites end to end.
      `cargo clippy --all-targets` — expected clean. `cargo fmt --all -- --check` — expected clean.

- [ ] **Step 8: Commit.**

```
fix(R-2): buffer segment appends, and read batches off the runtime

inner.writer was a plain std::fs::File, so push issued one write(2) per
event on a tokio worker thread while holding the queue mutex, and
peek_batch did File::open + metadata + seek + N read_exact + N
serde_json::from_slice under that same mutex, also on a worker thread. With
worker_threads(2), one busy destination could consume half the agent's
async capacity in syscalls and serde, starving the pipeline task, every
input task and the web server.

- inner.writer is now a BufWriter<File> (8 KiB), collapsing ~40
  syslog-sized appends into one syscall. Records larger than the buffer
  bypass it, so a 2 MiB record is still a single write.
- Flush audit for the new buffer: peek_batch already flushed;
  oldest_age_secs now does too (it opens the write segment by path for
  /api/buffer, which the GUI polls every 3 s, and would otherwise report no
  oldest event for a queue holding one). open()'s scan runs before any
  writer exists, ack and drop_oldest_segment never touch the write segment,
  and push's error path deliberately reads the unflushed length.
- roll_segment flushes explicitly instead of relying on Drop, which flushes
  but swallows the error — that would silently discard every record still
  buffered for the segment being left while write_off/bytes/count still
  counted them. On flush failure the buffer is discarded via into_parts (so
  Drop cannot retry it behind our back), write_off is re-based on the real
  file length, and the segment index is left alone so the next push reopens
  and appends.
- push's write_all error path discards the buffer the same way, for the same
  reason.
- OutputWorker::run calls peek_batch through spawn_blocking at both call
  sites (main loop and shutdown flush).

push stays on the router task deliberately: run_router dispatches one event
per iteration, so a spawn_blocking per push would add a task allocation and
a blocking-pool round trip per event only to have all of them queue on the
same mutex, and push_blocking's tokio::select! over space_notify/cancel
cannot move into a blocking closure without redesigning shutdown. With the
fsyncs out of ack and the write buffered, push's critical section is a
crc32 and a memcpy.
```

---

### Task 7: R-5 — add `Event::get_str`, a borrowing field accessor

**Files:**
- Modify: `src/event.rs` — add `get_str` inside `impl Event` immediately after `get_field` (which ends at line 83, before `set_field` at line 86); new test appended at the end of `mod tests` (module is lines 183-213).

**Interfaces:**
- Consumes: the `Event` fields `message: String`, `raw_message: Option<String>`, `hostname: Option<String>`, `application: Option<String>`, `process_id: Option<String>`, `source: String`, `source_type: String`, `fields: Map<String, Value>` (`src/event.rs:12-33`); `serde_json::Value` (already imported, `src/event.rs:5`).
- Produces: `pub fn get_str(&self, name: &str) -> Option<&str>`.
- Deliberately **not** covered by `get_str`: `timestamp`, `received_at`, `severity`, `facility`, `collector_version`, and non-`String` `fields` entries. Callers must fall back to `get_field` for those; Task 8 does exactly that, which is what keeps the behaviour identical.
- Key implication Task 8 relies on: **`get_str(n).is_some()` implies `get_field(n).is_some()`.** For `message`/`source`/`source_type` both are always `Some`; for `raw_message`/`hostname`/`application`/`process_id` both are `Some` for exactly the same `Option`; for a `fields` entry, `get_str` answers only for a present `Value::String`, which `get_field` also reports as present.

- [ ] **Step 1: Write the failing test.**
      Append to the end of `mod tests` in `src/event.rs`, immediately before the module's closing brace:

```rust
    /// R-5: `get_field` returns an owned `Value`, so every condition
    /// evaluation on `message` deep-copied the whole event body — and
    /// `value_to_string` then copied it again. `get_str` borrows instead.
    #[test]
    fn get_str_borrows_string_fields_without_copying() {
        let mut ev = Event::new("src-1", "test", "a message body");
        ev.hostname = Some("host-a".to_string());
        ev.application = Some("app".to_string());
        ev.process_id = Some("4242".to_string());
        ev.raw_message = Some("<11>a message body".to_string());
        ev.fields
            .insert("env".to_string(), Value::String("prod".to_string()));
        ev.fields
            .insert("retries".to_string(), Value::Number(7.into()));
        ev.severity = Some(3);

        // The whole point: a borrow of the event's own buffer, not a copy.
        assert!(
            std::ptr::eq(
                ev.get_str("message").unwrap().as_ptr(),
                ev.message.as_ptr()
            ),
            "get_str must borrow the body, not clone it"
        );

        assert_eq!(ev.get_str("message"), Some("a message body"));
        assert_eq!(ev.get_str("raw_message"), Some("<11>a message body"));
        assert_eq!(ev.get_str("hostname"), Some("host-a"));
        assert_eq!(ev.get_str("application"), Some("app"));
        assert_eq!(ev.get_str("process_id"), Some("4242"));
        assert_eq!(ev.get_str("source"), Some("src-1"));
        assert_eq!(ev.get_str("source_type"), Some("test"));
        assert_eq!(ev.get_str("env"), Some("prod"));

        // Deliberately not covered: callers fall back to get_field for these,
        // which is what keeps eval_condition's behaviour identical.
        assert_eq!(ev.get_str("retries"), None, "non-string fields entry");
        assert_eq!(ev.get_str("severity"), None, "numeric core field");
        assert_eq!(ev.get_str("timestamp"), None, "formatted core field");
        assert_eq!(ev.get_str("collector_version"), None);
        assert_eq!(ev.get_str("nope"), None, "absent field");

        // Absent optionals report absent, not empty.
        let bare = Event::new("s", "t", "body");
        assert_eq!(bare.get_str("hostname"), None);
        assert_eq!(bare.get_str("raw_message"), None);
        assert_eq!(bare.get_str("application"), None);
        assert_eq!(bare.get_str("process_id"), None);

        // The implication eval_condition's fast path depends on: whenever
        // get_str answers, get_field would have answered too.
        for name in [
            "message",
            "raw_message",
            "hostname",
            "application",
            "process_id",
            "source",
            "source_type",
            "env",
            "retries",
            "severity",
            "timestamp",
            "collector_version",
            "nope",
        ] {
            if ev.get_str(name).is_some() {
                assert!(
                    ev.get_field(name).is_some(),
                    "get_str answered for {name} but get_field did not"
                );
            }
        }
    }
```

- [ ] **Step 2: Run the test and confirm it fails.**
      `cargo test --lib event::tests::get_str_borrows_string_fields_without_copying`
      Expected failure: a compile error, `error[E0599]: no method named get_str found for struct Event in the current scope`, at every `get_str` call in the new test.

- [ ] **Step 3: Implement `get_str`.**
      In `src/event.rs`, insert after `get_field`'s closing brace (line 83) and before the `/// Set a field by name` comment (line 85):

```rust
    /// Borrow a field's value as a `&str`, for callers that only need to read
    /// it.
    ///
    /// `get_field` has to return an owned `Value`, so reading `message`
    /// through it copies the entire event body — and `value_to_string` then
    /// copies it a second time. With a `when:` condition on `message` per
    /// output, a 4 KB event cost ~8 KB of allocate-copy-free per output
    /// before it reached any queue.
    ///
    /// Covers the string-valued fields the condition DSL and the `mask`
    /// transform are actually pointed at. Everything else — `timestamp`,
    /// `received_at`, `severity`, `facility`, `collector_version`, and any
    /// non-`String` entry in `fields` — returns `None`, and callers fall back
    /// to `get_field` for those. That fallback is load-bearing: it is what
    /// makes the borrowing fast path exactly equivalent to the owned one.
    ///
    /// Whenever this returns `Some`, `get_field` for the same name would also
    /// return `Some`.
    pub fn get_str(&self, name: &str) -> Option<&str> {
        match name {
            "message" => Some(self.message.as_str()),
            "raw_message" => self.raw_message.as_deref(),
            "hostname" => self.hostname.as_deref(),
            "application" => self.application.as_deref(),
            "process_id" => self.process_id.as_deref(),
            "source" => Some(self.source.as_str()),
            "source_type" => Some(self.source_type.as_str()),
            other => match self.fields.get(other) {
                Some(Value::String(s)) => Some(s.as_str()),
                _ => None,
            },
        }
    }
```

- [ ] **Step 4: Run and confirm.**
      `cargo test --lib event::` — expected: all `event::tests` pass, including the new one. `cargo test --all-targets` — expected **127 total** (121 lib + 0 bin + 6 e2e).
      `cargo clippy --all-targets` — expected clean; `get_str` is a `pub fn` on a `pub struct` in a crate with a `[lib]` target, so `dead_code` does not fire even before Task 8 consumes it.
      `cargo fmt --all -- --check` — expected clean.

- [ ] **Step 5: Commit.**

```
fix(R-5): add Event::get_str, a borrowing field accessor

Event::get_field returns an owned serde_json::Value, so reading `message`
through it clones the whole event body, and event::value_to_string then
clones the result again. That is the shape of every condition evaluation:
eval_condition is called once per output per event in route_event, plus once
per transform step with a `when:`.

get_str borrows instead, covering message, raw_message, hostname,
application, process_id, source, source_type and String-valued `fields`
entries. Numeric and formatted core fields, collector_version and
non-string fields entries deliberately return None so callers fall back to
get_field — that fallback is what will let eval_condition use this without
any behaviour change.

The test pins the borrow with a pointer-identity assertion, the full set of
covered and uncovered names, and the implication the fast path will depend
on: whenever get_str answers, get_field would have answered too.
```

---

### Task 8: R-5 — evaluate string conditions without cloning

**Files:**
- Modify: `src/pipeline/condition.rs` — `CompiledCondition`, lines 15-20; `CompiledCondition::compile`, lines 22-42; `eval_condition`, lines 44-89; new tests appended at the end of `mod tests` (module is lines 109-138).

**Interfaces:**
- Consumes: `Event::get_str(&self, name: &str) -> Option<&str>` (Task 7); `Event::get_field(&self, name: &str) -> Option<Value>` (`src/event.rs:67`); `crate::event::value_to_string(v: &Value) -> Option<String>` (`src/event.rs:137`, already imported at `src/pipeline/condition.rs:2`); `crate::config::Condition { field: String, op: String, value: Option<Value> }`; `regex::Regex::is_match(&self, text: &str) -> bool`.
- Produces: `CompiledCondition` gains a private `value_str: Option<String>` field. `pub fn eval_condition(cond: &CompiledCondition, ev: &Event) -> bool` keeps its signature and its exact truth table. Three new private helpers: `fn field_present(cond: &CompiledCondition, ev: &Event) -> bool`, `fn eval_str_op(cond: &CompiledCondition, ev: &Event) -> Option<bool>`, `fn eval_value_op(cond: &CompiledCondition, ev: &Event) -> bool`.
- Callers unchanged: `src/engine.rs:605` (`eval_condition(cond, &ev)` in `route_event`) and `src/pipeline/transform.rs:110,115,120,128,142,163,168`.

- [ ] **Step 1: Write the failing tests.**
      Append to the end of `mod tests` in `src/pipeline/condition.rs`, immediately before the module's closing brace:

```rust
    fn compile(field: &str, op: &str, value: Option<Value>) -> CompiledCondition {
        CompiledCondition::compile(&Condition {
            field: field.to_string(),
            op: op.to_string(),
            value,
        })
        .unwrap()
    }

    fn s(v: &str) -> Option<Value> {
        Some(Value::String(v.to_string()))
    }

    /// R-5: the condition's own literal is stringified once at compile time
    /// instead of by `value_to_string` on every evaluation.
    #[test]
    fn the_condition_literal_is_stringified_once_at_compile_time() {
        assert_eq!(
            compile("message", "contains", s("ERROR")).value_str.as_deref(),
            Some("ERROR")
        );
        assert_eq!(
            compile("severity", "eq", Some(serde_json::json!(3)))
                .value_str
                .as_deref(),
            Some("3"),
            "numeric literals must stringify exactly as value_to_string did"
        );
        assert_eq!(
            compile("flag", "eq", Some(Value::Bool(true)))
                .value_str
                .as_deref(),
            Some("true")
        );
        assert_eq!(compile("message", "exists", None).value_str, None);
        assert_eq!(
            compile("message", "eq", Some(Value::Null)).value_str,
            None,
            "null does not stringify, matching value_to_string"
        );
    }

    /// R-5 equivalence table, populated event. Every expectation here is the
    /// answer the pre-fix `get_field` + `value_to_string` implementation gave,
    /// so the borrowing fast path must reproduce all of it: string fields,
    /// numeric fields, `fields`-map lookups (string and non-string), formatted
    /// core fields, and a missing field, across every operator.
    #[test]
    fn eval_condition_is_unchanged_on_a_populated_event() {
        let mut ev = Event::new("src-1", "test", "database ERROR code 42");
        ev.hostname = Some("host-a".to_string());
        ev.application = Some("app".to_string());
        ev.process_id = Some("123".to_string());
        ev.severity = Some(3);
        ev.raw_message = Some("<11>database ERROR code 42".to_string());
        ev.fields
            .insert("env".to_string(), Value::String("prod".to_string()));
        ev.fields
            .insert("retries".to_string(), Value::Number(7.into()));

        let cases: Vec<(&str, &str, Option<Value>, bool)> = vec![
            // --- borrowed string core field ---
            ("message", "contains", s("ERROR"), true),
            ("message", "contains", s("WARN"), false),
            ("message", "eq", s("database ERROR code 42"), true),
            ("message", "eq", s("other"), false),
            ("message", "ne", s("database ERROR code 42"), false),
            ("message", "ne", s("other"), true),
            ("message", "matches", s(r"code \d+"), true),
            ("message", "matches", s(r"^code"), false),
            ("message", "exists", None, true),
            ("message", "not_exists", None, false),
            // gt/lt keep the owned numeric path; a non-numeric body is false
            ("message", "gt", Some(serde_json::json!(5)), false),
            ("message", "lt", Some(serde_json::json!(5)), false),
            // a null / absent literal must answer exactly as before
            ("message", "eq", Some(Value::Null), false),
            ("message", "ne", Some(Value::Null), true),
            ("message", "eq", None, false),
            ("message", "ne", None, false),
            ("message", "contains", Some(Value::Null), false),
            ("message", "matches", None, false),
            ("message", "frobnicate", s("x"), false),
            // --- other borrowed core fields ---
            ("raw_message", "contains", s("<11>"), true),
            ("hostname", "eq", s("host-a"), true),
            ("hostname", "contains", s("host"), true),
            ("hostname", "not_exists", None, false),
            ("application", "eq", s("app"), true),
            ("source", "eq", s("src-1"), true),
            ("source_type", "eq", s("test"), true),
            // cross-type eq stringifies both sides, before and after
            ("process_id", "eq", s("123"), true),
            ("process_id", "eq", Some(serde_json::json!(123)), true),
            // --- numeric core field: owned fallback ---
            ("severity", "eq", Some(serde_json::json!(3)), true),
            ("severity", "eq", s("3"), true),
            ("severity", "eq", Some(serde_json::json!(4)), false),
            ("severity", "ne", Some(serde_json::json!(4)), true),
            ("severity", "contains", s("3"), true),
            ("severity", "exists", None, true),
            ("severity", "not_exists", None, false),
            ("severity", "gt", Some(serde_json::json!(2)), true),
            ("severity", "lt", Some(serde_json::json!(2)), false),
            // --- formatted core field: owned fallback ---
            ("timestamp", "contains", s("T"), true),
            ("timestamp", "exists", None, true),
            ("collector_version", "exists", None, true),
            // --- fields map, string entry: borrowed ---
            ("env", "eq", s("prod"), true),
            ("env", "ne", s("dev"), true),
            ("env", "contains", s("pro"), true),
            ("env", "matches", s("^pr"), true),
            ("env", "exists", None, true),
            ("env", "not_exists", None, false),
            // --- fields map, non-string entry: owned fallback ---
            ("retries", "eq", Some(serde_json::json!(7)), true),
            ("retries", "eq", s("7"), true),
            ("retries", "contains", s("7"), true),
            ("retries", "exists", None, true),
            ("retries", "gt", Some(serde_json::json!(6)), true),
            // --- missing field ---
            ("nope", "exists", None, false),
            ("nope", "not_exists", None, true),
            ("nope", "eq", s("x"), false),
            ("nope", "ne", s("x"), true),
            ("nope", "contains", s("x"), false),
            ("nope", "matches", s("x"), false),
            ("nope", "gt", Some(serde_json::json!(1)), false),
        ];

        for (field, op, value, expected) in cases {
            let compiled = compile(field, op, value.clone());
            assert_eq!(
                eval_condition(&compiled, &ev),
                expected,
                "field={field} op={op} value={value:?}"
            );
        }
    }

    /// R-5 equivalence table, event with every optional field absent.
    #[test]
    fn eval_condition_is_unchanged_when_optional_fields_are_absent() {
        let ev = Event::new("s", "t", "body");

        let cases: Vec<(&str, &str, Option<Value>, bool)> = vec![
            ("hostname", "exists", None, false),
            ("hostname", "not_exists", None, true),
            ("hostname", "eq", s("x"), false),
            ("hostname", "ne", s("x"), true),
            ("hostname", "contains", s("x"), false),
            ("hostname", "matches", s("x"), false),
            ("raw_message", "exists", None, false),
            ("raw_message", "contains", s("x"), false),
            ("application", "not_exists", None, true),
            ("process_id", "eq", s("1"), false),
            ("severity", "exists", None, false),
            ("severity", "gt", Some(serde_json::json!(1)), false),
            ("severity", "ne", Some(serde_json::json!(1)), true),
            ("message", "eq", s("body"), true),
            ("source", "eq", s("s"), true),
        ];

        for (field, op, value, expected) in cases {
            let compiled = compile(field, op, value.clone());
            assert_eq!(
                eval_condition(&compiled, &ev),
                expected,
                "field={field} op={op} value={value:?}"
            );
        }
    }
```

- [ ] **Step 2: Run the tests and confirm they fail.**
      `cargo test --lib pipeline::condition::`
      Expected failure: a compile error, `error[E0609]: no field value_str on type CompiledCondition`, at the four `.value_str` accesses in `the_condition_literal_is_stringified_once_at_compile_time`. That error fails the whole test module, so all five tests in it (the two pre-existing ones included) fail to build until Step 3 lands.

- [ ] **Step 3: Pre-stringify the literal at compile time.**
      In `src/pipeline/condition.rs`, replace lines 15-20:

```rust
pub struct CompiledCondition {
    field: String,
    op: String,
    value: Option<serde_json::Value>,
    regex: Option<Regex>,
}
```

      with:

```rust
pub struct CompiledCondition {
    field: String,
    op: String,
    value: Option<serde_json::Value>,
    /// `value` run through `value_to_string` once, at compile time, instead of
    /// on every evaluation. Lets the string operators compare `&str` to `&str`
    /// without allocating either side per event. `None` when there is no
    /// value, or when the value is a `Value::Null` (which `value_to_string`
    /// also declines) — both cases the operators below handle explicitly.
    value_str: Option<String>,
    regex: Option<Regex>,
}
```

      and in `compile`, replace lines 35-40:

```rust
        Ok(CompiledCondition {
            field: c.field.clone(),
            op: c.op.clone(),
            value: c.value.clone(),
            regex,
        })
```

      with:

```rust
        Ok(CompiledCondition {
            field: c.field.clone(),
            op: c.op.clone(),
            value_str: c.value.as_ref().and_then(value_to_string),
            value: c.value.clone(),
            regex,
        })
```

- [ ] **Step 4: Rewrite `eval_condition` with a borrowing fast path and an exact fallback.**
      In `src/pipeline/condition.rs`, replace lines 44-89 (all of `eval_condition`) with:

```rust
/// Evaluate a compiled condition.
///
/// Split into a borrowing fast path and the original owned-`Value` path. The
/// old implementation started with `ev.get_field(&cond.field)`, which clones
/// the whole event body for `message`/`raw_message`, and then
/// `value_to_string` cloned it again — twice per output per event for the two
/// most natural fields to filter on. `Event::get_str` borrows instead.
///
/// The fallback is what makes this a pure refactor: the fast path runs only
/// when `get_str` answers, i.e. only for string-valued fields, and every
/// other field (numeric core fields, `timestamp`, `collector_version`,
/// non-string `fields` entries, absent fields) goes through `eval_value_op`,
/// which is the previous code verbatim.
pub fn eval_condition(cond: &CompiledCondition, ev: &Event) -> bool {
    match cond.op.as_str() {
        "exists" => field_present(cond, ev),
        "not_exists" => !field_present(cond, ev),
        "eq" | "ne" | "contains" | "matches" => match eval_str_op(cond, ev) {
            Some(hit) => hit,
            None => eval_value_op(cond, ev),
        },
        "gt" | "lt" => {
            // Numeric comparison keeps the owned path: it needs the field's
            // `Value` to distinguish a number from a numeric string, and the
            // clone is of a `Number`, not of a body.
            let field_val = ev.get_field(&cond.field);
            let (Some(a), Some(b)) = (&field_val, &cond.value) else {
                return false;
            };
            let (Some(a), Some(b)) = (value_to_f64(a), value_to_f64(b)) else {
                return false;
            };
            if cond.op == "gt" {
                a > b
            } else {
                a < b
            }
        }
        _ => false,
    }
}

/// Presence check without the clone.
///
/// `Event::get_str` returning `Some` implies `get_field` would too (it covers
/// a subset of the same names, and the only `fields` entries it answers for
/// are present ones), so this is exactly `get_field(..).is_some()` with the
/// copy skipped whenever the field is a string.
fn field_present(cond: &CompiledCondition, ev: &Event) -> bool {
    ev.get_str(&cond.field).is_some() || ev.get_field(&cond.field).is_some()
}

/// Allocation-free path for the string operators. `Some(result)` when the
/// field is one `get_str` can borrow; `None` when the caller must fall back
/// to `eval_value_op`.
///
/// Each arm reproduces the corresponding arm of the old implementation for the
/// case where the field resolved to a `Value::String`:
/// - `contains`/`eq`: the old code needed `value_to_string` to succeed on both
///   sides, so a non-stringifiable literal (`null`, or no literal at all)
///   answered `false`.
/// - `ne`: the old code answered `!values_eq(..)`, which is `true` when the
///   literal is present but does not stringify, and `false` when there is no
///   literal at all (that fell through to the catch-all `_ => false`).
/// - `matches`: `regex` is only ever `Some` for `op == "matches"` with a
///   string literal, and the old code answered `false` otherwise.
fn eval_str_op(cond: &CompiledCondition, ev: &Event) -> Option<bool> {
    let a = ev.get_str(&cond.field)?;
    match cond.op.as_str() {
        "contains" => Some(match &cond.value_str {
            Some(b) => a.contains(b.as_str()),
            None => false,
        }),
        "eq" => Some(match &cond.value_str {
            Some(b) => a == b.as_str(),
            None => false,
        }),
        "ne" => Some(match (&cond.value, &cond.value_str) {
            (Some(_), Some(b)) => a != b.as_str(),
            (Some(_), None) => true,
            (None, _) => false,
        }),
        "matches" => Some(match &cond.regex {
            Some(re) => re.is_match(a),
            None => false,
        }),
        _ => None,
    }
}

/// The original owned-`Value` comparison, unchanged. Used for every field
/// `get_str` cannot borrow as a string.
fn eval_value_op(cond: &CompiledCondition, ev: &Event) -> bool {
    let field_val = ev.get_field(&cond.field);
    match cond.op.as_str() {
        "eq" => match (&field_val, &cond.value) {
            (Some(a), Some(b)) => values_eq(a, b),
            _ => false,
        },
        "ne" => match (&field_val, &cond.value) {
            (Some(a), Some(b)) => !values_eq(a, b),
            (None, Some(_)) => true,
            _ => false,
        },
        "contains" => match (&field_val, &cond.value) {
            (Some(a), Some(b)) => {
                let (Some(a), Some(b)) = (value_to_string(a), value_to_string(b)) else {
                    return false;
                };
                a.contains(&b)
            }
            _ => false,
        },
        "matches" => match (&field_val, &cond.regex) {
            (Some(a), Some(re)) => match value_to_string(a) {
                Some(a) => re.is_match(&a),
                None => false,
            },
            _ => false,
        },
        _ => false,
    }
}
```

- [ ] **Step 5: Run and confirm.**
      `cargo test --lib pipeline::` — expected: all pass, including the two pre-existing tests (`compiled_condition_matches_like_the_interpreted_one`, `an_invalid_regex_is_rejected_at_compile_time_not_per_event`), the three new ones, and every `pipeline::transform` test (which exercises `eval_condition` through `when:` on `severity`, i.e. the owned fallback).
      `cargo test --all-targets` — expected **130 total** (124 lib + 0 bin + 6 e2e). The e2e `conditional_routing_to_multiple_destinations` must still pass; it is the end-to-end check that `when:` routing is unchanged.
      `cargo clippy --all-targets` — expected clean.
      `cargo fmt --all -- --check` — expected clean.

- [ ] **Step 6: Commit.**

```
fix(R-5): evaluate string conditions without cloning the event body

eval_condition began with ev.get_field(&cond.field), which returns an owned
Value and therefore clones the entire body for message/raw_message, and the
contains/matches/eq/ne arms then called value_to_string, which clones it
again. route_event evaluates one condition per output per event, so three
outputs each carrying `when: {field: message, op: contains}` cost ~24 KB of
allocate-copy-free per 4 KB event before it reached any queue.

The string operators now run on Event::get_str, a borrow, against the
condition's literal pre-stringified once at compile time (value_str). Zero
allocations on the hot path.

Equivalence is structural, not hopeful: the fast path runs only when get_str
answers — i.e. only for string-valued fields — and every other field falls
through to eval_value_op, which is the previous code verbatim. exists /
not_exists use the same short-circuit, which is exact because get_str
answering implies get_field would answer. gt/lt keep the owned path; they
need the Value to tell a number from a numeric string, and the clone there
is of a Number, not a body.

Three tests: the compile-time stringification (including numeric, bool and
null literals), and two tables covering every operator against borrowed
string fields, numeric core fields, formatted core fields, string and
non-string fields-map entries, absent optionals and a missing field. Every
expectation in them is the answer the pre-fix implementation gave.
```

---

### Task 9: R-5 — mask without the triple copy

**Files:**
- Modify: `src/pipeline/transform.rs` — the `CompiledStep::Mask` arm's field-masking block, lines 143-148; new test appended at the end of `mod tests` (module starts at line 218).

**Interfaces:**
- Consumes: `Event::get_str(&self, name: &str) -> Option<&str>` (Task 7); `Event::get_field(&self, name: &str) -> Option<Value>` (`src/event.rs:67`); `Event::set_field(&mut self, name: &str, value: Value)` (`src/event.rs:86`); `crate::event::value_to_string(v: &Value) -> Option<String>` (already imported, `src/pipeline/transform.rs:2`); `Regex::replace_all(&self, text: &str, rep: R) -> Cow<'_, str>`.
- Produces: no signature changes. The `raw_message` block at lines 149-159 is left exactly as it is — it already reads `ev.raw_message.take()` directly and never went through `get_field`.

- [ ] **Step 1: Write the failing test.**
      Append to the end of `mod tests` in `src/pipeline/transform.rs`, immediately before the module's closing brace:

```rust
    /// R-5: the mask step did get_field (clone) -> value_to_string (clone) ->
    /// replace_all (clone) -> set_field (move): three full copies of the
    /// message per masked event. It now borrows the body for string fields.
    /// Non-string fields must keep working exactly as before, including the
    /// coercion to a string that masking them has always done.
    #[test]
    fn mask_covers_string_and_non_string_fields() {
        let cfg: PipelineConfig = serde_yaml::from_str(
            r#"
transforms:
  - type: mask
    field: message
    pattern: "\\d{4}"
    replacement: "[X]"
  - type: mask
    field: env
    pattern: "prod"
    replacement: "[ENV]"
  - type: mask
    field: retries
    pattern: "7"
    replacement: "9"
  - type: mask
    field: absent
    pattern: "x"
    replacement: "y"
"#,
        )
        .unwrap();
        let t = Transformer::compile(&cfg).unwrap();

        let mut ev = Event::new("s", "test", "code 1234 here");
        ev.fields
            .insert("env".to_string(), Value::String("prod".to_string()));
        ev.fields
            .insert("retries".to_string(), Value::Number(7.into()));
        assert!(t.apply(&mut ev));

        assert_eq!(ev.message, "code [X] here", "core string field");
        assert_eq!(
            ev.fields["env"],
            Value::String("[ENV]".to_string()),
            "fields-map string entry"
        );
        // Unchanged behaviour: a non-string field is stringified, masked and
        // written back as a string.
        assert_eq!(
            ev.fields["retries"],
            Value::String("9".to_string()),
            "non-string fields entry must still be masked via the owned path"
        );
        assert!(
            !ev.fields.contains_key("absent"),
            "masking a missing field must not create it"
        );

        // A pattern that does not match must leave the value byte-identical.
        let mut untouched = Event::new("s", "test", "no digits here");
        assert!(t.apply(&mut untouched));
        assert_eq!(untouched.message, "no digits here");
    }
```

- [ ] **Step 2: Run the test and confirm it passes for now.**
      `cargo test --lib pipeline::transform::tests::mask_covers_string_and_non_string_fields` — expected: **PASSES** on the current implementation. Per Ruling TDD-A this is a characterization test: it is written first specifically to pin the behaviour the refactor in Step 3 must not change, including the two cases the refactor could plausibly break (a non-string field, and a missing field). Record the pass, then proceed.

- [ ] **Step 3: Borrow the field instead of cloning it three times.**
      In `src/pipeline/transform.rs`, replace lines 143-148:

```rust
                        if let Some(v) = ev.get_field(field) {
                            if let Some(s) = value_to_string(&v) {
                                let masked = re.replace_all(&s, replacement.as_str());
                                ev.set_field(field, Value::String(masked.into_owned()));
                            }
                        }
```

      with:

```rust
                        // R-5: the old chain was get_field (clones the body)
                        // -> value_to_string (clones it again) -> replace_all
                        // (a third copy) -> set_field. `get_str` borrows the
                        // body, so a masked string field costs one copy.
                        // Fields `get_str` cannot borrow — numbers, bools,
                        // non-string `fields` entries — keep the original
                        // stringify-then-set path, including its long-standing
                        // coercion of the masked field to a string.
                        let masked: Option<String> = match ev.get_str(field) {
                            Some(s) => Some(re.replace_all(s, replacement.as_str()).into_owned()),
                            None => ev
                                .get_field(field)
                                .as_ref()
                                .and_then(value_to_string)
                                .map(|s| re.replace_all(&s, replacement.as_str()).into_owned()),
                        };
                        if let Some(s) = masked {
                            ev.set_field(field, Value::String(s));
                        }
```

- [ ] **Step 4: Run and confirm.**
      `cargo test --lib pipeline::transform::` — expected: all pass, including `mask_covers_string_and_non_string_fields` and the pre-existing `transforms_apply` (which is the PIPE-006 regression guard: masking `message` must also scrub `raw_message`, and that block is untouched).
      `cargo test --all-targets` — expected **131 total** (125 lib + 0 bin + 6 e2e).
      `cargo clippy --all-targets` — expected clean. `cargo fmt --all -- --check` — expected clean.

- [ ] **Step 5: Commit.**

```
fix(R-5): mask string fields without the triple copy

The mask step did get_field (clones the whole body) -> value_to_string
(clones it again) -> replace_all (a third copy) -> set_field (move): three
full copies of the message per masked event, once per masking step, per
event.

Borrow the body with Event::get_str and copy once. Fields get_str cannot
borrow — numbers, bools, non-string `fields` entries — keep the original
stringify-then-set path verbatim, including its long-standing coercion of
the masked field to a string, so behaviour is unchanged for every field
type.

The raw_message scrub (PIPE-006) is untouched: it already reads
ev.raw_message.take() directly and never went through get_field.

The test is a characterization test written before the change: it pins
masking a core string field, a string fields-map entry, a numeric
fields-map entry (the owned fallback), a missing field, and a
non-matching pattern.
```

---

## Coverage check against the spec's suggested fixes

| Spec suggestion | Where |
| --- | --- |
| R-1: compute cursor bytes under the lock, `write_atomic` outside | Task 5, Step 3 |
| R-1: wrap `ack` in `spawn_blocking` from `worker.rs` | Task 5, Step 4 (both call sites) |
| R-1: optionally drop the directory `sync_all()` to one fsync per ack | **Scoped out.** `fsutil::write_atomic` is shared with `StateManager::flush` (`src/state.rs:170-192`), so weakening it changes the durability of `state.json` too, and the whole point of `write_atomic` per its doc comment is that "a torn cursor.json makes the agent replay its entire backlog after a power loss". With both fsyncs off the lock and off the runtime, their cost no longer blocks anything. R-7 is the finding that revisits `write_atomic`'s callers and is out of scope here. |
| R-2: make `inner.writer` a `BufWriter<File>` | Task 6, Step 3, plus the three-site flush audit in Steps 3 and 5 |
| R-2: move `push`/`peek_batch`/`ack` into `spawn_blocking` | `peek_batch` in Task 6 Step 6, `ack` in Task 5 Step 4. `push`/`push_blocking` deliberately **not** moved — Ruling R2-A. |
| R-3: create the file first, mutate state on success | Task 1, Step 4 |
| R-3: add `.create(true)` to the append open | Task 1, Step 3 |
| R-3: rate-limit `run_router`'s error path like `route_event`'s shed log | Task 2, Steps 3-4 |
| R-4: `peek_batch(max, max_bytes)` with a `peeked_bytes` accumulator on `rec_len` | Task 3, Step 3 |
| R-4: pass ~8 MiB from the worker | Task 3, Step 5 (`PEEK_MAX_BYTES`) |
| R-4: validate `retry.batch_size <= 10_000` | Task 4, Step 3 |
| R-4: `frame_batch`'s second full copy | **Scoped out** — Ruling R4-A (transitively bounded by the byte budget; no change to `stdout.rs`). |
| R-5: `get_field_ref -> Option<Cow<'_, Value>>` | **Not taken.** The spec itself names `fn get_str(&self, name: &str) -> Option<&str>` as "the cheapest high-value change ... with no API churn elsewhere"; that is what Task 7 adds. A `Cow<Value>` accessor would still allocate a `Value` wrapper for the core fields, which are exactly the hot ones. |
| R-5: use it from the `contains`/`matches`/`eq`/`ne` arms | Task 8, Step 4, plus `exists`/`not_exists` via `field_present` |
| R-5: the `mask` triple copy | Task 9, Step 3 — Ruling R5-A |

## Risks / known trade-offs recorded by this plan

1. **`BufWriter` widens the loss window on a write error (Task 6).** Today a failed `write_all` can only tear the record being written; with an 8 KiB buffer, a failed flush can discard up to 8 KiB of already-"pushed" records, leaving `count` and `bytes` overstated until `saturating_sub` catches up. This is bounded, non-wedging (the next `push` reopens the same segment and appends at the real file end), and no worse than the existing durability model — `push` has never fsynced, so those records were only ever in the page cache and were already lost on a process crash. The new exposure is loss on an I/O error without a crash.
2. **The `into_parts` discard paths are not directly tested.** Reproducing them needs a `write(2)`/flush that fails on an already-open fd, i.e. real ENOSPC or a fault-injecting filesystem, neither of which is reachable without a new dependency. The reasoning is recorded in code comments instead, and the surrounding torn-tail accounting is exercised by the existing `open()` repair tests.
3. **Task 1's read-only-directory test is skipped for uid 0.** `chmod` is not enforced for root, so the test probes enforcement first and returns early with an `eprintln!` if the probe succeeds. In a container that runs tests as root, R-3's reproduction is not exercised; the second, cross-platform test (which constructs the wedged state directly) still runs everywhere.
4. **`drop_oldest` can persist a cursor older than the in-memory one (Task 5).** With the lock released across the cursor write, a concurrent `push` under `full_policy: drop_oldest` can advance `inner.cursor` past segments it just deleted while an older cursor value is mid-write. The persisted value then points at a deleted segment, which `DiskQueue::open` already clamps to the next surviving segment (`src/buffer.rs:108-114`), so the effect is bounded by the documented at-least-once guarantee. `block` is the shipped default and has no such writer.
5. **Task 2 changes two metric semantics.** `events_dropped` now counts a failed `push` (previously uncounted), and `last_error` is refreshed only every 100th consecutive queue-write failure (the `errors` counter stays exact). Both are deliberate; see the commit message.
