# softnix-log-agent — memory / CPU resource analysis

Scope: every `loop`, every collection, every `spawn`, every synchronous I/O call
reachable from an async task. Commit `f0de07b`, branch `develop`.
Runtime is `worker_threads(2)` (`src/main.rs:100-103`, `src/main.rs:150-154`), so
anything that blocks a worker costs 50% of the agent's async capacity.

Items listed in the task brief as already-fixed or already-parked are **not**
re-reported; where I found one to be worse than described it is called out
explicitly (findings R-13 and the note under R-3).

---

## R-1 — `DiskQueue::ack` holds the queue mutex across two `fsync` calls, on a tokio worker

- **Severity**: High
- **Category**: runtime blocking
- **Verified**

**Where**

`src/buffer.rs:283-310`:

```rust
pub fn ack(&self, acked_events: u64) -> Result<()> {
    let mut inner = self.inner.lock().unwrap();
    ...
    let cursor_path = inner.dir.join("cursor.json");
    crate::fsutil::write_atomic(&cursor_path, &serde_json::to_vec(&inner.cursor)?)
        .with_context(|| format!("cannot persist queue cursor {}", cursor_path.display()))?;
    drop(inner);
```

`src/fsutil.rs:12-34` — `write_atomic` does `write_all` + `f.sync_all()` + `rename` +
a second `sync_all()` on the parent directory. Two `fsync`s.

Called from `src/outputs/worker.rs:121` (`self.queue.ack(n as u64)`) directly
inside `async fn run`, i.e. on a tokio worker thread.

**Mechanism**

`inner` is a `std::sync::Mutex` (`src/buffer.rs:62`). It is held across both
`fsync`s. Meanwhile `run_router` calls `queue.push(&ev)` (`src/engine.rs:484`),
which takes the *same* mutex at `src/buffer.rs:157`, also on a tokio worker.
So every ack:
1. parks a tokio worker thread inside `fsync` (no `spawn_blocking`, no yield), and
2. blocks the router task for the full duration of both `fsync`s.

At the default `retry.batch_size: 200` (`src/config/schema.rs:509-511`) and
10k events/s, that is 50 acks/s x 2 fsyncs = 100 fsyncs/s. On a consumer SSD at
~5-10 ms/fsync the mutex is held roughly 50-100% of wall-clock time.

This is the actual root cause behind the "brief lock contention" that
`ROUTER_CAPACITY` and the `router_shed` counter were built to absorb — see the
comment at `src/engine.rs:40-49`. It is not brief.

**Trigger**

Any sustained throughput on any destination. Normal production use.

**Suggested fix**

Compute the bytes under the lock, release it, then do the `write_atomic`
outside — the cursor is single-consumer so no other task can advance it:

```rust
let bytes = { let mut inner = ...; ...; serde_json::to_vec(&inner.cursor)? };
// lock dropped here
crate::fsutil::write_atomic(&cursor_path, &bytes)?;
```

And wrap the whole `ack` call in `tokio::task::spawn_blocking` from
`worker.rs`. Optionally drop the directory `sync_all()` to one fsync per ack
(the rename is already atomic within the filesystem; the directory fsync only
buys durability across a power cut, which the segment data itself does not
have either since `push` never fsyncs).

---

## R-2 — The entire `DiskQueue` hot path runs synchronously on the async runtime

- **Severity**: High
- **Category**: runtime blocking
- **Verified**

**Where**

- `src/engine.rs:484` — `queue.push(&ev)` inside `async fn run_router`.
- `src/buffer.rs:154-210` — `push` does `serde_json::to_vec(ev)` (CPU),
  `crc32fast::hash` (CPU), a `write(2)` syscall, and possibly
  `File::create` for a segment roll — **all under `self.inner.lock()`**.
- `src/outputs/worker.rs:90` — `self.queue.peek_batch(self.retry.batch_size)`
  inside `async fn run`.
- `src/buffer.rs:230-279` — `peek_batch` does `File::open` + `metadata` + `seek`
  + N x `read_exact` + N x `serde_json::from_slice::<Event>` under the same lock.

**Mechanism**

`inner.writer` is a plain `std::fs::File` (`src/buffer.rs:36`), not a
`BufWriter`, so `push` issues **one `write(2)` syscall per event** on a tokio
worker thread while holding the queue mutex. `peek_batch` deserializes up to
`batch_size` events from disk on a tokio worker while holding the same mutex.

With 2 worker threads, a single busy destination can consume one of them
entirely in syscalls and serde, starving the pipeline task, every input task
and the web server.

**Trigger**

Normal production throughput; worse the more destinations are configured
(each has its own router doing this concurrently on the same 2 threads).

**Suggested fix**

Two small, independent changes:
1. Make `inner.writer` a `BufWriter<File>` — `peek_batch` already calls
   `w.flush()` at `src/buffer.rs:233-235`, so the read-visibility contract is
   already in place. This collapses N syscalls into one per ~8 KB.
2. Move `push` / `peek_batch` / `ack` calls in `run_router` and
   `OutputWorker::run` into `spawn_blocking` (the batching granularity already
   makes this cheap — one dispatch per batch on the read side).

---

## R-3 — A single transient `roll_segment` failure wedges the queue permanently, turning `run_router` into a per-event `format!` + mutex loop

- **Severity**: High
- **Category**: hot loop / allocation churn (plus total silent data loss)
- **Verified — reproduced**

**Where**

`src/buffer.rs:423-433`:

```rust
fn roll_segment(inner: &mut Inner) -> Result<()> {
    if let Some(w) = inner.writer.take() { drop(w); }
    inner.write_seg += 1;          // <-- state mutated BEFORE the fallible call
    inner.write_off = 0;
    File::create(seg_path(&inner.dir, inner.write_seg))?;   // <-- can fail
    let seg = inner.write_seg;
    inner.segments.insert(seg);
    Ok(())
}
```

`src/buffer.rs:180-185`:

```rust
if inner.writer.is_none() {
    let f = OpenOptions::new()
        .append(true)                 // <-- no .create(true)
        .open(seg_path(&inner.dir, inner.write_seg))?;
```

**Mechanism**

If `File::create` fails for any reason (EMFILE, ENOSPC on inode exhaustion, a
read-only or momentarily-unwritable queue directory, SELinux/AppArmor denial, an
antivirus lock on Windows), `write_seg` has *already* been incremented and
`segments` was *not* updated. The queue now points its write cursor at a segment
file that does not exist and that nothing will ever create — `OpenOptions::append(true)`
without `.create(true)` returns `NotFound` (confirmed empirically). Every
subsequent `push` returns `Err` **forever**, even after the original fault clears.

`run_router` then hits `src/engine.rs:498-500` on every single event:

```rust
Err(e) => {
    metrics.record_error(format!("queue {} write: {e}", out.id));
}
```

`record_error` (`src/metrics.rs:24-27`) allocates a `String` and takes a
`Mutex<Option<String>>` — per event, at full input rate, forever. Events are
neither queued nor counted in `events_dropped`; `/healthz` still reports `ok`
because `is_full()` looks at `bytes`, which never grows.

**Repro** (run against the crate as a path dependency; no repo files modified):

```
seg0 size before the rollover push: 1025670
rollover push (dir read-only): Err(Permission denied (os error 13))
post-recovery push 0: Err(No such file or directory (os error 2))
post-recovery push 1: Err(No such file or directory (os error 2))
post-recovery push 2: Err(No such file or directory (os error 2))
post-recovery push 3: Err(No such file or directory (os error 2))
post-recovery push 4: Err(No such file or directory (os error 2))
seg files: ["00000000000000000000.seg"]
```

(The directory was chmod'd back to 0755 before the "post-recovery" pushes.)

**Trigger**

One transient failure of `File::create` in the queue directory, at a segment
boundary. `segment_size_mb` defaults to 8, so on a busy destination a rollover
happens every few seconds — the exposure window is continuous.

**Suggested fix**

Create the file first, mutate state only on success:

```rust
fn roll_segment(inner: &mut Inner) -> Result<()> {
    let next = inner.write_seg + 1;
    File::create(seg_path(&inner.dir, next))?;   // fallible work first
    inner.writer = None;
    inner.write_seg = next;
    inner.write_off = 0;
    inner.segments.insert(next);
    Ok(())
}
```

Independently, add `.create(true)` to the append open at `src/buffer.rs:181-183`
as a self-healing belt-and-braces, and rate-limit `run_router`'s error path the
same way `route_event` already rate-limits its shed log (`src/engine.rs:638-645`).

---

## R-4 — `peek_batch` is bounded by event *count*, not bytes; `frame_batch` then doubles it; `batch_size` has no upper bound

- **Severity**: High
- **Category**: unbounded growth / backpressure gap
- **Verified**

**Where**

- `src/buffer.rs:230` — `pub fn peek_batch(&self, max: usize) -> Result<Vec<Event>>`;
  `max` is a count, nothing caps the total bytes of `out`.
- `src/outputs/worker.rs:90` — `self.queue.peek_batch(self.retry.batch_size)`.
- `src/outputs/stdout.rs:41-57` — `frame_batch` builds a second, full copy as
  `Vec<u8>` while `batch` is still alive.
- `src/config/validate.rs:220-222` — the only check is
  `if o.retry.batch_size == 0 { bail!(...) }`. No upper bound.
- `src/config/schema.rs:509-511` — default is 200.

**Mechanism**

Event bodies are bounded per-event but not per-batch. `src/inputs/file.rs:27`
sets `MAX_LINE: usize = 1024 * 1024`, and `read_new_lines` can emit an
unterminated line up to `READ_BUDGET` = 4 MiB (`src/inputs/file.rs:710-713`).
With the default `batch_size: 200`, `batch` can therefore reach ~200 MB, and
`frame_batch`'s `payload` another ~200 MB simultaneously — against an advertised
~12 MB footprint. The `CHANNEL_BYTES` semaphore does not cover this at all: it
gates the input->pipeline channel, and this memory is allocated downstream of the
disk queue.

A misconfigured `retry.batch_size: 100000` is accepted by validation and will OOM
the agent on first flush.

**Trigger**

Any destination whose queue holds large events (a JSON-log file input, a
`keep_raw_message: true` eventlog input) plus a brief outage that lets a backlog
build.

**Suggested fix**

Add a byte budget to `peek_batch`:

```rust
pub fn peek_batch(&self, max: usize, max_bytes: usize) -> Result<Vec<Event>>
```

stopping when either limit is hit (a `peeked_bytes` accumulator in the existing
record loop; `rec_len` is already computed). Pass e.g. 8 MiB from the worker.
Separately, validate `retry.batch_size <= 10_000` in `config/validate.rs` next
to the existing `== 0` check.

---

## R-5 — `Event::get_field` deep-clones the message on every condition evaluation, once per output per event

- **Severity**: High
- **Category**: allocation churn
- **Verified**

**Where**

`src/event.rs:67-83`:

```rust
pub fn get_field(&self, name: &str) -> Option<Value> {
    match name {
        ...
        "message" => Some(Value::String(self.message.clone())),
        "raw_message" => self.raw_message.clone().map(Value::String),
        other => self.fields.get(other).cloned(),
```

`src/pipeline/condition.rs:45` — `let field_val = ev.get_field(&cond.field);`
then `src/pipeline/condition.rs:58-66`:

```rust
"contains" => match (&field_val, &cond.value) {
    (Some(a), Some(b)) => {
        let (Some(a), Some(b)) = (value_to_string(a), value_to_string(b)) else { ... };
```

and `value_to_string` (`src/event.rs:137-145`) clones **again**:
`Value::String(s) => Some(s.clone())`.

Call sites on the hot path:
- `src/engine.rs:604-607` — `eval_condition(cond, &ev)` inside the per-output
  loop in `route_event`, i.e. once per output per event.
- `src/pipeline/transform.rs:110,115,120,128,142,163,168` — once per transform
  step with a `when:`, per event.
- `src/pipeline/transform.rs:143-146` — the `mask` step: `get_field` (clone) ->
  `value_to_string` (clone) -> `replace_all` (clone) -> `set_field` (move). Three
  full copies of the message per masked event.

**Mechanism**

The condition DSL is value-returning rather than borrow-returning, so evaluating
`when: { field: message, op: contains, value: "ERROR" }` allocates and copies the
entire message body twice, then throws both away. With 3 outputs each carrying a
`when:` on `message`, a 4 KB event costs 24 KB of allocate-copy-free per event
before it reaches any queue.

**Trigger**

Any config using `when:` or `mask` on `message` / `raw_message` — the two most
natural fields to filter on. Normal production use.

**Suggested fix**

Add a borrowing accessor used by the condition evaluator:

```rust
pub fn get_field_ref(&self, name: &str) -> Option<Cow<'_, Value>>
```

returning `Cow::Borrowed` for `fields` lookups and, for the core string fields,
a `&str` fast path. Concretely, the cheapest high-value change is a
`fn get_str(&self, name: &str) -> Option<&str>` covering
`message` / `raw_message` / `hostname` / `application` / `source` /
`source_type` / `process_id`, used by the `contains` / `matches` / `eq` / `ne`
arms of `eval_condition`. That removes both clones for the common cases with no
API churn elsewhere.

---

## R-6 — `Engine::stop` detaches, never aborts — a slow task survives a reload and reopens the same queue directory as a second writer

- **Severity**: Medium
- **Category**: task leak
- **Verified** (code path); **plausible** for the specific stall conditions

**Where**

`src/engine.rs:450-460`:

```rust
pub async fn stop(self) {
    self.cancel.cancel();
    for t in self.tasks {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(8), t).await;
    }
```

Contrast with the partial-start teardown at `src/engine.rs:275-280`, which does
call `t.abort()`.

**Mechanism**

`tokio::time::timeout` on a `JoinHandle` **drops** the handle when it elapses.
Dropping a `JoinHandle` *detaches* the task; it does not cancel it. So any task
that has not returned within 8 s of cancellation keeps running for the life of
the process.

Reload = `engine.stop().await` then `Engine::start(new_cfg)`
(`src/main.rs:373-380`). `DiskQueue::open` has no lock file
(`src/buffer.rs:73-152`), so the new engine's `DiskQueue` for the same
destination id opens the same directory while the leaked old-generation
`run_router` / `OutputWorker` still holds an `Arc<DiskQueue>` on it. Two
independent `Inner` states then append to the same segment and race on
`cursor.json` — a data-corruption path, not just a memory one. One leaked task
set accumulates per reload.

Tasks that can plausibly exceed 8 s past cancellation:
- `run_router` parked in `queue.push()` -> `write(2)` / `File::create` on a hung
  NFS or failing disk (`src/engine.rs:484`, no timeout, no cancel check).
- `OutputWorker`'s shutdown flush: `peek_batch(batch_size)` is unbounded in time
  (`src/outputs/worker.rs:169`) and runs *before* the 3 s send timeout.
- `FileInput::tail_once` awaiting `spawn_blocking` with **no cancel select**
  (`src/inputs/file.rs:482-492`) — a blocking read on a dead mount hangs it.
- Windows eventlog `spawn_blocking` threads (`src/inputs/eventlog.rs:99`) —
  `spawn_blocking` tasks cannot be aborted *at all*; a hang inside
  `EvtFormatMessage` (loads a provider DLL) leaks a blocking-pool thread per
  reload.

**Trigger**

Any reload (SIGHUP, GUI "Save & Reload") while a destination's disk or a tailed
filesystem is slow.

**Suggested fix**

```rust
let mut pending = self.tasks;
for t in &pending { /* nothing */ }
// abort whatever did not finish
let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
for t in &mut pending {
    if tokio::time::timeout_at(deadline, &mut *t).await.is_err() { t.abort(); }
}
```

i.e. use one shared deadline for the whole set (today's 8 s is per task, so N
tasks can take 8N seconds) and call `abort()` on expiry. Separately, add a
`.lock` file or a `flock` to `DiskQueue::open` so a second writer on the same
directory fails loudly instead of silently corrupting.

---

## R-7 — `StateManager::flush` does JSON serialization plus two fsyncs on a tokio worker every 5 s

- **Severity**: Medium
- **Category**: runtime blocking
- **Verified**

**Where**

`src/engine.rs:417-428`:

```rust
tasks.push(tokio::spawn(async move {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                if let Err(e) = state.flush() { ... }
```

`src/state.rs:170-192` — `flush` serializes the whole `StateFile` and calls
`crate::fsutil::write_atomic`, which fsyncs the temp file and then the directory
(`src/fsutil.rs:23,31`).

**Mechanism**

Two `fsync`s plus a full `serde_json::to_vec` of every tracked file cursor, on a
tokio worker thread, with no `spawn_blocking`. On a host with a few hundred
tailed files the serialization alone is tens of KB; on a busy or network-backed
`data_dir` an fsync routinely takes 10-100 ms. That is 1-2% of one of the two
worker threads stalled on I/O with zero throughput benefit — and it lands in a
burst that also contends with `DiskQueue::ack`'s fsyncs on the same device.

The dirty-flag guard at `src/state.rs:171` means idle agents pay nothing, so this
only bites while files are actively advancing — which is exactly when the runtime
is busiest.

**Trigger**

Any file input under sustained traffic. Normal production use.

**Suggested fix**

`tokio::task::spawn_blocking({ let state = state.clone(); move || state.flush() }).await`
in the flusher loop, and in `Engine::stop`'s final flush (`src/engine.rs:456`).

---

## R-8 — `/api/buffer` holds the `DiskQueue` mutex across synchronous file I/O, every 3 seconds

- **Severity**: Medium
- **Category**: runtime blocking
- **Verified**

**Where**

`src/buffer.rs:371-393`:

```rust
pub fn oldest_age_secs(&self) -> Option<i64> {
    let inner = self.inner.lock().unwrap();
    ...
    for seg in segs {
        ...
        let mut f = File::open(seg_path(&inner.dir, seg)).ok()?;
        let file_len = f.metadata().ok()?.len();
        f.seek(SeekFrom::Start(start)).ok()?;
        if let Ok(RecordRead::Ok { payload, .. }) = read_record(&mut f, file_len) {
```

Called from `src/web.rs:454` (`"oldest_event_age_seconds": q.oldest_age_secs()`),
inside an axum handler on the shared runtime. `src/ui.html:216` —
`timer=setInterval(tick,3000)` — the GUI re-polls the visible page every 3 s.

**Mechanism**

`File::open` + `metadata` + `seek` + `read_exact` + `serde_json::from_slice`, all
under the queue's `std::sync::Mutex`, on a tokio worker. It blocks `push` (the
router) and `peek_batch`/`ack` (the worker) for the duration. `read_record`
additionally does `vec![0u8; len]` where `len` comes from the on-disk header
bounded only by the file size — a corrupt header can request a
`segment_size_mb`-sized allocation here.

Worst case the loop opens *every* remaining segment: it only returns early when
a record both reads cleanly and deserializes, so a queue whose head is corrupt
walks the whole segment set on every 3 s poll.

**Trigger**

An operator leaving the Buffer page open in the GUI. Routine.

**Suggested fix**

Cache the oldest-event timestamp in `Inner` (updated on `ack` / `drop_oldest`),
or wrap the `/api/buffer` handler body in `spawn_blocking`. Cheapest correct
change: release the lock before touching the filesystem — snapshot
`(dir, cursor, segments)` under the lock, then read outside it.

---

## R-9 — Both syslog receive paths take a global `Mutex<HashMap>` once per event

- **Severity**: Medium
- **Category**: allocation churn / lock contention
- **Verified**

**Where**

`src/inputs/syslog.rs:206` (UDP) and `src/inputs/syslog.rs:357` (TCP/TLS):

```rust
status.update_input(&self.cfg.id, |s| s.events += 1);
```

`src/metrics.rs:88-93` — `update_input` locks `self.inputs`, a
`Mutex<HashMap<String, InputStatus>>`, and does a hash lookup by `&str`.

**Mechanism**

One mutex acquire + one string hash per event, on a registry shared by every
input task and by the web server's `inputs_snapshot()`. With 512 concurrent TCP
connections (the default cap, `src/config/schema.rs:180-182`) on 2 worker
threads, this is a single global serialization point on the receive path. The
file and eventlog inputs correctly batch this (`src/inputs/file.rs:263-266`,
`src/inputs/eventlog.rs:531-533`) — syslog is the outlier.

The rate-limited rejection logger already avoids exactly this cost on the reject
path and documents why (`src/inputs/syslog.rs:34-37`); the accept path did not
get the same treatment.

**Trigger**

High-rate syslog ingest. Normal production use for the primary use case.

**Suggested fix**

Make `InputStatus.events` an `Arc<AtomicU64>` held by the input and read by
`inputs_snapshot()`, or accumulate locally and flush to the registry every N
events / every second (mirroring what the file input already does).

---

## R-10 — `tail_once`'s per-batch staging is ~64 MiB of raw bytes before amplification, entirely upstream of the channel byte budget

- **Severity**: Medium
- **Category**: startup spike / backpressure gap
- **Verified** (this is the acknowledged residual of the known batching fix, not a new regression — flagged because the residual is larger than the doc comment implies)

**Where**

`src/inputs/file.rs:48` — `const TAIL_BATCH_SIZE: usize = 16;`
`src/inputs/file.rs:25` — `const READ_BUDGET: u64 = 4 * 1024 * 1024;`
`src/inputs/file.rs:677-715` — `read_new_lines` allocates `vec![0u8; to_read]`
(up to 4 MiB) and then a `Vec<String>` with one heap `String` per line.
`src/inputs/file.rs:499-519` — the whole `results: Vec<TailReadResult>` for the
batch is alive while events are parsed and sent one at a time.

**Mechanism**

The doc comment at `src/inputs/file.rs:38-41` states the bound as
`TAIL_BATCH_SIZE * READ_BUDGET` ~ 64 MiB. That is the *raw byte* bound. The
staged form is `Vec<String>`, one allocation plus 24 bytes of `String` header per
line. For 50-byte log lines, 4 MiB of file becomes ~84k `String`s ~ 4 MiB of
payload + ~2 MiB of headers + per-allocation malloc overhead — call it 2-3x. So
the real transient ceiling is closer to 130-190 MB, and it sits entirely
*upstream* of the `CHANNEL_BYTES` semaphore, which cannot see it.

`READ_BUDGET` is described as "a safety cap rather than a typical read size",
which is true in steady state — but the case where it is *not* a safety cap is
exactly the one that matters: `read_from_start: true` on first run, or an agent
restarted after a long outage, where every tracked file has a multi-MB backlog.

**Trigger**

First start with `read_from_start: true` over a directory of large logs, or
restart after downtime with >= 16 files holding backlogs.

**Suggested fix**

Lower `TAIL_BATCH_SIZE` to 4 (32 spawn_blocking dispatches/s at 1000 files and
the default 500 ms poll — still trivial), and add a per-batch byte accumulator
in `tail_paths_blocking` that stops the chunk once ~4 MiB total has been staged
across all files in it, rather than 4 MiB per file.

---

## R-11 — Per-event `String` allocations on the syslog receive path and in `Event::new`

- **Severity**: Medium
- **Category**: allocation churn
- **Verified**

**Where**

`src/inputs/syslog.rs:376-397`:

```rust
fn make_event(&self, line: &str, peer: &SocketAddr) -> Event {
    let mut ev = Event::new(
        &format!("{}:{}", self.cfg.id, peer.ip()),   // alloc 1 (formatting) ...
        ...
    if ev.hostname.is_none() {
        ev.hostname = Some(peer.ip().to_string());   // alloc 3
    }
    ev.fields.insert(
        "remote_addr".to_string(),                   // alloc 4 (constant key!)
        serde_json::Value::String(peer.ip().to_string()),  // alloc 5
    );
```

`src/event.rs:36-56`:

```rust
source: source.to_string(),               // alloc 2 (copies the format! result again)
source_type: source_type.to_string(),
message: raw.to_string(),
collector_version: AGENT_VERSION.to_string(),   // <-- a &'static str, cloned per event
```

`src/pipeline/syslog.rs:120` — `ev.message = msg.strip_prefix(...).to_string();`
a *second* full copy of the body, on top of `Event::new`'s.

**Mechanism**

Counting only the fixed overhead (ignoring the body): ~7 heap allocations per
syslog event, of which at least three are avoidable — `collector_version` is a
compile-time constant re-allocated per event *and* re-serialized into every
queue record and every JSON output line; `"remote_addr".to_string()` is a
constant key; the `format!("{}:{}")` result is immediately copied again by
`Event::new`'s `to_string()`.

The double body copy (`Event::new` then `parse_syslog_into`) is the largest by
bytes: a 4 KB syslog line is allocated, copied, and freed twice per event.

**Trigger**

High-rate syslog ingest. Normal production use.

**Suggested fix**

- `collector_version: &'static str` (or `Cow<'static, str>`) on `Event` — it is
  `env!("CARGO_PKG_VERSION")`, `src/event.rs:7`. Removes one alloc/event and
  shrinks every queue record.
- Add `Event::new_owned(source: String, ...)` so `make_event`'s `format!`
  result is moved rather than re-copied.
- Cache the peer IP string once per connection in `read_stream` (it is constant
  for the connection's lifetime) instead of re-rendering it per line.

---

## R-12 — A persistent write error creates one new segment file per push, growing `segments` without bound

- **Severity**: Medium
- **Category**: unbounded growth / hot loop
- **Plausible** (code path traced and verified by reading; the specific
  OS behaviour of `File::create` succeeding while `write_all` fails under ENOSPC
  was not reproduced here)

**Where**

`src/buffer.rs:186-199`:

```rust
if let Err(e) = inner.writer.as_mut().unwrap().write_all(&rec) {
    ...
    inner.writer = None;
    roll_segment(&mut inner)?;      // creates a NEW segment file
    return Err(e.into());
}
```

**Mechanism**

If `write_all` fails but `File::create` succeeds — the classic ENOSPC shape on
ext4/XFS, where a data write fails for lack of blocks while creating an empty
inode still succeeds from the reserved pool — every subsequent `push` repeats the
cycle: open the fresh (empty) segment, fail the write, create another segment.
At full input rate this creates one file and one `BTreeSet<u64>` entry per event.
The set is in-memory and unbounded; the directory fills with empty `.seg` files
until inodes are exhausted. `ack` only removes segments strictly behind
`cursor.seg` and never the write segment (`src/buffer.rs:289-294`), so nothing
reclaims them while the consumer is stalled. `peek_batch` then walks
`segments.range(pos.seg..)` opening every one of them per call
(`src/buffer.rs:238-251`), turning each poll into thousands of `File::open`s
under the mutex.

If instead `File::create` *also* fails, you land in R-3's permanent wedge.

**Trigger**

Disk full on the queue volume with `full_policy: block` (the product default per
the project's own decision record) and traffic still arriving.

**Suggested fix**

Don't roll on write failure. The torn-tail accounting at `src/buffer.rs:190-195`
already records the real file length, so the next `push` can safely append after
it — reopen the same segment instead:

```rust
inner.writer = None;   // reopen lazily; do NOT roll
return Err(e.into());
```

and let the normal `write_off >= seg_bytes` check at `src/buffer.rs:204` handle
rolling. Add a consecutive-write-failure counter that stops attempting pushes
(and surfaces via `/healthz`) after N failures.

---

## R-13 — `retry.max_backoff_ms` is unvalidated: `0` produces the hot retry loop even with the default `initial_backoff_ms`

- **Severity**: Medium
- **Category**: hot loop
- **Verified**
- *(This is the parked `initial_backoff_ms: 0` item, but with a strictly worse
  trigger than described — reporting the delta only.)*

**Where**

`src/outputs/worker.rs:163`:

```rust
backoff = (backoff * 2).min(self.retry.max_backoff_ms);
```

`src/config/validate.rs:220-222` — the only retry validation is
`batch_size == 0`. Neither `initial_backoff_ms` nor `max_backoff_ms` is checked.

**Mechanism**

The parked finding requires an operator to write `initial_backoff_ms: 0`, which
looks obviously wrong. But `.min(max_backoff_ms)` is applied *unconditionally*,
so `max_backoff_ms: 0` — or any `max_backoff_ms < initial_backoff_ms` — clamps
the backoff to that value on the very first failure regardless of
`initial_backoff_ms`. With `max_backoff_ms: 0`, the first failure sets
`backoff = min(1000, 0) = 0` and the retry loop spins at full speed against a
dead destination: `wait_data` returns immediately (data present), `peek_batch`
reads and deserializes the batch under the mutex, `send_batch` fails,
`reset_peek`, `sleep(0)`, repeat — pinning a worker thread *and* holding the queue
mutex, which also stalls `run_router`.

`max_backoff_ms` reads like a safety cap, so `0` meaning "no cap" is a natural
operator mistake in a way that `initial_backoff_ms: 0` is not.

**Trigger**

`retry: { max_backoff_ms: 0 }` in config plus any destination outage.

**Suggested fix**

In `config/validate.rs`, next to the `batch_size` check:

```rust
if o.retry.initial_backoff_ms < 10 { bail!("outputs[{}]: retry.initial_backoff_ms must be >= 10", o.id); }
if o.retry.max_backoff_ms < o.retry.initial_backoff_ms {
    bail!("outputs[{}]: retry.max_backoff_ms must be >= retry.initial_backoff_ms", o.id);
}
```

and defensively clamp in the worker: `backoff = (backoff * 2).clamp(10, max)`.

---

## R-14 — 512 concurrent TCP connections x up to ~72 KB codec buffer is an unaccounted ~36 MB ceiling

- **Severity**: Low
- **Category**: unbounded growth (bounded, but far above the advertised footprint)
- **Verified**

**Where**

`src/inputs/syslog.rs:343` —
`FramedRead::new(stream, LinesCodec::new_with_max_length(MAX_MSG))` with
`MAX_MSG = 64 * 1024` (`src/inputs/syslog.rs:23`).
`src/config/schema.rs:180-182` — `default_max_connections() -> 512`.

**Mechanism**

`LinesCodec` correctly errors at 64 KB and the connection is dropped
(`src/inputs/syslog.rs:360`), so there is no unbounded growth — but a peer that
sends 63 KB without a newline holds a 64 KB `BytesMut` for up to
`idle_timeout_secs` (default 300 s, `src/config/schema.rs:184-186`). 512 such
peers = ~32-36 MB resident, against an advertised ~12 MB footprint, sustained for
5 minutes, from unauthenticated senders.

**Trigger**

Adversarial or misbehaving senders; not reachable by well-formed syslog traffic.

**Suggested fix**

None strictly required — but document the real worst-case RSS as
`max_connections * 64 KB` alongside `CHANNEL_BYTES`, and consider lowering the
default `max_connections` to 128 (a syslog relay rarely needs 512 concurrent
*streams*).

---

## R-15 — `read_record` trusts an on-disk length header bounded only by the file size

- **Severity**: Low
- **Category**: startup spike / allocation
- **Verified**

**Where**

`src/buffer.rs:536-539`:

```rust
if len == 0 || len > max_believable_len { return Ok(RecordRead::Eof); }
let mut payload = vec![0u8; len as usize];
```

`max_believable_len` is the *file's* size, passed from `peek_batch`
(`src/buffer.rs:249`), `scan_segment` (`src/buffer.rs:477`) and
`oldest_age_secs` (`src/buffer.rs:384`).

**Mechanism**

A corrupt 4-byte header can request an allocation up to the segment file's size.
With `segment_size_mb: 8` that is an 8 MB `vec![0u8; ...]` per corrupt record
encountered, and `open()`'s startup `scan_segment` walks the whole write segment.
The comment at `src/buffer.rs:515-524` correctly explains why the bound cannot be
`segment_size_mb` — a legitimate record can exceed it — but the resulting bound
is far looser than any real record.

**Trigger**

Segment corruption (power loss, bad sector). Rare.

**Suggested fix**

Bound on `max_believable_len.min(a configured absolute record ceiling)`, e.g.
`min(file_len, 64 * 1024 * 1024)`, and reserve incrementally
(`Vec::with_capacity` + `take(len).read_to_end`) so a bogus length costs a failed
read rather than an upfront allocation.

---

## R-16 — Smaller per-event / per-tick churn worth batching into one cleanup pass

- **Severity**: Low
- **Category**: allocation churn
- **Verified**

1. `src/pipeline/enrich.rs:60-88` — `Enricher::apply` allocates a fresh `String`
   key per enrichment entry per event (`"os".to_string()`, `key.to_string()`,
   `k.clone()`), because `serde_json::Map::entry` requires an owned key. With 8
   enrichment fields that is 8 key allocations per event on top of the value
   clones.
2. `src/inputs/file.rs:469` and `src/inputs/file.rs:477` — `tail_once` clones
   every tracked `PathBuf` twice per poll tick
   (`tracked.keys().cloned().collect()` then `chunk.to_vec()`). At 1000 tracked
   files and the default 500 ms poll that is 4000 path allocations/second for
   no benefit; the second clone could be avoided by chunking an `Arc<[PathBuf]>`
   or by draining indices.
3. `src/logbuf.rs:57-66` — `MessageVisitor::record_debug` allocates
   `format!("{value:?}")` plus a `format!("{}={:?}")` per non-message field for
   every event at DEBUG or above, *before* any level filtering beyond the TRACE
   guard at `src/logbuf.rs:71`. Only matters at `log_level: debug`.
4. `src/outputs/format.rs:83-92` — `sd_escape` allocates a new `String` per
   structured-data param per event on the rfc5424 path, even when nothing needs
   escaping (the common case). A `memchr`-style pre-scan returning
   `Cow::Borrowed` removes it.

**Suggested fix**

All four are mechanical. (4) and (1) are the highest value per line changed.

---

# Things I checked and found to be fine

- **`StatusRegistry` growth across reloads** — `src/metrics.rs:78-81` has no
  removal method, but `StatusRegistry::default()` is constructed fresh inside
  `Engine::build` (`src/engine.rs:297`) and reload creates a whole new engine, so
  stale entries cannot accumulate. Entries are keyed by config-declared
  input/output ids, never by anything client-controlled.
- **`Tracked` file-map eviction** — `src/inputs/file.rs:423`,
  `owned.retain(|p, _| p.exists())` runs on every discovery pass, so
  rotated-away and deleted paths *are* evicted from memory (not just from
  `state.json`). The map is bounded by files currently on disk matching the glob.
- **Detached per-connection syslog tasks** — `src/inputs/syslog.rs:294` spawns
  without keeping the handle, and `Engine::stop` never awaits them. Not a leak:
  they receive a clone of the engine's cancellation token and
  `read_stream`'s `tokio::select!` (`src/inputs/syslog.rs:349-372`) polls
  `cancel.cancelled()` on every iteration while already parked on the read, so
  cancellation wakes them immediately. They also cannot deadlock on the byte
  budget at shutdown: `run_pipeline`'s drain arm (`src/engine.rs:550-553`) calls
  `budget.release` for every event it pulls, returning all forgotten permits
  before `rx` is dropped, so a task parked in `acquire_many_owned` unblocks and
  then fails the send cleanly.
- **`OutputWorker`'s empty-batch hot loop** — the 100 ms floor at
  `src/outputs/worker.rs:94-97` is on the only early-`continue` path that can
  fire repeatedly; the other `continue` (`src/outputs/worker.rs:99-103`) sleeps
  1 s. Both are covered.
- **`wait_data` lost/spurious wakeup degenerating into a spin** —
  `src/buffer.rs:396-416`. The `notify_waiters()` at `src/buffer.rs:208` can be
  lost in the window between the lock release and `notified()` registration, but
  the `sleep(500ms)` arm bounds the worst case to a 2 Hz re-check, and the
  `has` predicate (`peek != write position && count > 0`) converges: after
  `peek_batch` walks past unusable records, `peek` reaches the write position and
  the loop parks.
- **`peek_batch` wedging on an unskippable record** — I hypothesised that a
  `len == 0` header (`src/buffer.rs:536`) would pin `peek` and spin the worker at
  10 Hz forever. **Eliminated by repro**: the segment `for` loop at
  `src/buffer.rs:239-276` continues to the next segment after the inner `break`,
  so `pos` always advances to the last segment. The write segment (the only one
  where `pos` could stall) is repaired by `open()`'s `set_len(valid_len)`
  (`src/buffer.rs:95-100`). *However*, the same repro showed that everything after
  a zero-hole in a non-write segment is silently discarded **without**
  incrementing `corrupt_records` — a correctness/observability bug, outside this
  report's resource remit but worth a ticket.
- **`LinesCodec` unbounded framing buffer** — bounded at `MAX_MSG` (64 KB) via
  `new_with_max_length` (`src/inputs/syslog.rs:343`); exceeding it returns an
  error that closes the connection (`src/inputs/syslog.rs:360`). See R-14 for the
  aggregate ceiling.
- **UDP flood** — the receive buffer is allocated once outside the loop
  (`src/inputs/syslog.rs:178`); rejected datagrams take only an atomic increment,
  with log/status writes throttled to 1-in-100 (`src/inputs/syslog.rs:38-55`).
  Every admitted event goes through `EventSender::send`, so the byte budget
  covers it.
- **`router_shed` / `queues` / `EngineShared`** — all `HashMap`s keyed by
  config-declared output ids (`src/engine.rs:305,327`), fixed size for the life of
  an engine.
- **`logbuf` ring buffer** — hard capacity 500 with `pop_front`
  (`src/logbuf.rs:11,43-49`); `recent()` clamps `limit` to `CAPACITY`
  (`src/logbuf.rs:38`) and `/api/logs` clamps to 500 again (`src/web.rs:474`).
- **`Metrics::last_error`** — a single `Mutex<Option<String>>` overwritten in
  place (`src/metrics.rs:26`), not a growing list.
- **`state.json` growth** — bounded by `retention_secs` pruning on every
  `flush()` (`src/state.rs:175-178`) plus the once-a-minute `touched` refresh
  guard (`src/state.rs:104-109`) that stops idle files re-dirtying it.
- **Regex compilation** — all pre-compiled at engine start:
  `CompiledCondition::compile` (`src/pipeline/condition.rs:23-41`),
  `CompiledStep::Mask` (`src/pipeline/transform.rs:90`),
  `Parser::compile` (`src/pipeline/parser.rs:30`). No per-event `Regex::new`
  anywhere. Startup cost scales linearly with the number of conditions and is
  milliseconds, not seconds.
- **Windows eventlog blocking threads and shutdown** — `run_channel`'s
  cancellation reach is bounded: `WaitForSingleObject(signal, WAIT_MS)` with
  `WAIT_MS = 1000` (`src/inputs/eventlog.rs:39,464`), a cancel check at the top
  of both drain loops (`src/inputs/eventlog.rs:460,467`), and a backoff sleep
  that polls cancellation every 100 ms (`src/inputs/eventlog.rs:225-230`). Normal
  shutdown reaches them well inside `Engine::stop`'s 8 s. (The residual risk is
  R-6's: `spawn_blocking` tasks cannot be aborted at all if they *do* hang.)
- **`route_event` fan-out** — `Arc::new(ev)` once, `Arc::clone` per destination
  (`src/engine.rs:596,627`), so the event body is not duplicated per output. This
  is done right.
- **`EventSender` coverage** — every input path goes through `send`
  (`src/inputs/syslog.rs:207,358`, `src/inputs/file.rs:510`) or `blocking_send`
  (`src/inputs/eventlog.rs:510`). No producer bypasses the byte budget.

---

# Overall verdict

This codebase's resource hygiene is unusually good *at the level it was designed
at*: the byte-budgeted channel, per-destination router isolation with explicit
shedding, the `Arc<Event>` fan-out, pre-compiled regexes, opt-in `raw_message`,
dirty-flag state persistence, bounded log ring, connection caps with idle
timeouts, and correct eviction of vanished files all show a team that has already
been through one serious resource pass and internalised the lessons. There is no
classic unbounded-collection memory leak anywhere in the agent — I looked
specifically at everything keyed by a client-controlled string (source IP,
hostname, provider name, file path) and found nothing that accumulates. The
remaining problems are concentrated in one place and are of one kind: **the
`DiskQueue` is a synchronous, mutex-guarded, fsync-heavy component being driven
directly from a 2-thread async runtime** (R-1, R-2, R-7, R-8), which is both the
dominant CPU cost under load and the real explanation for the shed counter that
was added to paper over it. Alongside that sit two genuine correctness-shaped
resource bugs in the same file — a fallible-operation-after-state-mutation
ordering bug that permanently wedges a queue and converts the router into a
per-event allocation loop (R-3, reproduced), and a batch reader bounded by count
rather than bytes (R-4) — plus one real allocation hot spot in the condition DSL
(R-5). Fixing R-1 through R-5 is perhaps 150 lines of change and would address
the large majority of the agent's CPU-under-load and worst-case-RSS exposure;
everything below that is polish.
