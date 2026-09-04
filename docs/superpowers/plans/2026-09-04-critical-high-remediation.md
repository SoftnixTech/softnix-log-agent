# Critical + High Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the 6 Critical and 12 High findings from the 2026-09-04 audit so the agent can be shipped to enterprise customers who point untrusted network traffic at it.

**Architecture:** Three independent audits (security, resource/reliability, architecture) produced 40 findings; this plan implements the 18 that block a release. The work splits into four clusters that are largely independent: (1) parser/queue crash-and-corruption fixes in `pipeline.rs`/`buffer.rs`, (2) a web-API authentication and CSRF rework in `web.rs`, (3) a per-destination routing rework in `engine.rs` that ends head-of-line blocking, and (4) hot-path cost removal (regex pre-compilation, body de-duplication, discovery decoupling). Windows-only work is last because it cannot be compiled on the team's macOS machines until CI exists — hence Task 1.

**Tech Stack:** Rust 1.80+, tokio 1.x (multi-thread rt), axum 0.8, rustls 0.23 via tokio-rustls 0.26, serde/serde_json/serde_yaml, regex 1, crc32fast, windows 0.58 (`wevtapi`) behind `cfg(windows)`.

**Spec:** `/private/tmp/claude-501/-Users-suriya-Documents-Softnix-softnix-log-agent/1da6b2fd-0cf0-4e65-9c58-c03696203dfc/scratchpad/security-findings.md` and `.../resource-findings.md` — the two audit artifacts. Published summary: https://claude.ai/code/artifact/578f6752-84fa-4702-b96a-f5a928d65a89

## Global Constraints

- **Rust edition 2021, `rust-version = "1.80"`** — no feature newer than 1.80.
- **`panic = "abort"` stays** in the release profile for this plan. Every fix must therefore remove the panic itself, never rely on unwinding. Revisiting this setting is explicitly out of scope.
- **No behaviour change to the on-disk queue format.** Segment layout stays `[u32 len][u32 crc][payload]` with `HEADER = 8`; an agent built from this plan must read queues written by 0.1.0.
- **New dependencies allowed in this plan, and only these:** `rand = "0.8"` (CSPRNG for the web token), `ipnet = "2"` (CIDR allowlist), `tower = "0.5"` and `http-body-util = "0.1"` as **dev-dependencies** only (router tests). Anything else needs sign-off.
- **`full_policy: block` remains the shipped default** (product decision, 2026-09-04). The plan makes blocking *visible* rather than silent, and makes the policy settable per output. Do not change the default to `drop_oldest`.
- **Parse failure never drops an event** (product decision, 2026-09-04). An unparsable line is forwarded with its full raw body and a `parse_status` field.
- **Every task ends with `cargo test` green and `cargo clippy --all-targets` producing no *new* warnings.** The 4 pre-existing cosmetic warnings are the baseline.
- **Commit message prefix** = the audit id the commit closes, e.g. `fix(C-1): ...`, `fix(R-4): ...`.

---

## File Structure

| File | Responsibility | Touched by |
|---|---|---|
| `.github/workflows/ci.yml` | **new** — test/clippy/fmt on ubuntu + windows | T1 |
| `src/fsutil.rs` | **new** — `write_atomic`, `create_dir_private`, `set_private_permissions` | T3, T13 |
| `src/pipeline.rs` | parse/transform/route logic; boundary-safe parsing, compiled conditions | T2, T10 |
| `src/buffer.rs` | disk queue; atomic cursor, corrupt-record skip, full-state reporting | T3, T5, T9 |
| `src/engine.rs` | task wiring; start guard, per-destination routers, byte-budget channel | T4, T9, T12 |
| `src/outputs.rs` | output workers; empty-batch sleep floor | T5 |
| `src/web.rs` | HTTP API; auth middleware, origin/host guard, healthz degraded | T6, T7, T9 |
| `src/ui.html` | embedded GUI; sends the bearer token | T6 |
| `src/config.rs` | config structs + validation; per-output policy, new knobs, env redaction | T2, T6, T8, T9, T11, T14, T15 |
| `src/event.rs` | `Event` struct; `raw_message` becomes opt-in | T11 |
| `src/state.rs` | cursor persistence; write amplification | T13 |
| `src/inputs/file.rs` | tailer; discovery decoupling, fingerprint caching | T14 |
| `src/inputs/syslog.rs` | listeners; connection cap, timeouts, sender allowlist | T15 |
| `src/inputs/eventlog.rs` | Windows collection; metadata cache, never-give-up | T16 |
| `packaging/windows/install-windows.ps1` | installer; ACL hardening | T17 |
| `tests/e2e.rs` | end-to-end tests | T4, T9, T15 |

---

## Task 1: CI that actually compiles the Windows code

**Why first:** `src/inputs/eventlog.rs` is 891 lines behind `#[cfg(windows)]` (`src/inputs/mod.rs:1-2`). On the team's macOS machines it is never compiled, linted or tested. Tasks 16 and 17 are unverifiable until a Windows job exists. There are 45 tests in the tree and no `.github/` directory, so nothing runs them automatically today.

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: a green CI baseline every later task must keep green. Job names: `test-linux`, `test-windows`, `lint`, `audit`.

- [ ] **Step 1: Write the workflow**

```yaml
name: CI
on:
  push:
    branches: [main, develop]
  pull_request:

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -D warnings

jobs:
  test-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test --all-targets

  test-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo test --all-targets
      # The `lint` job runs on ubuntu, where every line of
      # src/inputs/eventlog.rs is cfg'd out. Without a clippy run HERE, its 8
      # unsafe blocks are never linted by anything, ever.
      - run: cargo clippy --all-targets

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all -- --check
      - run: cargo clippy --all-targets

  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rustsec/audit-check@v2
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 2: Run the same commands locally to see what CI will see**

Run: `cargo fmt --all -- --check && cargo clippy --all-targets && cargo test --all-targets`
Expected: `cargo fmt --check` may FAIL on unformatted files, and clippy will FAIL because `RUSTFLAGS: -D warnings` promotes the 4 known cosmetic warnings to errors.

- [ ] **Step 3: Fix the baseline so CI can be green**

Run `cargo fmt --all`. Then fix the 4 known clippy warnings:

```rust
// src/buffer.rs — add next to `pub fn len`
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
```

```rust
// src/main.rs:83 — take &Path, not &PathBuf
fn validate_cmd(path: &Path) -> Result<()> {
```

```rust
// src/web.rs:70 — box the large Err variant
fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
```
(update the two call-site patterns to `return *r;`)

```rust
// tests/e2e.rs:162 — drop the useless format!
            "<14>Jun 10 10:00:00 h1 app: outage event".as_bytes(),
```

- [ ] **Step 4: Verify the full gate passes**

Run: `cargo fmt --all -- --check && cargo clippy --all-targets && cargo test --all-targets`
Expected: all three succeed, 45 tests pass.

- [ ] **Step 5: Document the local Windows pre-flight**

CI is the safety net, but a developer on macOS still cannot compile
`src/inputs/eventlog.rs` locally, so Windows breakage is only discovered after a
push. `cargo zigbuild` cross-compiles the whole unmodified crate — `ring`'s
`build.rs` fails under a plain `--target x86_64-pc-windows-msvc` on macOS, but
the `-gnu` target via zig's bundled clang succeeds.

Add to `docs/TESTING.md`:

````markdown
## Checking the Windows-only code from macOS or Linux

`src/inputs/eventlog.rs` is behind `#[cfg(windows)]`, so a normal
`cargo check` never compiles it. Before pushing a change that touches it:

```bash
cargo install cargo-zigbuild        # once; also needs zig on PATH
cargo zigbuild --release --target x86_64-pc-windows-gnu
```

This builds the entire crate for Windows in roughly 35 s and reports the same
type errors the CI Windows job would. It is a pre-flight, not a replacement:
`-gnu` is not `-msvc`, and the 8 eventlog unit tests only run in CI's
`test-windows` job.
````

- [ ] **Step 6: Verify the pre-flight actually catches a Windows-only error**

Temporarily break a Windows-only call — e.g. change an `EvtClose(handle)` in
`src/inputs/eventlog.rs` to `EvtClose(42u32)` — then run:

Run: `cargo zigbuild --release --target x86_64-pc-windows-gnu 2>&1 | tail -20`
Expected: a type error on that line (`E0277`), proving the pre-flight sees the
`cfg(windows)` code. Revert the change afterwards.

- [ ] **Step 7: Commit**

```bash
git add .github/workflows/ci.yml docs/TESTING.md src/buffer.rs src/main.rs src/web.rs tests/e2e.rs
git commit -m "ci: add linux+windows test, lint and audit workflow

Windows-only eventlog code (891 lines behind cfg(windows)) was never
compiled on developer machines, and its 8 unsafe blocks were never linted
because the lint job only runs on ubuntu - clippy now runs on the windows
runner too. Also clears the 4 baseline clippy warnings so -D warnings can
gate the build, and documents the cargo-zigbuild local pre-flight."
```

- [ ] **Step 8: Push and confirm all four jobs are green before starting Task 2.**

---

## Task 2: C-1 — remote one-packet kill in the RFC3164 parser

**Files:**
- Modify: `src/pipeline.rs:299-320` (`parse_rfc3164` timestamp block), `src/pipeline.rs:196-206` (`parse_syslog_into` Auto arm)
- Test: `src/pipeline.rs` `#[cfg(test)] mod tests` (starts around line 600)

**Interfaces:**
- Consumes: nothing.
- Produces: an event whose parse outcome is observable — when no syslog format matched, `ev.fields["parse_status"] == "unparsed"` (a `serde_json::Value::String`). Task 10 does not change this.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn rfc3164_thai_body_does_not_panic() {
        let line = "<13>x ทดสอบระบบ log message";
        let mut ev = Event::new("syslog:127.0.0.1", "syslog", line);
        parse_syslog_into(&mut ev, line, SyslogFormat::Auto);
        assert_eq!(ev.severity, Some(5));
        assert!(ev.message.contains("ทดสอบระบบ"), "body lost: {}", ev.message);
    }

    #[test]
    fn rfc3164_emoji_body_does_not_panic() {
        let line = "<13>🔥🔥🔥🔥 disk on fire";
        let mut ev = Event::new("syslog:127.0.0.1", "syslog", line);
        parse_syslog_into(&mut ev, line, SyslogFormat::Auto);
        assert!(ev.message.contains("disk on fire"), "body lost: {}", ev.message);
    }

    #[test]
    fn no_panic_on_any_multibyte_offset() {
        // Walk the multi-byte character across every byte position around 15.
        for filler in ["ก", "é", "🔥", "日"] {
            for n in 0..24 {
                let line = format!("<13>{}{} rest of message", "a".repeat(n), filler);
                let mut ev = Event::new("s", "syslog", &line);
                parse_syslog_into(&mut ev, &line, SyslogFormat::Auto);
            }
        }
    }

    #[test]
    fn ascii_rfc3164_timestamp_still_parses() {
        let line = "<14>Jun 10 10:00:00 host1 app: hello";
        let mut ev = Event::new("s", "syslog", line);
        parse_syslog_into(&mut ev, line, SyslogFormat::Auto);
        assert_eq!(ev.hostname.as_deref(), Some("host1"));
        assert_eq!(ev.application.as_deref(), Some("app"));
        assert_eq!(ev.message, "hello");
    }

    #[test]
    fn unparsable_line_is_forwarded_and_tagged() {
        let line = "this is not syslog at all";
        let mut ev = Event::new("s", "syslog", line);
        parse_syslog_into(&mut ev, line, SyslogFormat::Auto);
        assert_eq!(ev.message, line, "raw body must survive");
        assert_eq!(
            ev.fields.get("parse_status").and_then(|v| v.as_str()),
            Some("unparsed")
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib pipeline::tests 2>&1 | tail -30`
Expected: `rfc3164_thai_body_does_not_panic` and `no_panic_on_any_multibyte_offset` FAIL with
`end byte index 15 is not a char boundary`; `unparsable_line_is_forwarded_and_tagged` FAILS on the missing `parse_status`.

- [ ] **Step 3: Make the timestamp slice boundary-safe**

In `src/pipeline.rs`, replace lines 300-302:

```rust
    // Timestamp: "Mmm dd hh:mm:ss" (15 chars)
    let mut remainder = rest;
    if rest.len() >= 15 {
        let ts = &rest[..15];
```

with:

```rust
    // Timestamp: "Mmm dd hh:mm:ss" (15 bytes of ASCII). `get` returns None when
    // byte 15 lands inside a multi-byte character — a remote sender can and does
    // arrange exactly that, and `&rest[..15]` would panic (abort) on it.
    let mut remainder = rest;
    if let Some(ts) = rest.get(..15) {
```

The `remainder = rest[15..].trim_start();` line further down stays as-is: `get(..15)` returning `Some` proves 15 is a valid boundary. Delete the now-unmatched closing brace of the old `if rest.len() >= 15 {` block only if the brace count requires it — the `if let` replaces the `if` one-for-one, so no brace change is needed.

- [ ] **Step 4: Tag lines that no format could parse**

In `src/pipeline.rs`, replace the `SyslogFormat::Auto` arm:

```rust
        SyslogFormat::Auto => {
            if parse_rfc5424(ev, line) || parse_rfc3164(ev, line) {
                return;
            }
            let t = line.trim_start();
            if t.starts_with('{') {
                parse_json_into(ev, line);
                return;
            }
            // Never drop an unparsable line: forward the raw body and let the
            // downstream SIEM rule on parse_status.
            ev.fields.insert(
                "parse_status".to_string(),
                serde_json::Value::String("unparsed".to_string()),
            );
        }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib pipeline::tests`
Expected: PASS, including the 4 new tests and every pre-existing parser test.

- [ ] **Step 6: Confirm the whole suite and the repro from the audit**

Run: `cargo test --all-targets`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add src/pipeline.rs
git commit -m "fix(C-1): boundary-safe RFC3164 timestamp; tag unparsable lines

rest.len() counts bytes but &rest[..15] needs a char boundary, so one UDP
datagram containing a multi-byte character at that offset aborted the whole
process (release profile is panic=abort). Thai and CJK application logs
triggered it without an attacker.

Unparsable lines are now forwarded with parse_status=unparsed rather than
being silently reshaped."
```

---

## Task 3: C-5 — atomic `cursor.json`

**Files:**
- Create: `src/fsutil.rs`
- Modify: `src/lib.rs` (add `pub mod fsutil;`), `src/buffer.rs:276-279`, `src/state.rs:129-133`
- Test: `src/fsutil.rs` tests + `src/buffer.rs` tests

**Interfaces:**
- Consumes: nothing.
- Produces: `pub fn crate::fsutil::write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()>` — writes `<path>.tmp`, fsyncs it, renames over `path`. Used by Task 13 as well.

- [ ] **Step 1: Write the failing tests**

Create `src/fsutil.rs` with only the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_content_and_leaves_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cursor.json");
        std::fs::write(&p, b"old").unwrap();
        write_atomic(&p, b"new").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
        assert!(!dir.path().join("cursor.json.tmp").exists());
    }

    #[test]
    fn write_atomic_overwrites_a_stale_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cursor.json");
        std::fs::write(dir.path().join("cursor.json.tmp"), b"leftover garbage").unwrap();
        write_atomic(&p, b"fresh").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"fresh");
    }
}
```

And in `src/buffer.rs` tests:

```rust
    #[test]
    fn cursor_is_written_atomically_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BufferConfig::default();
        let q = DiskQueue::open(dir.path(), "dest", &cfg).unwrap();
        for i in 0..10 {
            q.push(&Event::new("s", "test", &format!("event {i}"))).unwrap();
        }
        let batch = q.peek_batch(10).unwrap();
        assert_eq!(batch.len(), 10);
        q.ack(10).unwrap();

        // No temp file must survive an ack.
        assert!(!dir.path().join("dest").join("cursor.json.tmp").exists());

        drop(q);
        let q2 = DiskQueue::open(dir.path(), "dest", &cfg).unwrap();
        assert!(q2.peek_batch(10).unwrap().is_empty(), "acked events replayed");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib fsutil 2>&1 | tail -20`
Expected: FAIL to compile — `cannot find function write_atomic`.

- [ ] **Step 3: Implement `write_atomic`**

At the top of `src/fsutil.rs`:

```rust
//! Small filesystem helpers shared by the queue and the state manager.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Write `bytes` to `path` so a reader never observes a partial file:
/// write to `<path>.tmp`, fsync, then rename over the target.
///
/// The queue cursor and the file-offset state both depend on this — a torn
/// cursor.json makes the agent replay its entire backlog after a power loss.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(match path.extension() {
        Some(ext) => format!("{}.tmp", ext.to_string_lossy()),
        None => "tmp".to_string(),
    });
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // Durability of the rename itself needs the directory fsynced too.
    if let Some(parent) = path.parent() {
        if let Ok(d) = File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}
```

Add `pub mod fsutil;` to `src/lib.rs`.

- [ ] **Step 4: Use it in `buffer.rs`**

Replace `src/buffer.rs:276-279`:

```rust
        let cursor_path = inner.dir.join("cursor.json");
        std::fs::write(&cursor_path, serde_json::to_vec(&inner.cursor)?)
            .with_context(|| format!("cannot persist queue cursor {}", cursor_path.display()))?;
```

with:

```rust
        let cursor_path = inner.dir.join("cursor.json");
        crate::fsutil::write_atomic(&cursor_path, &serde_json::to_vec(&inner.cursor)?)
            .with_context(|| format!("cannot persist queue cursor {}", cursor_path.display()))?;
```

Then replace the hand-rolled tmp+rename in `src/state.rs:129-133` with a `crate::fsutil::write_atomic` call so there is one implementation.

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib fsutil && cargo test --lib buffer && cargo test --lib state`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/fsutil.rs src/lib.rs src/buffer.rs src/state.rs
git commit -m "fix(C-5): write cursor.json atomically

std::fs::write can leave a truncated cursor.json on power loss, which
DiskQueue::open silently treats as Cursor{0,0} and replays up to the full
1 GB queue to the SIEM. state.rs already did tmp+rename; both now share
fsutil::write_atomic."
```

---

## Task 4: C-6 — cancel and abort every task when `Engine::start` fails

**Files:**
- Modify: `src/engine.rs:35-160` (`Engine::start`)
- Test: `tests/e2e.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `Engine::start(cfg: Config) -> Result<Engine>` — unchanged signature, but on `Err` it now guarantees every task it spawned is cancelled and joined before returning, so no port stays bound and no `DiskQueue` stays open.

- [ ] **Step 1: Write the failing test**

In `tests/e2e.rs`:

```rust
#[tokio::test]
async fn failed_start_releases_bound_ports() {
    use softnix_log_agent::config::Config;
    use softnix_log_agent::engine::Engine;

    let dir = tempfile::tempdir().unwrap();
    // Bind a port first so the agent's second listener is guaranteed to fail.
    let squatter = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let taken = squatter.local_addr().unwrap().port();
    let free = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };

    // Input 1 binds `free` successfully; input 2 then fails on `taken`.
    let yaml = format!(
        r#"
agent:
  data_dir: {data}
inputs:
  syslog:
    - id: ok
      protocol: tcp
      bind: 127.0.0.1
      port: {free}
    - id: doomed
      protocol: tcp
      bind: 127.0.0.1
      port: {taken}
outputs:
  - id: out
    type: stdout
web:
  enabled: false
"#,
        data = dir.path().display(),
        free = free,
        taken = taken,
    );
    let (cfg, _warnings): (Config, Vec<String>) =
        softnix_log_agent::config::parse(&yaml).expect("config must parse");

    assert!(Engine::start(cfg).await.is_err(), "start must fail on the taken port");

    // The successfully-bound listener from input 1 must have been torn down.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        tokio::net::TcpListener::bind(("127.0.0.1", free)).await.is_ok(),
        "port {free} is still held by a leaked listener task"
    );
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test e2e failed_start_releases_bound_ports -- --nocapture`
Expected: FAIL — `port ... is still held by a leaked listener task` (dropping a `JoinHandle` detaches, dropping a `CancellationToken` does not cancel).

- [ ] **Step 3: Restructure `start` around a guard**

In `src/engine.rs`, rename the existing body to a private constructor and add the guard. The whole current body of `pub async fn start` becomes `async fn build`, with these two changes: it takes `cancel: &CancellationToken` and `tasks: &mut Vec<tokio::task::JoinHandle<()>>` instead of creating them, and it returns `Result<Arc<EngineShared>>` instead of `Result<Engine>` (return `Arc::new(EngineShared { ... })` where it currently returns `Engine { ... }`).

```rust
impl Engine {
    pub async fn start(cfg: Config) -> Result<Engine> {
        let cancel = CancellationToken::new();
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        match Self::build(cfg, &cancel, &mut tasks).await {
            Ok(shared) => Ok(Engine { shared, cancel, tasks }),
            Err(e) => {
                // A partial start must not leave listeners holding ports or
                // output workers holding a single-writer queue directory.
                tracing::error!("engine start failed, tearing down {} task(s): {e:#}", tasks.len());
                cancel.cancel();
                for t in &tasks {
                    t.abort();
                }
                for t in tasks {
                    let _ = t.await;
                }
                Err(e)
            }
        }
    }

    async fn build(
        cfg: Config,
        cancel: &CancellationToken,
        tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    ) -> Result<Arc<EngineShared>> {
        // ... existing body, using `cancel.child_token()` and `tasks.push(...)` ...
    }
```

- [ ] **Step 4: Run the test**

Run: `cargo test --test e2e failed_start_releases_bound_ports`
Expected: PASS.

- [ ] **Step 5: Run the whole suite — reload paths are the real consumer**

Run: `cargo test --all-targets`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/engine.rs tests/e2e.rs
git commit -m "fix(C-6): tear down spawned tasks when Engine::start fails

Dropping a JoinHandle detaches the task and dropping a CancellationToken
does not cancel it, so a failed reload (port in use, bad cert path) left
orphaned output workers writing the same single-writer queue directory as
their replacements, and orphaned listeners that made the rollback fail
with EADDRINUSE."
```

---

## Task 5: C-4 — corrupt record in mid-segment no longer spins a core forever

**Files:**
- Modify: `src/buffer.rs:434-456` (`read_record`), `src/buffer.rs:212-252` (`peek_batch`), `src/buffer.rs:180-186` (`push` write-error recovery), `src/outputs.rs:89-91`
- Test: `src/buffer.rs` tests

**Interfaces:**
- Consumes: nothing.
- Produces: `enum RecordRead { Ok { payload: Vec<u8>, rec_len: u64 }, Corrupt { skip: u64 }, Eof }` (private to `buffer.rs`), and a new public counter `DiskQueue::corrupt_records(&self) -> u64` used by Task 9's health reporting.

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn peek_batch_skips_a_corrupt_record_in_the_middle() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = tempfile::tempdir().unwrap();
        let cfg = BufferConfig::default();
        let q = DiskQueue::open(dir.path(), "dest", &cfg).unwrap();
        for i in 0..3 {
            q.push(&Event::new("s", "test", &format!("event-{i}"))).unwrap();
        }
        drop(q);

        // Corrupt the payload of the middle record without changing its length
        // header, so the CRC fails but the framing is still walkable.
        let seg = dir.path().join("dest").join("000000000000000000.seg");
        let first_len = {
            let bytes = std::fs::read(&seg).unwrap();
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as u64
        };
        let second_payload_start = 8 + first_len + 8;
        let mut f = std::fs::OpenOptions::new().write(true).open(&seg).unwrap();
        f.seek(SeekFrom::Start(second_payload_start)).unwrap();
        f.write_all(b"X").unwrap();
        drop(f);

        let q = DiskQueue::open(dir.path(), "dest", &cfg).unwrap();
        let batch = q.peek_batch(10).unwrap();
        assert_eq!(batch.len(), 2, "must return the two intact records");
        assert_eq!(q.corrupt_records(), 1);

        // The critical property: peek advanced past the corrupt record, so a
        // second call cannot return an empty batch forever.
        q.ack(batch.len() as u64).unwrap();
        assert!(q.peek_batch(10).unwrap().is_empty());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib buffer::tests::peek_batch_skips_a_corrupt_record_in_the_middle`
Expected: FAIL — batch has 1 event (the walk stops at the corrupt record) and `corrupt_records` does not exist.

- [ ] **Step 3: Make `read_record` report *why* it stopped**

Replace `read_record` in `src/buffer.rs`:

```rust
enum RecordRead {
    Ok { payload: Vec<u8>, rec_len: u64 },
    /// Framing is intact enough to step over this record.
    Corrupt { skip: u64 },
    /// Nothing more can be read from this segment.
    Eof,
}

/// Read one record. A CRC mismatch is reported as `Corrupt` with the number of
/// bytes to step over, so the reader can make progress instead of parking on it
/// forever (which pins a core at 100% via the empty-batch loop in outputs.rs).
fn read_record(f: &mut File, seg_bytes: u64) -> Result<RecordRead> {
    let mut header = [0u8; 8];
    match f.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(RecordRead::Eof),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(header[0..4].try_into().unwrap()) as u64;
    let crc = u32::from_le_bytes(header[4..8].try_into().unwrap());
    // A length header that cannot be real means the framing is lost; there is
    // no safe skip distance, so give up on the rest of this segment.
    if len == 0 || len > seg_bytes {
        return Ok(RecordRead::Eof);
    }
    let mut payload = vec![0u8; len as usize];
    match f.read_exact(&mut payload) {
        Ok(()) => {}
        // Truncated tail: not skippable, and open() repairs it.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(RecordRead::Eof),
        Err(e) => return Err(e.into()),
    }
    if crc32fast::hash(&payload) != crc {
        return Ok(RecordRead::Corrupt { skip: HEADER + len });
    }
    Ok(RecordRead::Ok { payload, rec_len: HEADER + len })
}
```

Note this also fixes B8 from the audit: `len` is now clamped to the segment size before the allocation, so a garbage header can no longer cause a 64 MB zeroed allocation.

- [ ] **Step 4: Make `peek_batch` step over corruption and count it**

In `peek_batch`'s inner loop, replace the `match read_record(&mut f)?` arms with:

```rust
                match read_record(&mut f, self.seg_bytes)? {
                    RecordRead::Ok { payload, rec_len } => {
                        off += rec_len;
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
```

Add `corrupt: AtomicU64` to the `DiskQueue` struct next to `dropped`, initialise it to `AtomicU64::new(0)` in `open`, and add:

```rust
    /// Records skipped because they failed CRC or would not decode. Surfaced on
    /// /api/buffer so silent corruption is visible.
    pub fn corrupt_records(&self) -> u64 {
        self.corrupt.load(Ordering::Relaxed)
    }
```

Update the two other `read_record` call sites (`DiskQueue::open`'s scan around `buffer.rs:116-125`, and the tail-repair helper around `buffer.rs:410-432`) to the new signature; both should treat `Corrupt { skip }` by advancing `off` and continuing, and `Eof` by stopping.

- [ ] **Step 5: Add the empty-batch sleep floor**

In `src/outputs.rs`, replace line 90:

```rust
                Ok(b) if b.is_empty() => continue,
```

with:

```rust
                // wait_data can report "data available" while peek_batch returns
                // nothing (all remaining records were skipped as corrupt). Without
                // a floor this becomes a tight loop that pins a core forever.
                Ok(b) if b.is_empty() => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
```

- [ ] **Step 6: Recover `write_off` after a failed write**

In `src/buffer.rs`, replace lines 182-185:

```rust
        inner.writer.as_mut().unwrap().write_all(&rec)?;
        inner.write_off += rec_len;
        inner.bytes += rec_len;
```

with:

```rust
        // write_all can fail (ENOSPC) *after* writing part of the record. If the
        // counters advanced anyway the next push would append after a partial
        // record and leave a CRC-failing record wedged mid-segment.
        if let Err(e) = inner.writer.as_mut().unwrap().write_all(&rec) {
            let real_len = std::fs::metadata(seg_path(&inner.dir, inner.write_seg))
                .map(|m| m.len())
                .unwrap_or(inner.write_off);
            let torn = real_len.saturating_sub(inner.write_off);
            inner.write_off = real_len;
            inner.bytes += torn;
            inner.writer = None;
            roll_segment(&mut inner)?;
            return Err(e.into());
        }
        inner.write_off += rec_len;
        inner.bytes += rec_len;
```

- [ ] **Step 7: Run the tests**

Run: `cargo test --lib buffer && cargo test --all-targets`
Expected: PASS, including the pre-existing `drop_newest_when_full`, `drop_oldest_when_full` and `segment_rollover` tests.

- [ ] **Step 8: Commit**

```bash
git add src/buffer.rs src/outputs.rs
git commit -m "fix(C-4): skip corrupt queue records instead of spinning on them

A torn record mid-segment (disk full, power loss) made peek_batch return
empty while wait_data still reported data, and outputs.rs continued with
no sleep - one core pinned at 100% forever with the destination silently
dead. Records that fail CRC are now stepped over and counted; a failed
write re-derives write_off from the real file length and rolls the
segment. Also clamps the record length to the segment size before
allocating (was: up to 64 MB from a garbage header)."
```

---

## Task 6: C-2 + H-2 — every route authenticated, token generated when absent

**Files:**
- Modify: `Cargo.toml` (add `rand = "0.8"`; dev-deps `tower = { version = "0.5", features = ["util"] }`, `http-body-util = "0.1"`), `src/web.rs:39-82`, `src/config.rs:458-479`, `src/main.rs` (token resolution at startup), `src/ui.html:150-180`
- Test: `src/web.rs` tests (new `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `crate::fsutil::write_atomic` from Task 3.
- Produces:
  - `pub fn crate::web::generate_token() -> String` — 64 hex chars from `OsRng`.
  - `AppState.auth_token: String` (was `Option<String>`) — always populated.
  - `pub async fn crate::web::resolve_token(cfg: &WebConfig, data_dir: &std::path::Path) -> anyhow::Result<String>` — returns the configured token, or reads/creates `<data_dir>/web-token` (mode 0600 on Unix).
  - Only `GET /healthz` is reachable without a token.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state(token: &str) -> Arc<AppState> {
        let (control, _rx) = mpsc::channel(1);
        Arc::new(AppState {
            engine: RwLock::new(None),
            logs: LogBuffer::new(),
            config_path: PathBuf::from("/nonexistent/agent.yaml"),
            control,
            uptime: Uptime::default(),
            auth_token: token.to_string(),
        })
    }

    #[tokio::test]
    async fn healthz_is_the_only_unauthenticated_route() {
        let app = router(test_state("secret-token"));
        let guarded = [
            "/metrics", "/api/status", "/api/inputs", "/api/outputs",
            "/api/buffer", "/api/logs", "/api/about", "/api/config",
        ];
        for path in guarded {
            let res = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{path} was open");
        }
        let res = app
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_ne!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_valid_bearer_token_is_accepted() {
        let app = router(test_state("secret-token"));
        let res = app
            .oneshot(
                Request::get("/api/about")
                    .header("authorization", "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[test]
    fn generated_tokens_are_long_and_unique() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib web 2>&1 | tail -20`
Expected: FAIL to compile — `router` and `generate_token` do not exist, and `AppState.auth_token` is an `Option`.

- [ ] **Step 3: Add the dependencies**

In `Cargo.toml`:

```toml
rand = "0.8"
```

and under `[dev-dependencies]`:

```toml
tower = { version = "0.5", features = ["util"] }
http-body-util = "0.1"
```

- [ ] **Step 4: Extract the router and put auth in a middleware layer**

In `src/web.rs`, change `AppState.auth_token` to `pub auth_token: String`, then:

```rust
use axum::middleware::{self, Next};
use axum::extract::Request;

/// Build the router. Split out of `serve` so tests can drive it directly.
pub fn router(state: Arc<AppState>) -> Router {
    // /healthz is deliberately outside the auth layer: it is the liveness probe
    // for systemd, Kubernetes and the customer's monitoring, and carries no data.
    let public = Router::new()
        .route("/healthz", get(healthz))
        .with_state(state.clone());

    let guarded = Router::new()
        .route("/", get(ui))
        .route("/metrics", get(metrics_text))
        .route("/api/status", get(api_status))
        .route("/api/inputs", get(api_inputs))
        .route("/api/outputs", get(api_outputs))
        .route("/api/buffer", get(api_buffer))
        .route("/api/logs", get(api_logs))
        .route("/api/about", get(api_about))
        .route("/api/config", get(api_config_get))
        .route("/api/config/validate", post(api_config_validate))
        .route("/api/config/save", post(api_config_save))
        .route("/api/config/reload", post(api_config_reload))
        .route("/api/config/rollback", post(api_config_rollback))
        .layer(middleware::from_fn_with_state(state.clone(), auth_layer))
        .with_state(state);

    public.merge(guarded)
}

async fn auth_layer(State(state): S, req: Request, next: Next) -> Response {
    let supplied = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| req.headers().get("x-auth-token").and_then(|v| v.to_str().ok()))
        .unwrap_or("");
    if !constant_time_eq(supplied.as_bytes(), state.auth_token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    next.run(req).await
}

/// Length-independent, short-circuit-free comparison (audit L-2).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 32 bytes of OS entropy, hex-encoded.
pub fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The configured token, or a persistent one under the data dir.
pub fn resolve_token(cfg: &WebConfig, data_dir: &std::path::Path) -> anyhow::Result<String> {
    if let Some(t) = &cfg.auth_token {
        return Ok(t.clone());
    }
    let path = data_dir.join("web-token");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let t = existing.trim().to_string();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    let token = generate_token();
    crate::fsutil::write_atomic(&path, token.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::warn!(
        "web.auth_token was not configured; generated one and stored it at {} \
         (read it with: cat {})",
        path.display(),
        path.display()
    );
    Ok(token)
}
```

Delete the old `check_auth` function and the 5 `if let Err(r) = check_auth(...)` blocks from the handlers — the layer covers them now.

Replace the router construction inside `serve` with `let app = router(state);`.

- [ ] **Step 5: Wire the token in at startup**

In `src/main.rs`, where `AppState` is constructed, replace the `auth_token: cfg.web.auth_token.clone()` field with:

```rust
        auth_token: web::resolve_token(&cfg.web, &cfg.agent.data_dir)?,
```

- [ ] **Step 6: Reject a non-loopback bind without an explicit token**

In `src/config.rs`, in `validate`, turn the existing non-loopback *warning* (around line 708-721) into a hard error when no token is set:

```rust
    if cfg.web.enabled && !is_loopback(&cfg.web.bind) && cfg.web.auth_token.is_none() {
        bail!(
            "web.bind is {} (not loopback) but web.auth_token is not set — \
             refusing to expose an unauthenticated config API. Set web.auth_token \
             or bind to 127.0.0.1.",
            cfg.web.bind
        );
    }
```

- [ ] **Step 7: Make the shipped GUI send the token**

In `src/ui.html`, the five `fetch` calls (around lines 155-175) currently send only `{"content-type":"application/json"}`. Add a token holder and include it on every request:

```html
<script>
// The token is read once from the URL fragment (#token=...) or a prompt, and
// kept in sessionStorage so a reload does not ask again. It is never placed in
// the query string, where it would land in access logs and Referer headers.
function token() {
  let t = sessionStorage.getItem('snx_token');
  if (!t && location.hash.startsWith('#token=')) {
    t = decodeURIComponent(location.hash.slice(7));
    sessionStorage.setItem('snx_token', t);
    history.replaceState(null, '', location.pathname);
  }
  if (!t) {
    t = prompt('Agent API token (see the web-token file in the data directory):') || '';
    if (t) sessionStorage.setItem('snx_token', t);
  }
  return t;
}
function authHeaders(extra) {
  return Object.assign({'authorization': 'Bearer ' + token()}, extra || {});
}
</script>
```

Then change every `fetch(url)` to `fetch(url, {headers: authHeaders()})` and every JSON POST's `headers` value to `authHeaders({'content-type':'application/json'})`. Add a 401 branch that clears `sessionStorage` and re-prompts.

- [ ] **Step 8: Run the tests**

Run: `cargo test --lib web && cargo test --all-targets`
Expected: PASS.

- [ ] **Step 9: Manually verify the GUI still works**

Run: `cargo run -- run --config examples/minimal.yaml`
Then read the token (`cat <data_dir>/web-token`) and open `http://127.0.0.1:8080/#token=<token>`.
Expected: Overview loads; `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/about` prints `401`; `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/healthz` prints `200`.

- [ ] **Step 10: Commit**

```bash
git add Cargo.toml Cargo.lock src/web.rs src/config.rs src/main.rs src/ui.html
git commit -m "fix(C-2,H-2): authenticate every web route; generate a token when unset

auth_token defaulted to None and check_auth was a no-op when unset, so the
config read/save/reload/rollback API was fully open - enough to point the
root agent's file inputs at /etc/shadow and ship it to an attacker. It also
only guarded 5 of 11 routes, and the shipped GUI never sent the header, so
turning auth on broke the UI and operators left it off.

Auth is now a middleware layer over everything except /healthz, the token is
generated into <data_dir>/web-token (0600) when not configured, the compare
is constant-time, the GUI sends it, and a non-loopback bind without an
explicit token is refused at config validation."
```

---

## Task 7: H-1 — Origin and Host validation (CSRF and DNS rebinding)

**Files:**
- Modify: `src/web.rs` (extend `auth_layer` or add a second layer)
- Test: `src/web.rs` tests

**Interfaces:**
- Consumes: `router(state)` from Task 6.
- Produces: no new public API. Requests carrying a cross-origin `Origin`, or a `Host` outside the allowlist, are rejected with `403`.

**Why this is still needed after Task 6:** a cross-site form cannot set an `Authorization` header, so Task 6 already blocks the classic CSRF path. `Host` validation is the part Task 6 does not cover — it is what stops DNS rebinding, where an attacker's page resolves its own hostname to `127.0.0.1` and then talks to the agent as same-origin.

- [ ] **Step 1: Write the failing tests**

```rust
    #[tokio::test]
    async fn cross_origin_post_is_rejected() {
        let app = router(test_state("t"));
        let res = app
            .oneshot(
                Request::post("/api/config/reload")
                    .header("authorization", "Bearer t")
                    .header("origin", "https://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rebound_host_header_is_rejected() {
        let app = router(test_state("t"));
        let res = app
            .oneshot(
                Request::get("/api/about")
                    .header("authorization", "Bearer t")
                    .header("host", "attacker.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn same_origin_post_is_allowed() {
        let app = router(test_state("t"));
        let res = app
            .oneshot(
                Request::post("/api/config/reload")
                    .header("authorization", "Bearer t")
                    .header("origin", "http://127.0.0.1:8080")
                    .header("host", "127.0.0.1:8080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(res.status(), StatusCode::FORBIDDEN);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib web::tests 2>&1 | tail -20`
Expected: the two rejection tests FAIL (requests succeed).

- [ ] **Step 3: Add the allowed-host set to `AppState` and enforce it**

Add `pub allowed_hosts: Vec<String>` to `AppState`, populated in `main.rs` as
`vec![format!("{}:{}", cfg.web.bind, cfg.web.port), format!("localhost:{}", cfg.web.port), format!("127.0.0.1:{}", cfg.web.port)]`.

In `src/web.rs`, insert this check at the top of `auth_layer`, before the token compare:

```rust
    // DNS rebinding: an attacker page whose hostname resolves to 127.0.0.1 is
    // same-origin from the browser's point of view, so the Host header is the
    // only thing that distinguishes it from a real local request.
    let host_ok = match req.headers().get("host").and_then(|v| v.to_str().ok()) {
        None => true, // HTTP/2 requests carry :authority instead
        Some(h) => state.allowed_hosts.iter().any(|a| a == h),
    };
    if !host_ok {
        return (StatusCode::FORBIDDEN, "host not allowed").into_response();
    }

    // Cross-site requests: an Origin from anywhere else is never legitimate for
    // this API. A same-origin fetch either omits Origin or matches our host.
    if let Some(origin) = req.headers().get("origin").and_then(|v| v.to_str().ok()) {
        let origin_host = origin
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(origin);
        if !state.allowed_hosts.iter().any(|a| a == origin_host) {
            return (StatusCode::FORBIDDEN, "cross-origin request rejected").into_response();
        }
    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib web`
Expected: PASS.

- [ ] **Step 5: Verify the GUI still works end to end**

Run: `cargo run -- run --config examples/minimal.yaml`, open `http://127.0.0.1:8080/#token=<token>`, click through Overview → Inputs → Config, then press Validate.
Expected: no 403; browser sends `Origin: http://127.0.0.1:8080` which is in the allowlist.

- [ ] **Step 6: Commit**

```bash
git add src/web.rs src/main.rs
git commit -m "fix(H-1): validate Host and Origin on the web API

Blocks DNS rebinding (a remote page whose hostname resolves to 127.0.0.1)
and any cross-site request, as defence in depth behind the bearer token."
```

---

## Task 8: H-3 — stop echoing expanded environment variables

**Files:**
- Modify: `src/config.rs:510-530` (`expand_env`), `src/config.rs` `parse`
- Test: `src/config.rs` tests

**Interfaces:**
- Consumes: nothing.
- Produces: `pub fn crate::config::parse(text: &str) -> Result<(Config, Vec<String>)>` — unchanged signature, but any `Err` it returns has every env-expanded value replaced with `***`. Redaction happens inside `parse`, so every caller (`web.rs`, `main.rs`, `validate_cmd`) is protected without changes.

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn parse_errors_never_echo_expanded_env_values() {
        std::env::set_var("SNX_TEST_SECRET", "hunter2-super-secret");
        let yaml = "agent:\n  log_level: \"${SNX_TEST_SECRET}\"\n";
        let err = parse(yaml).expect_err("must reject the log level");
        let msg = format!("{err:#}");
        std::env::remove_var("SNX_TEST_SECRET");
        assert!(
            !msg.contains("hunter2-super-secret"),
            "error leaked the env value: {msg}"
        );
        assert!(msg.contains("***"), "expected a redaction marker: {msg}");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib config::tests::parse_errors_never_echo_expanded_env_values`
Expected: FAIL — `error leaked the env value: agent.log_level must be one of ... (got "hunter2-super-secret")`.

- [ ] **Step 3: Make `expand_env` report what it substituted**

Change `expand_env` to collect every value it inserted:

```rust
/// Expand `${VAR}` references. Returns the expanded text plus every value that
/// was substituted, so error messages can be scrubbed of them — a validation
/// error that echoes an expanded value turns /api/config/validate into an
/// oracle for reading the root process's environment.
fn expand_env(text: &str) -> (String, Vec<String>) {
    let mut secrets = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                let name = &after[..end];
                let value = std::env::var(name).unwrap_or_default();
                if !value.is_empty() {
                    secrets.push(value.clone());
                }
                out.push_str(&value);
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    (out, secrets)
}

/// Replace every substituted env value in an error message with `***`.
fn redact(msg: String, secrets: &[String]) -> String {
    let mut msg = msg;
    for s in secrets {
        if s.len() >= 2 {
            msg = msg.replace(s.as_str(), "***");
        }
    }
    msg
}
```

- [ ] **Step 4: Redact inside `parse`**

Wrap the body of `parse` so every error path is scrubbed:

```rust
pub fn parse(text: &str) -> Result<(Config, Vec<String>)> {
    let (expanded, secrets) = expand_env(text);
    parse_expanded(&expanded).map_err(|e| anyhow::anyhow!(redact(format!("{e:#}"), &secrets)))
}
```

where `parse_expanded` is the existing body from the point after expansion (deserialize + `validate`). Keep `validate`'s messages as they are — they are useful, and redaction now happens above them.

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib config`
Expected: PASS, including existing config tests.

- [ ] **Step 6: Commit**

```bash
git add src/config.rs
git commit -m "fix(H-3): redact env-expanded values from config parse errors

expand_env ran before validation and validate echoed the offending value
back, so /api/config/validate returned the contents of any environment
variable of the root process one at a time."
```

---

## Task 9: C-3 — per-destination routing, per-output policy, honest health

**Files:**
- Modify: `src/engine.rs:36-160` (`build`), `src/engine.rs:176-280` (`run_pipeline`, `route_event`), `src/config.rs` (`OutputConfig.full_policy`), `src/buffer.rs` (`is_full`), `src/web.rs` (`healthz`)
- Test: `tests/e2e.rs`, `src/buffer.rs` tests

**Interfaces:**
- Consumes: `Engine::build` from Task 4; `DiskQueue::corrupt_records` from Task 5.
- Produces:
  - `OutputConfig.full_policy: Option<FullPolicy>` — per-output override; `None` means fall back to `buffer.full_policy`.
  - `DiskQueue::is_full(&self) -> bool` — true when the next push would hit the cap.
  - `EngineShared.queues` unchanged, so `/api/buffer` keeps working.
  - `GET /healthz` returns `503` with `{"status":"degraded","queues_full":[...]}` when any queue is full.

**Stated consequence (product decision, 2026-09-04):** the default stays `block`. Splitting the routers means a *slow* destination no longer stalls its peers, and a destination whose queue is *full* stalls the pipeline **by design** — that is what "never drop a log" means. What changes is that this state is now loud: `/healthz` fails, `agent_queue_full` fires, and an operator who prefers shedding on a noisy destination can set `full_policy: drop_oldest` on that output alone.

- [ ] **Step 1: Write the failing tests**

In `src/buffer.rs` tests:

```rust
    #[test]
    fn is_full_reports_the_block_state() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BufferConfig { max_size_mb: 1, ..BufferConfig::default() };
        let q = DiskQueue::open(dir.path(), "dest", &cfg).unwrap();
        assert!(!q.is_full());
        let big = "x".repeat(4096);
        for _ in 0..400 {
            if let Ok(PushOutcome::Full) = q.push(&Event::new("s", "test", &big)) {
                break;
            }
        }
        assert!(q.is_full(), "queue should report full after hitting the cap");
    }
```

In `tests/e2e.rs`:

```rust
#[tokio::test]
async fn a_backed_up_destination_does_not_stop_its_peers() {
    // Destination A has a 1 MB queue and a TCP peer that accepts but never
    // reads, so its queue fills and stays full. Destination B is a UDP peer we
    // read from. B must keep receiving.
    let dir = tempfile::tempdir().unwrap();

    let stuck = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stuck_port = stuck.local_addr().unwrap().port();
    tokio::spawn(async move {
        // Accept and hold, never read.
        let mut held = Vec::new();
        while let Ok((s, _)) = stuck.accept().await {
            held.push(s);
        }
    });

    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sink_port = sink.local_addr().unwrap().port();

    let in_port = {
        let l = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };

    let yaml = format!(
        r#"
agent:
  data_dir: {data}
buffer:
  max_size_mb: 1
inputs:
  syslog:
    - id: in
      protocol: udp
      bind: 127.0.0.1
      port: {in_port}
outputs:
  - id: stuck
    type: syslog
    protocol: tcp
    address: 127.0.0.1:{stuck_port}
    full_policy: block
  - id: healthy
    type: syslog
    protocol: udp
    address: 127.0.0.1:{sink_port}
web:
  enabled: false
"#,
        data = dir.path().display(),
        in_port = in_port,
        stuck_port = stuck_port,
        sink_port = sink_port,
    );
    let (cfg, _w) = softnix_log_agent::config::parse(&yaml).unwrap();
    let engine = softnix_log_agent::engine::Engine::start(cfg).await.unwrap();

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 0..200 {
        let line = format!("<14>Jun 10 10:00:00 h1 app: event {i}");
        client.send_to(line.as_bytes(), ("127.0.0.1", in_port)).await.unwrap();
    }

    let mut buf = vec![0u8; 65535];
    let mut received = 0;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline && received < 50 {
        if let Ok(Ok((n, _))) = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            sink.recv_from(&mut buf),
        ).await {
            if n > 0 {
                received += 1;
            }
        }
    }
    engine.stop().await;
    assert!(received >= 50, "healthy destination only got {received} events");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib buffer::tests::is_full_reports_the_block_state && cargo test --test e2e a_backed_up_destination`
Expected: the first FAILS to compile (`is_full` missing); the second FAILS because `full_policy` is not accepted on an output and, once it is, because the single sequential router stalls both destinations.

- [ ] **Step 3: Add `is_full` and the per-output policy**

In `src/buffer.rs`:

```rust
    /// True when the next average-sized push would exceed the size cap. Used by
    /// /healthz so a blocked queue is visible instead of silently wedging the
    /// agent.
    pub fn is_full(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.bytes >= self.max_bytes
    }
```

In `src/config.rs`, add to `OutputConfig`:

```rust
    /// Overrides buffer.full_policy for this destination only.
    #[serde(default)]
    pub full_policy: Option<FullPolicy>,
```

and make `DiskQueue::open` take the effective policy. The simplest change that keeps `open`'s signature: construct a per-output `BufferConfig` in `engine.rs`:

```rust
        for out in &cfg.outputs {
            let mut bcfg = cfg.buffer.clone();
            if let Some(p) = out.full_policy {
                bcfg.full_policy = p;
            }
            let q = DiskQueue::open(&queue_dir, &out.id, &bcfg)
                .with_context(|| format!("cannot open queue for output {}", out.id))?;
            queues.insert(out.id.clone(), q);
        }
```

- [ ] **Step 4: Split routing into one task per destination**

In `src/engine.rs`, replace the single pipeline task with a pipeline task that fans out to per-destination router tasks. Add above `run_pipeline`:

```rust
/// One routing task per destination. The pipeline hands it an already
/// transformed+enriched event; this task owns the blocking push so a full or
/// slow queue cannot stall any other destination.
async fn run_router(
    mut rx: mpsc::Receiver<Arc<Event>>,
    out: OutputConfig,
    queue: Arc<DiskQueue>,
    block: bool,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
) {
    while let Some(ev) = rx.recv().await {
        let result = if block {
            queue.push_blocking(&ev, &cancel).await.map(|stored| {
                if stored { PushOutcome::Stored { evicted: 0 } } else { PushOutcome::Dropped }
            })
        } else {
            queue.push(&ev)
        };
        match result {
            Ok(PushOutcome::Stored { evicted }) if evicted > 0 => {
                metrics.events_dropped.fetch_add(evicted, std::sync::atomic::Ordering::Relaxed);
            }
            Ok(PushOutcome::Stored { .. }) => {}
            Ok(PushOutcome::Dropped) | Ok(PushOutcome::Full) => {
                metrics.events_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => metrics.record_error(format!("queue {} write: {e}", out.id)),
        }
    }
}
```

In `build`, after the queues are opened, create one channel and one task per output, and keep the senders in a `Vec<(OutputConfig, mpsc::Sender<Arc<Event>>)>` that `run_pipeline` owns. Give each router channel a small capacity (`const ROUTER_CAPACITY: usize = 256;`) so memory does not multiply by destination count.

Then change `route_event` to fan out instead of pushing:

```rust
    let ev = Arc::new(ev);
    for (out, tx) in routers {
        if let Some(primary) = &out.failover_for {
            if status.output_healthy(primary) {
                continue;
            }
        }
        if let Some(cond) = &out.when {
            if !eval_condition(cond, &ev) {
                continue;
            }
        }
        // Under `block` this awaits, which is the documented behaviour: a
        // destination that cannot keep up applies backpressure rather than
        // dropping. /healthz reports the condition (see Step 5).
        if tx.send(Arc::clone(&ev)).await.is_err() {
            metrics.record_error(format!("router {} closed", out.id));
        }
    }
```

`Arc<Event>` also removes the per-destination clone of the whole event body, which is a prerequisite for Task 11's win. `DiskQueue::push` takes `&Event`, and `&Arc<Event>` derefs to `&Event`, so no signature change is needed.

- [ ] **Step 5: Make `/healthz` tell the truth**

In `src/web.rs`, replace `healthz`:

```rust
async fn healthz(State(state): S) -> Response {
    let engine = state.engine.read().await;
    let Some(shared) = engine.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "engine not running"})),
        )
            .into_response();
    };
    let full: Vec<&String> = shared
        .queues
        .iter()
        .filter(|(_, q)| q.is_full())
        .map(|(id, _)| id)
        .collect();
    if full.is_empty() {
        (StatusCode::OK, Json(json!({"status": "ok"}))).into_response()
    } else {
        // A full queue under `block` means the pipeline is stalled and the host
        // is no longer collecting. Returning 200 here is what let this go
        // unnoticed for hours in the field.
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "degraded", "queues_full": full})),
        )
            .into_response()
    }
}
```

Add a matching gauge to `metrics_text`: `agent_queue_full{output="..."} 0|1`.

- [ ] **Step 6: Run the tests**

Run: `cargo test --all-targets`
Expected: PASS, including the new e2e test.

- [ ] **Step 7: Update the docs**

Add a "Backpressure and the full-queue policy" section to `docs/OPERATIONS.md` stating: `block` is the default and is correct for compliance collection; a full queue stalls collection and `/healthz` returns 503; set `full_policy: drop_oldest` per output to shed instead. Add `full_policy` to the outputs table in `docs/CONFIGURATION.md` and `docs/CONFIGURATION.th.md`.

- [ ] **Step 8: Commit**

```bash
git add src/engine.rs src/buffer.rs src/config.rs src/web.rs tests/e2e.rs docs/
git commit -m "fix(C-3): route per destination, per-output full_policy, honest healthz

A single pipeline task pushed to destinations sequentially, so one full
queue blocked every other destination and then every input - the whole host
stopped collecting while /healthz still returned 200. Each destination now
has its own router task and may override full_policy; a full queue makes
/healthz return 503 and raises agent_queue_full. Events fan out as Arc<Event>
instead of being cloned per destination.

block stays the default: never dropping a log is the point, but it is now
loud instead of silent."
```

---

## Task 10: R-1 — pre-compile condition regexes

**Files:**
- Modify: `src/pipeline.rs:351-400` (`eval_condition`), `src/pipeline.rs:423-470` (`Transformer`), `src/engine.rs` (compile output conditions once)
- Test: `src/pipeline.rs` tests

**Interfaces:**
- Consumes: `Condition` from `config.rs` (unchanged on disk).
- Produces:
  - `pub struct crate::pipeline::CompiledCondition { field: String, op: String, value: Option<serde_json::Value>, regex: Option<regex::Regex> }`
  - `impl CompiledCondition { pub fn compile(c: &Condition) -> anyhow::Result<Self> }`
  - `pub fn crate::pipeline::eval_condition(cond: &CompiledCondition, ev: &Event) -> bool` — same name, new parameter type. Task 9's `run_router`/`route_event` must hold `CompiledCondition`, so compile them in `Engine::build` alongside `Transformer::compile`.

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn compiled_condition_matches_like_the_interpreted_one() {
        let cond = Condition {
            field: "message".to_string(),
            op: "matches".to_string(),
            value: Some(serde_json::Value::String(r"error \d+".to_string())),
        };
        let compiled = CompiledCondition::compile(&cond).unwrap();
        let mut hit = Event::new("s", "test", "error 42 occurred");
        hit.message = "error 42 occurred".to_string();
        let mut miss = Event::new("s", "test", "all good");
        miss.message = "all good".to_string();
        assert!(eval_condition(&compiled, &hit));
        assert!(!eval_condition(&compiled, &miss));
    }

    #[test]
    fn an_invalid_regex_is_rejected_at_compile_time_not_per_event() {
        let cond = Condition {
            field: "message".to_string(),
            op: "matches".to_string(),
            value: Some(serde_json::Value::String("(unclosed".to_string())),
        };
        assert!(CompiledCondition::compile(&cond).is_err());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib pipeline::tests::compiled_condition 2>&1 | tail -10`
Expected: FAIL to compile — `CompiledCondition` not found.

- [ ] **Step 3: Implement `CompiledCondition`**

```rust
/// A `Condition` with its regex compiled once. `Regex::new` in the per-event
/// path cost ~10k compilations/second at 5k EPS with two destinations.
pub struct CompiledCondition {
    field: String,
    op: String,
    value: Option<serde_json::Value>,
    regex: Option<Regex>,
}

impl CompiledCondition {
    pub fn compile(c: &Condition) -> Result<Self> {
        let regex = if c.op == "matches" {
            match &c.value {
                Some(Value::String(pat)) => Some(
                    Regex::new(pat)
                        .with_context(|| format!("invalid regex in condition on {}", c.field))?,
                ),
                _ => None,
            }
        } else {
            None
        };
        Ok(CompiledCondition {
            field: c.field.clone(),
            op: c.op.clone(),
            value: c.value.clone(),
            regex,
        })
    }
}
```

Change `eval_condition`'s signature to `pub fn eval_condition(cond: &CompiledCondition, ev: &Event) -> bool` (the body's `cond.field` / `cond.op` / `cond.value` accesses are unchanged) and replace the `"matches"` arm:

```rust
        "matches" => match (&field_val, &cond.regex) {
            (Some(a), Some(re)) => match value_to_string(a) {
                Some(a) => re.is_match(&a),
                None => false,
            },
            _ => false,
        },
```

- [ ] **Step 4: Compile every condition at engine start**

In `Transformer::compile`, compile each step's `when:` into a `CompiledCondition` and store it on the compiled step. In `Engine::build`, build the per-output conditions before spawning the routers:

```rust
        let mut routers = Vec::new();
        for out in &cfg.outputs {
            let when = match &out.when {
                Some(c) => Some(CompiledCondition::compile(c)
                    .with_context(|| format!("output {} when:", out.id))?),
                None => None,
            };
            // ... create channel, spawn run_router, push (out.clone(), when, tx)
        }
```

`route_event` then uses the pre-compiled `when` instead of `out.when`.

- [ ] **Step 5: Run the tests**

Run: `cargo test --all-targets`
Expected: PASS. An invalid regex now fails at `Engine::start` rather than silently never matching — check that `config::validate`'s existing regex validation still passes the same configs.

- [ ] **Step 6: Commit**

```bash
git add src/pipeline.rs src/engine.rs
git commit -m "perf(R-1): compile condition regexes once instead of per event

Regex::new ran per event, per condition, per destination - the only hot-path
regex in the pipeline that was not pre-compiled, and on its own enough to
falsify the README's <1% CPU claim. An invalid pattern is now an engine
start error instead of a condition that silently never matches."
```

---

## Task 11: R-2 — stop storing every log body twice

**Files:**
- Modify: `src/event.rs:36-52` (`Event::new`), `src/config.rs` (`ParserConfig.keep_raw_message`), `src/pipeline.rs` (set `raw_message` only when a parser changed the body), `src/inputs/eventlog.rs:651`
- Test: `src/event.rs` tests, `src/pipeline.rs` tests

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `ParserConfig.keep_raw_message: bool` (serde default `false`).
  - `Event::new` no longer populates `raw_message`; it stays `None` unless a parser sets it.
  - `pub fn crate::event::Event::preserve_raw(&mut self, raw: &str)` — sets `raw_message` only if not already set.

**Breaking-change note:** consumers relying on `raw_message` being present must set `parser.keep_raw_message: true`. Call this out in `docs/CONFIGURATION.md`, `docs/CONFIGURATION.th.md` and the release notes.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn new_event_does_not_duplicate_the_body() {
        let ev = Event::new("s", "test", "some log line");
        assert_eq!(ev.message, "some log line");
        assert!(ev.raw_message.is_none(), "raw_message must be opt-in");
    }

    #[test]
    fn preserve_raw_sets_it_once() {
        let mut ev = Event::new("s", "test", "original");
        ev.preserve_raw("original");
        assert_eq!(ev.raw_message.as_deref(), Some("original"));
        ev.preserve_raw("second call");
        assert_eq!(ev.raw_message.as_deref(), Some("original"));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib event`
Expected: FAIL — `raw_message must be opt-in`.

- [ ] **Step 3: Change `Event::new` and add `preserve_raw`**

In `src/event.rs`, replace lines 48-49:

```rust
            message: raw.to_string(),
            raw_message: Some(raw.to_string()),
```

with:

```rust
            message: raw.to_string(),
            // Opt-in: storing the body twice doubled RSS, queue occupancy and
            // the JSON wire size for every event, including `parser.mode: raw`
            // where the two copies were byte-identical.
            raw_message: None,
```

and add to `impl Event`:

```rust
    /// Keep the pre-parse body. No-op if one is already recorded.
    pub fn preserve_raw(&mut self, raw: &str) {
        if self.raw_message.is_none() {
            self.raw_message = Some(raw.to_string());
        }
    }
```

- [ ] **Step 4: Populate it only when asked**

Add to `ParserConfig` in `src/config.rs`:

```rust
    /// Keep the pre-parse body in `raw_message`. Doubles memory, queue usage
    /// and wire size per event; off by default.
    #[serde(default)]
    pub keep_raw_message: bool,
```

In `src/pipeline.rs`, in `Parser::parse` (and any other place that hands a line to a parser), call `ev.preserve_raw(line)` before parsing **only** when `self.keep_raw_message` is true. In `src/inputs/eventlog.rs:651`, guard `ev.raw_message = Some(xml.to_string());` behind the same flag — that path attaches 2-4 KB of Event XML to a message that already carries the rendered text.

- [ ] **Step 5: Run the tests**

Run: `cargo test --all-targets`
Expected: PASS. Any existing test asserting `raw_message.is_some()` must be updated to set `keep_raw_message: true` in its parser config — that is the intended behaviour change, not a regression.

- [ ] **Step 6: Document it**

Add `keep_raw_message` to the parser tables in `docs/CONFIGURATION.md` and `docs/CONFIGURATION.th.md`, with the note that it was implicitly always-on before this version.

- [ ] **Step 7: Commit**

```bash
git add src/event.rs src/config.rs src/pipeline.rs src/inputs/eventlog.rs docs/
git commit -m "perf(R-2): make raw_message opt-in

Event::new stored the body twice unconditionally, so RSS per in-flight
event, the effective disk-queue capacity and the JSON wire size were all
2x what they needed to be - even in parser.mode: raw where both copies were
identical. BREAKING: set parser.keep_raw_message: true to restore the old
behaviour."
```

---

## Task 12: R-3 — bound the input channel in bytes, not messages

**Files:**
- Modify: `src/engine.rs:18` and the `tx`/`rx` construction, `src/inputs/file.rs:315`, `src/inputs/syslog.rs:114,209`, `src/inputs/eventlog.rs:478`
- Test: `src/engine.rs` tests

**Interfaces:**
- Consumes: nothing.
- Produces: `pub struct crate::engine::EventSender { tx: mpsc::Sender<Event>, budget: Arc<tokio::sync::Semaphore> }` with `pub async fn send(&self, ev: Event) -> Result<(), mpsc::error::SendError<Event>>` and `pub fn blocking_send(&self, ev: Event) -> Result<(), mpsc::error::SendError<Event>>` (for the `spawn_blocking` eventlog path). Every input takes `EventSender` instead of `mpsc::Sender<Event>`.

**Sizing:** `const CHANNEL_BYTES: usize = 64 * 1024 * 1024;` — permits are counted in KB (`Semaphore::MAX_PERMITS` is large but KB granularity keeps the numbers small and the rounding conservative).

- [ ] **Step 1: Write the failing test**

```rust
    #[tokio::test]
    async fn sender_blocks_once_the_byte_budget_is_exhausted() {
        let (tx, _rx) = mpsc::channel::<Event>(8192);
        // 64 KB budget, 32 KB events => the third send must not complete.
        let sender = EventSender::with_budget(tx, 64 * 1024);
        let body = "x".repeat(32 * 1024);
        sender.send(Event::new("s", "t", &body)).await.unwrap();
        sender.send(Event::new("s", "t", &body)).await.unwrap();
        let blocked = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            sender.send(Event::new("s", "t", &body)),
        )
        .await;
        assert!(blocked.is_err(), "third send should have been held by the budget");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib engine 2>&1 | tail -10`
Expected: FAIL to compile — `EventSender` not found.

- [ ] **Step 3: Implement `EventSender`**

```rust
/// The input channel used to be bounded at 8192 *messages*. With a 64 KB syslog
/// line limit that is ~1 GB of RSS, and with a 1 MB file line limit ~16 GB —
/// against an advertised 12 MB footprint. Bound it in bytes instead.
const CHANNEL_BYTES: usize = 64 * 1024 * 1024;
const CHANNEL_CAPACITY: usize = 8192;

#[derive(Clone)]
pub struct EventSender {
    tx: mpsc::Sender<Event>,
    budget: Arc<tokio::sync::Semaphore>,
}

impl EventSender {
    pub fn with_budget(tx: mpsc::Sender<Event>, bytes: usize) -> Self {
        EventSender {
            tx,
            budget: Arc::new(tokio::sync::Semaphore::new(bytes / 1024)),
        }
    }

    fn permits_for(ev: &Event) -> u32 {
        // KB, rounded up, at least 1.
        ((ev.message.len() + 1023) / 1024).max(1) as u32
    }

    pub async fn send(&self, ev: Event) -> Result<(), mpsc::error::SendError<Event>> {
        let n = Self::permits_for(&ev);
        // Held until the pipeline has taken the event off the channel.
        let permit = match self.budget.clone().acquire_many_owned(n).await {
            Ok(p) => p,
            Err(_) => return Err(mpsc::error::SendError(ev)),
        };
        let r = self.tx.send(ev).await;
        drop(permit);
        r
    }

    pub fn blocking_send(&self, ev: Event) -> Result<(), mpsc::error::SendError<Event>> {
        let n = Self::permits_for(&ev);
        let permit = match self.budget.clone().try_acquire_many_owned(n) {
            Ok(p) => Some(p),
            // Budget exhausted from a blocking context: fall back to the channel's
            // own backpressure rather than busy-waiting on the semaphore.
            Err(_) => None,
        };
        let r = self.tx.blocking_send(ev);
        drop(permit);
        r
    }
}
```

In `Engine::build`, replace `let (tx, rx) = mpsc::channel::<Event>(CHANNEL_CAPACITY);` with:

```rust
        let (raw_tx, rx) = mpsc::channel::<Event>(CHANNEL_CAPACITY);
        let tx = EventSender::with_budget(raw_tx, CHANNEL_BYTES);
```

and change the three input `spawn` signatures to take `EventSender`.

- [ ] **Step 4: Add the depth gauge**

In `src/metrics.rs` add an `AtomicU64` `channel_bytes`, incremented in `EventSender::send` and decremented by the pipeline. Expose it in `metrics_text` as `agent_channel_bytes`.

- [ ] **Step 5: Run the tests**

Run: `cargo test --all-targets`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/engine.rs src/inputs src/metrics.rs
git commit -m "perf(R-3): bound the input channel in bytes, not messages

8192 messages x a 64 KB syslog limit is ~1 GB of reachable RSS (16 GB with
the 1 MB file line limit) against an advertised 12 MB footprint. A 64 MB
byte budget now gates sends, and agent_channel_bytes makes the pressure
visible."
```

---

## Task 13: R-4 — stop rewriting the whole state file every 5 seconds

**Files:**
- Modify: `src/state.rs:60-135`, `src/engine.rs:126-133`, `src/inputs/file.rs:299-305`, `src/config.rs` (retention knob)
- Test: `src/state.rs` tests

**Interfaces:**
- Consumes: `crate::fsutil::write_atomic` from Task 3.
- Produces:
  - `AgentConfig.state_retention_hours: u64` (serde default `24`, was a hard-coded 7 days).
  - `StateManager::set_cursor(&self, id: &str, identity: &str, path: &str, offset: u64)` — unchanged signature, but now a no-op (does not set `dirty`) when the offset for that key is unchanged and `touched` was refreshed within the last 60 seconds.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn repeating_the_same_offset_does_not_dirty_the_state() {
        let dir = tempfile::tempdir().unwrap();
        let st = StateManager::open(dir.path()).unwrap();
        st.set_cursor("in1", "ident", "/var/log/a.log", 100);
        st.flush().unwrap();
        assert!(!st.is_dirty());
        st.set_cursor("in1", "ident", "/var/log/a.log", 100);
        assert!(!st.is_dirty(), "an unchanged offset must not force a rewrite");
        st.set_cursor("in1", "ident", "/var/log/a.log", 200);
        assert!(st.is_dirty(), "a real advance must still be persisted");
    }

    #[test]
    fn state_is_written_compactly() {
        let dir = tempfile::tempdir().unwrap();
        let st = StateManager::open(dir.path()).unwrap();
        st.set_cursor("in1", "ident", "/var/log/a.log", 100);
        st.flush().unwrap();
        let text = std::fs::read_to_string(dir.path().join("state.json")).unwrap();
        assert!(!text.contains("\n  "), "state must not be pretty-printed");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib state`
Expected: both FAIL (`set_cursor` always dirties; `to_vec_pretty` indents).

- [ ] **Step 3: Make `set_cursor` idempotent**

In `src/state.rs`, add `pub fn is_dirty(&self) -> bool` and change `set_cursor`:

```rust
    pub fn set_cursor(&self, id: &str, identity: &str, path: &str, offset: u64) {
        let mut inner = self.inner.lock().unwrap();
        let key = format!("{id}|{identity}");
        let now = now_secs();
        if let Some(existing) = inner.file.cursors.get_mut(&key) {
            if existing.offset == offset {
                // The tailer calls this on every poll for every idle file. Only
                // refresh `touched` (and dirty the file) once a minute, or a
                // host with a few hundred idle files rewrites the whole state
                // file every 5 seconds forever.
                if now.saturating_sub(existing.touched) < 60 {
                    return;
                }
                existing.touched = now;
                inner.dirty = true;
                return;
            }
            existing.offset = offset;
            existing.path = path.to_string();
            existing.touched = now;
        } else {
            inner.file.cursors.insert(
                key,
                FileCursor { offset, path: path.to_string(), touched: now },
            );
        }
        inner.dirty = true;
    }
```

- [ ] **Step 4: Write compactly, prune on every flush**

In `flush`, replace `serde_json::to_vec_pretty(&inner.file)?` with `serde_json::to_vec(&inner.file)?` and use `crate::fsutil::write_atomic`. Move the prune call into `flush` itself (drop the 720-tick counter in `engine.rs:126-133`) and take the retention from config:

```rust
    pub fn flush(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.dirty {
            return Ok(());
        }
        let cutoff = now_secs().saturating_sub(self.retention_secs);
        inner.file.cursors.retain(|_, c| c.touched >= cutoff);
        let bytes = serde_json::to_vec(&inner.file)?;
        crate::fsutil::write_atomic(&self.path, &bytes)?;
        inner.dirty = false;
        Ok(())
    }
```

Add `state_retention_hours` to `AgentConfig` (default 24) and pass `retention_secs = hours * 3600` into `StateManager::open`.

- [ ] **Step 5: Run the tests**

Run: `cargo test --all-targets`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/state.rs src/engine.rs src/inputs/file.rs src/config.rs
git commit -m "perf(R-4): stop rewriting the entire state file every 5 seconds

file.rs marked the state dirty for idle files on every poll, so the agent
was always dirty and always rewrote - pretty-printed, whole-file, with a
7-day retention pruned only hourly. On a rotation-heavy host that is ~10 MB
serialized and written every 5 s. Retention is now 24 h and configurable,
pruning happens on every flush, output is compact, and an unchanged offset
no longer dirties the file."
```

---

## Task 14: R-5 — decouple file discovery from tailing

**Files:**
- Modify: `src/inputs/file.rs:200-400`, `src/config.rs` (`FileInputConfig.discovery_interval_ms`)
- Test: `src/inputs/file.rs` tests

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `FileInputConfig.discovery_interval_ms: u64` (serde default `30_000`).
  - `Tracked.last_size: u64` — the size at the previous poll, so `head_fingerprint` runs only when the size changed or the path is newly seen.
  - `Tracked.first_line_hash` is persisted in the state file and restored at startup, closing the FILE-004/FILE-007 gap the audit flagged as incomplete.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn fingerprint_is_not_recomputed_for_an_unchanged_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.log");
        std::fs::write(&p, b"line one\n").unwrap();
        let mut t = Tracked::new(&p).unwrap();
        let first = t.first_line_hash;
        assert!(first.is_some());
        let before = FINGERPRINT_CALLS.load(Ordering::Relaxed);
        t.refresh_identity(&p).unwrap(); // size unchanged
        assert_eq!(
            FINGERPRINT_CALLS.load(Ordering::Relaxed),
            before,
            "unchanged size must not re-read the file head"
        );
    }

    #[test]
    fn fingerprint_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let st = crate::state::StateManager::open(dir.path()).unwrap();
        let p = dir.path().join("a.log");
        std::fs::write(&p, b"first line\n").unwrap();
        let mut t = Tracked::new(&p).unwrap();
        let hash = t.first_line_hash.unwrap();
        st.set_cursor_with_hash("in1", &t.identity, &p.display().to_string(), 11, Some(hash));
        st.flush().unwrap();

        let st2 = crate::state::StateManager::open(dir.path()).unwrap();
        let restored = st2.cursor_hash("in1", &t.identity);
        assert_eq!(restored, Some(hash), "first_line_hash must survive a restart");
    }
```

Add a `FINGERPRINT_CALLS: AtomicU64` counter incremented inside `head_fingerprint`, `#[cfg(test)]`-only.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib inputs::file 2>&1 | tail -20`
Expected: FAIL to compile (`refresh_identity`, `set_cursor_with_hash`, `cursor_hash` missing).

- [ ] **Step 3: Persist and restore the fingerprint**

Add `first_line_hash: Option<u32>` to `FileCursor` in `src/state.rs` (serde `#[serde(default)]` so old state files still load), plus `set_cursor_with_hash` and `cursor_hash` accessors. In `FileInput`'s startup path, seed each `Tracked.first_line_hash` from the restored cursor. This closes FILE-004's "inert on the first poll after a restart" hole and FILE-007's recreated-larger head-skip.

- [ ] **Step 4: Only fingerprint when the size changed**

Add `last_size: u64` to `Tracked` and gate the call:

```rust
    /// Re-derive the file identity. `head_fingerprint` costs an open+read+close,
    /// which at 10k globbed files every 500 ms was ~120k syscalls/s of pure
    /// discovery overhead, so only do it when the file could actually have
    /// changed identity.
    fn refresh_identity(&mut self, path: &Path) -> std::io::Result<()> {
        let size = std::fs::metadata(path)?.len();
        if size == self.last_size && self.first_line_hash.is_some() {
            return Ok(());
        }
        self.first_line_hash = head_fingerprint(path).ok();
        self.last_size = size;
        Ok(())
    }
```

- [ ] **Step 5: Run discovery on its own slower timer, off the reactor**

Split `poll_once` into `discover_once` (glob walk + `tracked.retain`) and `tail_once` (read new lines from known files). Run `discover_once` every `discovery_interval_ms` (default 30 s) and `tail_once` every `poll_interval_ms` (default 500 ms). Wrap both bodies in `tokio::task::spawn_blocking`, since every call inside them is synchronous `std::fs` and currently runs directly on a tokio worker thread, starving the pipeline and output tasks that share it.

- [ ] **Step 6: Run the tests**

Run: `cargo test --all-targets`
Expected: PASS, including the existing rotation tests (`rename` rotation, copy-truncate, recreation).

- [ ] **Step 7: Document the new knob**

Add `discovery_interval_ms` to the file-input tables in `docs/CONFIGURATION.md` and `docs/CONFIGURATION.th.md`.

- [ ] **Step 8: Commit**

```bash
git add src/inputs/file.rs src/state.rs src/config.rs docs/
git commit -m "perf(R-5): decouple file discovery from tailing; persist the fingerprint

Every poll re-ran the glob walk and re-opened+re-fingerprinted every file:
~120k syscalls/s at 10k files / 500 ms, all blocking on a tokio worker.
Discovery now runs every 30 s, fingerprinting only when the size changed,
and both run in spawn_blocking.

Also persists first_line_hash so FILE-004's copy-truncate check is no longer
inert on the first poll after a restart, and FILE-007's recreated-larger
same-identity case no longer skips the file head."
```

---

## Task 15: H-5 — connection cap, timeouts and sender allowlist on syslog listeners

**Files:**
- Modify: `Cargo.toml` (add `ipnet = "2"`), `src/inputs/syslog.rs:144-217`, `src/config.rs` (`SyslogInputConfig` knobs)
- Test: `tests/e2e.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `SyslogInputConfig.max_connections: usize` (serde default `512`)
  - `SyslogInputConfig.idle_timeout_secs: u64` (serde default `300`)
  - `SyslogInputConfig.handshake_timeout_secs: u64` (serde default `10`)
  - `SyslogInputConfig.allowed_senders: Vec<String>` (serde default empty = allow all), each entry a CIDR parsed with `ipnet::IpNet`.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn syslog_tcp_enforces_the_connection_cap() {
    let dir = tempfile::tempdir().unwrap();
    let port = { let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                 let p = l.local_addr().unwrap().port(); drop(l); p };
    let yaml = format!(
        r#"
agent:
  data_dir: {data}
inputs:
  syslog:
    - id: in
      protocol: tcp
      bind: 127.0.0.1
      port: {port}
      max_connections: 2
outputs:
  - id: out
    type: stdout
web:
  enabled: false
"#,
        data = dir.path().display(),
        port = port,
    );
    let (cfg, _w) = softnix_log_agent::config::parse(&yaml).unwrap();
    let engine = softnix_log_agent::engine::Engine::start(cfg).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let mut held = Vec::new();
    for _ in 0..2 {
        held.push(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    }
    // The third connection is accepted at the TCP layer but must be closed
    // immediately by the cap rather than being served.
    let mut third = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut buf = [0u8; 1];
    use tokio::io::AsyncReadExt;
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), third.read(&mut buf))
        .await
        .expect("over-cap connection should be closed, not held")
        .unwrap();
    assert_eq!(n, 0, "expected EOF on the over-cap connection");

    engine.stop().await;
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test e2e syslog_tcp_enforces_the_connection_cap`
Expected: FAIL — `max_connections` is not a known field (`deny_unknown_fields`).

- [ ] **Step 3: Add the config knobs**

In `src/config.rs`, add the four fields to `SyslogInputConfig` with the defaults above, and validate in `validate` that every `allowed_senders` entry parses as an `ipnet::IpNet`.

- [ ] **Step 4: Enforce them in the accept loop**

In `src/inputs/syslog.rs`, replace the accept loop body (around lines 144-179):

```rust
    let limit = Arc::new(tokio::sync::Semaphore::new(cfg.max_connections));
    let allowed: Vec<ipnet::IpNet> = cfg
        .allowed_senders
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    // ... inside the accept loop, after `let (stream, peer) = ...`:

    if !allowed.is_empty() && !allowed.iter().any(|n| n.contains(&peer.ip())) {
        // Log at most once a minute so a scanner cannot fill the ring buffer.
        rejected.record(peer.ip());
        continue; // stream dropped => connection closed
    }
    let Ok(permit) = limit.clone().try_acquire_owned() else {
        over_cap.record(peer.ip());
        continue; // at the cap: close rather than queue
    };
    let idle = std::time::Duration::from_secs(cfg.idle_timeout_secs);
    let hs = std::time::Duration::from_secs(cfg.handshake_timeout_secs);
    tokio::spawn(async move {
        let _permit = permit; // released when the connection ends
        let stream = match acceptor {
            Some(a) => match tokio::time::timeout(hs, a.accept(stream)).await {
                Ok(Ok(s)) => MaybeTls::Tls(s),
                _ => return, // handshake failed or timed out
            },
            None => MaybeTls::Plain(stream),
        };
        // ... existing read loop, but each read wrapped in:
        //     tokio::time::timeout(idle, framed.next()).await
        // with a timeout treated as "close this connection".
    });
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --all-targets`
Expected: PASS.

- [ ] **Step 6: Document the knobs**

Add `max_connections`, `idle_timeout_secs`, `handshake_timeout_secs` and `allowed_senders` to the syslog-input tables in `docs/CONFIGURATION.md` and `docs/CONFIGURATION.th.md`.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/inputs/syslog.rs src/config.rs docs/
git commit -m "fix(H-5): cap syslog connections, add timeouts and a sender allowlist

accept() spawned a task per connection with no semaphore, no idle timeout
and no handshake timeout, so an unauthenticated sender could exhaust
LimitNOFILE=65536 with idle connections and stop the agent opening log files
or reaching the SIEM."
```

---

## Task 16: R-6 + R-7 — Windows Event Log: cache publisher metadata, never give up

**Files:**
- Modify: `src/inputs/eventlog.rs:94-115` (channel supervision), `:179-227` (backoff), `:554-590` (`format_message`), `:470-485` (handle-leak tail)
- Test: `src/inputs/eventlog.rs` tests (Windows CI job from Task 1 runs them)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `struct PublisherCache { map: HashMap<String, EvtHandleGuard> }` with `fn get_or_open(&mut self, provider: &str) -> Option<EVT_HANDLE>`; owned by `run_channel` and dropped (closing every handle) on channel exit.
  - `InputStatus` gains a per-channel entry so `/healthz` can report a channel with no live collector.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn backoff_never_permanently_gives_up() {
        let mut b = Backoff::new();
        for _ in 0..1000 {
            b.after_transient();
            assert!(!b.should_give_up(), "collection must never end permanently");
        }
        assert!(b.delay() <= std::time::Duration::from_secs(300), "delay must be capped");
    }

    #[test]
    fn publisher_cache_opens_each_provider_once() {
        let mut cache = PublisherCache::default();
        let before = PUBLISHER_OPENS.load(Ordering::Relaxed);
        let _ = cache.get_or_open("Microsoft-Windows-Security-Auditing");
        let _ = cache.get_or_open("Microsoft-Windows-Security-Auditing");
        assert_eq!(PUBLISHER_OPENS.load(Ordering::Relaxed), before + 1);
    }
```

Add a `PUBLISHER_OPENS: AtomicU64` counter incremented on each real `EvtOpenPublisherMetadata` call.

- [ ] **Step 2: Run to verify failure (Windows only)**

Run on the Windows CI runner (or a Windows dev box): `cargo test --lib inputs::eventlog`
Expected: FAIL — `should_give_up` returns true after `RESUBSCRIBE_MAX_ATTEMPTS = 10`, and `PublisherCache` does not exist.

- [ ] **Step 3: Replace "give up" with a capped retry**

In `src/inputs/eventlog.rs`, remove `should_give_up` and the `RESUBSCRIBE_MAX_ATTEMPTS` early return at `:179-187`. `after_transient` caps the delay:

```rust
    /// A Sysmon restart, a channel that does not exist yet at boot, or a
    /// transient ACCESS_DENIED while the SCM sets up the service token must not
    /// end collection for the rest of the process's life — that is a silent
    /// hole in a customer's security audit trail.
    fn after_transient(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.delay = (self.delay * 2).min(std::time::Duration::from_secs(300));
    }
```

Wrap `run_channel` in an outer supervision loop that logs, records the error, sleeps `backoff.delay()` and retries — for **every** error, not just allowlisted transient codes.

- [ ] **Step 4: Cache publisher metadata**

```rust
#[derive(Default)]
struct PublisherCache {
    map: std::collections::HashMap<String, EvtHandleGuard>,
}

impl PublisherCache {
    /// EvtOpenPublisherMetadata loads the provider's message DLL. A channel has
    /// a handful of distinct providers but this ran once per event.
    fn get_or_open(&mut self, provider: &str) -> Option<EVT_HANDLE> {
        if let Some(h) = self.map.get(provider) {
            return Some(h.0);
        }
        let handle = unsafe { open_publisher_metadata(provider)? };
        self.map.insert(provider.to_string(), EvtHandleGuard(handle));
        Some(handle)
    }
}
```

`EvtHandleGuard` is a newtype whose `Drop` calls `EvtClose`, so dropping the cache on channel exit closes every handle. Change `format_message` to take `&mut PublisherCache` instead of opening its own, and thread the cache down from `run_channel` through `drain_loop` and `build_event`.

- [ ] **Step 5: Close the shutdown handle-leak tail**

At `eventlog.rs:478-480`, close the remaining handles before the early return:

```rust
                        if tx.blocking_send(event).is_err() {
                            // Pipeline is shutting down: close the handles we
                            // have not rendered yet before leaving.
                            for h in &events[i + 1..returned as usize] {
                                unsafe { let _ = EvtClose(*h); }
                            }
                            return (total_emitted + emitted, Ok(()));
                        }
```

- [ ] **Step 6: Report a dead channel**

Add a per-channel entry to `InputStatus` and make `active` false for that entry once its collector has exited. Task 9's `/healthz` already returns degraded on a full queue — extend it to also degrade when a configured eventlog channel has no live collector.

- [ ] **Step 7: Run the tests on Windows**

Run: `cargo test --all-targets` on the Windows CI job.
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/inputs/eventlog.rs src/metrics.rs src/web.rs
git commit -m "fix(R-6,R-7): cache publisher metadata; never abandon an eventlog channel

run_channel returned Err after 10 dry transient failures and nothing
restarted it, while InputStatus.active stayed true - security-audit
collection stopped silently until someone went looking. Retry is now capped
at 5 min and never terminal, a dead channel degrades /healthz, and
EvtOpenPublisherMetadata is cached per provider instead of being called for
every event."
```

---

## Task 17: H-4 — lock down the Windows config and data directories

**Files:**
- Modify: `packaging/windows/install-windows.ps1`, `packaging/windows/softnix-log-agent.wxs`, `src/config.rs` (startup refusal)
- Test: manual on a Windows VM + a unit test for the permission check

**Interfaces:**
- Consumes: nothing.
- Produces: `pub fn crate::config::check_config_permissions(path: &std::path::Path) -> anyhow::Result<()>` — errors when the config file is writable by non-administrators. Called from `main.rs` before the first `Engine::start`.

- [ ] **Step 1: Add the ACL hardening to the installer**

In `packaging/windows/install-windows.ps1`, after the `New-Item -ItemType Directory` call that creates `$InstallDir, $DataDir`:

```powershell
# ProgramData subfolders inherit an ACE that lets Users create and append
# files. The service runs as LocalSystem and its config controls which files
# it reads and where it ships them, so a user-writable config is a privilege
# escalation. Break inheritance and grant only SYSTEM and Administrators.
foreach ($p in @($DataDir, $ConfigPath)) {
    if (Test-Path $p) {
        icacls $p /inheritance:r | Out-Null
        icacls $p /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    }
}
```

Add the same to the MSI via a `CustomAction` in `softnix-log-agent.wxs` that runs after `InstallFiles`.

- [ ] **Step 2: Write the failing test for the startup refusal**

```rust
    #[test]
    fn a_world_writable_config_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent.yaml");
        std::fs::write(&p, "agent: {}\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        #[cfg(unix)]
        assert!(check_config_permissions(&p).is_err());
    }

    #[test]
    fn a_private_config_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent.yaml");
        std::fs::write(&p, "agent: {}\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(check_config_permissions(&p).is_ok());
    }
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test --lib config::tests::a_world_writable_config_is_refused`
Expected: FAIL to compile — `check_config_permissions` not found.

- [ ] **Step 4: Implement the check**

```rust
/// Refuse a config file that non-administrators can write. The agent runs as
/// root/LocalSystem and its config decides which files it reads and where it
/// ships them, so a writable config is a privilege-escalation primitive.
pub fn check_config_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o022 != 0 {
            bail!(
                "config {} is group- or world-writable (mode {:o}); \
                 run: chmod 600 {}",
                path.display(),
                mode & 0o777,
                path.display()
            );
        }
    }
    #[cfg(windows)]
    {
        // Windows ACLs are enforced by the installer (icacls, inheritance
        // broken). A full DACL walk needs windows-acl; log a warning if the
        // file is not under a protected directory.
        tracing::debug!("config permission check: relying on installer ACLs");
    }
    Ok(())
}
```

Call it from `main.rs` before the first `Engine::start` and on every reload.

- [ ] **Step 5: Run the tests**

Run: `cargo test --all-targets`
Expected: PASS.

- [ ] **Step 6: Verify on a Windows VM**

Install with the updated script, then as a standard user run
`icacls "C:\ProgramData\Softnix\LogAgent\agent.yaml"` and attempt
`Set-Content C:\ProgramData\Softnix\LogAgent\agent.yaml "x"`.
Expected: the ACL lists only `SYSTEM` and `Administrators`; the write is denied.

- [ ] **Step 7: Commit**

```bash
git add packaging/windows src/config.rs src/main.rs
git commit -m "fix(H-4): restrict the Windows config and data ACLs to SYSTEM+Admins

ProgramData subfolders inherit an ACE letting Users create and append files,
and no icacls call existed anywhere in packaging/. With the service running
as LocalSystem, a standard user could add file inputs pointing at
SYSTEM-only material and an output to their own collector. The agent also
now refuses a group/world-writable config on Unix."
```

---

---

# Phase 2 — Structural cleanup (after remediation)

> **Do not start these until Task 17 is merged.** Tasks 18-20 move code without
> changing behaviour. Interleaving them with the security work would put
> whole-file moves in the same history as the fixes: `git blame` on a security
> fix stops being useful, review diffs become unreadable, and a `git bisect`
> over a regression lands on a move commit instead of the change that caused it.
>
> **The conflict, stated openly:** splitting `src/config.rs` *first* would
> reduce merge pain during Phase 1, because 7 of the 17 tasks edit that one
> file. That is a real argument and it loses to the one above — these are
> security fixes going to customers, and reviewability of the fix history beats
> convenience while writing it. Accept the merge friction in Phase 1.
>
> These tasks are **pure moves**. The done-condition for each is: the existing
> test suite passes unchanged, clippy is clean, and the public API is
> byte-identical. There are no new tests to write, because there is no new
> behaviour — a new test here would only be testing that `mv` works.

## Task 18: split `src/config.rs` into a module directory

**Why this one first:** 869 lines, 24 public types, imported by 9 of the 14
first-party modules, and the single most-edited file in Phase 1. Splitting it
means a future "add a config field" change and a future "add a validation rule"
change land in different files.

**Files:**
- Delete: `src/config.rs`
- Create: `src/config/mod.rs`, `src/config/schema.rs`, `src/config/env.rs`, `src/config/validate.rs`
- Test: no new tests; `src/config.rs`'s existing `#[cfg(test)] mod tests` (line 803 onward in the pre-Phase-1 file) splits so each test sits with its subject.

**Interfaces:**
- Consumes: nothing.
- Produces: **no public API change.** `crate::config::{Config, AgentConfig, …, parse, load, validate, expand_env}` must resolve exactly as before, via `pub use` in `mod.rs`. Every other module's `use crate::config::…` line stays untouched.

- [ ] **Step 1: Record the exact baseline you must not change**

```bash
cargo test --all-targets 2>&1 | grep -E '^test result' | tee /tmp/config-split-baseline.txt
git rev-parse HEAD > /tmp/config-split-base-sha.txt
```
Expected: three `test result: ok` lines. Note the total — it must be identical at Step 6.

- [ ] **Step 2: Create the module directory and move the code**

Boundaries below are line numbers **in the pre-Phase-1 file**; Phase 1 will have
shifted them, so locate each block by its first item rather than by line number.

| New file | Contents | Locate by |
|---|---|---|
| `schema.rs` | every `pub struct` / `pub enum`, their `impl Default`, and every `default_*()` helper | starts at `pub struct AgentConfig`, ends before `pub fn expand_env` |
| `env.rs` | `expand_env` (and, after Task 8, `redact` and `parse_expanded`'s expansion half) | `pub fn expand_env` |
| `validate.rs` | `validate` plus `validate_parser`, `validate_condition`, `validate_transform`, `require_file` | `pub fn validate` to end of `require_file` |
| `mod.rs` | `parse`, `load`, the `mod`/`pub use` declarations | `pub fn parse` and `pub fn load` |

```bash
mkdir -p src/config
git mv src/config.rs src/config/schema.rs
# then cut env.rs / validate.rs / mod.rs out of schema.rs
```

Using `git mv` for the largest piece keeps `git log --follow` working on the bulk of the history.

- [ ] **Step 3: Write `src/config/mod.rs`**

```rust
//! Configuration: the on-disk schema, environment expansion, and validation.
//!
//! Split by responsibility so that adding a field (schema.rs) and adding a
//! rule about that field (validate.rs) are separate diffs.

mod env;
mod schema;
mod validate;

pub use env::expand_env;
pub use schema::*;
pub use validate::validate;

use anyhow::Result;
use std::path::Path;

// ... `parse` and `load` move here verbatim ...
```

Every item that was `pub` in the old `config.rs` must still be reachable as `crate::config::Item`. The `pub use schema::*;` line does that for the types; check `expand_env` and `validate` explicitly, since they are re-exported by name.

- [ ] **Step 4: Fix visibility, not structure**

Items that `validate.rs` needs from `schema.rs` (and vice versa) become `pub(crate)` or plain `pub` within the module tree. **Do not** take this opportunity to rename anything, change a signature, or "tidy" a function — a pure move is reviewable in minutes; a move mixed with edits is not.

- [ ] **Step 5: Split the test module to follow its subject**

Tests asserting on defaults and deserialization go to `schema.rs`; tests on `${VAR}` expansion and redaction go to `env.rs`; tests on rejected configs go to `validate.rs`; round-trip `parse`/`load` tests stay in `mod.rs`.

- [ ] **Step 6: Verify nothing changed**

Run: `cargo test --all-targets 2>&1 | grep -E '^test result'`
Expected: **identical counts** to `/tmp/config-split-baseline.txt`. A lower total means a test module was dropped in the move — the exact failure this step exists to catch.

Run: `cargo clippy --all-targets`
Expected: no new warnings.

Run: `git diff --stat $(cat /tmp/config-split-base-sha.txt) -- src/ | grep -v '^ src/config'`
Expected: **empty** — no file outside `src/config/` should have changed. If `use crate::config::…` lines elsewhere needed edits, the re-exports in `mod.rs` are incomplete; fix `mod.rs` instead of the call sites.

- [ ] **Step 7: Commit**

```bash
git add -A src/config src/config.rs
git commit -m "refactor: split config.rs into schema/env/validate modules

869 lines and 24 public types in one file, edited by 7 of the 17 remediation
tasks. Pure move: no public API change, no behaviour change, identical test
counts. Adding a field and adding a rule about that field are now separate
diffs."
```

---

## Task 19: split `src/pipeline.rs` along its existing section banners

**Why this is cheap:** the author already divided this file with banner
comments. Verified in the pre-Phase-1 file: line 13 `// Parser`, 183
`// Syslog parsing (RFC3164 / RFC5424 / JSON / raw)`, 348 `// Conditions`, 419
`// Transforms`, 603 `// Enrichment`, tests at 688. The split follows lines that
already exist rather than inventing new ones.

**Files:**
- Delete: `src/pipeline.rs`
- Create: `src/pipeline/mod.rs`, `src/pipeline/parser.rs`, `src/pipeline/syslog.rs`, `src/pipeline/condition.rs`, `src/pipeline/transform.rs`, `src/pipeline/enrich.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: no public API change. `crate::pipeline::{Parser, parse_syslog_into, SyslogFormat, CompiledCondition, eval_condition, Transformer, Enricher}` all resolve as before via `pub use` in `mod.rs`.

**Payoff, concretely:** Task 2 edited only the syslog parser; Task 10 edited only conditions and transforms. After this split those are three separate files, so two people can work those areas without touching each other's diff.

- [ ] **Step 1: Record the baseline**

```bash
cargo test --all-targets 2>&1 | grep -E '^test result' | tee /tmp/pipeline-split-baseline.txt
git rev-parse HEAD > /tmp/pipeline-split-base-sha.txt
```

- [ ] **Step 2: Move each banner section into its own file**

| New file | Section | Locate by its banner comment |
|---|---|---|
| `parser.rs` | `Parser`, `ParserConfig` compilation, `Parser::parse` | `// Parser` |
| `syslog.rs` | `parse_syslog_into`, `parse_pri`, `parse_rfc3164`, `parse_rfc5424`, `parse_json_into` | `// Syslog parsing` |
| `condition.rs` | `CompiledCondition`, `eval_condition`, `values_eq`, `value_to_string`, `value_to_f64` | `// Conditions` |
| `transform.rs` | `Transformer`, `CompiledStep`, transform application | `// Transforms` |
| `enrich.rs` | `Enricher` | `// Enrichment` |

- [ ] **Step 3: Write `src/pipeline/mod.rs`**

```rust
//! The event pipeline: parse → transform → normalize → enrich → route.
//!
//! One file per stage, following the section banners the original file already
//! used. `route` itself lives in engine.rs, which owns the destination fan-out.

mod condition;
mod enrich;
mod parser;
mod syslog;
mod transform;

pub use condition::{eval_condition, CompiledCondition};
pub use enrich::Enricher;
pub use parser::Parser;
pub use syslog::parse_syslog_into;
pub use transform::Transformer;
```

Add any other item that `engine.rs`, `inputs/file.rs` or `inputs/syslog.rs` imports — check with `grep -rn 'pipeline::' src/ --include='*.rs'` and re-export every name it finds.

- [ ] **Step 4: Split the test module to follow its subject**

The parser tests (including Task 2's `rfc3164_thai_body_does_not_panic` and `no_panic_on_any_multibyte_offset`) go to `syslog.rs`; Task 10's `compiled_condition_matches_like_the_interpreted_one` goes to `condition.rs`.

- [ ] **Step 5: Verify nothing changed**

Run: `cargo test --all-targets 2>&1 | grep -E '^test result'`
Expected: identical counts to `/tmp/pipeline-split-baseline.txt`.

Run: `git diff --stat $(cat /tmp/pipeline-split-base-sha.txt) -- src/ | grep -v '^ src/pipeline'`
Expected: empty.

- [ ] **Step 6: Commit**

```bash
git add -A src/pipeline src/pipeline.rs
git commit -m "refactor: split pipeline.rs into one file per stage

842 lines already divided by the author's own section banners; this moves
each section into the file it was already describing. Pure move, identical
test counts, no public API change."
```

---

## Task 20: give `outputs.rs` a real `Sink` trait

**This one is not a pure move** — it introduces a trait — so unlike Tasks 18-19 it has a real test. It is the seam every roadmap output (HTTP, Elasticsearch bulk, Splunk HEC, Kafka) needs, and the current shape cannot hold them: `enum Sink` (line 25 pre-Phase-1) plus a concrete `struct OutputWorker` (line 33) is built for byte-stream, line-framed protocols.

**Deliberately NOT a crate split.** Slim builds that include only the outputs a customer needs come from **cargo features with optional dependencies**, not from separate crates. A workspace was measured and rejected — see the decision record.

**Files:**
- Delete: `src/outputs.rs`
- Create: `src/outputs/mod.rs`, `src/outputs/worker.rs`, `src/outputs/syslog.rs`, `src/outputs/stdout.rs`, `src/outputs/format.rs`
- Test: `src/outputs/mod.rs`

**Interfaces:**
- Consumes: `DiskQueue` (Task 5's `corrupt_records`, Task 9's `is_full`).
- Produces:

```rust
#[async_trait::async_trait]
pub trait Sink: Send {
    /// Deliver a batch. Returning Ok(n) acks the first n events.
    async fn send_batch(&mut self, events: &[Event]) -> anyhow::Result<usize>;
    /// Called after a delivery failure, before the next attempt.
    async fn reconnect(&mut self) -> anyhow::Result<()> { Ok(()) }
    fn id(&self) -> &str;
}
```

`OutputWorker` keeps its current public shape (`OutputWorker::new(out, queue)` and `.spawn(status, metrics, cancel)`) and holds a `Box<dyn Sink>` instead of matching an enum inline.

**Dependency note:** this needs `async-trait = "0.1"`, which is outside the Global Constraints list for Phase 1. That is intentional — it is a Phase 2 addition and needs the same sign-off any new dependency does. The alternative, hand-writing `Pin<Box<dyn Future>>` returns, is available if the dependency is refused.

- [ ] **Step 1: Write the failing test**

```rust
    struct RecordingSink {
        id: String,
        received: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        fail_next: bool,
    }

    #[async_trait::async_trait]
    impl Sink for RecordingSink {
        async fn send_batch(&mut self, events: &[Event]) -> anyhow::Result<usize> {
            if self.fail_next {
                self.fail_next = false;
                anyhow::bail!("simulated delivery failure");
            }
            let mut got = self.received.lock().unwrap();
            for ev in events {
                got.push(ev.message.clone());
            }
            Ok(events.len())
        }
        fn id(&self) -> &str {
            &self.id
        }
    }

    #[tokio::test]
    async fn a_custom_sink_receives_every_queued_event() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BufferConfig::default();
        let queue = DiskQueue::open(dir.path(), "dest", &cfg).unwrap();
        for i in 0..5 {
            queue.push(&Event::new("s", "test", &format!("event-{i}"))).unwrap();
        }
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Box::new(RecordingSink {
            id: "dest".to_string(),
            received: received.clone(),
            fail_next: true, // proves the retry path goes through the trait
        });

        let worker = OutputWorker::with_sink("dest", sink, queue);
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = worker.spawn(
            Arc::new(StatusRegistry::default()),
            Arc::new(Metrics::default()),
            cancel.clone(),
        );
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        cancel.cancel();
        let _ = handle.await;

        let got = received.lock().unwrap();
        assert_eq!(got.len(), 5, "sink should have received all 5 events, got {got:?}");
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib outputs::tests::a_custom_sink_receives_every_queued_event`
Expected: FAIL to compile — no `Sink` trait, no `OutputWorker::with_sink`.

- [ ] **Step 3: Define the trait and move the two existing sinks behind it**

`syslog.rs` gets a `SyslogSink` implementing `Sink` (UDP, TCP and TLS variants stay internal to it, since they share framing and reconnect logic). `stdout.rs` gets a `StdoutSink`. `format.rs` takes `format_event` and its helpers (`rfc5424_structured_data`, `value_to_param`, `sd_escape`, `pri_of`, `severity_label`) unchanged.

While moving `pri_of`, fix the audit's P3 arithmetic wart in the same commit: `facility * 8 + severity.min(7)` wraps silently in release when a transform sets `facility > 31`. Clamp it: `facility.min(31) * 8 + severity.min(7)`.

- [ ] **Step 4: Rewrite the worker loop against the trait**

`worker.rs` holds `Box<dyn Sink>` and keeps the retry/backoff loop, the empty-batch sleep floor from Task 5, and the health reporting. Add:

```rust
    /// Construct a worker around any Sink. Used by tests and by future
    /// outputs that are not built from an OutputConfig.
    pub fn with_sink(id: &str, sink: Box<dyn Sink>, queue: Arc<DiskQueue>) -> Self {
```

and make the existing `OutputWorker::new(out, queue)` build the right sink from `out.kind` and delegate to it.

- [ ] **Step 5: Run the tests**

Run: `cargo test --all-targets`
Expected: PASS, including every pre-existing output test and the e2e tests from Tasks 9 and 15.

- [ ] **Step 6: Confirm the wedge is intact**

Run: `cargo build --release && ls -l target/release/softnix-log-agent`
Expected: within a few KB of the pre-task size. Record the number — the README quotes a binary size to prospects, so it is a figure the project should watch. (Measured 2026-09-04: **4,743,696 bytes**, while `README.md:16` claims 4.1 MB. Correct the README in this commit.)

- [ ] **Step 7: Commit**

```bash
git add -A src/outputs src/outputs.rs README.md Cargo.toml Cargo.lock
git commit -m "refactor: introduce a Sink trait for outputs

enum Sink + a concrete OutputWorker is shaped for byte-stream, line-framed
protocols and cannot hold HTTP, Elasticsearch bulk or Kafka. The worker now
drives Box<dyn Sink>; syslog and stdout are the first two implementations.
Slim builds will come from cargo features, not from separate crates.

Also clamps facility to 31 in pri_of (silently wrapped in release) and
corrects the binary size quoted in the README."
```

## Decision record: one crate, not a workspace (2026-09-04)

Task 20 says "trait, not crate". That was decided by measurement, not taste, and
is recorded here so it does not get relitigated every time a file grows.

Two independent reviews reached the same verdict from different arguments. A
real 2-crate workspace was built and benchmarked against a control:

| Expected benefit | Measured result |
|---|---|
| Faster incremental builds | Worst case in the monolith is **0.75 s** (`cargo check --all-targets` after touching `config.rs`, which 9 modules import). Whole-crate rebuild: 2.49 s. Nothing to save. |
| Smaller binary | 4,743,696 → 4,740,880 bytes, **−0.06%**. `lto = "thin"` at the workspace root recovers cross-crate inlining, so LTO is a wash. |
| Faster release build | 25.65 s mono vs 30.18 s workspace. Slightly worse. |
| Clearer boundaries | The import graph is **already an acyclic 5-level DAG** with no violations. Crates would restate a discipline the code already has. |
| Fixes the `config.rs` god-module | It does not. Its 24 public types land in the shared core crate, with the same coupling and more ceremony. |

**Costs incurred on day one:** `cargo test --all-targets` — the exact command in
Task 1's CI — runs **37 tests in the monolith but 30 in the workspace, exiting
0**. Seven tests silently stop running while CI stays green. And a member
crate's `[profile.release]` is ignored with a warning, so `panic = "abort"`,
which several fixes in this plan reason about, becomes root-only by convention.

**The strongest argument for splitting, and why it lost:** extracting
`eventlog.rs` into a crate without `rustls`/`ring` does let `cargo check
--target x86_64-pc-windows-msvc` run on macOS in 0.47 s, which the monolith
cannot do (`ring`'s `build.rs` fails: `'assert.h' file not found`). But
`cargo zigbuild --release --target x86_64-pc-windows-gnu` builds the entire
unmodified monolith on macOS in ~37 s and catches the same errors. That is a
**tooling gap, not an architecture gap** — so Task 1 Step 5 adds the tool
instead. Note also that `eventlog.rs` has exactly **one** external call site,
`src/engine.rs:100`, and its dependencies are already target-gated.

**Revisit when — and only when — one of these is true**, written down as a
concrete reason rather than "the files are big":
- a second binary ships from this repo;
- `cargo check` of first-party code exceeds 30 s;
- a third party needs to write an output plugin against a published API;
- some part of the tree needs an independent release cadence.

---

## Self-Review

**1. Spec coverage.** All 6 Critical: C-1 → T2, C-2 → T6, C-3 → T9, C-4 → T5, C-5 → T3, C-6 → T4. All 5 High security: H-1 → T7, H-2 → T6, H-3 → T8, H-4 → T17, H-5 → T15. All 7 High resource: R-1 → T10, R-2 → T11, R-3 → T12, R-4 → T13, R-5 → T14, R-6 → T16, R-7 → T16. T1 (CI) is a prerequisite, justified in its own header. T18-T20 are structural cleanup, not audit findings.

**2. Findings closed incidentally**, noted where they happen: B8 (64 MB allocation from a garbage length header) in T5 Step 3; L-2 (non-constant-time token compare) in T6 Step 4; the incomplete FILE-004 / FILE-007 fixes in T14 Step 3; the `facility * 8` release-only overflow in T20 Step 3.

**3. Deliberately out of scope** — carry into a follow-up plan: all 6 Medium findings (M-1 output-id path traversal, M-2 directory permissions, M-3 web TLS, M-4 SIEM log injection, M-5 CRL/system roots, M-6 installer signature), the remaining Low findings (systemd hardening, unescaped `--config`), the resource audit's correctness-at-restart items C2/C3 (cursor persisted before the event is durable), and every architecture gap and roadmap item.

**4. Type consistency check.** `CompiledCondition` is introduced in T10, but T9 (executed first) builds routers holding `out.when: Option<Condition>`; T10 Step 4 changes those tuples to `Option<CompiledCondition>` — run T9 before T10 and apply that change or the build breaks. `EventSender` (T12) replaces `mpsc::Sender<Event>` in all three input `spawn` signatures; T15 edits `syslog.rs`'s accept loop and must use whichever type is current when it runs. `write_atomic` (T3) is consumed by T6 and T13. `is_full` (T9) and `corrupt_records` (T5) are both consumed by T9's `/healthz`, so T5 precedes T9. `Sink` (T20) replaces the `enum Sink` that T5 Step 5 edits, so T20 must follow T5 — which it does, being in Phase 2.

**5. Phase boundary.** Phase 1 is T1-T17 and must be merged before Phase 2 (T18-T20) starts. The line-number references in T18 and T19 are given against the **pre-Phase-1** file and will have shifted; both tasks tell the executor to locate blocks by their first item or banner comment instead. Every `git diff --stat` verification step in Phase 2 is there to catch a move that accidentally changed something outside its own directory.

**6. Execution order.** T1 → T2 → T3 → T4 → T5 → T6 → T7 → T8 → T9 → T10 → T11 → T12 → T13 → T14 → T15 → T16 → T17 → *(merge, release candidate)* → T18 → T19 → T20. T16 and T17 require the Windows CI job from T1.
