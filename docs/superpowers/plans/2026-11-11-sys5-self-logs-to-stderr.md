# SYS-5 Agent Self-Logs to stderr Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking. Execute the tasks in order. The commit-producing task shows a red run before its fix, and ends with the full gate.

**Goal:** Every line the tracing subscriber writes goes to stderr, so stdout carries only what a `type: stdout` output writes.

**Architecture:** One line in `run_agent` (`src/main.rs:424`): the `fmt` layer gets `.with_writer(std::io::stderr)`. A new integration test spawns the real binary, because the subscriber is installed inside it and can only be observed from outside the process.

**Tech Stack:** Rust 2021, `tracing_subscriber`, `std::process`, `tempfile` and `serde_json` (all already dependencies).

**Spec:** `docs/superpowers/specs/2026-11-11-sys5-self-logs-to-stderr.md`

## Global Constraints

- Branch `develop_fix_bug_known-issues`, order #8 in `ISSUES.md`'s Fix plan. `rust-version = "1.98"`. If `cargo` is not on `PATH`, use `export PATH="$HOME/.cargo/bin:$PATH"`.
- **Code changes only in** `src/main.rs` (one line) and the new `tests/self_logs_on_stderr.rs`. Docs: `ISSUES.md` (T2).
- **Test counts:** lib, bin and `e2e` are unchanged. There is one new test binary, `self_logs_on_stderr`, with **1** test.
- **Gate** (after T1):

  ```bash
  cargo fmt --all -- --check
  RUSTFLAGS="-D warnings" cargo clippy --all-targets
  RUSTFLAGS="-D warnings" cargo test --all-targets
  RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets
  ```

  Do **not** set `CARGO_TARGET_DIR`.
- Stage files **by name**, never `git add -A`. Every commit message ends with `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`.
- **Not prototyped.** At the owner's request no source was touched while writing this plan, so the test below has never been compiled or run. T1 step 2's red run is its verification. Its YAML keys are copied from the harness's SYS-5 case, which runs against this binary, and its path quoting follows `tests/e2e.rs` (R-2). `data_dir` does not need to exist: the engine creates it (`src/engine.rs`, `create_dir_all`).

## Rulings

**R-0: No owner decision.** The spec has no open question. `docs/OPERATIONS.md:132` already documents stderr.

**R-1: The test kills the process.** It does not wait for a clean shutdown: once the event line is on stdout, everything the test asserts has been written. A deadline keeps it from hanging CI.

**R-2: Paths are written in single-quoted YAML scalars.** A Windows temp path contains backslashes, which a double-quoted YAML scalar would treat as escapes. `tests/e2e.rs` (`file_to_tcp_syslog_end_to_end`) does the same for `paths` (`paths: ['{glob}']`) and explains why in a comment, and that test runs on Windows CI. It writes `data_dir` unquoted. This test single-quotes it, which YAML reads the same way.

---

## Dependency graph

```text
T0 C1 docs: spec + plan
T1 C2 fix(main): self-logs to stderr   (red 1 → green)
   harness re-run (no commit)
T2 C3 ISSUES.md: SYS-5 fixed           (needs the C2 hash)
```

---

### Task 0: C1, spec and plan

- [ ] **Step 1:**

  ```bash
  git add docs/superpowers/specs/2026-11-11-sys5-self-logs-to-stderr.md docs/superpowers/plans/2026-11-11-sys5-self-logs-to-stderr.md
  git commit -m "docs: spec and plan for SYS-5 self-logs to stderr" -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

---

### Task 1: C2, write self-logs to stderr

**Files:** `tests/self_logs_on_stderr.rs` (new), `src/main.rs`.

- [ ] **Step 1: the test.** Create `tests/self_logs_on_stderr.rs`:

```rust
//! SYS-5: the agent's own log lines go to stderr, so stdout carries only what
//! a `type: stdout` output writes. The tracing subscriber is installed inside
//! the binary, so this spawns the real executable.

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const MARKER: &str = "SYS5-EVENT";

#[test]
fn self_logs_go_to_stderr_not_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("in.jsonl");
    std::fs::write(&input, format!("{{\"message\":\"{MARKER}\"}}\n")).unwrap();
    let config = dir.path().join("agent.yaml");
    std::fs::write(
        &config,
        format!(
            "agent:\n  data_dir: '{data}'\n  log_level: info\n\
             web:\n  enabled: false\n\
             inputs:\n  files:\n    - id: f\n      paths: ['{input}']\n      read_from_start: true\n      poll_interval_ms: 100\n      parser:\n        mode: json\n\
             outputs:\n  - id: out\n    type: stdout\n    format: json\n",
            data = dir.path().join("data").display(),
            input = input.display(),
        ),
    )
    .unwrap();
    // `check_config_permissions` refuses a group- or world-writable config.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_softnix-log-agent"))
        .arg("run")
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Read stdout on a thread, so the wait below can time out.
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stdout_lines = Vec::new();
    let mut saw_event = false;
    while !saw_event {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(line) => {
                saw_event = line.contains(MARKER);
                stdout_lines.push(line);
            }
            Err(_) => break,
        }
    }

    child.kill().unwrap();
    child.wait().unwrap();
    // The reader thread ends when the pipe closes: collect what is left.
    stdout_lines.extend(rx.iter());
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();

    assert!(
        saw_event,
        "the event never reached stdout.\nstdout: {stdout_lines:#?}\nstderr: {stderr}"
    );
    for line in stdout_lines.iter().filter(|l| !l.trim().is_empty()) {
        assert!(
            serde_json::from_str::<serde_json::Value>(line).is_ok(),
            "stdout must carry only events, but got this line: {line}"
        );
    }
    assert!(
        stderr.contains("Softnix Log Agent v"),
        "the startup log line must be on stderr, got: {stderr}"
    );
}
```

- [ ] **Step 2: red.** `cargo test --test self_logs_on_stderr`. Expected: **FAILED** with "stdout must carry only events, but got this line: … Softnix Log Agent v… starting …". If it fails any other way (the config is rejected, or "the event never reached stdout"), the test's config is wrong: fix the YAML (see R-2 and the harness's `sys5` case) until the failure is the expected one. Do not go on to step 3 with a different failure.

- [ ] **Step 3: the fix (green).** In `src/main.rs`'s `run_agent`, change:

```rust
        .with(tracing_subscriber::fmt::layer().with_target(false))
```

  to:

```rust
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_writer(std::io::stderr),
        )
```

  The comment above it (`// Tracing: stderr + in-memory ring buffer for the web UI.`) is now true and stays. `cargo test --test self_logs_on_stderr` passes.

- [ ] **Step 4: gate.**
- [ ] **Step 5: harness (no commit).** If `/tmp/softnix-smoke.LTIcHO/harness/issues_repro.py` still exists:

  ```bash
  cargo build && mkdir -p /tmp/sys5-runs
  python3 /tmp/softnix-smoke.LTIcHO/harness/issues_repro.py "$PWD/target/debug/softnix-log-agent" /tmp/sys5-runs 3
  python3 -c 'import json; [print(r) for r in json.load(open("/tmp/sys5-runs/results.json"))["runs"]["SYS-5"]]'
  ```

  Expected in each run: `stdout_lines: 2`, `stdout_events: 2`, `stdout_selflog_lines: 0` (was 8) and `stderr_bytes` greater than 0 (was 0). If the harness is gone, skip this step and say so in the commit body.

- [ ] **Step 6: commit.**

  ```bash
  git add src/main.rs tests/self_logs_on_stderr.rs
  git commit -m "fix(main): write agent self-logs to stderr" -m "tracing_subscriber's fmt layer writes to stdout by default, so with a type: stdout output the agent's own log lines were mixed into the event stream (SYS-5). The comment above it and docs/OPERATIONS.md both already said stderr.

Anyone who captured the logs by redirecting stdout only must now redirect stderr as well." -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

---

### Task 2: C3, mark SYS-5 fixed in `ISSUES.md`

- [ ] **Step 1:** In the summary table, set SYS-5's status to **fixed** with the `<C2>` hash. Replace the entry's status line with: **Status: fixed** in `<C2>` (branch `develop_fix_bug_known-issues`, not yet merged). Move the row from **Remaining** to **Done** in the Fix plan.
- [ ] **Step 2:**

  ```bash
  git add ISSUES.md
  git commit -m "docs: mark SYS-5 fixed" -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

---

### Owner follow-up (not part of these commits)

- **Release note:** "The agent's own log lines now go to stderr, as documented. If you captured them with `> agent.log`, add `2>&1` or redirect stderr. systemd, Docker and Kubernetes collect both streams and are unaffected."

## Coverage check against the spec

| Spec item | Where |
| --- | --- |
| Goal 1 (tracing goes to stderr) | the test's last assertion, T1 step 5 (`stderr_bytes`) |
| Goal 2 (stdout carries only events) | the test's JSON assertion, T1 step 5 (`stdout_selflog_lines: 0`) |
| Goal 3 (nothing else changes) | the one-line diff in `src/main.rs`, and the gate (the web UI log buffer has its own tests) |
| Risk 1 (stdout-only log capture) | the release note |
| Risk 2 (the test spawns the binary) | R-1, the 30-second deadline |

## Risks

- **Unverified test code** (see Global Constraints). The red run in step 2 must fail for the stated reason before the fix is applied.
- **Windows CI.** The test runs in `test-windows` too. If the file input does not pick up a single-quoted backslash path there, follow R-2. This can only be seen on a real CI run, which needs push access.
