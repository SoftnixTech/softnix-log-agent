# Agent self-logs go to stdout, not stderr — design spec

Status: **draft — owner review** (no decision is needed; the documented
behaviour is already stderr). Nothing is implemented yet.
Branch: `develop_fix_bug_known-issues`.

## Problem

`run_agent` (`src/main.rs:418-426`) installs the tracing subscriber:

```rust
// Tracing: stderr + in-memory ring buffer for the web UI.
...
    .with(tracing_subscriber::fmt::layer().with_target(false))
```

`fmt::layer()`'s default writer is **stdout**. The comment, and
`docs/OPERATIONS.md:132` ("Agent self-logs go to stderr (journald under
systemd)"), both say stderr. With an output of `type: stdout`, the agent's
own log lines (`INFO … starting`, `WARN web.auth_token was not
configured…`) are interleaved with the event stream, so anything that
reads stdout as events (a pipe into a SIEM forwarder, `| jq`, a container
log collector parsing JSON) gets lines that are not events.

### Evidence (2026-11-11, branch HEAD after `a508a6d`, 3 independent runs)

The harness (`issues_repro.py`, the self-logs case) runs the agent with a file
input of 2 JSON events, a `type: stdout, format: json` output,
`log_level: info` and the web UI on. Every run was identical:

| Stream | Content |
| --- | --- |
| stdout | 10 lines: **2 events + 8 self-log lines** |
| stderr | **0 bytes** |

## Impact

Low. It affects only deployments that use a `stdout` output *and* consume
stdout as data, but there it corrupts the stream: a JSON consumer fails on
every log line. Under systemd, journald captures both streams, so operators
reading `journalctl` (`docs/INSTALL-LINUX.md:64`) see no difference.

## Goals

1. Every line the tracing subscriber writes goes to **stderr**.
2. stdout carries only what the `stdout` output writes (events), plus the
   CLI subcommands' deliberate `println!` output (`validate` and the
   others), which are not tracing.
3. Nothing else changes: the log format, the levels, the web UI ring buffer
   (`LogBufferLayer`), and `RUST_LOG` / `agent.log_level` handling.

## Non-goals

- ANSI colouring, the log format, or log rotation.
- The Windows service. Its stdout and stderr are not attached to anything,
  before and after.

## Design

One change, at `src/main.rs:424`:

```rust
.with(tracing_subscriber::fmt::layer().with_target(false).with_writer(std::io::stderr))
```

`std::io::stderr` is a `fn() -> Stderr`, which implements `MakeWriter`. No
new dependency or import is needed. The existing comment at `:418` becomes
true and stays as it is.

## Testing

`run_agent` builds its subscriber inside the binary, so the behaviour can
only be observed from outside the process. Add an integration test
`tests/self_logs_on_stderr.rs` that uses `env!("CARGO_BIN_EXE_softnix-log-agent")`:

1. Write to a temp dir (`tempfile::tempdir()`, as `tests/e2e.rs` does):
   one JSON input line, and a config with `web: { enabled: false }`,
   `agent.log_level: info`, **`agent.data_dir` pointing inside the temp
   dir** (the default is a system path, which the test must not write to
   and may not be allowed to), a `files` input with
   `read_from_start: true`, and `outputs: [{ type: stdout, format: json }]`.
   `tempfile` creates files with mode 0600, which passes
   `check_config_permissions`.
2. Spawn the binary with piped stdout and stderr. Read stdout until the
   event line arrives (with a timeout), then kill the process and collect
   both streams.
3. Assert that **every** non-empty stdout line parses as JSON (Goal 2), and
   that stderr contains `Softnix Log Agent v` (the startup `info!`,
   `src/main.rs:428`) (Goal 1).

Before the fix, step 3 fails on its first assertion: the startup line is
on stdout. The test needs no network port, and it runs on Linux, macOS and
Windows CI.

End-to-end: the harness's self-logs case. Expected: stdout 2 lines (2 events,
0 self-log), and stderr greater than 0 bytes.

Gate: fmt, clippy `-D warnings`, test `-D warnings`, `+1.98 check`.

## Risks and behaviour changes

1. **Anyone who captured the agent's logs by redirecting stdout only**
   (`agent run > agent.log`) stops getting logs in that file. They now go
   to stderr, which is what `docs/OPERATIONS.md` has always said. systemd,
   Docker and Kubernetes collect both streams, so they are unaffected.
2. **The new integration test spawns the real binary.** It kills the
   process after the event arrives rather than waiting for a clean
   shutdown, and uses a timeout so it cannot hang CI.

## Rollout

On `develop_fix_bug_known-issues`, after the spec and plan:

1. `fix(main): write agent self-logs to stderr` (the one-line change and the
   integration test).
2. `docs`: record the fix in the issue tracker. `OPERATIONS.md` already says
   stderr. If the owner wants, add a release-note line for risk 1.

## Open questions

None.
