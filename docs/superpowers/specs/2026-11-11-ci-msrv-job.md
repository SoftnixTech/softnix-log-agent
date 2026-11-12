# CI never builds on the declared MSRV (1.98) — design spec

Status: **draft — owner review** (open question 1, Linux only or also
Windows, has a proposed answer). Nothing is implemented yet.
Found while fixing the `AtomicU64::fetch_update` deprecation on Rust 1.99.
Branch: `develop_fix_bug_known-issues`.

## Problem

`Cargo.toml:7` declares `rust-version = "1.98"`. Every CI job in
`.github/workflows/ci.yml` (`test-linux` `:12`, `test-windows` `:20`,
`lint` `:34`) installs its toolchain with
`dtolnay/rust-toolchain@6bed0761…` (the *stable branch* of the action),
so each run gets whatever stable is current. Nothing ever compiles the
crate on 1.98. A change that uses an API newer than the MSRV, or a
dependency bump that raises the MSRV, merges without notice, and the
`rust-version` claim silently stops being true.

So far the MSRV has been checked **by hand**, three times on this branch:
V4 of the `fetch_update` deprecation fix, and the gates of the fixes for
Eventlog `EventData` values with XML entities and for multi-line messages
split by newline framing, each with
`RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets`, which passed every
time.

### Facts checked for the design

- The pinned action's `action.yml` (fetched 2026-11-11 at
  `6bed0761d98439e5a578e2877258200ad565ba87`) has a `toolchain` input with
  `required: false` and `default: stable`. A given value is passed through
  to `rustup toolchain install <value>` and `rustup default <value>`. An
  empty value fails the step with "'toolchain' is a required input". So
  the **same pinned SHA** can install 1.98, and no new pin is needed.
- `sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml` prints `1.98` on
  the current `Cargo.toml`.
- The workflow-level `RUSTFLAGS: -D warnings` (`ci.yml:9`) applies to every
  job, including a new one.

## Impact

Low today, because the MSRV still holds. The cost is in the future: a
broken MSRV is found by a user building with 1.98, not by CI.

## Goals

1. A CI job fails on any pull request or push that does not compile with
   `-D warnings` on the declared MSRV.
2. **One source of truth.** The job reads the version from `Cargo.toml`,
   so bumping `rust-version` needs no CI edit.
3. No change to the existing jobs.

## Non-goals

- Pinning the other jobs' toolchain. That is the separate question of
  floating stable plus `-D warnings`, recorded in out of scope item 2
  of `docs/superpowers/specs/2026-11-11-atomic-fetch-update-deprecation.md`.
- Running the test suite or clippy on the MSRV. `check` is enough to catch
  API and syntax that are too new, and the 1.98 toolchain installed here
  has no clippy anyway.

## Design

Add a job to `.github/workflows/ci.yml`, after `lint`:

```yaml
  msrv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
      # Single source of truth: the MSRV is whatever Cargo.toml declares.
      - id: msrv
        run: echo "version=$(sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml)" >> "$GITHUB_OUTPUT"
      - uses: dtolnay/rust-toolchain@6bed0761d98439e5a578e2877258200ad565ba87 # stable branch, resolved 2026-09-07
        with:
          toolchain: ${{ steps.msrv.outputs.version }}
      - uses: Swatinem/rust-cache@63fed3e2fecf6f7b51dc6f043341b79ef82a9ae7 # v2.9.2
      - run: cargo check --all-targets
```

- It uses the same pinned SHAs as the other jobs, so there is no new
  third-party pin.
- If `rust-version` is ever removed or renamed, the output is empty and the
  toolchain step fails, which is visible rather than silently testing
  stable.
- `rust-cache` keys on the rustc version, so the MSRV cache does not
  collide with the stable jobs' cache.
- `Cargo.lock` is committed, so the job resolves the same dependency
  versions as the other jobs. It does not pass `--locked`, to stay
  consistent with them.
- `--all-targets` covers the tests too. They are compiled, not run, which is
  also how the `cfg(test)` module `eventlog_xml` from the Eventlog
  `EventData` entity fix (`2026-11-11-eventlog-xml-text-entities.md`) gets
  MSRV-checked on Linux.

## Testing

There is no local GitHub Actions runner, and `actionlint` is not installed
here, so:

1. **Locally**, run the job's commands exactly: the `sed` line prints
   `1.98`, and `RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets`
   passes. This was already verified on the current HEAD.
2. **Proof that the job can fail:** on a throw-away branch, add a call to
   any item stabilised after 1.98. `msrv` must turn red while `test-linux`
   stays green, which shows the job checks the MSRV and not stable. Then
   delete the branch. This step runs after push access exists, together
   with the PR's first CI run.
3. **The first CI run** on the PR shows `msrv` green, installing `1.98.x`
   (the action's step log prints the toolchain).

## Risks

- **A dependency raises its own MSRV above 1.98.** That is the point of the
  job: it fails, and the owner then either bumps `rust-version` or pins the
  dependency. A transitive bump can make the job red on an unrelated PR,
  which is the cost of the check.
- **The job adds a few minutes of CI time.** It does one `check` with a
  cache, which is cheaper than the test jobs.

## Rollout

On `develop_fix_bug_known-issues`, after the spec and plan:

1. `ci: add an msrv job that checks the declared rust-version`.
2. `docs`: record the fix in the issue tracker, noting that it is verified
   on the first CI run.

## Open questions

1. **Linux only, or also Windows?** `src/inputs/eventlog.rs` compiles only
   on Windows, so a Linux MSRV job does not check it. Proposed answer:
   **Linux only for now**. The parser itself (`eventlog_xml`) is now checked
   on Linux, and the remaining Windows-only code changes rarely. A
   `windows-latest` matrix entry can be added later if it does change.
