# CI MSRV Job Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking. Execute the tasks in order. T3 needs push access and cannot be done before it exists.

**Goal:** CI fails any pull request or push that does not compile, with `-D warnings`, on the `rust-version` declared in `Cargo.toml`.

**Architecture:** One new job, `msrv`, in `.github/workflows/ci.yml`. It reads the version from `Cargo.toml`, installs that toolchain with the already-pinned `dtolnay/rust-toolchain` SHA, and runs `cargo check --all-targets`. The existing jobs are not changed.

**Tech Stack:** GitHub Actions, the action SHAs already pinned in `ci.yml`.

**Spec:** `docs/superpowers/specs/2026-11-11-ci-msrv-job.md`

## Global Constraints

- Branch `develop_fix_bug_known-issues`.
- **Changes only in** `.github/workflows/ci.yml` (T1) and the issue tracker (T2, T3). No Rust source changes.
- Stage files **by name**, never `git add -A`. Every commit message ends with `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`.
- **What can be verified locally:** the job's two commands (T1 step 1) and the YAML's syntax. **What cannot:** that the job runs, installs 1.98 and can turn red. That needs a real CI run (T3), and CI only triggers on a pull request or a push to `main`/`develop`.

## Rulings

**R-0: Linux only.** The spec's one open question (Linux only, or also Windows) takes its proposed answer, which is used unless the owner vetoes it. If the owner wants Windows too, the job gets `strategy.matrix.os: [ubuntu-latest, windows-latest]` and `runs-on: ${{ matrix.os }}`, and the `sed` step needs `shell: bash`.

**R-1: No `--locked`.** `Cargo.lock` is committed and the other jobs do not pass `--locked`, so the new job stays consistent with them.

**R-2: The issue is marked "fixed, pending first CI run" in T2 and confirmed in T3.** The job cannot be seen running before push access exists, and the tracker must not claim more than was verified.

---

## Dependency graph

```text
T0 C1 docs: spec + plan
T1 C2 ci: add the msrv job              (local checks only)
T2 C3 tracker: fixed, pending CI run    (needs the C2 hash)
T3 (after push access) first CI run + proof the job can fail, then C4 tracker: confirmed
```

---

### Task 0: C1, spec and plan

- [ ] **Step 1:**

  ```bash
  git add docs/superpowers/specs/2026-11-11-ci-msrv-job.md docs/superpowers/plans/2026-11-11-ci-msrv-job.md
  git commit -m "docs: spec and plan for the CI MSRV job" -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

---

### Task 1: C2, the `msrv` job

**File:** `.github/workflows/ci.yml`.

- [ ] **Step 1: run the job's commands locally.**

  ```bash
  sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml
  RUSTFLAGS="-D warnings" cargo +1.98 check --all-targets
  ```

  Expected: the first prints exactly `1.98`, and the second finishes without errors. If the first prints anything else, stop: the job would install the wrong toolchain.

- [ ] **Step 2: confirm the pins.** `grep -n "uses:" .github/workflows/ci.yml` still shows `actions/checkout@11d5960a326750d5838078e36cf38b85af677262`, `dtolnay/rust-toolchain@6bed0761d98439e5a578e2877258200ad565ba87` and `Swatinem/rust-cache@63fed3e2fecf6f7b51dc6f043341b79ef82a9ae7`. If a pin has changed since this plan was written, use the file's current SHAs in step 3.

- [ ] **Step 3: add the job.** In `.github/workflows/ci.yml`, insert between the end of the `lint` job (its `- run: cargo clippy --all-targets` line) and the blank line before `  audit:`:

```yaml

  msrv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
      # Single source of truth: the MSRV is whatever Cargo.toml declares. If
      # rust-version is ever removed, the output is empty and the toolchain
      # step fails, instead of silently checking stable.
      - id: msrv
        run: echo "version=$(sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml)" >> "$GITHUB_OUTPUT"
      - uses: dtolnay/rust-toolchain@6bed0761d98439e5a578e2877258200ad565ba87 # stable branch, resolved 2026-09-07
        with:
          toolchain: ${{ steps.msrv.outputs.version }}
      - uses: Swatinem/rust-cache@63fed3e2fecf6f7b51dc6f043341b79ef82a9ae7 # v2.9.2
      # check, not test: enough to catch API and syntax newer than the MSRV.
      # --all-targets compiles the tests too.
      - run: cargo check --all-targets
```

- [ ] **Step 4: syntax check.** The file must still parse as YAML and have five jobs:

  ```bash
  python3 -c 'import yaml,sys; d=yaml.safe_load(open(".github/workflows/ci.yml")); print(sorted(d["jobs"]))'
  ```

  Expected: `['audit', 'lint', 'msrv', 'test-linux', 'test-windows']`. If PyYAML is not installed, use `ruby -ryaml -e 'puts YAML.load_file(".github/workflows/ci.yml")["jobs"].keys.sort.inspect'`. `git diff --stat` shows only `ci.yml`, with insertions only.

- [ ] **Step 5: commit.**

  ```bash
  git add .github/workflows/ci.yml
  git commit -m "ci: add an msrv job that checks the declared rust-version" -m "Cargo.toml declares rust-version = 1.98, but every CI job installed the latest stable, so nothing checked that the crate still builds on 1.98. The new job reads the version from Cargo.toml and runs cargo check --all-targets on it." -m "Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>"
  ```

---

### Task 2: C3, record the fix in the issue tracker

- [ ] **Step 1:** Record the issue as fixed in `<C2>`, but **not yet seen running**: the first CI run needs push access.
- [ ] **Step 2:** Commit the tracker change as `docs: mark the CI MSRV job fixed, pending its first CI run`.

---

### Task 3: verification on real CI (blocked on push access)

- [ ] **Step 1: the first CI run.** On the pull request's first run, the `msrv` job is green, and its toolchain step's log shows `1.98.x` being installed (not the current stable).
- [ ] **Step 2: proof that the job can fail.** On a throw-away branch with its own pull request, add to any `src/` file a call to an item stabilised after 1.98 (pick one from the 1.99 release notes). `msrv` must turn **red** while `test-linux` stays **green**. Close the pull request and delete the branch. Nothing from it is merged.
- [ ] **Step 3: C4.** Record in the issue tracker that the job is confirmed on CI, with the date and the run. Commit it as `docs: confirm the CI MSRV job on CI`.

---

## Coverage check against the spec

| Spec item | Where |
| --- | --- |
| Goal 1 (CI fails below the MSRV) | T1 step 3, T3 steps 1–2 |
| Goal 2 (one source of truth) | the `sed` step, T1 step 1 |
| Goal 3 (existing jobs unchanged) | T1 step 4 (insertions only) |
| Testing 1 (local) | T1 step 1 |
| Testing 2 (the job can fail) | T3 step 2 |
| Testing 3 (first CI run) | T3 step 1 |

## Risks

- **T3 is blocked** until the account has push access, or a fork workflow is agreed. Until then the job is unverified on CI, and the issue tracker says so (R-2).
- **A dependency whose own MSRV rises above 1.98** turns the job red on an unrelated pull request. That is the job doing its work: the owner then bumps `rust-version` or pins the dependency.
