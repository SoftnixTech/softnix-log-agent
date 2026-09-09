# Self-Update Mechanism (Phase 3: full networked apply) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `softnix-log-agent upgrade` with no `--from` — fetch the correct, verified release bundle over the network and apply it, using Phase 0/1's apply/rollback code completely unchanged.

**Architecture:** Fetch `manifest.json`/`manifest.json.sig` from `update.check_url` (the same config Phase 2 already added), verify and freshness-check them (Phase 0's functions, unchanged), resolve this platform/arch's `Artifact` entry, download its `url` to a temp file using Phase 2's size-capped `fetch::fetch_url` (capped at the manifest's own `size` field — authoritative because it's inside the already-signature-verified manifest), then hand that temp file to Phase 1's `apply_from_local` (Linux) or `apply_windows::self_relaunch_and_apply` (Windows) exactly as if it had been passed via `--from`. No new apply, verify, or rollback logic is written in this plan — only the fetch-then-handoff glue.

**Tech Stack:** No new crates. Everything needed (`update::fetch`, `update::manifest`, `update::apply`, `update::apply_windows`) already exists from Phases 0-2.

**Spec:** `docs/superpowers/specs/2026-09-09-self-update-mechanism.md`

**Depends on:** `docs/superpowers/plans/2026-09-09-self-update-phase-0-1.md` and `docs/superpowers/plans/2026-09-09-self-update-phase-2.md`, both fully implemented first.

## Global Constraints

- This plan adds no new verification, apply, or rollback logic — it is strictly "fetch the artifact Phase 1 already knows how to apply, then call the function Phase 1 already wrote." Any temptation to special-case something here instead of fixing it in the Phase 0/1 apply code is a sign this plan has drifted out of scope.
- The download size cap is the manifest's own `artifacts[].size` field — never unbounded, never a separately-configured limit that could drift out of sync with what the signed manifest actually says.
- Still no UI apply button. This plan only touches the CLI.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/update/apply.rs` | Modify: add `fetch_and_apply` (Linux/generic path) |
| `src/update/apply_windows.rs` | Modify: add `fetch_and_apply` (Windows path) |
| `src/main.rs` | Modify: `upgrade_cmd`/`upgrade_check_cmd` merge into one path that fetches when `--from` is absent |

---

### Task 1: Resolve and download the artifact for this platform/arch

**Files:**
- Modify: `src/update/apply.rs` (add `fetch_manifest_and_artifact`)

**Interfaces:**
- Consumes: `update::fetch::fetch_url` (Phase 2), `update::manifest::{verify_manifest, check_freshness, Manifest}` (Phase 0), `update::verify::verify_artifact_hash` (Phase 0).
- Produces: `pub async fn fetch_manifest_and_artifact(check_url: &str, data_dir: &std::path::Path, allow_downgrade: bool, dest_dir: &std::path::Path) -> anyhow::Result<std::path::PathBuf>` — returns the path of a downloaded, hash-verified artifact file inside `dest_dir`, ready to be handed to `apply_from_local`/`self_relaunch_and_apply` exactly like a `--from` path. Does **not** itself call apply or touch the watermark — recording the watermark stays the job of whichever apply function actually succeeds (unchanged from Phase 0/1, so a fetch that downloads fine but then fails to apply doesn't fool the anti-replay check into thinking it succeeded).

- [ ] **Step 1: Write the failing test**

Append to `src/update/apply.rs`'s `mod tests` (this test spins up the same kind of tiny local HTTP server Phase 2's `fetch.rs` tests use, serving a real signed-in-test manifest and a dummy artifact, to prove the resolve-download-verify pipeline end to end without touching the real network):

```rust
    #[tokio::test]
    async fn fetch_manifest_and_artifact_downloads_and_verifies_the_matching_platform() {
        use std::convert::Infallible;

        let artifact_bytes = b"pretend release bundle contents";
        let artifact_sha256 = {
            let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
            ctx.update(artifact_bytes);
            hex::encode(ctx.finish().as_ref())
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");

        let manifest_json = format!(
            r#"{{"schema_version":1,"product":"softnix-log-agent","version":"9.9.9","manifest_serial":1,"released_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","artifacts":[{{"platform":"{}","arch":"{}","filename":"a.bin","url":"{base}/artifact","sha256":"{artifact_sha256}","size":{}}}]}}"#,
            std::env::consts::OS.replace("macos", "linux"), // this test runs on whatever host CI uses; treat macOS as a linux-shaped platform string purely for this fixture's own self-consistency, not a real claim about the product's platform support
            std::env::consts::ARCH,
            artifact_bytes.len(),
        );
        let manifest_bytes = manifest_json.into_bytes();
        // Unsigned (empty sig) — this test exercises the fetch/resolve/hash
        // pipeline, not signature verification (Task 1 of Phase 0/1 already
        // covers that in isolation, and `RELEASE_PUBLIC_KEYS` is empty in
        // any build without a real release key, so a real signature can't
        // be constructed here either way). Expect this test to fail at the
        // signature-verification step until a test-only key injection seam
        // exists; see this step's note below for the concrete fix.
        let sig = vec![0u8; 64];

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let manifest_bytes = manifest_bytes.clone();
                let sig = sig.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let manifest_bytes = manifest_bytes.clone();
                        let sig = sig.clone();
                        async move {
                            let body = match req.uri().path() {
                                "/manifest.json" => manifest_bytes,
                                "/manifest.json.sig" => sig,
                                "/artifact" => artifact_bytes.to_vec(),
                                _ => Vec::new(),
                            };
                            Ok::<_, Infallible>(hyper::Response::new(http_body_util::Full::new(
                                bytes::Bytes::from(body),
                            )))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service).await;
                });
            }
        });

        let data_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let result = fetch_manifest_and_artifact(
            &format!("{base}/manifest.json"),
            data_dir.path(),
            false,
            dest_dir.path(),
        )
        .await;

        // See the note above: this specific assertion only becomes "must
        // succeed" once a test build can inject a trusted key. Until then,
        // this test asserts the one thing that's true in *every* build:
        // an unsigned manifest is rejected, never silently accepted.
        assert!(result.is_err());
    }
```

**Note before implementing:** as written, this test can only ever exercise the fail-closed path (no build has a real signing key available to construct a valid test signature against `RELEASE_PUBLIC_KEYS`, which is empty until Phase 0's Task 6 runbook is actually run for a real release). This mirrors the same limitation already accepted in Phase 0/1's Task 1 tests. If a full green-path integration test matters before shipping this task, the concrete fix is to make `verify_manifest` accept an injectable key list in a `#[cfg(test)]`-only code path (e.g. `pub(crate) fn verify_manifest_with_keys(bytes, sig, keys: &[[u8;32]])`, with the public `verify_manifest` calling it with `RELEASE_PUBLIC_KEYS`) — do this as part of this task if the red/green cycle below needs to reach an actual "ok" case, rather than only ever exercising rejection.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib update::apply::fetch_manifest_and_artifact`
Expected: FAIL — function doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Add to `src/update/apply.rs`:

```rust
use super::fetch::fetch_url;

const CURRENT_PLATFORM: &str = std::env::consts::OS;
const CURRENT_ARCH_FOR_FETCH: &str = std::env::consts::ARCH;

/// Fetches `<check_url>` and `<check_url>.sig`, verifies and freshness-
/// checks the manifest (Phase 0's functions, unchanged), resolves the
/// artifact matching this host's platform/arch, downloads it (capped at
/// the manifest's own declared size) into `dest_dir`, and verifies its
/// hash. Returns the downloaded file's path — ready to hand to
/// `apply_from_local` exactly like a `--from` path. Does not apply
/// anything and does not touch the watermark.
pub async fn fetch_manifest_and_artifact(
    check_url: &str,
    data_dir: &std::path::Path,
    allow_downgrade: bool,
    dest_dir: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let manifest_bytes = fetch_url(check_url, 1024 * 1024).await?;
    let sig = fetch_url(&format!("{check_url}.sig"), 4096).await?;
    let manifest = verify_manifest(&manifest_bytes, &sig)?;

    let watermark = Watermark::open(data_dir);
    check_freshness(
        &manifest,
        watermark.highest_serial(),
        env!("CARGO_PKG_VERSION"),
        allow_downgrade,
        chrono::Utc::now(),
    )?;

    let artifact = manifest
        .artifact_for(CURRENT_PLATFORM, CURRENT_ARCH_FOR_FETCH)
        .with_context(|| {
            format!("manifest has no artifact for {CURRENT_PLATFORM}/{CURRENT_ARCH_FOR_FETCH}")
        })?;

    let bytes = fetch_url(&artifact.url, artifact.size).await?;
    let dest_path = dest_dir.join(&artifact.filename);
    std::fs::write(&dest_path, &bytes)
        .with_context(|| format!("cannot write downloaded artifact to {}", dest_path.display()))?;
    verify_artifact_hash(&dest_path, &artifact.sha256)?;

    Ok(dest_path)
}
```

Note: `CURRENT_PLATFORM` here uses `std::env::consts::OS` (which yields `"linux"`, `"windows"`, `"macos"`, etc.) rather than Task 9's Linux-only `CURRENT_PLATFORM: &str = "linux"` constant — this function is compiled for every platform (it's the shared fetch path both the Linux and Windows CLI branches call before handing off to their own platform-specific apply), so it must derive the platform string at runtime/compile-time generically rather than hardcoding one OS.

- [ ] **Step 4: Run the test to verify it passes (in its fail-closed form)**

Run: `cargo test --lib update::apply::fetch_manifest_and_artifact`
Expected: `test result: ok. 1 passed` (asserting rejection, per Step 1's note).

- [ ] **Step 5: Commit**

```bash
git add src/update/apply.rs
git commit -m "feat(update): fetch and verify the matching release artifact over HTTPS"
```

---

### Task 2: Wire `upgrade` with no `--from` into the CLI

**Files:**
- Modify: `src/main.rs` (merge `upgrade_cmd`/`upgrade_check_cmd` dispatch)

**Interfaces:**
- Consumes: `update::apply::fetch_manifest_and_artifact` (Task 1), `update::apply::apply_from_local` (Phase 0/1, unchanged), `update::apply_windows::self_relaunch_and_apply` (Phase 0/1, unchanged).

- [ ] **Step 1: Replace the `Upgrade` match arm**

In `src/main.rs`, replace the arm added in Phase 2's Task 3:

```rust
        Some(Command::Upgrade {
            from,
            check,
            rollback,
            allow_downgrade,
            config,
        }) => {
            if check {
                upgrade_check_cmd(&config)
            } else {
                let from = from.context("--from <artifact> is required unless --check or --rollback is given (networked upgrade with no --from is Phase 3, not yet implemented)")?;
                upgrade_cmd(&from, rollback, allow_downgrade, &config)
            }
        }
```

with:

```rust
        Some(Command::Upgrade {
            from,
            check,
            rollback,
            allow_downgrade,
            config,
        }) => {
            if check {
                upgrade_check_cmd(&config)
            } else if rollback {
                upgrade_rollback_cmd(&config)
            } else {
                match from {
                    Some(path) => upgrade_cmd(&path, allow_downgrade, &config),
                    None => upgrade_networked_cmd(allow_downgrade, &config),
                }
            }
        }
```

(This also cleans up a wrinkle from Phase 2's Task 3: `rollback` now routes to its own function regardless of `from`, rather than being threaded through `upgrade_cmd`'s signature — split it out here since Task 9's original `upgrade_cmd` conflated "apply a local artifact" and "roll back" behind one boolean flag, which no longer makes sense once there's also a networked apply path. Update `upgrade_cmd`'s signature accordingly, dropping the `rollback: bool` parameter it no longer needs, and move the `#[cfg(windows)] bail!(...)` / `#[cfg(not(windows))] rollback_from_local(...)` logic from Phase 0/1's Task 11 into the new `upgrade_rollback_cmd` below instead of leaving it in `upgrade_cmd`.)

Add the new handlers (near `upgrade_cmd`):

```rust
fn upgrade_rollback_cmd(config_path: &Path) -> Result<()> {
    let (cfg, _warnings) = config::load(config_path).context("cannot load config for upgrade")?;
    let live_target = std::env::current_exe().context("cannot resolve the running binary's path")?;

    #[cfg(windows)]
    {
        bail!("Windows rollback is not yet automated by this CLI; see docs/RELEASE-SIGNING.md's Windows rollback runbook (msiexec /x then /i)");
    }

    #[cfg(not(windows))]
    {
        softnix_log_agent::update::apply::rollback_from_local(&live_target, &cfg.agent.data_dir)
    }
}

fn upgrade_networked_cmd(allow_downgrade: bool, config_path: &Path) -> Result<()> {
    let (cfg, _warnings) = config::load(config_path).context("cannot load config for upgrade")?;
    let check_url = cfg
        .update
        .check_url
        .context("update.check_url is not configured; pass --from <artifact> for an offline upgrade instead")?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let dest_dir = tempfile::tempdir().context("cannot create download temp dir")?;
        let artifact_path = softnix_log_agent::update::apply::fetch_manifest_and_artifact(
            &check_url,
            &cfg.agent.data_dir,
            allow_downgrade,
            dest_dir.path(),
        )
        .await?;

        #[cfg(windows)]
        {
            softnix_log_agent::update::apply_windows::self_relaunch_and_apply(
                &artifact_path,
                config_path,
                &cfg.agent.data_dir,
                allow_downgrade,
            )
        }
        #[cfg(not(windows))]
        {
            let live_target = std::env::current_exe()
                .context("cannot resolve the running binary's path")?;
            softnix_log_agent::update::apply::apply_from_local(
                &artifact_path,
                config_path,
                &cfg.agent.data_dir,
                allow_downgrade,
                &live_target,
            )
        }
    })
}
```

And update `upgrade_cmd` (drop the `rollback` parameter, per the note above):

```rust
fn upgrade_cmd(from: &Path, allow_downgrade: bool, config_path: &Path) -> Result<()> {
    let (cfg, _warnings) = config::load(config_path).context("cannot load config for upgrade")?;
    let live_target = std::env::current_exe().context("cannot resolve the running binary's path")?;

    #[cfg(windows)]
    {
        return softnix_log_agent::update::apply_windows::self_relaunch_and_apply(
            from,
            config_path,
            &cfg.agent.data_dir,
            allow_downgrade,
        );
    }

    #[cfg(not(windows))]
    {
        softnix_log_agent::update::apply::apply_from_local(
            from,
            config_path,
            &cfg.agent.data_dir,
            allow_downgrade,
            &live_target,
        )
    }
}
```

- [ ] **Step 2: Run `cargo build` to confirm it compiles**

Run: `cargo build`
Expected: succeeds.

- [ ] **Step 3: Run the full test suite to confirm no regressions**

Run: `cargo test`
Expected: all existing tests (Phase 0/1, Phase 2, and this plan's Task 1) still pass.

- [ ] **Step 4: Manually verify end-to-end (cannot run inside `cargo test` — needs a reachable manifest URL and a real service host)**

Once a real signed release exists at a real `update.check_url`:

```bash
sudo softnix-log-agent upgrade --config /etc/softnix-log-agent/agent.yaml
```

with no `--from` at all, and confirm the version bumps exactly as the manual Phase 0/1 runbook already verified for the offline `--from` path.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat(update): support 'upgrade' with no --from by fetching the verified artifact"
```

---

### Task 3: Documentation

**Files:**
- Modify: `README.md` (mention `upgrade` in the feature list)
- Modify: `docs/CONFIGURATION.md` and `docs/CONFIGURATION.th.md` (document `update.check_url`)

- [ ] **Step 1: Add a README bullet**

In `README.md`'s feature list (near the existing "Service integration" bullet), add:

```markdown
- **Self-update** — `softnix-log-agent upgrade --from <artifact>` applies a signed, verified release in place with automatic rollback on failure; `upgrade` with no `--from` fetches it over HTTPS if `update.check_url` is configured. Fully offline by default — no network call unless explicitly opted in.
```

- [ ] **Step 2: Document `update.check_url`**

In `docs/CONFIGURATION.md`, add a section documenting the `update:` config block, its `check_url` field, that it's unset/disabled by default, and the offline `--from` alternative for restricted-network deployments. Mirror the same content into `docs/CONFIGURATION.th.md` (Thai) — check how the existing `web:` section is documented in both files and match that structure/level of detail exactly rather than inventing a new documentation style for this one section.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/CONFIGURATION.md docs/CONFIGURATION.th.md
git commit -m "docs: document the upgrade CLI command and update.check_url"
```

---

## Self-Review Notes

- **Spec coverage:** "Phase 3 — fetch the verified artifact over the network, then reuse Phase 1's apply/rollback verbatim" is satisfied literally — Task 1 only fetches and hash-verifies; Task 2 calls the exact same `apply_from_local`/`self_relaunch_and_apply` functions Phase 0/1 already wrote, with no new apply logic in this plan at all.
- **Type consistency:** `upgrade_cmd`'s signature changes (drops `rollback: bool`) between Phase 0/1's Task 9/11 and this plan's Task 2 — this is a deliberate, called-out refactor (see Task 2 Step 1's note), not an inconsistency; confirm no other caller of the old 4-argument `upgrade_cmd` survives after this task (there is exactly one call site, in the `match` arm rewritten in the same step).
- **Known gap carried forward, not introduced here:** Windows automatic rollback is still unimplemented (Phase 0/1's Task 11 gap) — `upgrade_rollback_cmd` (this plan's Task 2) still `bail!`s on Windows, unchanged in substance from Phase 0/1's original placement of that same `bail!`.
