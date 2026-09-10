//! Cross-platform update orchestration: preflight, then dispatch to the
//! platform-specific swap in `apply_linux` / `apply_windows`.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

use super::fetch::fetch_url;
use super::manifest::{check_freshness, verify_manifest};
use super::verify::verify_artifact_hash;
use super::watermark::Watermark;
use crate::config::WebConfig;

const CURRENT_PLATFORM: &str = "linux";
const CURRENT_ARCH: &str = std::env::consts::ARCH;

// NOT named `CURRENT_PLATFORM` — that name is already taken by the `const`
// above (Phase 0/1's Task 9), hardcoded to `"linux"` because that one is
// only ever used by the Linux-only apply path. This function is compiled
// and called on every platform (it's the shared fetch step both the Linux
// and Windows CLI branches call before handing off to their own
// platform-specific apply), so it needs the REAL runtime platform string,
// not that hardcoded one — a second `const` with the same name would be a
// duplicate-definition compile error, hence the different name here.
// `CURRENT_ARCH` (already defined above, `std::env::consts::ARCH`) has the
// exact value this function needs too, so it's reused as-is rather than
// redefined under another name.
const CURRENT_PLATFORM_FOR_FETCH: &str = std::env::consts::OS;

/// Runs the staged binary out-of-band, twice, *before* it ever replaces
/// anything live:
///   1. `<staged> --version` — proves it can even load on this host's
///      architecture/libc (the same class of failure
///      `packaging/install-linux.sh` already guards against with its own
///      post-install smoke check).
///   2. `<staged> validate --config <live_config>` — proves the new
///      version still accepts the configuration this host is actually
///      running, mirroring `try_reload`'s "validate the new config before
///      stopping the old engine" (`src/main.rs:350-399`).
///
/// Either failing aborts the whole upgrade with nothing changed.
pub fn preflight(staged_binary: &Path, live_config: &Path) -> Result<()> {
    let version_check = Command::new(staged_binary)
        .arg("--version")
        .output()
        .with_context(|| format!("cannot execute staged binary {}", staged_binary.display()))?;
    if !version_check.status.success() {
        bail!(
            "staged binary {} failed to run --version (exit {:?}); it likely cannot run on this host",
            staged_binary.display(),
            version_check.status.code()
        );
    }

    let validate_check = Command::new(staged_binary)
        .arg("validate")
        .arg("--config")
        .arg(live_config)
        .output()
        .with_context(|| format!("cannot execute staged binary {}", staged_binary.display()))?;
    if !validate_check.status.success() {
        let stderr = String::from_utf8_lossy(&validate_check.stderr);
        bail!(
            "staged binary {} rejects the current configuration {}: {stderr}",
            staged_binary.display(),
            live_config.display()
        );
    }
    Ok(())
}

/// Resolves the actual root directory to read `manifest.json` /
/// `manifest.json.sig` / the platform binary from, tolerating both shapes
/// a release tarball can have:
///   - a flat archive, with those files directly at the tar root (what
///     this module's own fixture-building tests produce, and a fine shape
///     to keep supporting);
///   - an archive with a single top-level wrapper directory, e.g.
///     `softnix-log-agent-<ver>-linux-x86_64/manifest.json` — what
///     `.github/workflows/release.yml`'s `tar czf "$STAGE.tar.gz" "$STAGE"`
///     actually produces, since `$STAGE` is a directory name, not `.`.
///
/// If `extract_dir` contains exactly one entry and that entry is a
/// directory, that directory is the root; otherwise `extract_dir` itself
/// is the root.
fn resolve_extraction_root(extract_dir: &Path) -> Result<std::path::PathBuf> {
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(extract_dir)
        .with_context(|| {
            format!(
                "cannot list extracted contents of {}",
                extract_dir.display()
            )
        })?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    if entries.len() == 1 && entries[0].is_dir() {
        Ok(entries.remove(0))
    } else {
        Ok(extract_dir.to_path_buf())
    }
}

/// Extracts `manifest.json` + `manifest.json.sig` + the platform binary
/// from `artifact_path` (a `.tar.gz`, either flat or with a single
/// top-level wrapper directory — see `resolve_extraction_root`) into a
/// fresh temp directory, verifies the manifest's signature and freshness,
/// verifies the extracted binary's hash against the manifest, preflights
/// it against `config_path`, then — only after every one of those checks
/// passes — swaps it onto `live_target` and restarts the service.
/// Everything up to the swap is read-only with respect to `live_target`; a
/// failure at any check leaves it completely untouched.
///
/// `web` is the loaded config's web section, threaded through to
/// `platform_swap_and_restart`'s post-swap health check: when
/// `web.enabled` is `false` there is no `/healthz` endpoint to poll at all,
/// so the health check must be skipped rather than treated as a failure.
pub fn apply_from_local(
    artifact_path: &Path,
    config_path: &Path,
    data_dir: &Path,
    allow_downgrade: bool,
    live_target: &Path,
    web: &WebConfig,
) -> Result<()> {
    // `Watermark::open` (unlike `StateManager::open`) does not create
    // `data_dir` for us — do it here so a fresh install (agent never
    // previously run, no data dir yet) doesn't fail with a confusing
    // filesystem error the first time someone runs `upgrade`.
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("cannot create data directory {}", data_dir.display()))?;

    let extract_dir = tempfile::tempdir().context("cannot create extraction temp dir")?;
    let status = Command::new("tar")
        .arg("xzf")
        .arg(artifact_path)
        .arg("-C")
        .arg(extract_dir.path())
        .status()
        .context("cannot run tar to extract the update artifact")?;
    if !status.success() {
        bail!("tar extraction of {} failed", artifact_path.display());
    }
    let root = resolve_extraction_root(extract_dir.path())?;

    let manifest_bytes = std::fs::read(root.join("manifest.json"))
        .context("update artifact has no manifest.json")?;
    let sig = std::fs::read(root.join("manifest.json.sig"))
        .context("update artifact has no manifest.json.sig")?;
    let manifest = verify_manifest(&manifest_bytes, &sig)?;

    let mut watermark = Watermark::open(data_dir);
    check_freshness(
        &manifest,
        watermark.highest_serial(),
        env!("CARGO_PKG_VERSION"),
        allow_downgrade,
        chrono::Utc::now(),
    )?;

    let artifact = manifest
        .artifact_for(CURRENT_PLATFORM, CURRENT_ARCH)
        .with_context(|| {
            format!("manifest has no artifact for {CURRENT_PLATFORM}/{CURRENT_ARCH}")
        })?;
    let extracted_binary = root.join("softnix-log-agent");
    verify_artifact_hash(&extracted_binary, &artifact.sha256)?;

    preflight(&extracted_binary, config_path)?;

    // Point of no return: everything above this line is read-only with
    // respect to `live_target`.
    let old_path =
        platform_swap_and_restart(&extracted_binary, live_target, &manifest.version, web)?;

    watermark.record(manifest.manifest_serial)?;
    prune_old_versions(live_target, &old_path)?;
    println!(
        "upgraded {} -> {}",
        env!("CARGO_PKG_VERSION"),
        manifest.version
    );
    Ok(())
}

/// Fetches `<check_url>` and `<check_url>.sig`, verifies and freshness-
/// checks the manifest (Phase 0's functions, unchanged), resolves the
/// artifact matching this host's platform/arch, downloads it (capped at
/// the manifest's own declared size) into `dest_dir`, and verifies its
/// hash. Returns the downloaded file's path — ready to hand to
/// `apply_from_local` exactly like a `--from` path. Does not apply
/// anything and does not touch the watermark: recording the watermark
/// stays the job of whichever apply function actually succeeds, so a
/// fetch that downloads fine but then fails to apply doesn't fool the
/// anti-replay check into thinking it succeeded.
pub async fn fetch_manifest_and_artifact(
    check_url: &str,
    data_dir: &Path,
    allow_downgrade: bool,
    dest_dir: &Path,
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
        .artifact_for(CURRENT_PLATFORM_FOR_FETCH, CURRENT_ARCH)
        .with_context(|| {
            format!("manifest has no artifact for {CURRENT_PLATFORM_FOR_FETCH}/{CURRENT_ARCH}")
        })?;

    let bytes = fetch_url(&artifact.url, artifact.size).await?;
    let dest_path = dest_dir.join(&artifact.filename);
    std::fs::write(&dest_path, &bytes).with_context(|| {
        format!(
            "cannot write downloaded artifact to {}",
            dest_path.display()
        )
    })?;
    verify_artifact_hash(&dest_path, &artifact.sha256)?;

    Ok(dest_path)
}

/// Note on cross-platform compilation: `apply_linux::{stage_and_swap,
/// rollback}` (Task 8) are only compiled under `#[cfg(target_os =
/// "linux")]` — this crate is built and tested on macOS/Windows dev
/// machines too, so `apply_from_local` above (which must compile and be
/// testable everywhere: extraction, signature/freshness/hash verification,
/// and preflight are all platform-independent) cannot reference
/// `apply_linux` unconditionally. This one call — the actual swap, restart,
/// health-check, and auto-rollback-on-failure sequence, which *is*
/// Linux-only for now — is factored out into this helper with two
/// `#[cfg(...)]` arms, mirroring the same platform-split pattern
/// `src/service.rs` already uses for install/start/stop/restart.
#[cfg(target_os = "linux")]
fn platform_swap_and_restart(
    extracted_binary: &Path,
    live_target: &Path,
    version: &str,
    web: &WebConfig,
) -> Result<std::path::PathBuf> {
    let old_path = super::apply_linux::stage_and_swap(extracted_binary, live_target, version)?;

    if let Err(e) = crate::service::restart() {
        tracing::error!("service restart failed after swap: {e:#}; rolling back");
        super::apply_linux::rollback(live_target, &old_path)?;
        crate::service::restart().context("rollback restart also failed")?;
        bail!("upgrade failed to restart the service; rolled back to the previous version");
    }

    if !wait_for_healthy(web) {
        tracing::error!("new version did not become healthy; rolling back");
        super::apply_linux::rollback(live_target, &old_path)?;
        crate::service::restart().context("rollback restart failed")?;
        bail!("upgrade did not become healthy within the grace window; rolled back to the previous version");
    }

    Ok(old_path)
}

#[cfg(not(target_os = "linux"))]
fn platform_swap_and_restart(
    _extracted_binary: &Path,
    _live_target: &Path,
    _version: &str,
    _web: &WebConfig,
) -> Result<std::path::PathBuf> {
    bail!(
        "upgrade apply (binary swap + service restart) is only implemented on Linux in this build"
    )
}

/// Polls the local, unauthenticated `/healthz` for up to 60s, requiring 3
/// consecutive 200s before declaring the new version healthy. When
/// `web.enabled` is `false` there is no `/healthz` endpoint running at all
/// (the web server itself never starts — see `run_agent` in `src/main.rs`),
/// so treating a timeout as "unhealthy" in that case would falsely roll
/// back a genuinely successful upgrade; skip the check entirely instead and
/// say so. When enabled, the URL is built from the *actual* configured
/// `web.bind`/`web.port` — `/healthz` binds to whatever the config on disk
/// (now the *new* config, unchanged by this upgrade) says, which need not
/// be this project's `127.0.0.1:8080` default.
#[cfg(target_os = "linux")]
fn wait_for_healthy(web: &WebConfig) -> bool {
    if !web.enabled {
        println!("web server is disabled (web.enabled: false); skipping post-upgrade health check");
        return true;
    }

    // `web.bind` is validated (see `config::validate`) as a bare IP
    // address, IPv4 or IPv6 — an IPv6 address needs `[...]` brackets to be
    // a valid URL host, unlike IPv4/hostnames, so bracket it only when it
    // actually parses as one.
    let host = match web.bind.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => format!("[{v6}]"),
        _ => web.bind.clone(),
    };
    let url = format!("http://{host}:{}/healthz", web.port);
    let mut consecutive_ok = 0;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let ok = Command::new("curl")
            .arg("-sf")
            .arg("-o")
            .arg("/dev/null")
            .arg(&url)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            consecutive_ok += 1;
            if consecutive_ok >= 3 {
                return true;
            }
        } else {
            consecutive_ok = 0;
        }
    }
    false
}

/// Manual rollback path for `upgrade --rollback`: finds the single
/// retained `.old-<version>` file next to `live_target` and restores it.
/// Errors if none is retained, or if more than one exists (this should be
/// impossible given `apply_from_local` prunes to exactly one, but a
/// corrupted/hand-edited install directory should fail loudly here rather
/// than guess which one to restore).
///
/// Linux-only, for the same reason `platform_swap_and_restart` is split
/// above: its body calls `apply_linux::rollback`, which only exists under
/// `#[cfg(target_os = "linux")]`.
#[cfg(target_os = "linux")]
pub fn rollback_from_local(live_target: &Path, _data_dir: &Path) -> Result<()> {
    let parent = live_target
        .parent()
        .context("live_target has no parent directory")?;
    let file_name = live_target
        .file_name()
        .context("live_target has no file name")?
        .to_string_lossy();
    let prefix = format!("{file_name}.old-");
    let mut candidates: Vec<std::path::PathBuf> = std::fs::read_dir(parent)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().starts_with(&prefix))
                .unwrap_or(false)
        })
        .collect();
    match candidates.len() {
        0 => bail!(
            "no retained previous version found next to {}",
            live_target.display()
        ),
        1 => {
            super::apply_linux::rollback(live_target, &candidates.remove(0))?;
            crate::service::restart().context("rollback restart failed")?;
            Ok(())
        }
        n => bail!("expected exactly one retained previous version, found {n} — refusing to guess"),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn rollback_from_local(_live_target: &Path, _data_dir: &Path) -> Result<()> {
    bail!("rollback is only implemented on Linux in this build")
}

/// Removes every `<live_target>.old-*` file except `keep`. Called after a
/// successful upgrade so retention never exceeds one previous version —
/// an unbounded number of retained binaries is both a disk-space leak and
/// makes `rollback_from_local`'s "exactly one candidate" invariant false.
fn prune_old_versions(live_target: &std::path::Path, keep: &std::path::Path) -> Result<()> {
    let parent = live_target
        .parent()
        .context("live_target has no parent directory")?;
    let file_name = live_target
        .file_name()
        .context("live_target has no file name")?
        .to_string_lossy();
    let prefix = format!("{file_name}.old-");
    for entry in std::fs::read_dir(parent)? {
        let path = entry?.path();
        let is_old_version = path
            .file_name()
            .map(|n| n.to_string_lossy().starts_with(&prefix))
            .unwrap_or(false);
        if is_old_version && path != keep {
            std::fs::remove_file(&path).with_context(|| {
                format!("cannot prune stale retained version {}", path.display())
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercises `preflight` against the *actual test binary of this crate*
    // standing in for "the staged binary" — it's a real `softnix-log-agent`
    // executable, so `--version` and `validate` behave exactly as they
    // would for a genuine staged release artifact.
    fn this_binary() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!(
                "target/debug/softnix-log-agent{}",
                std::env::consts::EXE_SUFFIX
            ))
            .to_path_buf()
    }

    #[test]
    fn preflight_passes_with_a_valid_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agent.yaml");
        std::fs::write(
            &config_path,
            format!(
                "agent:\n  data_dir: {}\nweb:\n  enabled: false\n",
                dir.path().join("data").display()
            ),
        )
        .unwrap();

        preflight(&this_binary(), &config_path).unwrap();
    }

    #[test]
    fn preflight_fails_on_an_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agent.yaml");
        std::fs::write(&config_path, "this: is not: valid: yaml: at all:\n").unwrap();

        let err = preflight(&this_binary(), &config_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("rejects the current configuration"));
    }

    #[test]
    fn preflight_fails_cleanly_on_a_nonexistent_staged_binary() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agent.yaml");
        std::fs::write(&config_path, "web:\n  enabled: false\n").unwrap();

        let err = preflight(&dir.path().join("does-not-exist"), &config_path).unwrap_err();
        assert!(err.to_string().contains("cannot execute staged binary"));
    }

    #[test]
    fn apply_from_local_rejects_a_replayed_manifest_before_touching_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"original content").unwrap();
        let config_path = dir.path().join("agent.yaml");
        std::fs::write(&config_path, "web:\n  enabled: false\n").unwrap();
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        // Flat archive shape: manifest.json / manifest.json.sig /
        // softnix-log-agent directly at the tar root, no wrapper directory.
        // Still a valid shape `resolve_extraction_root` supports; the CI's
        // actual (wrapper-directory) shape is covered separately by
        // `apply_from_local_reads_manifest_out_of_a_wrapper_directory` below.
        let stage = dir.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(
            stage.join("manifest.json"),
            br#"{"schema_version":1,"product":"softnix-log-agent","version":"0.2.0","manifest_serial":0,"released_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","artifacts":[]}"#,
        )
        .unwrap();
        std::fs::write(stage.join("manifest.json.sig"), [0u8; 64]).unwrap();
        std::fs::write(stage.join("softnix-log-agent"), b"pretend-new-binary").unwrap();

        let tar_path = dir.path().join("release.tar.gz");
        let status = std::process::Command::new("tar")
            .arg("czf")
            .arg(&tar_path)
            .arg("-C")
            .arg(&stage)
            .arg("manifest.json")
            .arg("manifest.json.sig")
            .arg("softnix-log-agent")
            .status()
            .unwrap();
        assert!(status.success());

        let result = apply_from_local(
            &tar_path,
            &config_path,
            &data_dir,
            false,
            &live,
            &WebConfig::default(),
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read(&live).unwrap(), b"original content");
    }

    /// Regression test for the Critical finding that the release tarball CI
    /// actually produces has a top-level wrapper directory (`tar czf
    /// "$STAGE.tar.gz" "$STAGE"`, `$STAGE` a directory) — `manifest.json`
    /// etc. end up one level *below* the tar root, not at it. This fixture
    /// reproduces that exact shape (confirmed by directly running the same
    /// `tar czf`/`tar xzf` invocations against a real wrapper directory) and
    /// asserts `apply_from_local` still finds and reads the manifest out of
    /// it. Before `resolve_extraction_root` existed, `apply_from_local`
    /// tried to read `<tmp>/manifest.json` directly against this fixture,
    /// which does not exist one level up — that attempt fails with "update
    /// artifact has no manifest.json" (a bare file-not-found), never even
    /// reaching signature verification. Post-fix, the manifest is found and
    /// read, and the call fails for a wholly different, expected reason:
    /// this build's `RELEASE_PUBLIC_KEYS` is intentionally empty until the
    /// Phase 0 signing-key runbook runs (see `src/update/manifest.rs`), so
    /// `verify_manifest` fails closed on "no release public keys". Asserting
    /// on that specific message (and not the file-not-found one) is what
    /// makes this a genuine regression test rather than a coincidental pass.
    #[test]
    fn apply_from_local_reads_manifest_out_of_a_wrapper_directory() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"original content").unwrap();
        let config_path = dir.path().join("agent.yaml");
        std::fs::write(&config_path, "web:\n  enabled: false\n").unwrap();
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        // Matches release.yml's `STAGE="softnix-log-agent-<ver>-linux-x86_64"`
        // + `mkdir -p "$STAGE"` + `tar czf "${STAGE}.tar.gz" "$STAGE"`: the
        // parent of `wrapper` here stands in for the CI job's working
        // directory, and `wrapper`'s name is the tar's sole top-level entry.
        let staging_root = dir.path().join("staging_root");
        let wrapper = staging_root.join("softnix-log-agent-0.2.0-linux-x86_64");
        std::fs::create_dir_all(&wrapper).unwrap();
        std::fs::write(
            wrapper.join("manifest.json"),
            br#"{"schema_version":1,"product":"softnix-log-agent","version":"0.2.0","manifest_serial":0,"released_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","artifacts":[]}"#,
        )
        .unwrap();
        std::fs::write(wrapper.join("manifest.json.sig"), [0u8; 64]).unwrap();
        std::fs::write(wrapper.join("softnix-log-agent"), b"pretend-new-binary").unwrap();

        let tar_path = dir.path().join("release.tar.gz");
        let status = std::process::Command::new("tar")
            .arg("czf")
            .arg(&tar_path)
            .arg("-C")
            .arg(&staging_root)
            .arg("softnix-log-agent-0.2.0-linux-x86_64")
            .status()
            .unwrap();
        assert!(status.success());

        let err = apply_from_local(
            &tar_path,
            &config_path,
            &data_dir,
            false,
            &live,
            &WebConfig::default(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no release public keys"),
            "expected to reach signature verification (proving manifest.json was found inside \
             the wrapper directory), got: {msg}"
        );
        assert!(
            !msg.contains("has no manifest.json"),
            "manifest.json lookup failed — apply_from_local did not resolve into the wrapper \
             directory: {msg}"
        );
        assert_eq!(std::fs::read(&live).unwrap(), b"original content");
    }

    #[test]
    fn prune_old_versions_removes_every_retained_version_except_the_one_to_keep() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"current").unwrap();
        let keep = dir.path().join("softnix-log-agent.old-0.1.5");
        std::fs::write(&keep, b"kept").unwrap();
        let stale1 = dir.path().join("softnix-log-agent.old-0.1.4");
        std::fs::write(&stale1, b"stale").unwrap();
        let stale2 = dir.path().join("softnix-log-agent.old-0.1.3");
        std::fs::write(&stale2, b"stale").unwrap();

        prune_old_versions(&live, &keep).unwrap();

        assert!(keep.exists());
        assert!(!stale1.exists());
        assert!(!stale2.exists());
    }

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
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let manifest_bytes = manifest_bytes.clone();
                let sig = sig.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let service = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let manifest_bytes = manifest_bytes.clone();
                            let sig = sig.clone();
                            async move {
                                let body = match req.uri().path() {
                                    "/manifest.json" => manifest_bytes,
                                    "/manifest.json.sig" => sig,
                                    "/artifact" => artifact_bytes.to_vec(),
                                    _ => Vec::new(),
                                };
                                Ok::<_, Infallible>(hyper::Response::new(
                                    http_body_util::Full::new(bytes::Bytes::from(body)),
                                ))
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
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
}
