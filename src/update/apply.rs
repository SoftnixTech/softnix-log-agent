//! Cross-platform update orchestration: preflight, then dispatch to the
//! platform-specific swap in `apply_linux` / `apply_windows`.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

use super::manifest::{check_freshness, verify_manifest};
use super::verify::verify_artifact_hash;
use super::watermark::Watermark;

const CURRENT_PLATFORM: &str = "linux";
const CURRENT_ARCH: &str = std::env::consts::ARCH;

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

/// Extracts `manifest.json` + `manifest.json.sig` + the platform binary
/// from `artifact_path` (a `.tar.gz`) into a fresh temp directory, verifies
/// the manifest's signature and freshness, verifies the extracted binary's
/// hash against the manifest, preflights it against `config_path`, then —
/// only after every one of those checks passes — swaps it onto
/// `live_target` and restarts the service. Everything up to the swap is
/// read-only with respect to `live_target`; a failure at any check leaves
/// it completely untouched.
pub fn apply_from_local(
    artifact_path: &Path,
    config_path: &Path,
    data_dir: &Path,
    allow_downgrade: bool,
    live_target: &Path,
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

    let manifest_bytes = std::fs::read(extract_dir.path().join("manifest.json"))
        .context("update artifact has no manifest.json")?;
    let sig = std::fs::read(extract_dir.path().join("manifest.json.sig"))
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
    let extracted_binary = extract_dir.path().join("softnix-log-agent");
    verify_artifact_hash(&extracted_binary, &artifact.sha256)?;

    preflight(&extracted_binary, config_path)?;

    // Point of no return: everything above this line is read-only with
    // respect to `live_target`.
    platform_swap_and_restart(&extracted_binary, live_target, &manifest.version)?;

    watermark.record(manifest.manifest_serial)?;
    println!(
        "upgraded {} -> {}",
        env!("CARGO_PKG_VERSION"),
        manifest.version
    );
    Ok(())
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
fn platform_swap_and_restart(extracted_binary: &Path, live_target: &Path, version: &str) -> Result<()> {
    let old_path = super::apply_linux::stage_and_swap(extracted_binary, live_target, version)?;

    if let Err(e) = crate::service::restart() {
        tracing::error!("service restart failed after swap: {e:#}; rolling back");
        super::apply_linux::rollback(live_target, &old_path)?;
        crate::service::restart().context("rollback restart also failed")?;
        bail!("upgrade failed to restart the service; rolled back to the previous version");
    }

    if !wait_for_healthy() {
        tracing::error!("new version did not become healthy; rolling back");
        super::apply_linux::rollback(live_target, &old_path)?;
        crate::service::restart().context("rollback restart failed")?;
        bail!("upgrade did not become healthy within the grace window; rolled back to the previous version");
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn platform_swap_and_restart(_extracted_binary: &Path, _live_target: &Path, _version: &str) -> Result<()> {
    bail!("upgrade apply (binary swap + service restart) is only implemented on Linux in this build")
}

/// Polls the local, unauthenticated `/healthz` for up to 60s, requiring 3
/// consecutive 200s before declaring the new version healthy. Reading
/// `web.port`/`web.bind` from the live config would be more precise, but
/// `/healthz` binds to whatever the config on disk (now the *new* config,
/// unchanged by this upgrade) says — 127.0.0.1 is this project's default
/// and the common case; a non-default bind/port is a known limitation of
/// this first cut, tracked for Phase 1 hardening rather than blocking it.
#[cfg(target_os = "linux")]
fn wait_for_healthy() -> bool {
    let mut consecutive_ok = 0;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let ok = Command::new("curl")
            .arg("-sf")
            .arg("-o")
            .arg("/dev/null")
            .arg("http://127.0.0.1:8080/healthz")
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
        0 => bail!("no retained previous version found next to {}", live_target.display()),
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
        assert!(err.to_string().contains("rejects the current configuration"));
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

        let result = apply_from_local(&tar_path, &config_path, &data_dir, false, &live);
        assert!(result.is_err());
        assert_eq!(std::fs::read(&live).unwrap(), b"original content");
    }
}
