//! Cross-platform update orchestration: preflight, then dispatch to the
//! platform-specific swap in `apply_linux` / `apply_windows`.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

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
}
