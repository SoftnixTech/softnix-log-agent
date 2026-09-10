//! Linux binary swap: stage in the same directory as the live target
//! (never cross a filesystem boundary — `rename()` across filesystems
//! fails with `EXDEV` and has no atomic fallback), keep the previous
//! binary as a hardlink so the running process's already-open file
//! descriptor is unaffected, then a single atomic rename.

use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Copies `new_binary`'s content into the same directory as `live_target`,
/// makes it executable, hardlinks the *current* `live_target` aside as
/// `<live_target>.old-<version>` (so it survives even though its original
/// path is about to be overwritten — the running process keeps its own
/// inode regardless, this hardlink is purely for `rollback`/retention),
/// then atomically renames the staged file onto `live_target`.
///
/// Returns the path of the retained previous binary.
pub fn stage_and_swap(new_binary: &Path, live_target: &Path, version: &str) -> Result<PathBuf> {
    let parent = live_target
        .parent()
        .context("live_target has no parent directory")?;
    let staged = parent.join(format!(
        ".{}.new",
        live_target
            .file_name()
            .context("live_target has no file name")?
            .to_string_lossy()
    ));
    std::fs::copy(new_binary, &staged)
        .with_context(|| format!("cannot stage new binary at {}", staged.display()))?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("cannot chmod {}", staged.display()))?;

    let old_path = parent.join(format!(
        "{}.old-{version}",
        live_target.file_name().unwrap().to_string_lossy()
    ));
    // Remove any stale hardlink from a prior failed attempt at the same
    // version before creating a fresh one — `hard_link` errors if the
    // target already exists.
    let _ = std::fs::remove_file(&old_path);
    std::fs::hard_link(live_target, &old_path).with_context(|| {
        format!(
            "cannot hardlink current binary {} aside as {}",
            live_target.display(),
            old_path.display()
        )
    })?;

    std::fs::rename(&staged, live_target).with_context(|| {
        format!(
            "cannot rename staged binary {} onto {}",
            staged.display(),
            live_target.display()
        )
    })?;

    Ok(old_path)
}

/// Reverts a `stage_and_swap`: renames the retained previous binary back
/// onto `live_target`. Used both by automatic rollback-on-health-check-
/// failure (Task 10) and by the manual `upgrade --rollback` command.
pub fn rollback(live_target: &Path, old_path: &Path) -> Result<()> {
    std::fs::rename(old_path, live_target).with_context(|| {
        format!(
            "cannot roll back: rename {} onto {} failed",
            old_path.display(),
            live_target.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swaps_content_and_retains_the_previous_binary() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"old content").unwrap();
        let new_binary = dir.path().join("staged-source");
        std::fs::write(&new_binary, b"new content").unwrap();

        let old_path = stage_and_swap(&new_binary, &live, "0.2.0").unwrap();

        assert_eq!(std::fs::read(&live).unwrap(), b"new content");
        assert_eq!(std::fs::read(&old_path).unwrap(), b"old content");
        assert_eq!(old_path, dir.path().join("softnix-log-agent.old-0.2.0"));
    }

    #[test]
    fn the_swapped_in_binary_is_executable() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"old").unwrap();
        let new_binary = dir.path().join("staged-source");
        std::fs::write(&new_binary, b"new").unwrap();

        stage_and_swap(&new_binary, &live, "0.2.0").unwrap();

        let mode = std::fs::metadata(&live).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn no_staging_temp_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"old").unwrap();
        let new_binary = dir.path().join("staged-source");
        std::fs::write(&new_binary, b"new").unwrap();

        stage_and_swap(&new_binary, &live, "0.2.0").unwrap();

        assert!(!dir.path().join(".softnix-log-agent.new").exists());
    }

    #[test]
    fn rollback_restores_the_previous_binary() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"old content").unwrap();
        let new_binary = dir.path().join("staged-source");
        std::fs::write(&new_binary, b"new content").unwrap();

        let old_path = stage_and_swap(&new_binary, &live, "0.2.0").unwrap();
        rollback(&live, &old_path).unwrap();

        assert_eq!(std::fs::read(&live).unwrap(), b"old content");
    }

    #[test]
    fn a_second_swap_attempt_at_the_same_version_does_not_error_on_a_stale_hardlink() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"v1").unwrap();
        let new_binary = dir.path().join("staged-source");

        std::fs::write(&new_binary, b"v2-attempt-1").unwrap();
        stage_and_swap(&new_binary, &live, "0.2.0").unwrap();

        // Second attempt at the same target version (e.g. a retried
        // upgrade after a transient failure) must not fail merely because
        // `softnix-log-agent.old-0.2.0` already exists from the first try.
        std::fs::write(&new_binary, b"v2-attempt-2").unwrap();
        let old_path = stage_and_swap(&new_binary, &live, "0.2.0").unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"v2-attempt-2");
        assert_eq!(std::fs::read(&old_path).unwrap(), b"v2-attempt-1");
    }
}
