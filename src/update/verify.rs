//! Artifact selection and integrity verification. Signature verification
//! (`manifest::verify_manifest`) proves the *manifest* is authentic; this
//! module proves the *downloaded/staged file on disk* matches what that
//! manifest says it should be — a separate check, because the file is
//! read from disk here, not trusted from whatever was written moments ago.

use super::manifest::{Artifact, Manifest};
use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::Path;

impl Manifest {
    pub fn artifact_for(&self, platform: &str, arch: &str) -> Option<&Artifact> {
        self.artifacts
            .iter()
            .find(|a| a.platform == platform && a.arch == arch)
    }
}

/// Hashes the file at `path` and compares it (constant-time-insensitive
/// comparison is fine here — this isn't a MAC, it's a public checksum whose
/// only job is catching corruption/tampering already ruled out by the
/// manifest's signature; the signature is what carries the security
/// property) against `expected_hex` (lowercase hex, as the manifest stores
/// it). Re-reads the file from disk rather than trusting any in-memory
/// buffer the caller might have.
pub fn verify_artifact_hash(path: &Path, expected_hex: &str) -> Result<()> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let actual = hex::encode(ctx.finish().as_ref());
    let expected = expected_hex.to_lowercase();
    if actual != expected {
        bail!(
            "hash mismatch for {}: expected {expected}, got {actual}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::manifest::Manifest;
    use super::*;

    fn sample_manifest() -> Manifest {
        Manifest {
            schema_version: 1,
            product: "softnix-log-agent".into(),
            version: "0.2.0".into(),
            manifest_serial: 1,
            released_at: "2026-09-09T00:00:00Z".into(),
            expires_at: "2027-09-09T00:00:00Z".into(),
            min_upgrade_from: None,
            artifacts: vec![
                Artifact {
                    platform: "linux".into(),
                    arch: "x86_64".into(),
                    filename: "a.tar.gz".into(),
                    url: "https://example.invalid/a.tar.gz".into(),
                    sha256: "deadbeef".into(),
                    size: 1,
                },
                Artifact {
                    platform: "windows".into(),
                    arch: "x86_64".into(),
                    filename: "a.msi".into(),
                    url: "https://example.invalid/a.msi".into(),
                    sha256: "cafef00d".into(),
                    size: 1,
                },
            ],
        }
    }

    #[test]
    fn finds_the_matching_platform_and_arch() {
        let m = sample_manifest();
        assert_eq!(
            m.artifact_for("linux", "x86_64").unwrap().filename,
            "a.tar.gz"
        );
        assert_eq!(
            m.artifact_for("windows", "x86_64").unwrap().filename,
            "a.msi"
        );
    }

    #[test]
    fn returns_none_for_an_unlisted_platform() {
        let m = sample_manifest();
        assert!(m.artifact_for("macos", "aarch64").is_none());
    }

    #[test]
    fn verify_artifact_hash_accepts_a_matching_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"hello world").unwrap();
        // sha256("hello world")
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(verify_artifact_hash(&path, expected).is_ok());
    }

    #[test]
    fn verify_artifact_hash_rejects_a_mismatched_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let err = verify_artifact_hash(
            &path,
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn verify_artifact_hash_errors_cleanly_on_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.bin");
        assert!(verify_artifact_hash(&path, "deadbeef").is_err());
    }
}
