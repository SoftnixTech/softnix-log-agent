//! Persisted anti-replay state: the highest `manifest_serial` this host has
//! ever accepted. Mirrors `src/state.rs`'s write-through-`write_atomic`
//! pattern for a single small JSON file.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct WatermarkFile {
    highest_manifest_serial: u64,
}

pub struct Watermark {
    path: PathBuf,
    highest_serial: u64,
}

impl Watermark {
    /// Reads `<data_dir>/update-watermark.json` if present; a missing or
    /// unparseable file is treated as "nothing accepted yet" (serial 0),
    /// same tolerance `StateManager::open` already applies to `state.json`.
    pub fn open(data_dir: &Path) -> Self {
        let path = data_dir.join("update-watermark.json");
        let highest_serial = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<WatermarkFile>(&bytes).ok())
            .map(|w| w.highest_manifest_serial)
            .unwrap_or(0);
        Watermark {
            path,
            highest_serial,
        }
    }

    pub fn highest_serial(&self) -> u64 {
        self.highest_serial
    }

    /// Persists `serial` as the new watermark. Callers must only call this
    /// after a successful, health-checked upgrade — recording a serial for
    /// an upgrade that later rolls back would permanently lock this host
    /// out of ever re-accepting that manifest.
    pub fn record(&mut self, serial: u64) -> Result<()> {
        self.highest_serial = serial;
        let bytes = serde_json::to_vec(&WatermarkFile {
            highest_manifest_serial: serial,
        })?;
        crate::fsutil::write_atomic(&self.path, &bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_at_zero_when_no_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let w = Watermark::open(dir.path());
        assert_eq!(w.highest_serial(), 0);
    }

    #[test]
    fn record_then_reopen_persists_the_value() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = Watermark::open(dir.path());
        w.record(7).unwrap();

        let reopened = Watermark::open(dir.path());
        assert_eq!(reopened.highest_serial(), 7);
    }

    #[test]
    fn record_leaves_no_stray_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = Watermark::open(dir.path());
        w.record(1).unwrap();
        assert!(!dir.path().join("update-watermark.json.tmp").exists());
    }

    #[test]
    fn a_corrupt_watermark_file_is_treated_as_zero_not_a_crash() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("update-watermark.json"), b"not json").unwrap();
        let w = Watermark::open(dir.path());
        assert_eq!(w.highest_serial(), 0);
    }
}
