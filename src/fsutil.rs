//! Small filesystem helpers shared by the queue and the state manager.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Write `bytes` to `path` so a reader never observes a partial file:
/// write to `<path>.tmp`, fsync, then rename over the target.
///
/// The queue cursor and the file-offset state both depend on this — a torn
/// cursor.json makes the agent replay its entire backlog after a power loss.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(match path.extension() {
        Some(ext) => format!("{}.tmp", ext.to_string_lossy()),
        None => "tmp".to_string(),
    });
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // Durability of the rename itself needs the directory fsynced too.
    if let Some(parent) = path.parent() {
        if let Ok(d) = File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_content_and_leaves_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cursor.json");
        std::fs::write(&p, b"old").unwrap();
        write_atomic(&p, b"new").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
        assert!(!dir.path().join("cursor.json.tmp").exists());
    }

    #[test]
    fn write_atomic_overwrites_a_stale_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cursor.json");
        std::fs::write(dir.path().join("cursor.json.tmp"), b"leftover garbage").unwrap();
        write_atomic(&p, b"fresh").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"fresh");
    }
}
