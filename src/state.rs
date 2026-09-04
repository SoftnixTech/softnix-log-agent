//! Persistent agent state: file cursors and runtime checkpoints.
//! Written atomically (tmp + rename) and flushed periodically plus on shutdown.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Mutex;

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateFile {
    /// Keyed by "<input_id>|<file identity>".
    #[serde(default)]
    pub files: HashMap<String, FileCursor>,
    /// Input ids that have completed at least one discovery pass.
    #[serde(default)]
    pub known_inputs: HashSet<String>,
    /// Opaque resume tokens keyed by "<input_id>|<key>" (e.g. Windows Event Log
    /// bookmarks per channel). Kept separate from file cursors.
    #[serde(default)]
    pub checkpoints: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCursor {
    pub path: String,
    pub offset: u64,
    /// Last time this cursor was touched (unix seconds), for pruning.
    pub touched: i64,
}

pub struct StateManager {
    path: PathBuf,
    state: Mutex<StateFile>,
    dirty: AtomicBool,
    retention_secs: AtomicI64,
}

impl StateManager {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create state directory {}", dir.display()))?;
        let path = dir.join("state.json");
        let state = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                tracing::warn!("state file corrupt ({e}); starting with empty state");
                StateFile::default()
            }),
            Err(_) => StateFile::default(),
        };
        Ok(StateManager {
            path,
            state: Mutex::new(state),
            dirty: AtomicBool::new(false),
            retention_secs: AtomicI64::new(24 * 3600),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Relaxed)
    }

    /// Override the cursor-retention window (default 24h, set at `open`).
    pub fn set_retention_secs(&self, secs: i64) {
        self.retention_secs.store(secs, Ordering::Relaxed);
    }

    pub fn get_cursor(&self, input_id: &str, identity: &str) -> Option<FileCursor> {
        let key = format!("{input_id}|{identity}");
        self.state.lock().unwrap().files.get(&key).cloned()
    }

    pub fn set_cursor(&self, input_id: &str, identity: &str, path: &str, offset: u64) {
        let key = format!("{input_id}|{identity}");
        let now = now_secs();
        let mut st = self.state.lock().unwrap();
        if let Some(existing) = st.files.get_mut(&key) {
            if existing.offset == offset {
                // The tailer calls this on every poll for every idle file. Only
                // refresh `touched` (and dirty the file) once a minute, or a
                // host with a few hundred idle files rewrites the whole state
                // file every 5 seconds forever.
                if now.saturating_sub(existing.touched) < 60 {
                    return;
                }
                existing.touched = now;
                self.dirty.store(true, Ordering::Relaxed);
                return;
            }
            existing.offset = offset;
            existing.path = path.to_string();
            existing.touched = now;
        } else {
            st.files.insert(
                key,
                FileCursor {
                    offset,
                    path: path.to_string(),
                    touched: now,
                },
            );
        }
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Read an opaque resume token (e.g. an Event Log bookmark XML).
    pub fn get_checkpoint(&self, input_id: &str, key: &str) -> Option<String> {
        let k = format!("{input_id}|{key}");
        self.state.lock().unwrap().checkpoints.get(&k).cloned()
    }

    /// Store an opaque resume token. No-op (and not marked dirty) if unchanged.
    pub fn set_checkpoint(&self, input_id: &str, key: &str, value: &str) {
        let k = format!("{input_id}|{key}");
        let mut st = self.state.lock().unwrap();
        if st.checkpoints.get(&k).map(String::as_str) == Some(value) {
            return;
        }
        st.checkpoints.insert(k, value.to_string());
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub fn is_known_input(&self, input_id: &str) -> bool {
        self.state.lock().unwrap().known_inputs.contains(input_id)
    }

    pub fn mark_known_input(&self, input_id: &str) {
        let mut st = self.state.lock().unwrap();
        if st.known_inputs.insert(input_id.to_string()) {
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    /// Drop cursors not touched for `max_age_secs` (rotated-away files).
    pub fn prune(&self, max_age_secs: i64) {
        let cutoff = chrono::Utc::now().timestamp() - max_age_secs;
        let mut st = self.state.lock().unwrap();
        let before = st.files.len();
        st.files.retain(|_, c| c.touched >= cutoff);
        if st.files.len() != before {
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    /// Persist if dirty. Atomic write (tmp file + rename), compact JSON, and
    /// prunes cursors older than the configured retention window on every call.
    pub fn flush(&self) -> Result<()> {
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return Ok(());
        }
        let cutoff = now_secs().saturating_sub(self.retention_secs.load(Ordering::Relaxed));
        let bytes = {
            let mut st = self.state.lock().unwrap();
            st.files.retain(|_, c| c.touched >= cutoff);
            serde_json::to_vec(&*st)?
        };
        crate::fsutil::write_atomic(&self.path, &bytes)
            .with_context(|| format!("cannot write state file {}", self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let sm = StateManager::open(dir.path()).unwrap();
            sm.set_cursor("in1", "dev:1:42", "/var/log/a.log", 1234);
            sm.mark_known_input("in1");
            sm.flush().unwrap();
        }
        let sm = StateManager::open(dir.path()).unwrap();
        let c = sm.get_cursor("in1", "dev:1:42").unwrap();
        assert_eq!(c.offset, 1234);
        assert!(sm.is_known_input("in1"));
        assert!(!sm.is_known_input("in2"));
    }

    #[test]
    fn repeating_the_same_offset_does_not_dirty_the_state() {
        let dir = tempfile::tempdir().unwrap();
        let st = StateManager::open(dir.path()).unwrap();
        st.set_cursor("in1", "ident", "/var/log/a.log", 100);
        st.flush().unwrap();
        assert!(!st.is_dirty());
        st.set_cursor("in1", "ident", "/var/log/a.log", 100);
        assert!(
            !st.is_dirty(),
            "an unchanged offset must not force a rewrite"
        );
        st.set_cursor("in1", "ident", "/var/log/a.log", 200);
        assert!(st.is_dirty(), "a real advance must still be persisted");
    }

    #[test]
    fn state_is_written_compactly() {
        let dir = tempfile::tempdir().unwrap();
        let st = StateManager::open(dir.path()).unwrap();
        st.set_cursor("in1", "ident", "/var/log/a.log", 100);
        st.flush().unwrap();
        let text = std::fs::read_to_string(dir.path().join("state.json")).unwrap();
        assert!(!text.contains("\n  "), "state must not be pretty-printed");
    }
}
