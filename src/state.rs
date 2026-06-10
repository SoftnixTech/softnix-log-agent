//! Persistent agent state: file cursors and runtime checkpoints.
//! Written atomically (tmp + rename) and flushed periodically plus on shutdown.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateFile {
    /// Keyed by "<input_id>|<file identity>".
    #[serde(default)]
    pub files: HashMap<String, FileCursor>,
    /// Input ids that have completed at least one discovery pass.
    #[serde(default)]
    pub known_inputs: HashSet<String>,
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
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get_cursor(&self, input_id: &str, identity: &str) -> Option<FileCursor> {
        let key = format!("{input_id}|{identity}");
        self.state.lock().unwrap().files.get(&key).cloned()
    }

    pub fn set_cursor(&self, input_id: &str, identity: &str, path: &str, offset: u64) {
        let key = format!("{input_id}|{identity}");
        let mut st = self.state.lock().unwrap();
        st.files.insert(
            key,
            FileCursor {
                path: path.to_string(),
                offset,
                touched: chrono::Utc::now().timestamp(),
            },
        );
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

    /// Persist if dirty. Atomic write (tmp file + rename).
    pub fn flush(&self) -> Result<()> {
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return Ok(());
        }
        let bytes = {
            let st = self.state.lock().unwrap();
            serde_json::to_vec_pretty(&*st)?
        };
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes)
            .with_context(|| format!("cannot write state file {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("cannot replace state file {}", self.path.display()))?;
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
}
