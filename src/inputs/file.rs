//! File tailing input: glob discovery, rotation handling, offset persistence.
//!
//! Strategy: poll-based (cheap, portable, robust against editor/rotation
//! quirks on both Linux and Windows). Files are identified by OS identity
//! (inode on Unix; on Windows a content fingerprint of the file head, since
//! stable Rust exposes no volume/file-index and creation_time collides when
//! many files are created in the same 100 ns tick), so rename rotation and
//! recreation are detected; truncation resets the offset.

use crate::config::FileInputConfig;
use crate::event::Event;
use crate::metrics::{InputStatus, Metrics, StatusRegistry};
use crate::pipeline::Parser;
use crate::state::StateManager;
use anyhow::Result;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Max bytes consumed per file per poll cycle, to keep one busy file from
/// starving the rest.
const READ_BUDGET: u64 = 4 * 1024 * 1024;
/// Lines longer than this are emitted even without a trailing newline.
const MAX_LINE: usize = 1024 * 1024;

/// Upper bound on bytes scanned to fingerprint a file's first line on platforms
/// without a stable file-id. Caps the cost for a pathologically long first line.
#[cfg(any(windows, test))]
const FINGERPRINT_BYTES: usize = 512;

#[cfg(unix)]
fn file_identity(_path: &Path, md: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!("dev{}:ino{}", md.dev(), md.ino())
}

#[cfg(windows)]
fn file_identity(path: &Path, md: &std::fs::Metadata) -> String {
    use std::os::windows::fs::MetadataExt;
    // creation_time alone collides when many files are created in the same
    // 100 ns tick (e.g. 50 logs written at once) and is unstable across some
    // rotation schemes. Pair it with a hash of the file head so files with
    // distinct content are always told apart, while a rotated file (same head
    // content travels with the rename) keeps the same identity.
    let head = head_fingerprint(path).unwrap_or(0);
    format!("ct{}:h{:08x}", md.creation_time(), head)
}

/// Fingerprint a file by hashing its first line (bytes up to and including the
/// first newline), capped at `FINGERPRINT_BYTES`. Returns `None` if the file
/// cannot be read.
///
/// Hashing only the first line keeps the fingerprint **stable** for append-only
/// logs: once the first line is written it never changes, so subsequent growth
/// leaves the identity untouched (a growing prefix hash would instead flip the
/// identity mid-life and trigger spurious re-reads). Before the first newline
/// exists no complete line is emitted, so a hash change in that window cannot
/// duplicate data.
#[cfg(any(windows, test))]
fn head_fingerprint(path: &Path) -> Option<u32> {
    let mut f = File::open(path).ok()?;
    let mut buf = vec![0u8; FINGERPRINT_BYTES];
    let mut filled = 0usize;
    while filled < buf.len() {
        match f.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => {
                filled += n;
                if buf[..filled].contains(&b'\n') {
                    break;
                }
            }
            Err(_) => return None,
        }
    }
    // Truncate to the first newline (inclusive) so appended lines don't affect
    // the hash; if none was found within the cap, hash what we have.
    let end = buf[..filled]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(filled, |p| p + 1);
    Some(crc32fast::hash(&buf[..end]))
}

struct Tracked {
    identity: String,
    offset: u64,
}

pub struct FileInput {
    cfg: FileInputConfig,
    parser: Parser,
    source_type: String,
    exclude: globset::GlobSet,
}

impl FileInput {
    pub fn new(cfg: &FileInputConfig) -> Result<Self> {
        let parser = Parser::compile(&cfg.parser)?;
        let mut builder = globset::GlobSetBuilder::new();
        for pat in &cfg.exclude {
            builder.add(globset::Glob::new(&pat.replace('\\', "/"))?);
        }
        Ok(FileInput {
            source_type: cfg.source_type.clone().unwrap_or_else(|| "file".into()),
            parser,
            exclude: builder.build()?,
            cfg: cfg.clone(),
        })
    }

    pub fn spawn(
        self,
        tx: mpsc::Sender<Event>,
        state: Arc<StateManager>,
        status: Arc<StatusRegistry>,
        metrics: Arc<Metrics>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        status.set_input(InputStatus {
            id: self.cfg.id.clone(),
            kind: "file".into(),
            detail: self.cfg.paths.join(", "),
            active: true,
            events: 0,
            last_error: None,
        });
        tokio::spawn(async move {
            self.run(tx, state, status, metrics, cancel).await;
        })
    }

    async fn run(
        self,
        tx: mpsc::Sender<Event>,
        state: Arc<StateManager>,
        status: Arc<StatusRegistry>,
        metrics: Arc<Metrics>,
        cancel: CancellationToken,
    ) {
        let id = self.cfg.id.clone();
        // On the very first run of this input (no recorded state), existing
        // file content is skipped unless read_from_start is set. Files that
        // appear later are always read from the beginning.
        let first_run = !state.is_known_input(&id);
        let mut tracked: HashMap<PathBuf, Tracked> = HashMap::new();
        let interval = std::time::Duration::from_millis(self.cfg.poll_interval_ms);

        loop {
            let poll_result = self.poll_once(
                &tx,
                &state,
                &metrics,
                &mut tracked,
                first_run && !state.is_known_input(&id),
                &cancel,
            );
            match poll_result.await {
                Ok(n) => {
                    state.mark_known_input(&id);
                    if n > 0 {
                        let inc = n;
                        status.update_input(&id, |s| {
                            s.events += inc;
                            s.last_error = None;
                        });
                    }
                }
                Err(e) => {
                    let msg = format!("file input {id}: {e}");
                    tracing::warn!("{msg}");
                    metrics.record_error(&msg);
                    status.update_input(&id, |s| s.last_error = Some(e.to_string()));
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = cancel.cancelled() => {
                    status.update_input(&id, |s| s.active = false);
                    return;
                }
            }
        }
    }

    /// One discovery + read pass. Returns events emitted.
    async fn poll_once(
        &self,
        tx: &mpsc::Sender<Event>,
        state: &StateManager,
        metrics: &Metrics,
        tracked: &mut HashMap<PathBuf, Tracked>,
        skip_existing: bool,
        cancel: &CancellationToken,
    ) -> Result<u64> {
        let id = &self.cfg.id;
        let mut emitted = 0u64;

        for path in self.discover()? {
            if cancel.is_cancelled() {
                break;
            }
            let md = match std::fs::metadata(&path) {
                Ok(m) if m.is_file() => m,
                _ => continue,
            };
            let identity = file_identity(&path, &md);
            let size = md.len();
            let path_str = path.to_string_lossy().into_owned();

            let entry = tracked.entry(path.clone());
            let t = match entry {
                std::collections::hash_map::Entry::Occupied(mut o) => {
                    if o.get().identity != identity {
                        // Rotated: a new file replaced the old one at this path.
                        let offset = state
                            .get_cursor(id, &identity)
                            .map(|c| c.offset)
                            .unwrap_or(0);
                        *o.get_mut() = Tracked { identity, offset };
                    }
                    o.into_mut()
                }
                std::collections::hash_map::Entry::Vacant(v) => {
                    // Newly discovered path. Resume from saved cursor (same
                    // identity seen before, e.g. after agent restart), else
                    // start at 0 — or at EOF on the input's first ever run.
                    let offset = match state.get_cursor(id, &identity) {
                        Some(c) => c.offset.min(size),
                        None if skip_existing && !self.cfg.read_from_start => size,
                        None => 0,
                    };
                    v.insert(Tracked { identity, offset })
                }
            };

            // Copy-truncate rotation or manual truncation.
            if size < t.offset {
                tracing::info!("file {} truncated; restarting from 0", path.display());
                t.offset = 0;
            }
            if size == t.offset {
                state.set_cursor(id, &t.identity, &path_str, t.offset);
                continue;
            }

            match self.read_new_lines(&path, t.offset, size) {
                Ok((lines, new_offset)) => {
                    for line in lines {
                        let ev = self.parser.parse(&line, &path_str, &self.source_type);
                        metrics
                            .events_received
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        emitted += 1;
                        tokio::select! {
                            res = tx.send(ev) => {
                                if res.is_err() {
                                    return Ok(emitted);
                                }
                            }
                            _ = cancel.cancelled() => return Ok(emitted),
                        }
                    }
                    t.offset = new_offset;
                    state.set_cursor(id, &t.identity, &path_str, t.offset);
                }
                Err(e) => {
                    tracing::warn!("cannot read {}: {e}", path.display());
                }
            }
        }

        // Forget tracked entries whose paths vanished (deleted/rotated away).
        tracked.retain(|p, _| p.exists());
        Ok(emitted)
    }

    /// Read complete lines from `offset`, never past `size`. The offset only
    /// advances past the last full newline so partial writes are re-read.
    fn read_new_lines(&self, path: &Path, offset: u64, size: u64) -> Result<(Vec<String>, u64)> {
        let mut f = File::open(path)?;
        f.seek(SeekFrom::Start(offset))?;
        let to_read = (size - offset).min(READ_BUDGET);
        let mut buf = vec![0u8; to_read as usize];
        let mut filled = 0usize;
        while filled < buf.len() {
            match f.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        buf.truncate(filled);

        let mut lines = Vec::new();
        let mut consumed = 0usize;
        let mut start = 0usize;
        for (i, &b) in buf.iter().enumerate() {
            if b == b'\n' {
                let mut end = i;
                if end > start && buf[end - 1] == b'\r' {
                    end -= 1;
                }
                if end > start {
                    lines.push(String::from_utf8_lossy(&buf[start..end]).into_owned());
                }
                start = i + 1;
                consumed = start;
            }
        }
        // Force out an over-long unterminated line so we don't stall forever.
        if buf.len() - consumed >= MAX_LINE {
            lines.push(String::from_utf8_lossy(&buf[consumed..]).into_owned());
            consumed = buf.len();
        }
        Ok((lines, offset + consumed as u64))
    }

    fn discover(&self) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        for pat in &self.cfg.paths {
            let normalized = pat.replace('\\', "/");
            for entry in glob::glob(&normalized)? {
                let Ok(p) = entry else { continue };
                let p_str = p.to_string_lossy().replace('\\', "/");
                if self.exclude.is_match(&p_str) {
                    continue;
                }
                out.push(p);
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ParserConfig;
    use std::io::Write;

    fn input_for(dir: &Path) -> FileInput {
        FileInput::new(&FileInputConfig {
            id: "t".into(),
            paths: vec![format!("{}/*.log", dir.display())],
            exclude: vec![format!("{}/skip*.log", dir.display())],
            poll_interval_ms: 100,
            read_from_start: true,
            parser: ParserConfig::default(),
            source_type: None,
        })
        .unwrap()
    }

    #[test]
    fn head_fingerprint_distinguishes_concurrent_files() {
        // FILE-011 regression: files created in the same instant must still be
        // told apart. creation_time would collide; the content head must not.
        let dir = tempfile::tempdir().unwrap();
        let mut hashes = std::collections::HashSet::new();
        for i in 1..=50 {
            let p = dir.path().join(format!("multi{i}.log"));
            std::fs::write(&p, format!("from file {i}\n")).unwrap();
            hashes.insert(head_fingerprint(&p).unwrap());
        }
        assert_eq!(hashes.len(), 50, "every distinct log file must hash uniquely");
    }

    #[test]
    fn head_fingerprint_stable_as_file_grows() {
        // FILE-005 regression: a file's identity must not change as more lines
        // are appended, so the agent keeps tracking the same file across polls.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("app.log");
        std::fs::write(&p, "first line\n").unwrap();
        let h1 = head_fingerprint(&p).unwrap();
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"second line\nthird line\n").unwrap();
        let h2 = head_fingerprint(&p).unwrap();
        assert_eq!(h1, h2, "fingerprint must be stable as the file grows");
    }

    async fn collect(rx: &mut mpsc::Receiver<Event>) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev.message);
        }
        out
    }

    #[tokio::test]
    async fn tails_rotation_and_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("app.log");
        let skip = dir.path().join("skipme.log");
        std::fs::write(&skip, "excluded\n").unwrap();
        std::fs::write(&log, "line1\nline2\n").unwrap();

        let input = input_for(dir.path());
        let state = Arc::new(StateManager::open(state_dir.path()).unwrap());
        let metrics = Arc::new(Metrics::default());
        let (tx, mut rx) = mpsc::channel(1000);
        let cancel = CancellationToken::new();
        let mut tracked = HashMap::new();

        // Initial read
        input
            .poll_once(&tx, &state, &metrics, &mut tracked, false, &cancel)
            .await
            .unwrap();
        assert_eq!(collect(&mut rx).await, vec!["line1", "line2"]);

        // Append, including a partial line that must NOT be emitted yet
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
            f.write_all(b"line3\npart").unwrap();
        }
        input
            .poll_once(&tx, &state, &metrics, &mut tracked, false, &cancel)
            .await
            .unwrap();
        assert_eq!(collect(&mut rx).await, vec!["line3"]);

        // Complete the partial line
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
            f.write_all(b"ial\n").unwrap();
        }
        input
            .poll_once(&tx, &state, &metrics, &mut tracked, false, &cancel)
            .await
            .unwrap();
        assert_eq!(collect(&mut rx).await, vec!["partial"]);

        // Rename rotation: move file away, create fresh one at same path
        std::fs::rename(&log, dir.path().join("app.log.old")).unwrap();
        std::fs::write(&log, "fresh1\n").unwrap();
        input
            .poll_once(&tx, &state, &metrics, &mut tracked, false, &cancel)
            .await
            .unwrap();
        let got = collect(&mut rx).await;
        assert!(got.contains(&"fresh1".to_string()), "got: {got:?}");

        // Copy-truncate rotation: truncate in place (poll observes the
        // shrunken size, as it does in production), then new data arrives.
        std::fs::write(&log, "").unwrap();
        input
            .poll_once(&tx, &state, &metrics, &mut tracked, false, &cancel)
            .await
            .unwrap();
        std::fs::write(&log, "after-trunc\n").unwrap();
        input
            .poll_once(&tx, &state, &metrics, &mut tracked, false, &cancel)
            .await
            .unwrap();
        assert_eq!(collect(&mut rx).await, vec!["after-trunc"]);
    }

    #[tokio::test]
    async fn resumes_from_saved_offset() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("app.log");
        std::fs::write(&log, "a\nb\n").unwrap();
        let metrics = Arc::new(Metrics::default());
        let cancel = CancellationToken::new();

        {
            let input = input_for(dir.path());
            let state = Arc::new(StateManager::open(state_dir.path()).unwrap());
            let (tx, mut rx) = mpsc::channel(100);
            let mut tracked = HashMap::new();
            input
                .poll_once(&tx, &state, &metrics, &mut tracked, false, &cancel)
                .await
                .unwrap();
            assert_eq!(collect(&mut rx).await.len(), 2);
            state.flush().unwrap();
        }

        // "Restart": new input + reloaded state; append one more line.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(b"c\n")
            .unwrap();
        let input = input_for(dir.path());
        let state = Arc::new(StateManager::open(state_dir.path()).unwrap());
        let (tx, mut rx) = mpsc::channel(100);
        let mut tracked = HashMap::new();
        input
            .poll_once(&tx, &state, &metrics, &mut tracked, false, &cancel)
            .await
            .unwrap();
        assert_eq!(collect(&mut rx).await, vec!["c"]);
    }
}
