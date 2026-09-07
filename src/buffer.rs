//! Persistent on-disk queue, one per destination.
//!
//! Layout: <dir>/<dest_id>/NNNNNNNNNNNNNNNNNNNN.seg + cursor.json
//! Record format: [len: u32 LE][crc32: u32 LE][payload: serde_json(Event)]
//!
//! Single producer (pipeline) / single consumer (output worker).
//! The consumer peeks a batch, sends it, then acks; the persisted cursor only
//! advances on ack, giving at-least-once delivery across crashes.

use crate::config::{BufferConfig, FullPolicy};
use crate::event::Event;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const HEADER: u64 = 8;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
struct Cursor {
    seg: u64,
    off: u64,
}

struct Inner {
    dir: PathBuf,
    segments: BTreeSet<u64>,
    write_seg: u64,
    write_off: u64,
    writer: Option<File>,
    /// Persisted (acked) read position.
    cursor: Cursor,
    /// In-memory read position of un-acked peeks.
    peek: Cursor,
    /// Events between cursor and end of queue.
    count: u64,
    /// Total bytes across all segment files.
    bytes: u64,
}

#[derive(Debug)]
pub enum PushOutcome {
    /// Event was stored. `evicted` is the number of older events discarded to
    /// make room under the `drop_oldest` full policy (0 otherwise). Callers
    /// must count these toward the global dropped metric, otherwise oldest-drop
    /// evictions are invisible on the Overview page.
    Stored {
        evicted: u64,
    },
    Dropped,
    Full,
}

pub struct DiskQueue {
    pub id: String,
    inner: Mutex<Inner>,
    data_notify: Notify,
    space_notify: Notify,
    max_bytes: u64,
    seg_bytes: u64,
    policy: FullPolicy,
    dropped: AtomicU64,
    corrupt: AtomicU64,
}

impl DiskQueue {
    pub fn open(base_dir: &std::path::Path, id: &str, cfg: &BufferConfig) -> Result<Arc<Self>> {
        let dir = base_dir.join(id);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create queue directory {}", dir.display()))?;

        let mut segments = BTreeSet::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(stem) = name.strip_suffix(".seg") {
                if let Ok(n) = stem.parse::<u64>() {
                    segments.insert(n);
                }
            }
        }
        if segments.is_empty() {
            segments.insert(0);
            File::create(seg_path(&dir, 0))?;
        }

        // Only the last segment can have a torn tail record; repair it.
        let write_seg = *segments.iter().last().unwrap();
        let valid_len = scan_segment(&seg_path(&dir, write_seg), 0, None)?.0;
        let f = OpenOptions::new()
            .write(true)
            .open(seg_path(&dir, write_seg))?;
        f.set_len(valid_len)?;
        drop(f);

        // Load acked cursor; clamp to existing segments.
        let cursor_path = dir.join("cursor.json");
        let mut cursor: Cursor = std::fs::read(&cursor_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        if !segments.contains(&cursor.seg) {
            let next = segments.range(cursor.seg..).next().copied();
            cursor = Cursor {
                seg: next.unwrap_or(write_seg),
                off: 0,
            };
        }

        // Count unacked events and total bytes.
        let mut count = 0u64;
        let mut bytes = 0u64;
        for &seg in &segments {
            let path = seg_path(&dir, seg);
            bytes += std::fs::metadata(&path)?.len();
            if seg < cursor.seg {
                continue;
            }
            let start = if seg == cursor.seg { cursor.off } else { 0 };
            let (_end, n) = scan_segment(&path, start, None)?;
            count += n;
        }

        let q = DiskQueue {
            id: id.to_string(),
            inner: Mutex::new(Inner {
                write_off: std::fs::metadata(seg_path(&dir, write_seg))?.len(),
                dir,
                segments,
                write_seg,
                writer: None,
                cursor,
                peek: cursor,
                count,
                bytes,
            }),
            data_notify: Notify::new(),
            space_notify: Notify::new(),
            max_bytes: cfg.max_size_mb * 1024 * 1024,
            seg_bytes: cfg.segment_size_mb * 1024 * 1024,
            policy: cfg.full_policy,
            dropped: AtomicU64::new(0),
            corrupt: AtomicU64::new(0),
        };
        Ok(Arc::new(q))
    }

    pub fn push(&self, ev: &Event) -> Result<PushOutcome> {
        let payload = serde_json::to_vec(ev)?;
        let rec_len = HEADER + payload.len() as u64;
        let mut inner = self.inner.lock().unwrap();

        let mut evicted = 0u64;
        while inner.bytes + rec_len > self.max_bytes {
            match self.policy {
                FullPolicy::Block => return Ok(PushOutcome::Full),
                FullPolicy::DropNewest => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    return Ok(PushOutcome::Dropped);
                }
                FullPolicy::DropOldest => {
                    let n = drop_oldest_segment(&mut inner, self.seg_bytes)?;
                    self.dropped.fetch_add(n, Ordering::Relaxed);
                    evicted += n;
                }
            }
        }

        let mut rec = Vec::with_capacity(rec_len as usize);
        rec.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        rec.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
        rec.extend_from_slice(&payload);

        if inner.writer.is_none() {
            let path = seg_path(&inner.dir, inner.write_seg);
            // `.create(true)` is deliberate belt-and-braces for R-3: if the
            // write segment's file is missing for any reason — including a
            // queue left wedged by an older build, which advanced `write_seg`
            // before the fallible `File::create` — `append(true)` alone
            // returns NotFound from every push forever. Recreating it costs
            // nothing in the normal case (the file exists) and turns a
            // permanent wedge into a self-healing gap.
            let f = OpenOptions::new()
                .append(true)
                .create(true)
                .open(&path)
                .with_context(|| format!("cannot open queue segment {}", path.display()))?;
            inner.writer = Some(f);
        }
        // write_all can fail (ENOSPC) *after* writing part of the record. If the
        // counters advanced anyway the next push would append after a partial
        // record and leave a CRC-failing record wedged mid-segment.
        if let Err(e) = inner.writer.as_mut().unwrap().write_all(&rec) {
            let real_len = std::fs::metadata(seg_path(&inner.dir, inner.write_seg))
                .map(|m| m.len())
                .unwrap_or(inner.write_off);
            let torn = real_len.saturating_sub(inner.write_off);
            inner.write_off = real_len;
            inner.bytes += torn;
            inner.writer = None;
            roll_segment(&mut inner)?;
            return Err(e.into());
        }
        inner.write_off += rec_len;
        inner.bytes += rec_len;
        inner.count += 1;

        if inner.write_off >= self.seg_bytes {
            roll_segment(&mut inner)?;
        }
        drop(inner);
        self.data_notify.notify_waiters();
        Ok(PushOutcome::Stored { evicted })
    }

    /// Push honoring the full policy; with `block` this waits for space.
    /// Returns false if cancelled before the event could be stored.
    pub async fn push_blocking(&self, ev: &Event, cancel: &CancellationToken) -> Result<bool> {
        loop {
            match self.push(ev)? {
                PushOutcome::Stored { .. } | PushOutcome::Dropped => return Ok(true),
                PushOutcome::Full => {
                    tokio::select! {
                        _ = self.space_notify.notified() => {}
                        _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
                        _ = cancel.cancelled() => return Ok(false),
                    }
                }
            }
        }
    }

    /// Read up to `max` events, and at most `max_bytes` of on-disk record
    /// bytes, from the in-memory peek position.
    ///
    /// `max` alone is not a memory bound: event bodies are capped per event
    /// (1 MiB per line, up to a 4 MiB unterminated read from a file input) but
    /// not per batch, so a count-only limit let the default `batch_size: 200`
    /// materialise ~200 MB of `Event`s in one call — and the output sink then
    /// builds a second, equally large wire payload from it while the batch is
    /// still alive.
    ///
    /// `max_bytes` counts `rec_len` (`HEADER + payload`), the same quantity
    /// `push` adds to `inner.bytes`. A record that would take the running
    /// total over the budget is left unconsumed for the next call.
    ///
    /// Invariant: **at least one event is returned whenever one is readable**
    /// (for `max >= 1`), whatever `max_bytes` is. A single record bigger than
    /// the budget is returned on its own rather than refused forever, which
    /// would pin the peek offset and spin the worker's empty-batch floor.
    pub fn peek_batch(&self, max: usize, max_bytes: usize) -> Result<Vec<Event>> {
        let mut inner = self.inner.lock().unwrap();
        // Make appended-but-buffered data visible to the reader.
        if let Some(w) = inner.writer.as_mut() {
            w.flush().ok();
        }
        let mut out = Vec::new();
        let mut peeked_bytes: usize = 0;
        // Set when the byte budget refuses a record, so both loops unwind
        // without advancing `pos` past a record that was not consumed.
        let mut budget_hit = false;
        let mut pos = inner.peek;
        let segs: Vec<u64> = inner.segments.range(pos.seg..).copied().collect();
        for seg in segs {
            if out.len() >= max || budget_hit {
                break;
            }
            let start = if seg == pos.seg { pos.off } else { 0 };
            let path = seg_path(&inner.dir, seg);
            let mut f = File::open(&path)?;
            // Bound the length check on the file's actual size, not the
            // configured segment size — a legitimate record can exceed
            // `segment_size_mb` (see `read_record`'s doc comment).
            let file_len = f.metadata()?.len();
            f.seek(SeekFrom::Start(start))?;
            let mut off = start;
            loop {
                if out.len() >= max {
                    break;
                }
                match read_record(&mut f, file_len)? {
                    RecordRead::Ok { payload, rec_len } => {
                        // Stop before taking a record that would push the
                        // batch over the byte budget — but never return an
                        // empty batch just because the next record is
                        // oversized, or the peek offset would never advance.
                        if !out.is_empty()
                            && peeked_bytes.saturating_add(rec_len as usize) > max_bytes
                        {
                            budget_hit = true;
                            break;
                        }
                        off += rec_len;
                        peeked_bytes = peeked_bytes.saturating_add(rec_len as usize);
                        match serde_json::from_slice::<Event>(&payload) {
                            Ok(ev) => out.push(ev),
                            Err(e) => {
                                self.corrupt.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(queue = %self.id, "skipping undecodable queue record: {e}");
                            }
                        }
                    }
                    RecordRead::Corrupt { skip } => {
                        off += skip;
                        self.corrupt.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(queue = %self.id, skip, "skipping CRC-failed queue record");
                    }
                    RecordRead::Eof => break,
                }
            }
            pos = Cursor { seg, off };
        }
        inner.peek = pos;
        Ok(out)
    }

    /// Confirm delivery of everything peeked so far; persists the cursor and
    /// removes fully-consumed segments.
    pub fn ack(&self, acked_events: u64) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.cursor = inner.peek;
        inner.count = inner.count.saturating_sub(acked_events);

        // Delete segments wholly behind the cursor (never the write segment).
        let done: Vec<u64> = inner
            .segments
            .range(..inner.cursor.seg)
            .copied()
            .filter(|&s| s != inner.write_seg)
            .collect();
        for seg in done {
            let path = seg_path(&inner.dir, seg);
            if let Ok(md) = std::fs::metadata(&path) {
                inner.bytes = inner.bytes.saturating_sub(md.len());
            }
            std::fs::remove_file(&path).ok();
            inner.segments.remove(&seg);
        }

        let cursor_path = inner.dir.join("cursor.json");
        crate::fsutil::write_atomic(&cursor_path, &serde_json::to_vec(&inner.cursor)?)
            .with_context(|| format!("cannot persist queue cursor {}", cursor_path.display()))?;
        drop(inner);
        self.space_notify.notify_waiters();
        Ok(())
    }

    /// Forget un-acked peeks so the next peek re-reads them (send failed).
    pub fn reset_peek(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.peek = inner.cursor;
    }

    pub fn len(&self) -> u64 {
        self.inner.lock().unwrap().count
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn bytes(&self) -> u64 {
        self.inner.lock().unwrap().bytes
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// True when the next average-sized push would exceed the size cap. Used by
    /// /healthz so a blocked queue is visible instead of silently wedging the
    /// agent.
    ///
    /// `push` stops *before* writing a record that would cross the cap, so
    /// `bytes` alone rarely reaches `max_bytes` exactly — a queue can sit a few
    /// hundred bytes under the cap yet still be permanently rejecting every
    /// push (under `block`, stalling the router). Comparing against the
    /// average size of the records currently held catches that state.
    pub fn is_full(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        if inner.count == 0 {
            return false;
        }
        let avg = inner.bytes / inner.count;
        inner.bytes + avg >= self.max_bytes
    }

    /// The full-queue policy this queue was configured with. Lets callers
    /// (e.g. `/healthz`) distinguish a `block` queue that is genuinely
    /// stalled from a `drop_oldest`/`drop_newest` queue sitting at its cap as
    /// normal, correct operation.
    pub fn policy(&self) -> FullPolicy {
        self.policy
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Records skipped because they failed CRC or would not decode. Surfaced on
    /// /api/buffer so silent corruption is visible.
    pub fn corrupt_records(&self) -> u64 {
        self.corrupt.load(Ordering::Relaxed)
    }

    /// Age in seconds of the oldest unacked event, if any.
    pub fn oldest_age_secs(&self) -> Option<i64> {
        let inner = self.inner.lock().unwrap();
        if inner.count == 0 {
            return None;
        }
        let segs: Vec<u64> = inner.segments.range(inner.cursor.seg..).copied().collect();
        for seg in segs {
            let start = if seg == inner.cursor.seg {
                inner.cursor.off
            } else {
                0
            };
            let mut f = File::open(seg_path(&inner.dir, seg)).ok()?;
            let file_len = f.metadata().ok()?.len();
            f.seek(SeekFrom::Start(start)).ok()?;
            if let Ok(RecordRead::Ok { payload, .. }) = read_record(&mut f, file_len) {
                if let Ok(ev) = serde_json::from_slice::<Event>(&payload) {
                    return Some((chrono::Utc::now() - ev.received_at).num_seconds());
                }
            }
        }
        None
    }

    /// Wait until the queue has unpeeked data or cancellation.
    pub async fn wait_data(&self, cancel: &CancellationToken) {
        loop {
            {
                let inner = self.inner.lock().unwrap();
                let has = inner.peek
                    != Cursor {
                        seg: inner.write_seg,
                        off: inner.write_off,
                    }
                    && inner.count > 0;
                if has {
                    return;
                }
            }
            tokio::select! {
                _ = self.data_notify.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                _ = cancel.cancelled() => return,
            }
        }
    }
}

fn seg_path(dir: &std::path::Path, seg: u64) -> PathBuf {
    dir.join(format!("{seg:020}.seg"))
}

/// Advance the write cursor to a fresh segment.
///
/// Every fallible step happens **before** any state is mutated: the old code
/// incremented `write_seg` first, so a single transient `File::create` failure
/// (EMFILE, inode exhaustion, a momentarily unwritable queue directory, an
/// antivirus lock on Windows) left the write cursor pointing at a file that
/// nothing would ever create, and every subsequent `push` failed forever. On
/// failure here the caller's state is untouched, so the next `push` reopens
/// the current segment and appends to it as normal.
fn roll_segment(inner: &mut Inner) -> Result<()> {
    if let Some(w) = inner.writer.take() {
        drop(w);
    }
    let next = inner.write_seg + 1;
    let path = seg_path(&inner.dir, next);
    File::create(&path)
        .with_context(|| format!("cannot create queue segment {}", path.display()))?;
    inner.write_seg = next;
    inner.write_off = 0;
    inner.segments.insert(next);
    Ok(())
}

/// Delete the oldest segment to reclaim space; returns dropped event count.
fn drop_oldest_segment(inner: &mut Inner, _seg_bytes: u64) -> Result<u64> {
    let oldest = *inner.segments.iter().next().unwrap();
    if oldest == inner.write_seg {
        // Single segment holds everything: roll so we can drop it.
        roll_segment(inner)?;
    }
    let path = seg_path(&inner.dir, oldest);
    // Count events being dropped (only those not yet acked).
    let start = if inner.cursor.seg == oldest {
        inner.cursor.off
    } else if inner.cursor.seg > oldest {
        u64::MAX // fully acked already; nothing unread inside
    } else {
        0
    };
    let dropped = if start == u64::MAX {
        0
    } else {
        scan_segment(&path, start, None)
            .map(|(_, n)| n)
            .unwrap_or(0)
    };
    if let Ok(md) = std::fs::metadata(&path) {
        inner.bytes = inner.bytes.saturating_sub(md.len());
    }
    std::fs::remove_file(&path).ok();
    inner.segments.remove(&oldest);
    inner.count = inner.count.saturating_sub(dropped);

    let next = *inner.segments.iter().next().unwrap();
    if inner.cursor.seg <= oldest {
        inner.cursor = Cursor { seg: next, off: 0 };
    }
    if inner.peek.seg <= oldest {
        inner.peek = inner.cursor;
    }
    Ok(dropped)
}

/// Walk records from `start`; returns (offset after last valid record, count).
fn scan_segment(path: &std::path::Path, start: u64, max: Option<u64>) -> Result<(u64, u64)> {
    let seg_bytes = std::fs::metadata(path)?.len();
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(start))?;
    let mut off = start;
    let mut n = 0u64;
    loop {
        if let Some(m) = max {
            if n >= m {
                break;
            }
        }
        match read_record(&mut f, seg_bytes)? {
            RecordRead::Ok { rec_len, .. } => {
                off += rec_len;
                n += 1;
            }
            RecordRead::Corrupt { skip } => {
                off += skip;
            }
            RecordRead::Eof => break,
        }
    }
    Ok((off, n))
}

enum RecordRead {
    Ok {
        payload: Vec<u8>,
        rec_len: u64,
    },
    /// Framing is intact enough to step over this record.
    Corrupt {
        skip: u64,
    },
    /// Nothing more can be read from this segment.
    Eof,
}

/// Read one record. A CRC mismatch is reported as `Corrupt` with the number of
/// bytes to step over, so the reader can make progress instead of parking on it
/// forever (which pins a core at 100% via the empty-batch loop in outputs.rs).
///
/// `max_believable_len` must be a safe upper bound on a real record's length —
/// i.e. the actual size of the file being read, not the configured segment
/// size. A single record legitimately written by `push` can exceed
/// `segment_size_mb` (the rollover check only runs *after* the write), so
/// using the configured size here would misclassify a valid oversized record
/// as `Eof` and permanently stall the reader at that offset.
fn read_record(f: &mut File, max_believable_len: u64) -> Result<RecordRead> {
    let mut header = [0u8; 8];
    match f.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(RecordRead::Eof),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(header[0..4].try_into().unwrap()) as u64;
    let crc = u32::from_le_bytes(header[4..8].try_into().unwrap());
    // A length header that cannot be real means the framing is lost; there is
    // no safe skip distance, so give up on the rest of this segment.
    if len == 0 || len > max_believable_len {
        return Ok(RecordRead::Eof);
    }
    let mut payload = vec![0u8; len as usize];
    match f.read_exact(&mut payload) {
        Ok(()) => {}
        // Truncated tail: not skippable, and open() repairs it.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(RecordRead::Eof),
        Err(e) => return Err(e.into()),
    }
    if crc32fast::hash(&payload) != crc {
        return Ok(RecordRead::Corrupt { skip: HEADER + len });
    }
    Ok(RecordRead::Ok {
        payload,
        rec_len: HEADER + len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;

    /// A byte budget large enough never to bind in tests that are exercising
    /// something other than the budget itself.
    const TEST_PEEK_BYTES: usize = 64 * 1024 * 1024;

    fn cfg(max_mb: u64, policy: FullPolicy) -> BufferConfig {
        BufferConfig {
            dir: None,
            max_size_mb: max_mb,
            segment_size_mb: 1,
            full_policy: policy,
        }
    }

    fn ev(n: usize) -> Event {
        Event::new("test", "raw", &format!("event number {n}"))
    }

    #[test]
    fn push_peek_ack_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
        for i in 0..10 {
            assert!(matches!(
                q.push(&ev(i)).unwrap(),
                PushOutcome::Stored { .. }
            ));
        }
        assert_eq!(q.len(), 10);
        let batch = q.peek_batch(4, TEST_PEEK_BYTES).unwrap();
        assert_eq!(batch.len(), 4);
        assert_eq!(batch[0].message, "event number 0");
        q.ack(4).unwrap();
        assert_eq!(q.len(), 6);
        let batch = q.peek_batch(100, TEST_PEEK_BYTES).unwrap();
        assert_eq!(batch.len(), 6);
        assert_eq!(batch[0].message, "event number 4");
    }

    #[test]
    fn reset_peek_redelivers() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
        q.push(&ev(1)).unwrap();
        let b1 = q.peek_batch(10, TEST_PEEK_BYTES).unwrap();
        assert_eq!(b1.len(), 1);
        q.reset_peek();
        let b2 = q.peek_batch(10, TEST_PEEK_BYTES).unwrap();
        assert_eq!(b2.len(), 1);
        assert_eq!(b1[0].message, b2[0].message);
    }

    #[test]
    fn recovery_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
            for i in 0..5 {
                q.push(&ev(i)).unwrap();
            }
            q.peek_batch(2, TEST_PEEK_BYTES).unwrap();
            q.ack(2).unwrap();
            // 3 events remain unacked; "crash" here.
        }
        let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
        assert_eq!(q.len(), 3);
        let batch = q.peek_batch(10, TEST_PEEK_BYTES).unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].message, "event number 2");
    }

    #[test]
    fn drop_newest_when_full() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(1, FullPolicy::DropNewest)).unwrap();
        let big = "x".repeat(64 * 1024);
        let mut stored = 0;
        for _ in 0..64 {
            match q.push(&Event::new("t", "raw", &big)).unwrap() {
                PushOutcome::Stored { .. } => stored += 1,
                PushOutcome::Dropped => {}
                PushOutcome::Full => panic!("unexpected Full with drop_newest"),
            }
        }
        assert!(stored < 64);
        assert!(q.dropped() > 0);
        assert!(q.bytes() <= q.max_bytes());
    }

    #[test]
    fn drop_oldest_when_full() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(1, FullPolicy::DropOldest)).unwrap();
        let big = "x".repeat(64 * 1024);
        let mut reported_evicted = 0u64;
        for _ in 0..64 {
            match q.push(&Event::new("t", "raw", &big)).unwrap() {
                PushOutcome::Stored { evicted } => reported_evicted += evicted,
                other => panic!("unexpected outcome with drop_oldest: {other:?}"),
            }
        }
        assert!(q.dropped() > 0);
        // Evictions must be surfaced to the caller (Overview dropped counter),
        // not just tracked internally — regression guard for GUI-006.
        assert_eq!(reported_evicted, q.dropped());
        assert!(q.bytes() <= q.max_bytes() + 2 * 64 * 1024);
        // Remaining events are still readable.
        let batch = q.peek_batch(5, TEST_PEEK_BYTES).unwrap();
        assert!(!batch.is_empty());
    }

    #[test]
    fn segment_rollover() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(64, FullPolicy::Block)).unwrap();
        let big = "y".repeat(200 * 1024);
        for _ in 0..12 {
            q.push(&Event::new("t", "raw", &big)).unwrap();
        }
        assert_eq!(q.len(), 12);
        let batch = q.peek_batch(100, TEST_PEEK_BYTES).unwrap();
        assert_eq!(batch.len(), 12);
        q.ack(12).unwrap();
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn peek_batch_skips_a_corrupt_record_in_the_middle() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = tempfile::tempdir().unwrap();
        let cfg = BufferConfig::default();
        let q = DiskQueue::open(dir.path(), "dest", &cfg).unwrap();
        for i in 0..3 {
            q.push(&Event::new("s", "test", &format!("event-{i}")))
                .unwrap();
        }
        drop(q);

        // Corrupt the payload of the middle record without changing its length
        // header, so the CRC fails but the framing is still walkable.
        let seg = dir.path().join("dest").join("00000000000000000000.seg");
        let first_len = {
            let bytes = std::fs::read(&seg).unwrap();
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as u64
        };
        let second_payload_start = 8 + first_len + 8;
        let mut f = std::fs::OpenOptions::new().write(true).open(&seg).unwrap();
        f.seek(SeekFrom::Start(second_payload_start)).unwrap();
        f.write_all(b"X").unwrap();
        drop(f);

        let q = DiskQueue::open(dir.path(), "dest", &cfg).unwrap();
        let batch = q.peek_batch(10, TEST_PEEK_BYTES).unwrap();
        assert_eq!(batch.len(), 2, "must return the two intact records");
        assert_eq!(q.corrupt_records(), 1);

        // The critical property: peek advanced past the corrupt record, so a
        // second call cannot return an empty batch forever.
        q.ack(batch.len() as u64).unwrap();
        assert!(q.peek_batch(10, TEST_PEEK_BYTES).unwrap().is_empty());
    }

    #[test]
    fn peek_batch_returns_a_record_larger_than_the_configured_segment_size() {
        // segment_size_mb: 1 (see `cfg()` above), but push() only checks for
        // rollover *after* writing a record in full, so a single legitimate
        // record can exceed the configured segment size. Before the fix,
        // read_record compared the length header against `self.seg_bytes`
        // (the configured 1 MiB) instead of the file's actual size, so this
        // record was misclassified as Eof and `peek_batch` returned nothing
        // for it - permanently, since the peek offset never advanced past it.
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
        let huge = "z".repeat(2 * 1024 * 1024); // record body > 1 MiB segment_size_mb
        assert!(matches!(
            q.push(&Event::new("t", "raw", &huge)).unwrap(),
            PushOutcome::Stored { .. }
        ));
        assert_eq!(q.len(), 1);

        let batch = q.peek_batch(10, TEST_PEEK_BYTES).unwrap();
        assert_eq!(
            batch.len(),
            1,
            "a legitimate oversized record must not be treated as Eof"
        );
        assert_eq!(batch[0].message, huge);

        // The offset must have advanced past the record, not stayed pinned.
        q.ack(1).unwrap();
        assert!(q.peek_batch(10, TEST_PEEK_BYTES).unwrap().is_empty());
    }

    #[test]
    fn is_full_reports_the_block_state() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BufferConfig {
            max_size_mb: 1,
            ..BufferConfig::default()
        };
        let q = DiskQueue::open(dir.path(), "dest", &cfg).unwrap();
        assert!(!q.is_full());
        let big = "x".repeat(4096);
        for _ in 0..400 {
            if let Ok(PushOutcome::Full) = q.push(&Event::new("s", "test", &big)) {
                break;
            }
        }
        assert!(
            q.is_full(),
            "queue should report full after hitting the cap"
        );
    }

    #[test]
    fn cursor_is_written_atomically_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BufferConfig::default();
        let q = DiskQueue::open(dir.path(), "dest", &cfg).unwrap();
        for i in 0..10 {
            q.push(&Event::new("s", "test", &format!("event {i}")))
                .unwrap();
        }
        let batch = q.peek_batch(10, TEST_PEEK_BYTES).unwrap();
        assert_eq!(batch.len(), 10);
        q.ack(10).unwrap();

        // No temp file must survive an ack.
        assert!(!dir.path().join("dest").join("cursor.json.tmp").exists());

        drop(q);
        let q2 = DiskQueue::open(dir.path(), "dest", &cfg).unwrap();
        assert!(
            q2.peek_batch(10, TEST_PEEK_BYTES).unwrap().is_empty(),
            "acked events replayed"
        );
    }

    /// R-3: `roll_segment` used to increment `write_seg` *before* the fallible
    /// `File::create`, so one transient failure at a segment boundary left the
    /// write cursor pointing at a segment file that nothing would ever create.
    /// Every later `push` then returned `NotFound` forever, even after the
    /// original fault cleared, and `run_router` turned into a per-event
    /// `format!` + mutex loop while silently dropping every event.
    #[test]
    #[cfg(unix)]
    fn a_transient_segment_create_failure_does_not_wedge_the_queue() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(64, FullPolicy::Block)).unwrap();
        let qdir = dir.path().join("d1");
        // `cfg()` sets segment_size_mb: 1. Five ~205 KB records leave seg 0 at
        // ~1_025_670 bytes, just under the 1 MiB rollover threshold, so the
        // sixth push is the one that rolls.
        let big = "y".repeat(200 * 1024);
        for _ in 0..5 {
            assert!(matches!(
                q.push(&Event::new("t", "raw", &big)).unwrap(),
                PushOutcome::Stored { .. }
            ));
        }

        // Make the queue directory unwritable so the rollover's File::create
        // fails. Writes to the already-open segment fd are unaffected.
        let orig = std::fs::metadata(&qdir).unwrap().permissions();
        let mut ro = orig.clone();
        ro.set_mode(0o500);
        std::fs::set_permissions(&qdir, ro).unwrap();

        // Directory permissions are not enforced for uid 0; in a container that
        // runs tests as root there is nothing to reproduce.
        let probe = qdir.join(".probe");
        if std::fs::File::create(&probe).is_ok() {
            std::fs::remove_file(&probe).ok();
            std::fs::set_permissions(&qdir, orig).unwrap();
            eprintln!("skipping: directory permissions are not enforced for this user");
            return;
        }

        let boundary = q.push(&Event::new("t", "raw", &big));
        // Restore before asserting so a failure cannot leave an undeletable dir.
        std::fs::set_permissions(&qdir, orig).unwrap();
        assert!(
            boundary.is_err(),
            "the rollover must fail while the queue directory is read-only"
        );

        // The transient fault has cleared: pushes must work again.
        assert!(
            matches!(
                q.push(&Event::new("t", "raw", &big)).unwrap(),
                PushOutcome::Stored { .. }
            ),
            "queue stayed wedged after the fault cleared"
        );
        // 5 + the boundary push (whose write succeeded; only the roll failed)
        // + the recovery push.
        assert_eq!(q.len(), 7);
        let mut segs: Vec<String> = std::fs::read_dir(&qdir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".seg"))
            .collect();
        segs.sort();
        assert_eq!(
            segs,
            vec![
                "00000000000000000000.seg".to_string(),
                "00000000000000000001.seg".to_string()
            ],
            "recovery must roll into the next segment, not skip one"
        );
    }

    /// R-3, upgrade path: a queue already wedged by 0.1.1 has a write segment
    /// index whose file does not exist. `OpenOptions::append(true)` without
    /// `.create(true)` returns NotFound for that forever, so the append open
    /// must be self-healing or upgrading the agent does not un-wedge the queue.
    #[test]
    fn a_queue_whose_write_segment_file_is_missing_recreates_it() {
        let dir = tempfile::tempdir().unwrap();
        let qdir = dir.path().join("d1");
        {
            let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
            q.push(&ev(0)).unwrap();
        }
        // Reproduce the 0.1.1 wedge exactly: write_seg points at segment 1,
        // whose file is gone.
        std::fs::File::create(qdir.join("00000000000000000001.seg")).unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
        std::fs::remove_file(qdir.join("00000000000000000001.seg")).unwrap();

        assert!(
            matches!(q.push(&ev(1)).unwrap(), PushOutcome::Stored { .. }),
            "push must recreate the missing write segment instead of failing"
        );
        assert!(qdir.join("00000000000000000001.seg").exists());
        assert_eq!(q.len(), 2);
    }

    /// R-4: `peek_batch` was bounded by event count only, so with the default
    /// batch_size 200 and file-input events up to 4 MiB each, a batch could
    /// reach ~200 MB in RAM (and `frame_batch` another ~200 MB alongside it)
    /// against an advertised ~12 MB footprint.
    #[test]
    fn peek_batch_stops_at_the_byte_budget() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(64, FullPolicy::Block)).unwrap();
        let big = "b".repeat(64 * 1024);
        for i in 0..10 {
            assert!(matches!(
                q.push(&Event::new("t", "raw", &format!("{i}{big}")))
                    .unwrap(),
                PushOutcome::Stored { .. }
            ));
        }

        // Each record is ~65.7 KB on disk: a 65_537-byte body, ~180 bytes of
        // JSON envelope (two rfc3339 timestamps, source, source_type,
        // collector_version; every Option field is skipped when None) and the
        // 8-byte header. With a 150_000-byte budget two fit (~131.4 KB) and
        // the third does not (~197.1 KB), leaving ~18 KB
        // of margin on the accept side and ~47 KB on the reject side, so the
        // exact count below does not depend on the envelope's exact size.
        const BUDGET: usize = 150_000;
        let first = q.peek_batch(10, BUDGET).unwrap();
        assert!(
            !first.is_empty() && first.len() < 10,
            "byte budget must bind before the count budget, got {}",
            first.len()
        );
        assert_eq!(first.len(), 2, "two ~66 KB records fit in 150 000 bytes");
        assert!(first[0].message.starts_with('0'));
        assert!(first[1].message.starts_with('1'));

        // The refused record is not consumed: the next call starts there, so
        // nothing is lost and nothing is skipped.
        let second = q.peek_batch(10, BUDGET).unwrap();
        assert_eq!(second.len(), 2);
        assert!(second[0].message.starts_with('2'));

        // Draining with a generous budget still yields the rest in order.
        let rest = q.peek_batch(100, TEST_PEEK_BYTES).unwrap();
        assert_eq!(rest.len(), 6);
        assert!(rest[0].message.starts_with('4'));
        assert!(rest[5].message.starts_with('9'));
    }

    /// R-4 invariant: the budget must never produce an empty batch when a
    /// record is readable. An oversized record that was refused forever would
    /// pin the peek offset and spin the output worker's empty-batch floor at
    /// 10 Hz for the life of the process.
    #[test]
    fn peek_batch_always_returns_one_record_even_when_it_exceeds_the_budget() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(64, FullPolicy::Block)).unwrap();
        let huge = "z".repeat(2 * 1024 * 1024);
        q.push(&Event::new("t", "raw", &huge)).unwrap();
        q.push(&ev(1)).unwrap();

        let batch = q.peek_batch(10, 1024).unwrap();
        assert_eq!(
            batch.len(),
            1,
            "a record larger than max_bytes must still be returned, alone"
        );
        assert_eq!(batch[0].message, huge);

        // And the offset advanced past it, so the reader makes progress.
        q.ack(1).unwrap();
        let next = q.peek_batch(10, 1024).unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].message, "event number 1");
    }
}
