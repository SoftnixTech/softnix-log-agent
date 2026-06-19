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
    Stored { evicted: u64 },
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
            let f = OpenOptions::new()
                .append(true)
                .open(seg_path(&inner.dir, inner.write_seg))?;
            inner.writer = Some(f);
        }
        inner.writer.as_mut().unwrap().write_all(&rec)?;
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

    /// Read up to `max` events from the in-memory peek position.
    pub fn peek_batch(&self, max: usize) -> Result<Vec<Event>> {
        let mut inner = self.inner.lock().unwrap();
        // Make appended-but-buffered data visible to the reader.
        if let Some(w) = inner.writer.as_mut() {
            w.flush().ok();
        }
        let mut out = Vec::new();
        let mut pos = inner.peek;
        let segs: Vec<u64> = inner.segments.range(pos.seg..).copied().collect();
        for seg in segs {
            if out.len() >= max {
                break;
            }
            let start = if seg == pos.seg { pos.off } else { 0 };
            let path = seg_path(&inner.dir, seg);
            let mut f = File::open(&path)?;
            f.seek(SeekFrom::Start(start))?;
            let mut off = start;
            loop {
                if out.len() >= max {
                    break;
                }
                match read_record(&mut f)? {
                    Some((payload, rec_len)) => {
                        off += rec_len;
                        match serde_json::from_slice::<Event>(&payload) {
                            Ok(ev) => out.push(ev),
                            Err(e) => {
                                tracing::warn!(queue = %self.id, "skipping corrupt queue record: {e}");
                            }
                        }
                    }
                    None => break,
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
        std::fs::write(&cursor_path, serde_json::to_vec(&inner.cursor)?)
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

    pub fn bytes(&self) -> u64 {
        self.inner.lock().unwrap().bytes
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
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
            f.seek(SeekFrom::Start(start)).ok()?;
            if let Ok(Some((payload, _))) = read_record(&mut f) {
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
                let has = inner.peek != Cursor {
                    seg: inner.write_seg,
                    off: inner.write_off,
                } && inner.count > 0;
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

fn roll_segment(inner: &mut Inner) -> Result<()> {
    if let Some(w) = inner.writer.take() {
        drop(w);
    }
    inner.write_seg += 1;
    inner.write_off = 0;
    File::create(seg_path(&inner.dir, inner.write_seg))?;
    let seg = inner.write_seg;
    inner.segments.insert(seg);
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
        scan_segment(&path, start, None).map(|(_, n)| n).unwrap_or(0)
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
fn scan_segment(
    path: &std::path::Path,
    start: u64,
    max: Option<u64>,
) -> Result<(u64, u64)> {
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
        match read_record(&mut f)? {
            Some((_payload, rec_len)) => {
                off += rec_len;
                n += 1;
            }
            None => break,
        }
    }
    Ok((off, n))
}

/// Read one record; None on EOF, torn record, or CRC mismatch.
fn read_record(f: &mut File) -> Result<Option<(Vec<u8>, u64)>> {
    let mut header = [0u8; 8];
    match f.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
    let crc = u32::from_le_bytes(header[4..8].try_into().unwrap());
    if len == 0 || len > 64 * 1024 * 1024 {
        return Ok(None);
    }
    let mut payload = vec![0u8; len];
    match f.read_exact(&mut payload) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    if crc32fast::hash(&payload) != crc {
        return Ok(None);
    }
    Ok(Some((payload, HEADER + len as u64)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;

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
            assert!(matches!(q.push(&ev(i)).unwrap(), PushOutcome::Stored { .. }));
        }
        assert_eq!(q.len(), 10);
        let batch = q.peek_batch(4).unwrap();
        assert_eq!(batch.len(), 4);
        assert_eq!(batch[0].message, "event number 0");
        q.ack(4).unwrap();
        assert_eq!(q.len(), 6);
        let batch = q.peek_batch(100).unwrap();
        assert_eq!(batch.len(), 6);
        assert_eq!(batch[0].message, "event number 4");
    }

    #[test]
    fn reset_peek_redelivers() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
        q.push(&ev(1)).unwrap();
        let b1 = q.peek_batch(10).unwrap();
        assert_eq!(b1.len(), 1);
        q.reset_peek();
        let b2 = q.peek_batch(10).unwrap();
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
            q.peek_batch(2).unwrap();
            q.ack(2).unwrap();
            // 3 events remain unacked; "crash" here.
        }
        let q = DiskQueue::open(dir.path(), "d1", &cfg(16, FullPolicy::Block)).unwrap();
        assert_eq!(q.len(), 3);
        let batch = q.peek_batch(10).unwrap();
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
        let batch = q.peek_batch(5).unwrap();
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
        let batch = q.peek_batch(100).unwrap();
        assert_eq!(batch.len(), 12);
        q.ack(12).unwrap();
        assert_eq!(q.len(), 0);
    }
}
