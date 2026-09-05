//! Windows Event Log input (Windows-only).
//!
//! Uses the modern Windows Event Log API (`wevtapi`) via a *pull* subscription:
//! `EvtSubscribe` signals a kernel event when new records arrive, then
//! `EvtNext`/`EvtRender` drain them as XML. Progress is checkpointed with an
//! `EvtBookmark` persisted through [`StateManager`], giving at-least-once
//! delivery that resumes after a restart without re-sending old events.
//!
//! One blocking OS task is run per (input, channel) pair; the API is inherently
//! blocking (`WaitForSingleObject`) so it lives on the blocking thread pool.

use crate::config::EventLogInputConfig;
use crate::engine::EventSender;
use crate::event::Event;
use crate::metrics::{InputStatus, Metrics, StatusRegistry};
use crate::state::StateManager;
use chrono::Utc;
use serde_json::Value;
use std::ffi::c_void;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, HANDLE,
};
use windows::Win32::System::EventLog::{
    EvtClose, EvtCreateBookmark, EvtFormatMessage, EvtFormatMessageEvent, EvtNext,
    EvtOpenPublisherMetadata, EvtRender, EvtRenderBookmark, EvtRenderEventXml, EvtSubscribe,
    EvtSubscribeStartAfterBookmark, EvtSubscribeStartAtOldestRecord, EvtSubscribeToFutureEvents,
    EvtUpdateBookmark, EVT_HANDLE,
};
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};

/// Events fetched per `EvtNext` call.
const BATCH: usize = 64;
/// How often the WaitForSingleObject loop wakes to re-check cancellation.
const WAIT_MS: u32 = 1000;
/// Re-subscribe backoff (milliseconds): starts here, doubles, capped at 5 min.
/// A channel must never permanently stop retrying (R-7): a Sysmon restart, a
/// channel that does not exist yet at boot, or a transient ACCESS_DENIED while
/// the SCM is still setting up the service token must not end collection for
/// the rest of the process's life. The cap is generous specifically so a
/// long-broken channel doesn't hammer the API on a short cycle forever, while
/// still eventually retrying.
const RESUBSCRIBE_INITIAL_BACKOFF_MS: u64 = 500;
const RESUBSCRIBE_MAX_BACKOFF_MS: u64 = 300_000;
/// `HRESULT_FROM_WIN32(ERROR_INVALID_OPERATION)` — observed at the
/// real-time transition when the agent runs in Session 0 (Windows Service).
/// Re-subscribing from the persisted bookmark typically clears it.
const HRESULT_INVALID_OPERATION: i32 = 0x8007_10DD_u32 as i32;

pub struct EventLogInput {
    cfg: EventLogInputConfig,
    source_type: String,
}

impl EventLogInput {
    pub fn new(cfg: &EventLogInputConfig) -> Self {
        EventLogInput {
            source_type: cfg.source_type.clone().unwrap_or_else(|| "eventlog".into()),
            cfg: cfg.clone(),
        }
    }

    /// Spawn one blocking collector per channel; the returned task completes
    /// once every channel has stopped, which (R-7) only happens on
    /// cancellation — a channel retries indefinitely rather than ending
    /// collection permanently on error.
    pub fn spawn(
        self,
        tx: EventSender,
        state: Arc<StateManager>,
        status: Arc<StatusRegistry>,
        metrics: Arc<Metrics>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        status.set_input(InputStatus {
            id: self.cfg.id.clone(),
            kind: "eventlog".into(),
            detail: self.cfg.channels.join(", "),
            active: true,
            events: 0,
            last_error: None,
        });
        tokio::spawn(async move {
            let mut handles = Vec::new();
            for channel in self.cfg.channels.clone() {
                let cfg = self.cfg.clone();
                let source_type = self.source_type.clone();
                let (tx, state, status, metrics, cancel) = (
                    tx.clone(),
                    state.clone(),
                    status.clone(),
                    metrics.clone(),
                    cancel.clone(),
                );
                handles.push(tokio::task::spawn_blocking(move || {
                    // `run_channel` now retries forever (R-7: a channel must
                    // never permanently end collection) and only returns on
                    // cancellation, so there is no fatal-error path to report
                    // here any more.
                    run_channel(
                        &cfg,
                        &channel,
                        &source_type,
                        &tx,
                        &state,
                        &status,
                        &metrics,
                        &cancel,
                    );
                }));
            }
            for h in handles {
                let _ = h.await;
            }
            status.update_input(&self.cfg.id, |s| s.active = false);
        })
    }
}

/// Null `EVT_HANDLE` (local session / empty handle).
fn null_handle() -> EVT_HANDLE {
    EVT_HANDLE::default()
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Retry loop for one channel. Never returns on error — only on cancellation
/// (R-7: a Sysmon restart, a channel that does not exist yet at boot, or a
/// transient ACCESS_DENIED while the SCM is still setting up the service
/// token must not end collection for the rest of the process's life). Every
/// subscribe/drain failure, allowlisted-transient or not, is logged, surfaced
/// via `status.last_error`, and retried after a cancellation-aware backoff
/// sleep that grows without bound (see [`RESUBSCRIBE_MAX_BACKOFF_MS`]).
#[allow(clippy::too_many_arguments)]
fn run_channel(
    cfg: &EventLogInputConfig,
    channel: &str,
    source_type: &str,
    tx: &EventSender,
    state: &StateManager,
    status: &StatusRegistry,
    metrics: &Metrics,
    cancel: &CancellationToken,
) {
    let chan_w = wide(channel);
    let query_w = wide(&cfg.query);

    let mut backoff = Backoff::start();
    // Survives across resubscribe attempts within this channel so a
    // long-lived flapping channel doesn't keep reopening the same handful of
    // providers' message-resource DLLs on every attempt.
    let mut cache = PublisherCache::default();

    loop {
        if cancel.is_cancelled() {
            return;
        }
        // Read the latest bookmark before every attempt: a previous iteration
        // may have advanced it before failing, and re-subscribing from the
        // stale position would re-send already-delivered events.
        let saved = state.get_checkpoint(cfg.id.as_str(), channel);

        let (attempt, events) = unsafe {
            subscribe_and_drain(
                &chan_w,
                &query_w,
                saved.as_deref(),
                cfg,
                channel,
                source_type,
                tx,
                state,
                status,
                metrics,
                cancel,
                &mut cache,
            )
        };

        match attempt {
            Ok(()) => return,
            Err(e) => {
                // EVT-001: a failure only counts toward the backoff climb if
                // no progress was made this attempt. Draining events proves
                // the subscription is healthy and the error was a blip, so
                // the counter and delay reset — otherwise a channel that
                // flaps once an hour still climbs to the max backoff over
                // time. R-7: retrying is no longer gated on `is_transient` —
                // an error NOT on that narrow allowlist used to end the
                // channel's collection forever on its very first occurrence;
                // now every error retries, allowlisted or not. `is_transient`
                // is kept purely as a diagnostic classifier here (operators
                // can tell a known-recoverable blip from an unclassified
                // error in the logs) — it no longer decides retry-or-die.
                backoff = backoff.after_transient(events > 0);
                let kind = if is_transient(&e) {
                    "transient error"
                } else {
                    "error"
                };
                tracing::warn!(
                    "eventlog {} channel {channel}: {kind} {e} (attempt {}); \
                     re-subscribing from bookmark in {}ms",
                    cfg.id,
                    backoff.failures,
                    backoff.delay_ms
                );
                let attempt = backoff.failures;
                status.update_input(&cfg.id, |s| {
                    s.last_error = Some(format!("{e} (re-subscribing, attempt {attempt})"));
                });
                // Sleep on the blocking thread, but wake frequently enough to
                // honor cancellation promptly.
                let until = Instant::now() + Duration::from_millis(backoff.delay_ms);
                while Instant::now() < until {
                    if cancel.is_cancelled() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                backoff = backoff.doubled();
            }
        }
    }
}

/// Returns true if the error is potentially recoverable by re-subscribing from
/// the persisted bookmark. Kept narrow on purpose: only errors we have evidence
/// are recoverable. Add to this allowlist as new transient codes are confirmed.
fn is_transient(e: &windows::core::Error) -> bool {
    is_transient_code(e.code().0)
}

/// Pure form of [`is_transient`] over a raw HRESULT, split out so the recovery
/// policy is unit-testable without a live subscription (the module is
/// Windows-only, so these tests run on Windows CI).
fn is_transient_code(code: i32) -> bool {
    code == HRESULT_INVALID_OPERATION
}

/// Does an `EvtNext` error just mean "no more records right now" (drain caught
/// up) rather than a real failure? Both `ERROR_NO_MORE_ITEMS` and the idle
/// transition `ERROR_INVALID_OPERATION` (0x800710DD) belong here: after ~2 s of
/// channel silence a healthy pull subscription surfaces the latter, and treating
/// it as fatal runs the input into "giving up" within minutes (EVT-001). In both
/// cases the subscription is fine — reset the signal and wait for the next one.
fn is_drain_idle(code: windows::core::HRESULT) -> bool {
    code == ERROR_NO_MORE_ITEMS.to_hresult() || code.0 as u32 == HRESULT_INVALID_OPERATION as u32
}

/// Where a fresh subscription should start reading from. Bookmark wins when we
/// have one; otherwise `read_existing` chooses between backfilling the whole
/// channel and only future events. Crucially, the default (no bookmark,
/// `read_existing: false`) is future-only — never a full replay (EVT-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResumeMode {
    AfterBookmark,
    OldestRecord,
    FutureOnly,
}

fn resume_mode(has_bookmark: bool, read_existing: bool) -> ResumeMode {
    if has_bookmark {
        ResumeMode::AfterBookmark
    } else if read_existing {
        ResumeMode::OldestRecord
    } else {
        ResumeMode::FutureOnly
    }
}

/// Re-subscribe backoff after a failed attempt. Progress in the failed attempt
/// (events drained) proves the subscription is healthy, so the consecutive-
/// failure counter and delay reset to their starting values; a run of dry
/// failures climbs the delay toward [`RESUBSCRIBE_MAX_BACKOFF_MS`] — but the
/// channel never gives up retrying (R-7). Kept as a pure value type so the
/// EVT-001 flap accounting is unit-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Backoff {
    failures: u32,
    delay_ms: u64,
}

impl Backoff {
    fn start() -> Self {
        Backoff {
            failures: 0,
            delay_ms: RESUBSCRIBE_INITIAL_BACKOFF_MS,
        }
    }

    /// Account for one failed attempt; `made_progress` is whether any event
    /// was drained during the attempt that failed.
    fn after_transient(self, made_progress: bool) -> Self {
        if made_progress {
            Backoff::start()
        } else {
            Backoff {
                failures: self.failures + 1,
                delay_ms: self.delay_ms,
            }
        }
    }

    /// Double the delay for the next attempt, capped at the maximum.
    fn doubled(self) -> Self {
        Backoff {
            failures: self.failures,
            delay_ms: (self.delay_ms * 2).min(RESUBSCRIBE_MAX_BACKOFF_MS),
        }
    }
}

/// One full subscription lifecycle: create handles, EvtSubscribe, drain until
/// error/cancellation, persist bookmark, close handles. Returns the underlying
/// error and the number of events emitted in this attempt so the caller can
/// decide whether to retry and whether to reset backoff.
#[allow(clippy::too_many_arguments)]
unsafe fn subscribe_and_drain(
    chan_w: &[u16],
    query_w: &[u16],
    saved_bookmark: Option<&str>,
    cfg: &EventLogInputConfig,
    channel: &str,
    source_type: &str,
    tx: &EventSender,
    state: &StateManager,
    status: &StatusRegistry,
    metrics: &Metrics,
    cancel: &CancellationToken,
    cache: &mut PublisherCache,
) -> (windows::core::Result<()>, u64) {
    // Manual-reset signal event fired by the subscription on new records.
    let signal = match CreateEventW(None, true, false, PCWSTR::null()) {
        Ok(h) => h,
        Err(e) => return (Err(e), 0),
    };

    // Bookmark used to checkpoint progress (and to render the resume token).
    let upd_bookmark = match EvtCreateBookmark(PCWSTR::null()) {
        Ok(b) => b,
        Err(e) => {
            let _ = CloseHandle(signal);
            return (Err(e), 0);
        }
    };

    // Resume position: after the saved bookmark if we have one, else from
    // the oldest record (read_existing) or only future events.
    let (start_bookmark, flags) = match resume_mode(saved_bookmark.is_some(), cfg.read_existing) {
        ResumeMode::AfterBookmark => {
            let bw = wide(saved_bookmark.unwrap_or_default());
            match EvtCreateBookmark(PCWSTR(bw.as_ptr())) {
                Ok(b) => (Some(b), EvtSubscribeStartAfterBookmark.0),
                Err(e) => {
                    let _ = EvtClose(upd_bookmark);
                    let _ = CloseHandle(signal);
                    return (Err(e), 0);
                }
            }
        }
        ResumeMode::OldestRecord => (None, EvtSubscribeStartAtOldestRecord.0),
        ResumeMode::FutureOnly => (None, EvtSubscribeToFutureEvents.0),
    };

    let sub = match EvtSubscribe(
        null_handle(),
        signal,
        PCWSTR(chan_w.as_ptr()),
        PCWSTR(query_w.as_ptr()),
        start_bookmark.unwrap_or_default(),
        None,
        None,
        flags,
    ) {
        Ok(s) => s,
        Err(e) => {
            if let Some(b) = start_bookmark {
                let _ = EvtClose(b);
            }
            let _ = EvtClose(upd_bookmark);
            let _ = CloseHandle(signal);
            return (Err(e), 0);
        }
    };
    if let Some(b) = start_bookmark {
        let _ = EvtClose(b);
    }

    let mut last_flush = Instant::now();
    // Tracks whether `upd_bookmark` has ever been advanced via
    // EvtUpdateBookmark. An unupdated bookmark renders as a valid-but-empty
    // XML token that Windows interprets as "start at the oldest record"; if
    // we persisted it over a real bookmark we'd replay the entire log on
    // the next start (EVT-004 / EVT-005).
    let mut bookmark_updated = false;
    let result = drain_loop(
        sub,
        signal,
        upd_bookmark,
        cfg,
        channel,
        source_type,
        tx,
        state,
        status,
        metrics,
        cancel,
        &mut last_flush,
        &mut bookmark_updated,
        cache,
    );

    // Persist the latest position so the next attempt (or the next process
    // start) resumes here, not at the bookmark captured at process start —
    // but only if we actually advanced the bookmark this attempt.
    let (events_count, mapped) = result;
    if bookmark_updated {
        if let Ok(xml) = render_bookmark(upd_bookmark) {
            state.set_checkpoint(cfg.id.as_str(), channel, &xml);
        }
    }
    let _ = EvtClose(sub);
    let _ = EvtClose(upd_bookmark);
    let _ = CloseHandle(signal);
    (mapped, events_count)
}

#[allow(clippy::too_many_arguments)]
unsafe fn drain_loop(
    sub: EVT_HANDLE,
    signal: HANDLE,
    upd_bookmark: EVT_HANDLE,
    cfg: &EventLogInputConfig,
    channel: &str,
    source_type: &str,
    tx: &EventSender,
    state: &StateManager,
    status: &StatusRegistry,
    metrics: &Metrics,
    cancel: &CancellationToken,
    last_flush: &mut Instant,
    bookmark_updated: &mut bool,
    cache: &mut PublisherCache,
) -> (u64, windows::core::Result<()>) {
    let mut total_emitted = 0u64;
    loop {
        if cancel.is_cancelled() {
            return (total_emitted, Ok(()));
        }
        // Block (briefly) until new records arrive, then drain them all.
        let _ = WaitForSingleObject(signal, WAIT_MS);

        loop {
            if cancel.is_cancelled() {
                return (total_emitted, Ok(()));
            }
            let mut events = [0isize; BATCH];
            let mut returned = 0u32;
            let next = EvtNext(sub, &mut events, 0, 0, &mut returned);
            if let Err(e) = next {
                // EVT-001: both "no more records" and the idle-transition
                // 0x800710DD mean the drain is caught up on a healthy
                // subscription — reset the signal and wait for the next one
                // rather than treating either as a fatal error.
                if is_drain_idle(e.code()) {
                    let _ = ResetEvent(signal);
                    break;
                }
                // Return the count drained before the failure so the caller can
                // tell this attempt made progress (EVT-001 backoff reset).
                return (total_emitted, Err(e));
            }

            let mut emitted = 0u64;
            let returned = returned as usize;
            for (i, &raw) in events.iter().take(returned).enumerate() {
                let ev_handle = EVT_HANDLE(raw);
                match render_xml(ev_handle) {
                    Ok(xml) => {
                        let event = build_event(
                            &xml,
                            ev_handle,
                            channel,
                            source_type,
                            cfg.keep_raw_message,
                            cache,
                        );
                        emitted += 1;
                        metrics
                            .events_received
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        // Advance the bookmark before handing the event off so a
                        // crash re-sends at most the in-flight record.
                        let _ = EvtUpdateBookmark(upd_bookmark, ev_handle);
                        *bookmark_updated = true;
                        let _ = EvtClose(ev_handle);
                        if tx.blocking_send(event, cancel).is_err() {
                            // Pipeline shut down. `ev_handle` above is already
                            // closed, but any events later in this batch
                            // (indices i+1..returned) haven't been processed
                            // yet and would otherwise leak their EVT_HANDLEs.
                            for &raw in &events[i + 1..returned] {
                                let _ = EvtClose(EVT_HANDLE(raw));
                            }
                            return (total_emitted + emitted, Ok(()));
                        }
                    }
                    Err(e) => {
                        let _ = EvtClose(ev_handle);
                        let msg = format!("eventlog {}: render: {e}", cfg.id);
                        tracing::warn!("{msg}");
                        metrics.record_error(&msg);
                    }
                }
            }
            total_emitted += emitted;

            if emitted > 0 {
                status.update_input(&cfg.id, |s| s.events += emitted);
            }
            // Checkpoint at most once per second to bound state-file writes.
            // Skip if no event has ever advanced `upd_bookmark`: persisting an
            // empty bookmark would make the next start interpret it as "begin
            // at oldest record" and replay the whole log (EVT-004/EVT-005).
            if *bookmark_updated && last_flush.elapsed() >= Duration::from_secs(1) {
                if let Ok(xml) = render_bookmark(upd_bookmark) {
                    state.set_checkpoint(cfg.id.as_str(), channel, &xml);
                }
                *last_flush = Instant::now();
            }

            if returned < BATCH {
                let _ = ResetEvent(signal);
                break;
            }
        }
    }
}

/// Render an event handle to its XML representation.
unsafe fn render_xml(event: EVT_HANDLE) -> windows::core::Result<String> {
    render_handle(null_handle(), event, EvtRenderEventXml.0)
}

/// Render the bookmark handle to its persistable XML token.
unsafe fn render_bookmark(bookmark: EVT_HANDLE) -> windows::core::Result<String> {
    render_handle(null_handle(), bookmark, EvtRenderBookmark.0)
}

/// Shared two-pass `EvtRender`: probe for the buffer size, then render. The
/// buffer is UTF-16; `bufferused` is a byte count.
unsafe fn render_handle(
    context: EVT_HANDLE,
    fragment: EVT_HANDLE,
    flags: u32,
) -> windows::core::Result<String> {
    let mut used = 0u32;
    let mut props = 0u32;
    // First call sizes the buffer (expected to fail with INSUFFICIENT_BUFFER).
    if let Err(e) = EvtRender(context, fragment, flags, 0, None, &mut used, &mut props) {
        if e.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult() {
            return Err(e);
        }
    }
    let mut buf = vec![0u8; used as usize];
    EvtRender(
        context,
        fragment,
        flags,
        used,
        Some(buf.as_mut_ptr() as *mut c_void),
        &mut used,
        &mut props,
    )?;
    Ok(utf16_bytes_to_string(&buf[..used as usize]))
}

/// Closes the wrapped EVT_HANDLE on drop.
struct EvtHandleGuard(EVT_HANDLE);

impl Drop for EvtHandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = EvtClose(self.0);
        }
    }
}

/// Caches EvtOpenPublisherMetadata handles per provider name (R-6). A channel
/// typically has a handful of distinct providers; opening this per-event (as
/// before) loads the provider's message resource DLL on every single record.
#[derive(Default)]
struct PublisherCache {
    map: std::collections::HashMap<String, EvtHandleGuard>,
}

impl PublisherCache {
    /// Returns the cached (or newly opened) publisher metadata handle for
    /// `provider`, or `None` if it cannot be opened (unknown provider, etc).
    unsafe fn get_or_open(&mut self, provider: &str) -> Option<EVT_HANDLE> {
        if let Some(g) = self.map.get(provider) {
            return Some(g.0);
        }
        let pw = wide(provider);
        let meta =
            EvtOpenPublisherMetadata(null_handle(), PCWSTR(pw.as_ptr()), PCWSTR::null(), 0, 0)
                .ok()?;
        self.map.insert(provider.to_string(), EvtHandleGuard(meta));
        Some(meta)
    }
}

/// Best-effort human-readable message via the publisher's metadata. Falls back
/// to `None` when the provider is unknown or has no message for the event.
unsafe fn format_message(
    event: EVT_HANDLE,
    provider: &str,
    cache: &mut PublisherCache,
) -> Option<String> {
    if provider.is_empty() {
        return None;
    }
    let meta = cache.get_or_open(provider)?;
    let mut used = 0u32;
    // Probe length (in characters).
    let _ = EvtFormatMessage(
        meta,
        event,
        0,
        None,
        EvtFormatMessageEvent.0,
        None,
        &mut used,
    );
    let result = if used > 0 {
        let mut buf = vec![0u16; used as usize];
        match EvtFormatMessage(
            meta,
            event,
            0,
            None,
            EvtFormatMessageEvent.0,
            Some(&mut buf),
            &mut used,
        ) {
            Ok(()) => {
                let end = (used as usize).saturating_sub(1).min(buf.len());
                let s = String::from_utf16_lossy(&buf[..end]);
                let s = s.trim_end_matches(['\0', '\r', '\n']).to_string();
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            }
            Err(_) => None,
        }
    } else {
        None
    };
    result
}

fn utf16_bytes_to_string(bytes: &[u8]) -> String {
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
        .trim_end_matches('\0')
        .to_string()
}

/// Windows event Level -> syslog severity (0..7).
fn level_to_severity(level: u8) -> u8 {
    match level {
        1 => 2, // Critical
        2 => 3, // Error
        3 => 4, // Warning
        4 => 6, // Information
        5 => 7, // Verbose
        _ => 6, // LogAlways / unknown
    }
}

/// Parse the rendered System/EventData XML and assemble an [`Event`].
unsafe fn build_event(
    xml: &str,
    event: EVT_HANDLE,
    channel: &str,
    source_type: &str,
    keep_raw_message: bool,
    cache: &mut PublisherCache,
) -> Event {
    let p = parse_event_xml(xml);

    // Message: prefer the formatted publisher message, then EventData, then a
    // synthesized line; the full XML is retained as raw_message only when
    // `keep_raw_message` is set (see EventLogInputConfig::keep_raw_message).
    let message = format_message(event, &p.provider, cache)
        .or_else(|| {
            if p.data.is_empty() {
                None
            } else {
                Some(
                    p.data
                        .iter()
                        .map(|(k, v)| {
                            if k.is_empty() {
                                v.clone()
                            } else {
                                format!("{k}={v}")
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" "),
                )
            }
        })
        .unwrap_or_else(|| {
            format!(
                "{} event {} on {}",
                if p.provider.is_empty() {
                    "Windows"
                } else {
                    &p.provider
                },
                p.event_id.unwrap_or(0),
                channel
            )
        });

    let mut ev = Event::new(channel, source_type, &message);
    // The full XML is 2-4 KB, well beyond the already-rendered `message`;
    // only pay for it when the operator explicitly asks to keep it.
    if keep_raw_message {
        ev.raw_message = Some(xml.to_string());
    }

    if let Some(ts) = p
        .time_created
        .as_deref()
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
    {
        ev.timestamp = ts.with_timezone(&Utc);
    }
    if !p.provider.is_empty() {
        ev.application = Some(p.provider.clone());
    }
    if let Some(c) = &p.computer {
        ev.hostname = Some(c.clone());
    }
    if let Some(pid) = &p.process_id {
        ev.process_id = Some(pid.clone());
    }
    if let Some(level) = p.level {
        ev.severity = Some(level_to_severity(level));
        ev.fields.insert("level".into(), Value::from(level));
    }
    if let Some(id) = p.event_id {
        ev.fields.insert("event_id".into(), Value::from(id));
    }
    if let Some(rid) = &p.record_id {
        ev.fields
            .insert("record_id".into(), Value::from(rid.clone()));
    }
    if let Some(k) = &p.keywords {
        ev.fields.insert("keywords".into(), Value::from(k.clone()));
    }
    ev.fields.insert("channel".into(), Value::from(channel));
    for (k, v) in &p.data {
        if !k.is_empty() {
            ev.fields
                .insert(format!("data_{k}"), Value::from(v.clone()));
        }
    }
    ev
}

#[derive(Default)]
struct ParsedEvent {
    provider: String,
    event_id: Option<u64>,
    level: Option<u8>,
    time_created: Option<String>,
    computer: Option<String>,
    record_id: Option<String>,
    process_id: Option<String>,
    keywords: Option<String>,
    data: Vec<(String, String)>,
}

/// Minimal parser for the fixed Event Log XML schema. Pulls System metadata
/// and EventData `Data` items without assuming attribute ordering.
fn parse_event_xml(xml: &str) -> ParsedEvent {
    use quick_xml::events::Event as Xml;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(xml);
    let mut p = ParsedEvent::default();
    let mut cur: Vec<u8> = Vec::new(); // current text-bearing element name
    let mut cur_data_name = String::new();
    let mut in_event_data = false;

    let attr = |e: &quick_xml::events::BytesStart, name: &[u8]| -> Option<String> {
        e.attributes().flatten().find_map(|a| {
            if a.key.as_ref() == name {
                Some(String::from_utf8_lossy(&a.value).into_owned())
            } else {
                None
            }
        })
    };

    loop {
        match reader.read_event() {
            Ok(Xml::Start(e)) | Ok(Xml::Empty(e)) => {
                let name = e.name().as_ref().to_vec();
                match name.as_slice() {
                    b"Provider" => {
                        if let Some(v) = attr(&e, b"Name") {
                            p.provider = v;
                        }
                    }
                    b"TimeCreated" => p.time_created = attr(&e, b"SystemTime"),
                    b"Execution" => p.process_id = attr(&e, b"ProcessID"),
                    b"EventData" => in_event_data = true,
                    b"Data" => cur_data_name = attr(&e, b"Name").unwrap_or_default(),
                    _ => {}
                }
                cur = name;
            }
            Ok(Xml::Text(t)) => {
                let text = t.unescape().map(|c| c.into_owned()).unwrap_or_default();
                if text.trim().is_empty() {
                    continue;
                }
                if in_event_data && cur.as_slice() == b"Data" {
                    p.data.push((std::mem::take(&mut cur_data_name), text));
                } else {
                    match cur.as_slice() {
                        b"EventID" => p.event_id = text.trim().parse().ok(),
                        b"Level" => p.level = text.trim().parse().ok(),
                        b"Computer" => p.computer = Some(text),
                        b"EventRecordID" => p.record_id = Some(text),
                        b"Keywords" => p.keywords = Some(text),
                        _ => {}
                    }
                }
            }
            Ok(Xml::End(e)) => {
                if e.name().as_ref() == b"EventData" {
                    in_event_data = false;
                }
                cur.clear();
            }
            Ok(Xml::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System>
        <Provider Name='Microsoft-Windows-Security-Auditing'/>
        <EventID>4624</EventID>
        <Level>4</Level>
        <TimeCreated SystemTime='2026-06-19T09:52:35.713000000Z'/>
        <EventRecordID>91234</EventRecordID>
        <Execution ProcessID='720' ThreadID='810'/>
        <Channel>Security</Channel>
        <Computer>WIN-HOST</Computer>
      </System>
      <EventData>
        <Data Name='TargetUserName'>alice</Data>
        <Data Name='LogonType'>3</Data>
      </EventData>
    </Event>"#;

    #[test]
    fn parses_system_and_eventdata() {
        let p = parse_event_xml(SAMPLE);
        assert_eq!(p.provider, "Microsoft-Windows-Security-Auditing");
        assert_eq!(p.event_id, Some(4624));
        assert_eq!(p.level, Some(4));
        assert_eq!(p.computer.as_deref(), Some("WIN-HOST"));
        assert_eq!(p.record_id.as_deref(), Some("91234"));
        assert_eq!(p.process_id.as_deref(), Some("720"));
        assert_eq!(
            p.time_created.as_deref(),
            Some("2026-06-19T09:52:35.713000000Z")
        );
        assert_eq!(
            p.data,
            vec![
                ("TargetUserName".to_string(), "alice".to_string()),
                ("LogonType".to_string(), "3".to_string()),
            ]
        );
    }

    #[test]
    fn level_maps_to_syslog_severity() {
        assert_eq!(level_to_severity(1), 2); // Critical
        assert_eq!(level_to_severity(2), 3); // Error
        assert_eq!(level_to_severity(3), 4); // Warning
        assert_eq!(level_to_severity(4), 6); // Information
        assert_eq!(level_to_severity(0), 6); // LogAlways
    }

    #[test]
    fn transient_matches_only_known_idle_transition() {
        // EVT-001: 0x800710DD is the one code we treat as recoverable; anything
        // else (e.g. ACCESS_DENIED) must stay fatal so we don't spin forever.
        assert!(is_transient_code(HRESULT_INVALID_OPERATION));
        assert!(!is_transient_code(0));
        assert!(!is_transient_code(0x8007_0005u32 as i32)); // ERROR_ACCESS_DENIED
    }

    #[test]
    fn drain_idle_covers_no_more_items_and_idle_transition() {
        use windows::core::HRESULT;
        // Both of these must break the drain loop and wait for the next signal.
        assert!(is_drain_idle(ERROR_NO_MORE_ITEMS.to_hresult()));
        assert!(is_drain_idle(HRESULT(HRESULT_INVALID_OPERATION)));
        // A genuine error (channel not found) must propagate, not be swallowed.
        assert!(!is_drain_idle(HRESULT(0x8007_3A9Fu32 as i32)));
    }

    #[test]
    fn resume_mode_never_replays_by_default() {
        // Bookmark always wins, regardless of read_existing.
        assert_eq!(resume_mode(true, false), ResumeMode::AfterBookmark);
        assert_eq!(resume_mode(true, true), ResumeMode::AfterBookmark);
        // Explicit backfill when asked for and no bookmark yet.
        assert_eq!(resume_mode(false, true), ResumeMode::OldestRecord);
        // EVT-004: the default (no bookmark, read_existing=false) is future-only.
        // A regression here replays the entire channel on first start.
        assert_eq!(resume_mode(false, false), ResumeMode::FutureOnly);
    }

    #[test]
    fn backoff_resets_on_progress_but_climbs_on_dry_failures() {
        // EVT-001: a flap that still drained events must wipe the slate clean so
        // an occasional blip never accumulates unbounded backoff growth.
        let mut b = Backoff::start();
        for _ in 0..5 {
            b = b.after_transient(false).doubled();
        }
        assert_eq!(b.failures, 5);
        assert_eq!(b.after_transient(true), Backoff::start());
    }

    #[test]
    fn backoff_climbs_without_bound_on_sustained_dry_failures() {
        // R-7: a channel must never permanently stop retrying, so `Backoff`
        // has no "give up" threshold — the failure count is free to climb
        // indefinitely as long as the delay itself stays capped (see
        // `backoff_delay_doubles_and_caps`).
        let mut b = Backoff::start();
        for _ in 0..50 {
            b = b.after_transient(false);
        }
        assert_eq!(b.failures, 50);
    }

    #[test]
    fn backoff_delay_doubles_and_caps() {
        let b = Backoff::start();
        assert_eq!(b.delay_ms, RESUBSCRIBE_INITIAL_BACKOFF_MS);
        assert_eq!(b.doubled().delay_ms, RESUBSCRIBE_INITIAL_BACKOFF_MS * 2);
        let mut b = b;
        for _ in 0..20 {
            b = b.doubled();
        }
        assert_eq!(b.delay_ms, RESUBSCRIBE_MAX_BACKOFF_MS);
    }
}
