//! Lightweight internal metrics and component status registries.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Default)]
pub struct Metrics {
    pub events_received: AtomicU64,
    pub events_sent: AtomicU64,
    pub events_failed: AtomicU64,
    pub events_dropped: AtomicU64,
    pub errors: AtomicU64,
    pub last_error: Mutex<Option<String>>,
    /// Bytes currently admitted into the input→pipeline channel but not yet
    /// drained by `run_pipeline` (see `engine::EventSender`). A gauge, not a
    /// counter: it tracks live occupancy of the byte budget, not a total.
    pub channel_bytes: AtomicU64,
}

impl Metrics {
    pub fn record_error(&self, msg: impl Into<String>) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        *self.last_error.lock().unwrap() = Some(msg.into());
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            events_received: self.events_received.load(Ordering::Relaxed),
            events_sent: self.events_sent.load(Ordering::Relaxed),
            events_failed: self.events_failed.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            last_error: self.last_error.lock().unwrap().clone(),
            channel_bytes: self.channel_bytes.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub events_received: u64,
    pub events_sent: u64,
    pub events_failed: u64,
    pub events_dropped: u64,
    pub errors: u64,
    pub last_error: Option<String>,
    pub channel_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct InputStatus {
    pub id: String,
    pub kind: String,
    pub detail: String,
    pub active: bool,
    pub events: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct OutputStatus {
    pub id: String,
    pub kind: String,
    pub detail: String,
    pub healthy: bool,
    pub connected: bool,
    pub events_sent: u64,
    pub retries: u64,
    pub consecutive_failures: u64,
    pub last_error: Option<String>,
}

/// Shared registry of per-component status for the web UI / health checks.
#[derive(Default)]
pub struct StatusRegistry {
    pub inputs: Mutex<HashMap<String, InputStatus>>,
    pub outputs: Mutex<HashMap<String, OutputStatus>>,
}

impl StatusRegistry {
    pub fn set_input(&self, st: InputStatus) {
        self.inputs.lock().unwrap().insert(st.id.clone(), st);
    }

    pub fn update_input<F: FnOnce(&mut InputStatus)>(&self, id: &str, f: F) {
        let mut m = self.inputs.lock().unwrap();
        if let Some(st) = m.get_mut(id) {
            f(st);
        }
    }

    pub fn set_output(&self, st: OutputStatus) {
        self.outputs.lock().unwrap().insert(st.id.clone(), st);
    }

    pub fn update_output<F: FnOnce(&mut OutputStatus)>(&self, id: &str, f: F) {
        let mut m = self.outputs.lock().unwrap();
        if let Some(st) = m.get_mut(id) {
            f(st);
        }
    }

    pub fn output_healthy(&self, id: &str) -> bool {
        self.outputs
            .lock()
            .unwrap()
            .get(id)
            .map(|s| s.healthy)
            .unwrap_or(false)
    }

    pub fn inputs_snapshot(&self) -> Vec<InputStatus> {
        let mut v: Vec<_> = self.inputs.lock().unwrap().values().cloned().collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    pub fn outputs_snapshot(&self) -> Vec<OutputStatus> {
        let mut v: Vec<_> = self.outputs.lock().unwrap().values().cloned().collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }
}

/// Process start time, used for uptime reporting.
pub struct Uptime(Instant);

impl Default for Uptime {
    fn default() -> Self {
        Uptime(Instant::now())
    }
}

impl Uptime {
    pub fn seconds(&self) -> u64 {
        self.0.elapsed().as_secs()
    }
}
