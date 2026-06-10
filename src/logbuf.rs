//! In-memory ring buffer of recent agent log lines for the web UI.

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

const CAPACITY: usize = 500;

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub time: String,
    pub level: String,
    pub target: String,
    pub message: String,
}

#[derive(Clone, Default)]
pub struct LogBuffer {
    entries: Arc<Mutex<VecDeque<LogEntry>>>,
}

impl LogBuffer {
    pub fn recent(&self, limit: usize, min_level: Option<&str>) -> Vec<LogEntry> {
        let entries = self.entries.lock().unwrap();
        let filter = |e: &&LogEntry| match min_level {
            Some("error") => e.level == "ERROR",
            Some("warn") => e.level == "ERROR" || e.level == "WARN",
            _ => true,
        };
        entries
            .iter()
            .rev()
            .filter(filter)
            .take(limit.min(CAPACITY))
            .cloned()
            .collect()
    }

    fn push(&self, entry: LogEntry) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= CAPACITY {
            entries.pop_front();
        }
        entries.push_back(entry);
    }
}

pub struct LogBufferLayer(pub LogBuffer);

struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        } else {
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            self.0.push_str(&format!("{}={:?}", field.name(), value));
        }
    }
}

impl<S: Subscriber> Layer<S> for LogBufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        if *meta.level() > Level::DEBUG {
            return; // ignore trace
        }
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        self.0.push(LogEntry {
            time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            level: meta.level().to_string(),
            target: meta.target().to_string(),
            message: visitor.0,
        });
    }
}
