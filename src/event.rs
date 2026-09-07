//! Common event schema shared by the whole pipeline.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Normalized log event. Core fields are first-class; everything else
/// lives in the extensible `fields` map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub timestamp: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub source: String,
    pub source_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facility: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_message: Option<String>,
    pub collector_version: String,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub fields: Map<String, Value>,
}

impl Event {
    pub fn new(source: &str, source_type: &str, raw: &str) -> Self {
        let now = Utc::now();
        Event {
            timestamp: now,
            received_at: now,
            hostname: None,
            source: source.to_string(),
            source_type: source_type.to_string(),
            severity: None,
            facility: None,
            application: None,
            process_id: None,
            message: raw.to_string(),
            // Opt-in: storing the body twice doubled RSS, queue occupancy and
            // the JSON wire size for every event, including `parser.mode: raw`
            // where the two copies were byte-identical.
            raw_message: None,
            collector_version: AGENT_VERSION.to_string(),
            fields: Map::new(),
        }
    }

    /// Keep the pre-parse body. No-op if one is already recorded.
    pub fn preserve_raw(&mut self, raw: &str) {
        if self.raw_message.is_none() {
            self.raw_message = Some(raw.to_string());
        }
    }

    /// Read a field by name. Core fields resolve to their values; anything
    /// else is looked up in the custom field map.
    pub fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "timestamp" => Some(Value::String(self.timestamp.to_rfc3339())),
            "received_at" => Some(Value::String(self.received_at.to_rfc3339())),
            "hostname" => self.hostname.clone().map(Value::String),
            "source" => Some(Value::String(self.source.clone())),
            "source_type" => Some(Value::String(self.source_type.clone())),
            "severity" => self.severity.map(|v| Value::Number(v.into())),
            "facility" => self.facility.map(|v| Value::Number(v.into())),
            "application" => self.application.clone().map(Value::String),
            "process_id" => self.process_id.clone().map(Value::String),
            "message" => Some(Value::String(self.message.clone())),
            "raw_message" => self.raw_message.clone().map(Value::String),
            "collector_version" => Some(Value::String(self.collector_version.clone())),
            other => self.fields.get(other).cloned(),
        }
    }

    /// Borrow a field's value as a `&str`, for callers that only need to read
    /// it.
    ///
    /// `get_field` has to return an owned `Value`, so reading `message`
    /// through it copies the entire event body — and `value_to_string` then
    /// copies it a second time. With a `when:` condition on `message` per
    /// output, a 4 KB event cost ~8 KB of allocate-copy-free per output
    /// before it reached any queue.
    ///
    /// Covers the string-valued fields the condition DSL and the `mask`
    /// transform are actually pointed at. Everything else — `timestamp`,
    /// `received_at`, `severity`, `facility`, `collector_version`, and any
    /// non-`String` entry in `fields` — returns `None`, and callers fall back
    /// to `get_field` for those. That fallback is load-bearing: it is what
    /// makes the borrowing fast path exactly equivalent to the owned one.
    ///
    /// Whenever this returns `Some`, `get_field` for the same name would also
    /// return `Some`.
    pub fn get_str(&self, name: &str) -> Option<&str> {
        match name {
            "message" => Some(self.message.as_str()),
            "raw_message" => self.raw_message.as_deref(),
            "hostname" => self.hostname.as_deref(),
            "application" => self.application.as_deref(),
            "process_id" => self.process_id.as_deref(),
            "source" => Some(self.source.as_str()),
            "source_type" => Some(self.source_type.as_str()),
            other => match self.fields.get(other) {
                Some(Value::String(s)) => Some(s.as_str()),
                _ => None,
            },
        }
    }

    /// Set a field by name; core fields are coerced where sensible.
    pub fn set_field(&mut self, name: &str, value: Value) {
        match name {
            "hostname" => self.hostname = value_to_string(&value),
            "source" => {
                if let Some(s) = value_to_string(&value) {
                    self.source = s;
                }
            }
            "source_type" => {
                if let Some(s) = value_to_string(&value) {
                    self.source_type = s;
                }
            }
            "severity" => self.severity = value_to_u8(&value),
            "facility" => self.facility = value_to_u8(&value),
            "application" => self.application = value_to_string(&value),
            "process_id" => self.process_id = value_to_string(&value),
            "message" => {
                if let Some(s) = value_to_string(&value) {
                    self.message = s;
                }
            }
            "raw_message" => self.raw_message = value_to_string(&value),
            "timestamp" => {
                if let Some(s) = value_to_string(&value) {
                    if let Ok(ts) = DateTime::parse_from_rfc3339(&s) {
                        self.timestamp = ts.with_timezone(&Utc);
                    }
                }
            }
            other => {
                self.fields.insert(other.to_string(), value);
            }
        }
    }

    pub fn remove_field(&mut self, name: &str) {
        match name {
            "hostname" => self.hostname = None,
            "severity" => self.severity = None,
            "facility" => self.facility = None,
            "application" => self.application = None,
            "process_id" => self.process_id = None,
            "raw_message" => self.raw_message = None,
            other => {
                self.fields.remove(other);
            }
        }
    }
}

pub fn value_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

pub fn value_to_u8(v: &Value) -> Option<u8> {
    match v {
        Value::Number(n) => n.as_u64().and_then(|x| u8::try_from(x).ok()),
        Value::String(s) => s.parse::<u8>().ok().or_else(|| severity_from_name(s)),
        _ => None,
    }
}

/// Map textual severity names to syslog numeric severities.
pub fn severity_from_name(s: &str) -> Option<u8> {
    match s.to_ascii_lowercase().as_str() {
        "emerg" | "emergency" | "panic" => Some(0),
        "alert" => Some(1),
        "crit" | "critical" | "fatal" => Some(2),
        "err" | "error" => Some(3),
        "warn" | "warning" => Some(4),
        "notice" => Some(5),
        "info" | "informational" => Some(6),
        "debug" | "trace" => Some(7),
        _ => None,
    }
}

pub fn severity_name(sev: u8) -> &'static str {
    match sev {
        0 => "emerg",
        1 => "alert",
        2 => "crit",
        3 => "err",
        4 => "warning",
        5 => "notice",
        6 => "info",
        _ => "debug",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_roundtrip() {
        let mut e = Event::new("test", "raw", "hello");
        e.set_field("custom", Value::String("x".into()));
        e.set_field("severity", Value::String("error".into()));
        assert_eq!(e.get_field("custom"), Some(Value::String("x".into())));
        assert_eq!(e.severity, Some(3));
        e.remove_field("custom");
        assert!(e.get_field("custom").is_none());
    }

    #[test]
    fn new_event_does_not_duplicate_the_body() {
        let ev = Event::new("s", "test", "some log line");
        assert_eq!(ev.message, "some log line");
        assert!(ev.raw_message.is_none(), "raw_message must be opt-in");
    }

    #[test]
    fn preserve_raw_sets_it_once() {
        let mut ev = Event::new("s", "test", "original");
        ev.preserve_raw("original");
        assert_eq!(ev.raw_message.as_deref(), Some("original"));
        ev.preserve_raw("second call");
        assert_eq!(ev.raw_message.as_deref(), Some("original"));
    }

    /// R-5: `get_field` returns an owned `Value`, so every condition
    /// evaluation on `message` deep-copied the whole event body — and
    /// `value_to_string` then copied it again. `get_str` borrows instead.
    #[test]
    fn get_str_borrows_string_fields_without_copying() {
        let mut ev = Event::new("src-1", "test", "a message body");
        ev.hostname = Some("host-a".to_string());
        ev.application = Some("app".to_string());
        ev.process_id = Some("4242".to_string());
        ev.raw_message = Some("<11>a message body".to_string());
        ev.fields
            .insert("env".to_string(), Value::String("prod".to_string()));
        ev.fields
            .insert("retries".to_string(), Value::Number(7.into()));
        ev.severity = Some(3);

        // The whole point: a borrow of the event's own buffer, not a copy.
        assert!(
            std::ptr::eq(ev.get_str("message").unwrap().as_ptr(), ev.message.as_ptr()),
            "get_str must borrow the body, not clone it"
        );

        assert_eq!(ev.get_str("message"), Some("a message body"));
        assert_eq!(ev.get_str("raw_message"), Some("<11>a message body"));
        assert_eq!(ev.get_str("hostname"), Some("host-a"));
        assert_eq!(ev.get_str("application"), Some("app"));
        assert_eq!(ev.get_str("process_id"), Some("4242"));
        assert_eq!(ev.get_str("source"), Some("src-1"));
        assert_eq!(ev.get_str("source_type"), Some("test"));
        assert_eq!(ev.get_str("env"), Some("prod"));

        // Deliberately not covered: callers fall back to get_field for these,
        // which is what keeps eval_condition's behaviour identical.
        assert_eq!(ev.get_str("retries"), None, "non-string fields entry");
        assert_eq!(ev.get_str("severity"), None, "numeric core field");
        assert_eq!(ev.get_str("timestamp"), None, "formatted core field");
        assert_eq!(ev.get_str("collector_version"), None);
        assert_eq!(ev.get_str("nope"), None, "absent field");

        // Absent optionals report absent, not empty.
        let bare = Event::new("s", "t", "body");
        assert_eq!(bare.get_str("hostname"), None);
        assert_eq!(bare.get_str("raw_message"), None);
        assert_eq!(bare.get_str("application"), None);
        assert_eq!(bare.get_str("process_id"), None);

        // The implication eval_condition's fast path depends on: whenever
        // get_str answers, get_field would have answered too.
        for name in [
            "message",
            "raw_message",
            "hostname",
            "application",
            "process_id",
            "source",
            "source_type",
            "env",
            "retries",
            "severity",
            "timestamp",
            "collector_version",
            "nope",
        ] {
            if ev.get_str(name).is_some() {
                assert!(
                    ev.get_field(name).is_some(),
                    "get_str answered for {name} but get_field did not"
                );
            }
        }
    }
}
