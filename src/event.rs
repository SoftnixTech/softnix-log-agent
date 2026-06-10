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
            raw_message: Some(raw.to_string()),
            collector_version: AGENT_VERSION.to_string(),
            fields: Map::new(),
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
}
