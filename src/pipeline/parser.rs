//! Parsing, transformation, normalization and enrichment.

use crate::config::{ParserConfig, ParserMode, SyslogFormat};
use crate::event::{severity_from_name, value_to_string, Event};
use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use serde_json::Value;

use super::syslog::parse_syslog_into;

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Compiled parser; created once per input.
pub struct Parser {
    mode: ParserMode,
    regex: Option<Regex>,
    pair_sep: String,
    kv_sep: String,
    ts_format: Option<String>,
    keep_raw_message: bool,
}

impl Parser {
    pub fn compile(cfg: &ParserConfig) -> Result<Self> {
        Ok(Parser {
            mode: cfg.mode,
            regex: cfg.pattern.as_deref().map(Regex::new).transpose()?,
            pair_sep: cfg.pair_separator.clone(),
            kv_sep: cfg.kv_separator.clone(),
            ts_format: cfg.timestamp_format.clone(),
            keep_raw_message: cfg.keep_raw_message,
        })
    }

    pub fn parse(&self, line: &str, source: &str, source_type: &str) -> Event {
        let mut ev = Event::new(source, source_type, line);
        // Capture the line as originally received before parsing mutates
        // `ev.message`, so `raw_message` reflects true pre-parse text.
        if self.keep_raw_message {
            ev.preserve_raw(line);
        }
        match self.mode {
            ParserMode::Raw => {}
            ParserMode::Json => parse_json_into(&mut ev, line),
            ParserMode::Kv => parse_kv_into(&mut ev, line, &self.pair_sep, &self.kv_sep),
            ParserMode::Regex => {
                if let Some(re) = &self.regex {
                    parse_regex_into(&mut ev, line, re, self.ts_format.as_deref());
                }
            }
            ParserMode::Syslog => {
                parse_syslog_into(&mut ev, line, SyslogFormat::Auto);
            }
        }
        ev
    }
}

fn apply_known_key(ev: &mut Event, key: &str, val: &Value) -> bool {
    match key {
        "timestamp" | "time" | "@timestamp" | "ts" => {
            if let Some(s) = val.as_str() {
                if let Some(ts) = parse_timestamp(s, None) {
                    ev.timestamp = ts;
                    return true;
                }
            }
            false
        }
        "host" | "hostname" => {
            ev.hostname = value_to_string(val);
            true
        }
        "severity" | "level" | "loglevel" => {
            let sev = match val {
                Value::Number(n) => n.as_u64().and_then(|x| u8::try_from(x).ok()),
                Value::String(s) => severity_from_name(s).or_else(|| s.parse().ok()),
                _ => None,
            };
            if let Some(s) = sev {
                ev.severity = Some(s.min(7));
                return true;
            }
            false
        }
        "message" | "msg" => {
            if let Some(s) = val.as_str() {
                ev.message = s.to_string();
                return true;
            }
            false
        }
        "application" | "app" | "appname" | "program" => {
            ev.application = value_to_string(val);
            true
        }
        "pid" | "process_id" | "procid" => {
            ev.process_id = value_to_string(val);
            true
        }
        _ => false,
    }
}

pub(crate) fn parse_json_into(ev: &mut Event, line: &str) {
    let parsed: Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(_) => return, // keep raw event
    };
    if let Value::Object(map) = parsed {
        for (k, v) in map {
            if !apply_known_key(ev, &k, &v) {
                ev.fields.insert(k, v);
            }
        }
    }
}

fn parse_kv_into(ev: &mut Event, line: &str, pair_sep: &str, kv_sep: &str) {
    let pairs: Vec<&str> = if pair_sep == " " {
        line.split_whitespace().collect()
    } else {
        line.split(pair_sep).collect()
    };
    for pair in pairs {
        if let Some((k, v)) = pair.split_once(kv_sep) {
            let k = k.trim();
            let v = v.trim().trim_matches('"');
            if k.is_empty() {
                continue;
            }
            let val = Value::String(v.to_string());
            if !apply_known_key(ev, k, &val) {
                ev.fields.insert(k.to_string(), val);
            }
        }
    }
}

fn parse_regex_into(ev: &mut Event, line: &str, re: &Regex, ts_format: Option<&str>) {
    let caps = match re.captures(line) {
        Some(c) => c,
        None => return,
    };
    for name in re.capture_names().flatten() {
        if let Some(m) = caps.name(name) {
            let raw = m.as_str();
            if name == "timestamp" {
                if let Some(ts) = parse_timestamp(raw, ts_format) {
                    ev.timestamp = ts;
                    continue;
                }
            }
            let val = Value::String(raw.to_string());
            if !apply_known_key(ev, name, &val) {
                ev.fields.insert(name.to_string(), val);
            }
        }
    }
}

/// Best-effort timestamp parsing: explicit format, RFC3339, then common formats.
pub fn parse_timestamp(s: &str, format: Option<&str>) -> Option<DateTime<Utc>> {
    if let Some(fmt) = format {
        if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&naive));
        }
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%d/%b/%Y:%H:%M:%S %z",
    ] {
        if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&naive));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ParserConfig;

    #[test]
    fn json_parser_maps_known_fields() {
        let p = Parser::compile(&ParserConfig {
            mode: ParserMode::Json,
            ..Default::default()
        })
        .unwrap();
        let ev = p.parse(
            r#"{"level":"error","msg":"boom","host":"web1","custom":42}"#,
            "f",
            "file",
        );
        assert_eq!(ev.severity, Some(3));
        assert_eq!(ev.message, "boom");
        assert_eq!(ev.hostname.as_deref(), Some("web1"));
        assert_eq!(ev.fields["custom"], Value::Number(42.into()));
    }

    #[test]
    fn kv_parser() {
        let p = Parser::compile(&ParserConfig {
            mode: ParserMode::Kv,
            ..Default::default()
        })
        .unwrap();
        let ev = p.parse("action=block src=1.2.3.4 level=warning", "f", "file");
        assert_eq!(ev.fields["action"], Value::String("block".into()));
        assert_eq!(ev.severity, Some(4));
    }

    #[test]
    fn regex_parser() {
        let p = Parser::compile(&ParserConfig {
            mode: ParserMode::Regex,
            pattern: Some(r"^(?P<timestamp>\S+) (?P<level>\w+) (?P<message>.*)$".into()),
            ..Default::default()
        })
        .unwrap();
        let ev = p.parse("2026-06-10T10:00:00Z ERROR it broke", "f", "file");
        assert_eq!(ev.severity, Some(3));
        assert_eq!(ev.message, "it broke");
        assert_eq!(ev.timestamp.to_rfc3339(), "2026-06-10T10:00:00+00:00");
    }
}
