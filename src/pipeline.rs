//! Parsing, transformation, normalization and enrichment.

use crate::config::{
    Condition, EnrichConfig, ParserConfig, ParserMode, PipelineConfig, SyslogFormat, TransformStep,
};
use crate::event::{severity_from_name, value_to_string, Event};
use anyhow::Result;
use chrono::{DateTime, Datelike, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use serde_json::Value;

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
}

impl Parser {
    pub fn compile(cfg: &ParserConfig) -> Result<Self> {
        Ok(Parser {
            mode: cfg.mode,
            regex: cfg.pattern.as_deref().map(Regex::new).transpose()?,
            pair_sep: cfg.pair_separator.clone(),
            kv_sep: cfg.kv_separator.clone(),
            ts_format: cfg.timestamp_format.clone(),
        })
    }

    pub fn parse(&self, line: &str, source: &str, source_type: &str) -> Event {
        let mut ev = Event::new(source, source_type, line);
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

fn parse_json_into(ev: &mut Event, line: &str) {
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

// ---------------------------------------------------------------------------
// Syslog parsing (RFC3164 / RFC5424 / JSON / raw)
// ---------------------------------------------------------------------------

pub fn parse_syslog_into(ev: &mut Event, line: &str, format: SyslogFormat) {
    match format {
        SyslogFormat::Raw => {}
        SyslogFormat::Json => parse_json_into(ev, line),
        SyslogFormat::Rfc5424 => {
            parse_rfc5424(ev, line);
        }
        SyslogFormat::Rfc3164 => {
            parse_rfc3164(ev, line);
        }
        SyslogFormat::Auto => {
            if parse_rfc5424(ev, line) || parse_rfc3164(ev, line) {
                return;
            }
            let t = line.trim_start();
            if t.starts_with('{') {
                parse_json_into(ev, line);
                return;
            }
            // Never drop an unparsable line: forward the raw body and let the
            // downstream SIEM rule on parse_status.
            ev.fields.insert(
                "parse_status".to_string(),
                serde_json::Value::String("unparsed".to_string()),
            );
        }
    }
}

fn parse_pri(line: &str) -> Option<(u8, u8, &str)> {
    let rest = line.strip_prefix('<')?;
    let end = rest.find('>')?;
    if end == 0 || end > 3 {
        return None;
    }
    let pri: u16 = rest[..end].parse().ok()?;
    if pri > 191 {
        return None;
    }
    Some(((pri / 8) as u8, (pri % 8) as u8, &rest[end + 1..]))
}

/// RFC5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
fn parse_rfc5424(ev: &mut Event, line: &str) -> bool {
    let Some((facility, severity, rest)) = parse_pri(line) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix("1 ") else {
        return false;
    };
    let mut parts = rest.splitn(6, ' ');
    let (Some(ts), Some(host), Some(app), Some(procid), Some(_msgid), Some(tail)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    ev.facility = Some(facility);
    ev.severity = Some(severity);
    if ts != "-" {
        if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
            ev.timestamp = dt.with_timezone(&Utc);
        }
    }
    if host != "-" {
        ev.hostname = Some(host.to_string());
    }
    if app != "-" {
        ev.application = Some(app.to_string());
    }
    if procid != "-" {
        ev.process_id = Some(procid.to_string());
    }
    // Structured data: keep raw; skip to message.
    let msg = if let Some(stripped) = tail.strip_prefix('-') {
        stripped.trim_start()
    } else if tail.starts_with('[') {
        // find end of (possibly multiple) SD elements
        let mut depth = 0usize;
        let mut idx = tail.len();
        let bytes = tail.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'[' => depth += 1,
                b']' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 && (i + 1 >= bytes.len() || bytes[i + 1] != b'[') {
                        idx = i + 1;
                        break;
                    }
                }
                b'\\' => i += 1, // skip escaped char
                _ => {}
            }
            i += 1;
        }
        let (sd, m) = tail.split_at(idx.min(tail.len()));
        ev.fields
            .insert("structured_data".to_string(), Value::String(sd.to_string()));
        m.trim_start()
    } else {
        tail
    };
    ev.message = msg.strip_prefix('\u{feff}').unwrap_or(msg).to_string();
    true
}

/// RFC3164: <PRI>Mmm dd hh:mm:ss HOSTNAME TAG[pid]: MSG
fn parse_rfc3164(ev: &mut Event, line: &str) -> bool {
    let Some((facility, severity, rest)) = parse_pri(line) else {
        return false;
    };
    ev.facility = Some(facility);
    ev.severity = Some(severity);

    // Timestamp: "Mmm dd hh:mm:ss" (15 bytes of ASCII). `get` returns None when
    // byte 15 lands inside a multi-byte character — a remote sender can and does
    // arrange exactly that, and `&rest[..15]` would panic (abort) on it.
    let mut remainder = rest;
    if let Some(ts) = rest.get(..15) {
        let now = Utc::now();
        let with_year = format!("{} {}", now.year(), ts);
        if let Ok(naive) = NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S") {
            let mut dt = Utc.from_utc_datetime(&naive);
            // Handle year rollover (log from Dec parsed in Jan).
            if dt > now + chrono::Duration::days(1) {
                if let Ok(prev) = NaiveDateTime::parse_from_str(
                    &format!("{} {}", now.year() - 1, ts),
                    "%Y %b %e %H:%M:%S",
                ) {
                    dt = Utc.from_utc_datetime(&prev);
                }
            }
            ev.timestamp = dt;
            remainder = rest[15..].trim_start();
        }
    }

    // HOSTNAME
    if let Some((host, after)) = remainder.split_once(' ') {
        if !host.is_empty() && !host.contains(':') {
            ev.hostname = Some(host.to_string());
            remainder = after;
        }
    }

    // TAG[pid]: message
    if let Some(colon) = remainder.find(':') {
        let (tag, msg) = remainder.split_at(colon);
        if !tag.contains(' ') && tag.len() <= 48 {
            if let Some(br) = tag.find('[') {
                ev.application = Some(tag[..br].to_string());
                ev.process_id = Some(tag[br + 1..].trim_end_matches(']').to_string());
            } else if !tag.is_empty() {
                ev.application = Some(tag.to_string());
            }
            ev.message = msg[1..].trim_start().to_string();
            return true;
        }
    }
    ev.message = remainder.to_string();
    true
}

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

pub fn eval_condition(cond: &Condition, ev: &Event) -> bool {
    let field_val = ev.get_field(&cond.field);
    match cond.op.as_str() {
        "exists" => field_val.is_some(),
        "not_exists" => field_val.is_none(),
        "eq" => match (&field_val, &cond.value) {
            (Some(a), Some(b)) => values_eq(a, b),
            _ => false,
        },
        "ne" => match (&field_val, &cond.value) {
            (Some(a), Some(b)) => !values_eq(a, b),
            (None, Some(_)) => true,
            _ => false,
        },
        "contains" => match (&field_val, &cond.value) {
            (Some(a), Some(b)) => {
                let (Some(a), Some(b)) = (value_to_string(a), value_to_string(b)) else {
                    return false;
                };
                a.contains(&b)
            }
            _ => false,
        },
        "matches" => match (&field_val, &cond.value) {
            (Some(a), Some(Value::String(pat))) => {
                let Some(a) = value_to_string(a) else {
                    return false;
                };
                Regex::new(pat).map(|re| re.is_match(&a)).unwrap_or(false)
            }
            _ => false,
        },
        "gt" | "lt" => {
            let (Some(a), Some(b)) = (&field_val, &cond.value) else {
                return false;
            };
            let (Some(a), Some(b)) = (value_to_f64(a), value_to_f64(b)) else {
                return false;
            };
            if cond.op == "gt" {
                a > b
            } else {
                a < b
            }
        }
        _ => false,
    }
}

fn values_eq(a: &Value, b: &Value) -> bool {
    if a == b {
        return true;
    }
    match (value_to_string(a), value_to_string(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn value_to_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Transforms
// ---------------------------------------------------------------------------

/// Pre-compiled transform chain.
pub struct Transformer {
    steps: Vec<CompiledStep>,
}

enum CompiledStep {
    AddField {
        field: String,
        value: Value,
        when: Option<Condition>,
    },
    RemoveField {
        field: String,
        when: Option<Condition>,
    },
    RenameField {
        from: String,
        to: String,
        when: Option<Condition>,
    },
    Convert {
        field: String,
        to: String,
        when: Option<Condition>,
    },
    Mask {
        field: String,
        re: Regex,
        replacement: String,
        when: Option<Condition>,
    },
    Drop {
        when: Condition,
    },
    Keep {
        when: Condition,
    },
}

impl Transformer {
    pub fn compile(cfg: &PipelineConfig) -> Result<Self> {
        let mut steps = Vec::new();
        for t in &cfg.transforms {
            steps.push(match t.clone() {
                TransformStep::AddField { field, value, when } => {
                    CompiledStep::AddField { field, value, when }
                }
                TransformStep::RemoveField { field, when } => {
                    CompiledStep::RemoveField { field, when }
                }
                TransformStep::RenameField { from, to, when } => {
                    CompiledStep::RenameField { from, to, when }
                }
                TransformStep::Convert { field, to, when } => {
                    CompiledStep::Convert { field, to, when }
                }
                TransformStep::Mask {
                    field,
                    pattern,
                    replacement,
                    when,
                } => CompiledStep::Mask {
                    field,
                    re: Regex::new(&pattern)?,
                    replacement,
                    when,
                },
                TransformStep::Drop { when } => CompiledStep::Drop { when },
                TransformStep::Keep { when } => CompiledStep::Keep { when },
            });
        }
        Ok(Transformer { steps })
    }

    /// Apply all steps; returns false if the event should be dropped.
    pub fn apply(&self, ev: &mut Event) -> bool {
        for step in &self.steps {
            match step {
                CompiledStep::AddField { field, value, when } => {
                    if when.as_ref().map_or(true, |w| eval_condition(w, ev)) {
                        ev.set_field(field, value.clone());
                    }
                }
                CompiledStep::RemoveField { field, when } => {
                    if when.as_ref().map_or(true, |w| eval_condition(w, ev)) {
                        ev.remove_field(field);
                    }
                }
                CompiledStep::RenameField { from, to, when } => {
                    if when.as_ref().map_or(true, |w| eval_condition(w, ev)) {
                        if let Some(v) = ev.get_field(from) {
                            ev.remove_field(from);
                            ev.set_field(to, v);
                        }
                    }
                }
                CompiledStep::Convert { field, to, when } => {
                    if when.as_ref().map_or(true, |w| eval_condition(w, ev)) {
                        if let Some(v) = ev.get_field(field) {
                            if let Some(converted) = convert_value(&v, to) {
                                ev.set_field(field, converted);
                            }
                        }
                    }
                }
                CompiledStep::Mask {
                    field,
                    re,
                    replacement,
                    when,
                } => {
                    if when.as_ref().map_or(true, |w| eval_condition(w, ev)) {
                        if let Some(v) = ev.get_field(field) {
                            if let Some(s) = value_to_string(&v) {
                                let masked = re.replace_all(&s, replacement.as_str());
                                ev.set_field(field, Value::String(masked.into_owned()));
                            }
                        }
                        // `raw_message` retains the original unparsed line, so
                        // masking only `message` would leak the secret through
                        // raw_message on outputs that emit every field (e.g.
                        // json). Apply the same masking to raw_message whenever
                        // we mask message, so no sensitive data escapes.
                        if field == "message" {
                            if let Some(raw) = ev.raw_message.take() {
                                let masked = re.replace_all(&raw, replacement.as_str());
                                ev.raw_message = Some(masked.into_owned());
                            }
                        }
                    }
                }
                CompiledStep::Drop { when } => {
                    if eval_condition(when, ev) {
                        return false;
                    }
                }
                CompiledStep::Keep { when } => {
                    if !eval_condition(when, ev) {
                        return false;
                    }
                }
            }
        }
        true
    }
}

fn convert_value(v: &Value, to: &str) -> Option<Value> {
    match to {
        "string" => value_to_string(v).map(Value::String),
        "int" => match v {
            Value::Number(n) => n.as_i64().map(|x| Value::Number(x.into())),
            Value::String(s) => s
                .trim()
                .parse::<i64>()
                .ok()
                .map(|x| Value::Number(x.into())),
            Value::Bool(b) => Some(Value::Number(i64::from(*b).into())),
            _ => None,
        },
        "float" => match v {
            Value::Number(n) => n
                .as_f64()
                .and_then(serde_json::Number::from_f64)
                .map(Value::Number),
            Value::String(s) => s
                .trim()
                .parse::<f64>()
                .ok()
                .and_then(serde_json::Number::from_f64)
                .map(Value::Number),
            _ => None,
        },
        "bool" => match v {
            Value::Bool(b) => Some(Value::Bool(*b)),
            Value::String(s) => match s.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => Some(Value::Bool(true)),
                "false" | "0" | "no" => Some(Value::Bool(false)),
                _ => None,
            },
            Value::Number(n) => Some(Value::Bool(n.as_f64() != Some(0.0))),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Enrichment
// ---------------------------------------------------------------------------

/// Static enrichment values resolved once at engine start.
pub struct Enricher {
    hostname: Option<String>,
    os: Option<String>,
    local_ip: Option<String>,
    environment: Option<String>,
    site: Option<String>,
    tenant: Option<String>,
    customer: Option<String>,
    tags: Vec<String>,
    fields: serde_json::Map<String, Value>,
}

impl Enricher {
    pub fn new(cfg: &EnrichConfig) -> Self {
        Enricher {
            hostname: if cfg.hostname {
                hostname::get()
                    .ok()
                    .map(|h| h.to_string_lossy().into_owned())
            } else {
                None
            },
            os: if cfg.os_info {
                Some(format!(
                    "{} {}",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                ))
            } else {
                None
            },
            local_ip: if cfg.local_ip {
                detect_local_ip()
            } else {
                None
            },
            environment: cfg.environment.clone(),
            site: cfg.site.clone(),
            tenant: cfg.tenant.clone(),
            customer: cfg.customer.clone(),
            tags: cfg.tags.clone(),
            fields: cfg.fields.clone(),
        }
    }

    pub fn apply(&self, ev: &mut Event) {
        if ev.hostname.is_none() {
            ev.hostname = self.hostname.clone();
        }
        if let Some(os) = &self.os {
            ev.fields
                .entry("os".to_string())
                .or_insert_with(|| Value::String(os.clone()));
        }
        if let Some(ip) = &self.local_ip {
            ev.fields
                .entry("local_ip".to_string())
                .or_insert_with(|| Value::String(ip.clone()));
        }
        for (key, val) in [
            ("environment", &self.environment),
            ("site", &self.site),
            ("tenant", &self.tenant),
            ("customer", &self.customer),
        ] {
            if let Some(v) = val {
                ev.fields
                    .entry(key.to_string())
                    .or_insert_with(|| Value::String(v.clone()));
            }
        }
        if !self.tags.is_empty() {
            ev.fields.entry("tags".to_string()).or_insert_with(|| {
                Value::Array(self.tags.iter().cloned().map(Value::String).collect())
            });
        }
        for (k, v) in &self.fields {
            ev.fields.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
}

/// Best-effort local IP discovery without extra dependencies: a UDP "connect"
/// (no packets sent) reveals the kernel-chosen source address.
fn detect_local_ip() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ParserConfig;

    fn raw_parser() -> Parser {
        Parser::compile(&ParserConfig::default()).unwrap()
    }

    #[test]
    fn rfc3164_parses() {
        let mut ev = Event::new("net", "syslog", "");
        let ok = parse_rfc3164(
            &mut ev,
            "<34>Oct 11 22:14:15 mymachine su[1234]: 'su root' failed for lonvick on /dev/pts/8",
        );
        assert!(ok);
        assert_eq!(ev.facility, Some(4));
        assert_eq!(ev.severity, Some(2));
        assert_eq!(ev.hostname.as_deref(), Some("mymachine"));
        assert_eq!(ev.application.as_deref(), Some("su"));
        assert_eq!(ev.process_id.as_deref(), Some("1234"));
        assert!(ev.message.starts_with("'su root' failed"));
    }

    #[test]
    fn rfc5424_parses() {
        let mut ev = Event::new("net", "syslog", "");
        let ok = parse_rfc5424(
            &mut ev,
            "<165>1 2026-06-10T22:14:15.003Z mymachine.example.com evntslog 2317 ID47 [exampleSDID@32473 iut=\"3\"] An application event",
        );
        assert!(ok);
        assert_eq!(ev.facility, Some(20));
        assert_eq!(ev.severity, Some(5));
        assert_eq!(ev.hostname.as_deref(), Some("mymachine.example.com"));
        assert_eq!(ev.application.as_deref(), Some("evntslog"));
        assert_eq!(ev.process_id.as_deref(), Some("2317"));
        assert_eq!(ev.message, "An application event");
        assert!(ev.fields.contains_key("structured_data"));
    }

    #[test]
    fn rfc3164_thai_body_does_not_panic() {
        let line = "<13>x ทดสอบระบบ log message";
        let mut ev = Event::new("syslog:127.0.0.1", "syslog", line);
        parse_syslog_into(&mut ev, line, SyslogFormat::Auto);
        assert_eq!(ev.severity, Some(5));
        assert!(
            ev.message.contains("ทดสอบระบบ"),
            "body lost: {}",
            ev.message
        );
    }

    #[test]
    fn rfc3164_emoji_body_does_not_panic() {
        let line = "<13>🔥🔥🔥🔥 disk on fire";
        let mut ev = Event::new("syslog:127.0.0.1", "syslog", line);
        parse_syslog_into(&mut ev, line, SyslogFormat::Auto);
        assert!(
            ev.message.contains("disk on fire"),
            "body lost: {}",
            ev.message
        );
    }

    #[test]
    fn no_panic_on_any_multibyte_offset() {
        // Walk the multi-byte character across every byte position around 15.
        for filler in ["ก", "é", "🔥", "日"] {
            for n in 0..24 {
                let line = format!("<13>{}{} rest of message", "a".repeat(n), filler);
                let mut ev = Event::new("s", "syslog", &line);
                parse_syslog_into(&mut ev, &line, SyslogFormat::Auto);
            }
        }
    }

    #[test]
    fn ascii_rfc3164_timestamp_still_parses() {
        let line = "<14>Jun 10 10:00:00 host1 app: hello";
        let mut ev = Event::new("s", "syslog", line);
        parse_syslog_into(&mut ev, line, SyslogFormat::Auto);
        assert_eq!(ev.hostname.as_deref(), Some("host1"));
        assert_eq!(ev.application.as_deref(), Some("app"));
        assert_eq!(ev.message, "hello");
    }

    #[test]
    fn unparsable_line_is_forwarded_and_tagged() {
        let line = "this is not syslog at all";
        let mut ev = Event::new("s", "syslog", line);
        parse_syslog_into(&mut ev, line, SyslogFormat::Auto);
        assert_eq!(ev.message, line, "raw body must survive");
        assert_eq!(
            ev.fields.get("parse_status").and_then(|v| v.as_str()),
            Some("unparsed")
        );
    }

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

    #[test]
    fn transforms_apply() {
        let cfg: PipelineConfig = serde_yaml::from_str(
            r#"
transforms:
  - type: add_field
    field: dc
    value: bkk-1
  - type: rename_field
    from: dc
    to: datacenter
  - type: mask
    field: message
    pattern: "\\b\\d{13,16}\\b"
    replacement: "[CARD]"
  - type: drop
    when: { field: severity, op: gt, value: 6 }
"#,
        )
        .unwrap();
        let t = Transformer::compile(&cfg).unwrap();

        let mut ev = raw_parser().parse("card 4111111111111111 charged", "f", "file");
        ev.severity = Some(3);
        assert!(t.apply(&mut ev));
        assert_eq!(ev.fields["datacenter"], Value::String("bkk-1".into()));
        assert!(ev.message.contains("[CARD]"));
        assert!(!ev.message.contains("4111111111111111"));
        // PIPE-006 regression: masking `message` must also scrub raw_message so
        // the secret can't leak through outputs that emit every field (json).
        let raw = ev.raw_message.as_deref().unwrap();
        assert!(raw.contains("[CARD]"), "raw_message not masked: {raw}");
        assert!(
            !raw.contains("4111111111111111"),
            "secret leaked in raw_message: {raw}"
        );

        let mut debug_ev = raw_parser().parse("noise", "f", "file");
        debug_ev.severity = Some(7);
        assert!(!t.apply(&mut debug_ev), "debug event should be dropped");
    }

    #[test]
    fn convert_types() {
        assert_eq!(
            convert_value(&Value::String("42".into()), "int"),
            Some(Value::Number(42.into()))
        );
        assert_eq!(
            convert_value(&Value::String("yes".into()), "bool"),
            Some(Value::Bool(true))
        );
    }

    #[test]
    fn enrichment_applies() {
        let cfg: EnrichConfig = serde_yaml::from_str(
            r#"
environment: production
tags: [edge, th]
fields:
  rack: r12
"#,
        )
        .unwrap();
        let e = Enricher::new(&cfg);
        let mut ev = raw_parser().parse("hello", "f", "file");
        e.apply(&mut ev);
        assert_eq!(ev.fields["environment"], Value::String("production".into()));
        assert_eq!(ev.fields["rack"], Value::String("r12".into()));
        assert!(ev.hostname.is_some());
    }
}
