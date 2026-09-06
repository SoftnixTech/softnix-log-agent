use crate::config::OutputFormat;
use crate::event::{severity_name, Event};
use chrono::SecondsFormat;

/// Render an event in the configured wire format.
pub fn format_event(ev: &Event, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string(ev).unwrap_or_else(|_| ev.message.clone()),
        OutputFormat::Raw => ev.message.clone(),
        OutputFormat::Rfc5424 => {
            let pri = pri_of(ev);
            let ts = ev.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true);
            let host = ev.hostname.as_deref().unwrap_or("-");
            let app = ev.application.as_deref().unwrap_or("softnix-log-agent");
            let pid = ev.process_id.as_deref().unwrap_or("-");
            let sd = rfc5424_structured_data(ev);
            format!("<{pri}>1 {ts} {host} {app} {pid} - {sd} {}", ev.message)
        }
        OutputFormat::Rfc3164 => {
            let pri = pri_of(ev);
            let ts = ev.timestamp.format("%b %e %H:%M:%S");
            let host = ev.hostname.as_deref().unwrap_or("-");
            let tag = ev.application.as_deref().unwrap_or("softnix");
            match &ev.process_id {
                Some(pid) => format!("<{pri}>{ts} {host} {tag}[{pid}]: {}", ev.message),
                None => format!("<{pri}>{ts} {host} {tag}: {}", ev.message),
            }
        }
    }
}

/// Build the RFC 5424 STRUCTURED-DATA element from the event's custom fields
/// (enrichment, parsed attributes, etc.). Returns the NILVALUE `-` when there
/// is nothing to emit. Without this, enriched fields such as
/// `environment=production` are silently dropped on the rfc5424 wire format.
fn rfc5424_structured_data(ev: &Event) -> String {
    let mut params = String::new();
    for (key, val) in &ev.fields {
        // `structured_data` holds the original raw SD text from a parsed
        // rfc5424 input; re-wrapping it as a param would be malformed, skip it.
        if key == "structured_data" {
            continue;
        }
        let Some(value) = value_to_param(val) else {
            continue;
        };
        // PARAM-NAME must be a valid SD-NAME (no space, '=', ']', '"').
        if key.is_empty()
            || key
                .chars()
                .any(|c| c == ' ' || c == '=' || c == ']' || c == '"' || (c as u32) < 33)
        {
            continue;
        }
        params.push(' ');
        params.push_str(key);
        params.push_str("=\"");
        params.push_str(&sd_escape(&value));
        params.push('"');
    }
    if params.is_empty() {
        "-".to_string()
    } else {
        format!("[softnix@32473{params}]")
    }
}

/// Render a field value as an SD PARAM-VALUE string. Scalars become their
/// natural text; arrays/objects are JSON-encoded so nothing is lost.
fn value_to_param(val: &serde_json::Value) -> Option<String> {
    use serde_json::Value;
    match val {
        Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        other => Some(other.to_string()),
    }
}

/// Escape the three characters that are special inside an SD PARAM-VALUE per
/// RFC 5424 §6.3.3: '"', '\' and ']'.
fn sd_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '"' || c == '\\' || c == ']' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn pri_of(ev: &Event) -> u8 {
    let facility = ev.facility.unwrap_or(1); // user-level
    let severity = ev.severity.unwrap_or(6); // info
    facility.min(31) * 8 + severity.min(7)
}

#[allow(dead_code)]
fn severity_label(ev: &Event) -> &'static str {
    severity_name(ev.severity.unwrap_or(6))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5424_format() {
        let mut ev = Event::new("s", "syslog", "hello world");
        ev.hostname = Some("web1".into());
        ev.application = Some("nginx".into());
        ev.severity = Some(4);
        ev.facility = Some(16);
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert!(line.starts_with("<132>1 "));
        assert!(line.contains(" web1 nginx "));
        assert!(line.ends_with("hello world"));
        // No custom fields -> NILVALUE structured data.
        assert!(line.contains(" - - hello world"));
    }

    #[test]
    fn rfc5424_emits_enrichment_as_structured_data() {
        // PIPE-001 regression: enrichment fields must reach the rfc5424 wire,
        // not just json. They belong in the STRUCTURED-DATA element.
        let mut ev = Event::new("s", "syslog", "enrich test line");
        ev.fields.insert(
            "environment".into(),
            serde_json::Value::String("production".into()),
        );
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert!(
            line.contains("[softnix@32473 environment=\"production\"]"),
            "{line}"
        );
        // The SD slot must carry the element, not the NILVALUE, right before msg.
        assert!(
            line.ends_with("[softnix@32473 environment=\"production\"] enrich test line"),
            "{line}"
        );
    }

    #[test]
    fn rfc5424_escapes_and_skips_raw_structured_data() {
        let mut ev = Event::new("s", "syslog", "msg");
        ev.fields.insert(
            "note".into(),
            serde_json::Value::String(r#"a"b]c\d"#.into()),
        );
        // structured_data holds raw parsed SD text and must not be re-wrapped.
        ev.fields.insert(
            "structured_data".into(),
            serde_json::Value::String("[orig x=1]".into()),
        );
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert!(line.contains(r#"note="a\"b\]c\\d""#), "{line}");
        assert!(!line.contains("structured_data="), "{line}");
    }

    #[test]
    fn rfc3164_format() {
        let mut ev = Event::new("s", "syslog", "msg");
        ev.hostname = Some("h".into());
        ev.application = Some("app".into());
        ev.process_id = Some("42".into());
        let line = format_event(&ev, OutputFormat::Rfc3164);
        assert!(line.contains("app[42]: msg"), "{line}");
    }

    #[test]
    fn json_format_roundtrips() {
        let ev = Event::new("s", "file", "data");
        let line = format_event(&ev, OutputFormat::Json);
        let back: Event = serde_json::from_str(&line).unwrap();
        assert_eq!(back.message, "data");
    }
}
