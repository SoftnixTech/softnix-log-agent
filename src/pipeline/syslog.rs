use crate::config::SyslogFormat;
use crate::event::Event;
use chrono::{DateTime, Datelike, NaiveDateTime, TimeZone, Utc};
use serde_json::Value;

use super::parser::parse_json_into;

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
        let (sd, m) = tail.split_at(sd_end(tail));
        ev.fields
            .insert("structured_data".to_string(), Value::String(sd.to_string()));
        m.trim_start()
    } else {
        tail
    };
    ev.message = msg.strip_prefix('\u{feff}').unwrap_or(msg).to_string();
    true
}

/// Byte index just past the last SD-ELEMENT of `tail`, which starts with `[`.
/// The index always follows an ASCII `]` (or is `tail.len()`), so it is a
/// char boundary.
fn sd_end(tail: &str) -> usize {
    sd_end_by_grammar(tail).unwrap_or_else(|| sd_end_by_brackets(tail))
}

/// The RFC 5424 §6.3 grammar: `[` and `]` delimit SD-ELEMENTs only outside a
/// quoted PARAM-VALUE, and inside quotes `\` escapes the next byte (`\"`,
/// `\\`, `\]`). Returns `None` when the line ends before the SD does, which
/// means the SD is malformed (for example an unterminated quote).
fn sd_end_by_grammar(tail: &str) -> Option<usize> {
    let bytes = tail.as_bytes();
    let mut depth = 0usize;
    let mut in_quotes = false;
    let mut i = 0;
    while i < bytes.len() {
        match (in_quotes, bytes[i]) {
            (true, b'\\') => i += 1, // skip the escaped byte
            (true, b'"') => in_quotes = false,
            (false, b'"') => in_quotes = true,
            (false, b'[') => depth += 1,
            (false, b']') => {
                depth = depth.saturating_sub(1);
                if depth == 0 && bytes.get(i + 1) != Some(&b'[') {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The scan used before SYS-2: every `[` and `]` counts, quoted or not. Kept
/// for malformed SD only, so such a line parses exactly as it always has.
/// Returns `tail.len()` when it finds no end either.
fn sd_end_by_brackets(tail: &str) -> usize {
    let bytes = tail.as_bytes();
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => depth += 1,
            b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 && (i + 1 >= bytes.len() || bytes[i + 1] != b'[') {
                    return i + 1;
                }
            }
            b'\\' => i += 1, // skip escaped char
            _ => {}
        }
        i += 1;
    }
    tail.len()
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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Parse an RFC 5424 line whose STRUCTURED-DATA and MSG are `tail`.
    /// Returns the `structured_data` field and `message`.
    fn parse_sd(tail: &str) -> (Option<String>, String) {
        let mut ev = Event::new("net", "syslog", "");
        let line = format!("<165>1 2026-06-10T22:14:15Z h1 app 1 ID47 {tail}");
        assert!(parse_rfc5424(&mut ev, &line));
        let sd = ev
            .fields
            .get("structured_data")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        (sd, ev.message)
    }

    fn assert_sd(tail: &str, sd: &str, message: &str) {
        let (got_sd, got_message) = parse_sd(tail);
        assert_eq!(got_sd.as_deref(), Some(sd), "structured_data of {tail:?}");
        assert_eq!(got_message, message, "message of {tail:?}");
    }

    // SYS-2: `[` inside a quoted PARAM-VALUE is valid (RFC 5424 §6.3.3) and
    // must not be counted as an SD-ELEMENT bracket.
    #[test]
    fn sd_value_with_open_bracket_keeps_message() {
        assert_sd(
            r#"[ex@32473 k="open [ only"] hello"#,
            r#"[ex@32473 k="open [ only"]"#,
            "hello",
        );
    }

    #[test]
    fn sd_value_with_escaped_close_and_open_bracket() {
        assert_sd(
            r#"[ex@32473 rule="Contoso [TCP 443\]"] hello"#,
            r#"[ex@32473 rule="Contoso [TCP 443\]"]"#,
            "hello",
        );
    }

    #[test]
    fn sd_value_bracket_in_first_of_two_elements() {
        assert_sd(
            r#"[a@32473 k="x [y\]"][b@32473 z="1"] hello"#,
            r#"[a@32473 k="x [y\]"][b@32473 z="1"]"#,
            "hello",
        );
    }

    #[test]
    fn sd_escaped_quote_before_bracket_in_value() {
        assert_sd(
            r#"[ex@32473 k="a\"]b"] hello"#,
            r#"[ex@32473 k="a\"]b"]"#,
            "hello",
        );
    }

    #[test]
    fn sd_plain_and_escaped_close_unchanged() {
        assert_sd(
            r#"[ex@32473 k="plain"] hello"#,
            r#"[ex@32473 k="plain"]"#,
            "hello",
        );
        assert_sd(
            r#"[ex@32473 k="a\]b"] hello"#,
            r#"[ex@32473 k="a\]b"]"#,
            "hello",
        );
    }

    #[test]
    fn sd_escaped_backslash_before_closing_quote() {
        assert_sd(
            r#"[ex@32473 k="a\\"] hello"#,
            r#"[ex@32473 k="a\\"]"#,
            "hello",
        );
    }

    /// Malformed SD (an unterminated quote): parsed as before SYS-2.
    #[test]
    fn sd_unterminated_quote_falls_back_to_old_scan() {
        assert_sd(
            r#"[ex@32473 k="never closed] hello"#,
            r#"[ex@32473 k="never closed]"#,
            "hello",
        );
    }

    /// Malformed SD whose stray quote pairs up with a quote in MSG: the
    /// grammar scan ends outside quotes without finding an end, and the old
    /// scan decides.
    #[test]
    fn sd_stray_quotes_fall_back_to_old_scan() {
        assert_sd(
            r#"[ex@32473 k="5" screen"] it's ""#,
            r#"[ex@32473 k="5" screen"]"#,
            r#"it's ""#,
        );
    }

    #[test]
    fn sd_without_message_unchanged() {
        assert_sd(r#"[ex@32473 k="v"]"#, r#"[ex@32473 k="v"]"#, "");
    }

    #[test]
    fn sd_nilvalue_unchanged() {
        assert_eq!(parse_sd("- hello"), (None, "hello".to_string()));
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
}
