use crate::config::OutputFormat;
use crate::event::{severity_name, Event};
use chrono::SecondsFormat;
use std::borrow::Cow;

/// Render an event in the configured wire format.
pub fn format_event(ev: &Event, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string(ev).unwrap_or_else(|_| ev.message.clone()),
        OutputFormat::Raw => ev.message.clone(),
        OutputFormat::Rfc5424 => {
            let pri = pri_of(ev);
            let ts = ev.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true);
            // Originals of header values that had to be sanitized; re-emitted
            // as SD-PARAMs so nothing is lost. Empty (no allocation) unless
            // something changed.
            let mut preserved = Vec::new();
            let host = rfc5424_header_field(
                ev.hostname.as_deref(),
                HOSTNAME_MAX,
                "-",
                "hostname",
                &mut preserved,
            );
            let app = rfc5424_header_field(
                ev.application.as_deref(),
                APP_NAME_MAX,
                "softnix-log-agent",
                "application",
                &mut preserved,
            );
            let pid = rfc5424_header_field(
                ev.process_id.as_deref(),
                PROCID_MAX,
                "-",
                "process_id",
                &mut preserved,
            );
            let sd = rfc5424_structured_data(ev, &preserved);
            format!("<{pri}>1 {ts} {host} {app} {pid} - {sd} {}", ev.message)
        }
        OutputFormat::Rfc3164 => {
            let pri = pri_of(ev);
            let ts = ev.timestamp.format("%b %e %H:%M:%S");
            let host = ev
                .hostname
                .as_deref()
                .map_or(Cow::Borrowed("-"), |h| header_token(h, HOSTNAME_MAX));
            // RFC 3164 has no structured data: the original value cannot be
            // kept on this wire (documented; use rfc5424 or json for that).
            // TAG length is deliberately not capped at RFC 3164's 32, which
            // would truncate common names like Microsoft-Windows-Security-Auditing.
            let tag = ev
                .application
                .as_deref()
                .map_or(Cow::Borrowed("softnix"), |a| {
                    sanitize_token(a, usize::MAX, RFC3164_TAG_DELIMS)
                });
            match ev.process_id.as_deref() {
                Some(pid) => {
                    let pid = sanitize_token(pid, PROCID_MAX, RFC3164_TAG_DELIMS);
                    format!("<{pri}>{ts} {host} {tag}[{pid}]: {}", ev.message)
                }
                None => format!("<{pri}>{ts} {host} {tag}: {}", ev.message),
            }
        }
    }
}

/// Build the RFC 5424 STRUCTURED-DATA element from the event's custom fields
/// (enrichment, parsed attributes, etc.). Returns the NILVALUE `-` when there
/// is nothing to emit. Without this, enriched fields such as
/// `environment=production` are silently dropped on the rfc5424 wire format.
///
/// `preserved` holds `(param, original)` pairs for header values that
/// `header_token` had to change; they are emitted first so the exact value
/// stays recoverable from the line.
fn rfc5424_structured_data(ev: &Event, preserved: &[(&str, &str)]) -> String {
    let mut params = String::new();
    for (name, original) in preserved {
        // A field of the same name that would itself be emitted wins, so a
        // PARAM-NAME never appears twice.
        if ev.fields.get(*name).and_then(value_to_param).is_some() {
            continue;
        }
        push_sd_param(&mut params, name, original);
    }
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
        push_sd_param(&mut params, key, &value);
    }
    if params.is_empty() {
        "-".to_string()
    } else {
        format!("[softnix@32473{params}]")
    }
}

fn push_sd_param(params: &mut String, name: &str, value: &str) {
    params.push(' ');
    params.push_str(name);
    params.push_str("=\"");
    params.push_str(&sd_escape(value));
    params.push('"');
}

/// Sanitize one RFC 5424 header field. `None` renders as `default`; a value
/// that had to change (and was not empty, so there is something to recover)
/// is recorded in `preserved` under the SD-PARAM name `param`.
fn rfc5424_header_field<'a>(
    value: Option<&'a str>,
    max: usize,
    default: &'static str,
    param: &'static str,
    preserved: &mut Vec<(&'static str, &'a str)>,
) -> Cow<'a, str> {
    let Some(raw) = value else {
        return Cow::Borrowed(default);
    };
    let token = header_token(raw, max);
    if token != raw && !raw.is_empty() {
        preserved.push((param, raw));
    }
    token
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

/// RFC 5424 §6 header field limits, in octets.
const HOSTNAME_MAX: usize = 255;
const APP_NAME_MAX: usize = 48;
const PROCID_MAX: usize = 128;

/// Characters that delimit PID and CONTENT in an RFC 3164 `TAG[PID]:`, so
/// they must not appear inside either.
const RFC3164_TAG_DELIMS: &[char] = &['[', ']', ':'];

/// Make `raw` a valid RFC 5424 header token (PRINTUSASCII = %d33-126, at most
/// `max` octets) or the NILVALUE "-". Returns `Cow::Borrowed(raw)` when `raw`
/// is already valid, so valid values reach the wire byte-identical.
///
/// Windows provider names such as "Service Control Manager" contain spaces;
/// interpolated verbatim they shift every following header field (see
/// docs/superpowers/specs/2026-11-10-syslog-header-sanitization.md).
fn header_token(raw: &str, max: usize) -> Cow<'_, str> {
    sanitize_token(raw, max, &[])
}

/// `header_token`, plus `extra` characters that must also be replaced (the
/// RFC 3164 TAG uses '[', ']' and ':' as PID / CONTENT delimiters).
///
/// Order: trim -> replace each run of disallowed chars with one '_' -> cap at
/// `max` octets -> empty or only '_' left => "-". An input that is already
/// valid is returned untouched, even if it is all '_'.
fn sanitize_token<'a>(raw: &'a str, max: usize, extra: &[char]) -> Cow<'a, str> {
    let allowed = |c: char| ('\x21'..='\x7e').contains(&c) && !extra.contains(&c);
    if !raw.is_empty() && raw.len() <= max && raw.chars().all(allowed) {
        return Cow::Borrowed(raw);
    }
    let trimmed = raw.trim();
    let mut out = String::with_capacity(trimmed.len().min(max));
    let mut last_replaced = false;
    for c in trimmed.chars() {
        if out.len() >= max {
            break;
        }
        if allowed(c) {
            out.push(c);
            last_replaced = false;
        } else if !last_replaced {
            out.push('_');
            last_replaced = true;
        }
    }
    // Every pushed char is ASCII, so `out.len()` counts characters too.
    debug_assert!(out.len() <= max && out.is_ascii());
    if out.bytes().all(|b| b == b'_') {
        // Also covers the empty case: nothing meaningful survived.
        return Cow::Borrowed("-");
    }
    Cow::Owned(out)
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

    #[test]
    fn header_token_table() {
        // Spec "Expected APP-NAME values" table, row for row.
        let a48 = "A".repeat(48);
        let b48 = "B".repeat(48);
        let b49 = "B".repeat(49);
        let cases: &[(&str, &str)] = &[
            (
                "Microsoft-Windows-Security-Auditing",
                "Microsoft-Windows-Security-Auditing",
            ),
            ("Service Control Manager", "Service_Control_Manager"),
            ("Application Error", "Application_Error"),
            (
                "Microsoft-Windows-User Profiles Service",
                "Microsoft-Windows-User_Profiles_Service",
            ),
            (
                "Microsoft-Windows-Windows Firewall With Advanced Security",
                "Microsoft-Windows-Windows_Firewall_With_Advanced",
            ),
            (" LeadingSpace", "LeadingSpace"),
            ("TrailingSpace ", "TrailingSpace"),
            ("Double  Space", "Double_Space"),
            ("Tab\tSeparated", "Tab_Separated"),
            ("ระบบ บันทึก", "-"),
            (&a48, &a48),
            (&b49, &b48),
            ("", "-"),
            ("-", "-"),
            ("Odd\"Name]x", "Odd\"Name]x"),
        ];
        for (input, want) in cases {
            assert_eq!(header_token(input, APP_NAME_MAX), *want, "input {input:?}");
        }
    }

    #[test]
    fn header_token_borrows_valid_input_unchanged() {
        // Goal 3: valid values come back as the same borrowed slice, which is
        // what lets format_event detect "unchanged" and stay byte-identical.
        // Plan R-1: a value made only of '_' is valid and stays as-is.
        for s in [
            "nginx",
            "Microsoft-Windows-Kernel-General",
            "-",
            "___",
            "Odd\"Name]x",
        ] {
            assert!(
                matches!(header_token(s, APP_NAME_MAX), Cow::Borrowed(b) if b == s),
                "{s:?}"
            );
        }
    }

    #[test]
    fn sanitize_token_extra_chars_and_caps() {
        let delims = ['[', ']', ':'];
        assert_eq!(
            sanitize_token("Foo:Bar[1]", usize::MAX, &delims),
            "Foo_Bar_1_"
        );
        assert_eq!(sanitize_token("ok", usize::MAX, &delims), "ok");
        // A run of replaced chars collapses; pre-existing '_' are kept.
        assert_eq!(header_token("a \t\n b", APP_NAME_MAX), "a_b");
        assert_eq!(header_token("a_ b", APP_NAME_MAX), "a__b");
        // A changed value that sanitizes to only '_' becomes NILVALUE.
        assert_eq!(header_token("_ _", APP_NAME_MAX), "-");
        // Non-ASCII runs collapse too; valid PRINTUSASCII ('"', ']') is kept.
        assert_eq!(header_token("ระบบ \"x\" ]", APP_NAME_MAX), "_\"x\"_]");
        // Truncation is by octets; the result is ASCII, so never mid-char.
        assert_eq!(header_token(&"x".repeat(300), HOSTNAME_MAX).len(), 255);
        assert_eq!(header_token(&"7".repeat(200), PROCID_MAX).len(), 128);
    }

    fn fixed_event(app: Option<&str>, msg: &str) -> Event {
        let mut ev = Event::new("s", "eventlog", msg);
        ev.timestamp = chrono::DateTime::parse_from_rfc3339("2026-11-10T08:58:07.110Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        ev.hostname = Some("WIN-SRV01".into());
        ev.application = app.map(str::to_string);
        ev.process_id = Some("4321".into());
        ev.severity = Some(6);
        ev.fields
            .insert("channel".into(), serde_json::Value::from("System"));
        ev.fields
            .insert("event_id".into(), serde_json::Value::from(7036));
        ev
    }

    #[test]
    fn rfc5424_valid_values_are_byte_identical() {
        // Goal 3. These strings are what the pre-fix formatter produces; they
        // must not change. ev.fields is a BTreeMap, so params are key-sorted.
        for app in [
            "Microsoft-Windows-Security-Auditing",
            "Microsoft-Windows-Kernel-General",
            "Microsoft-Windows-Sysmon",
            "EventLog",
            "VSS",
        ] {
            let line = format_event(&fixed_event(Some(app), "msg"), OutputFormat::Rfc5424);
            assert_eq!(
                line,
                format!(
                    "<14>1 2026-11-10T08:58:07.110Z WIN-SRV01 {app} 4321 - \
                     [softnix@32473 channel=\"System\" event_id=\"7036\"] msg"
                )
            );
        }
        let line = format_event(&fixed_event(None, "msg"), OutputFormat::Rfc5424);
        assert!(
            line.contains(" WIN-SRV01 softnix-log-agent 4321 - ["),
            "{line}"
        );
    }

    #[test]
    fn rfc5424_sanitizes_provider_with_spaces() {
        let ev = fixed_event(
            Some("Service Control Manager"),
            "The service entered the running state.",
        );
        assert_eq!(
            format_event(&ev, OutputFormat::Rfc5424),
            "<14>1 2026-11-10T08:58:07.110Z WIN-SRV01 Service_Control_Manager 4321 - \
             [softnix@32473 application=\"Service Control Manager\" channel=\"System\" \
             event_id=\"7036\"] The service entered the running state."
        );
    }

    #[test]
    fn rfc5424_preserved_param_creates_sd_element() {
        // No custom fields: the SD would have been "-"; the preserved original
        // must still get an element.
        let mut ev = Event::new("s", "eventlog", "msg");
        ev.application = Some("Application Error".into());
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert!(
            line.ends_with(
                " - Application_Error - - [softnix@32473 application=\"Application Error\"] msg"
            ),
            "{line}"
        );
    }

    #[test]
    fn rfc5424_preserved_param_is_escaped_and_utf8() {
        let mut ev = fixed_event(Some("ระบบ \"x\" ]"), "msg");
        ev.fields.clear();
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert!(line.contains(" WIN-SRV01 _\"x\"_] 4321 - "), "{line}");
        assert!(
            line.contains(r#"[softnix@32473 application="ระบบ \"x\" \]"] msg"#),
            "{line}"
        );
    }

    #[test]
    fn rfc5424_preserved_param_yields_to_existing_field() {
        // An emitted field with the same name wins; exactly one param.
        let mut ev = fixed_event(Some("Service Control Manager"), "msg");
        ev.fields
            .insert("application".into(), serde_json::Value::from("from-field"));
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert_eq!(line.matches("application=").count(), 1, "{line}");
        assert!(line.contains("application=\"from-field\""), "{line}");
        // ...but a null field (which emits nothing) does not suppress it.
        ev.fields
            .insert("application".into(), serde_json::Value::Null);
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert_eq!(line.matches("application=").count(), 1, "{line}");
        assert!(
            line.contains("application=\"Service Control Manager\""),
            "{line}"
        );
    }

    #[test]
    fn rfc5424_sanitizes_hostname_and_procid() {
        let mut ev = fixed_event(Some("VSS"), "msg");
        ev.hostname = Some("my host".into());
        ev.process_id = Some("12 34".into());
        let line = format_event(&ev, OutputFormat::Rfc5424);
        assert!(
            line.contains(
                " my_host VSS 12_34 - [softnix@32473 hostname=\"my host\" \
                 process_id=\"12 34\" channel="
            ),
            "{line}"
        );
    }

    #[test]
    fn rfc5424_empty_application_is_nilvalue_without_param() {
        // Some("") -> "-" and nothing to preserve.
        let line = format_event(&fixed_event(Some(""), "msg"), OutputFormat::Rfc5424);
        assert!(
            line.contains(" WIN-SRV01 - 4321 - [softnix@32473 channel="),
            "{line}"
        );
        assert!(!line.contains("application="), "{line}");
    }

    /// Byte length of a well-formed RFC 5424 STRUCTURED-DATA at the start of
    /// `s` (NILVALUE or 1*SD-ELEMENT), or None if malformed.
    fn sd_len(s: &str) -> Option<usize> {
        if s.starts_with('-') {
            return Some(1);
        }
        let b = s.as_bytes();
        let sd_name = |i: &mut usize| -> bool {
            let start = *i;
            while *i < b.len()
                && (0x21..=0x7e).contains(&b[*i])
                && !matches!(b[*i], b'=' | b' ' | b']' | b'"')
            {
                *i += 1;
            }
            (1..=32).contains(&(*i - start))
        };
        if b.first() != Some(&b'[') {
            return None;
        }
        let mut i = 0;
        while b.get(i) == Some(&b'[') {
            i += 1;
            if !sd_name(&mut i) {
                return None;
            }
            while b.get(i) == Some(&b' ') {
                i += 1;
                if !sd_name(&mut i) || b.get(i) != Some(&b'=') || b.get(i + 1) != Some(&b'"') {
                    return None;
                }
                i += 2;
                loop {
                    match *b.get(i)? {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b']' => return None, // must be escaped inside PARAM-VALUE
                        _ => i += 1,
                    }
                }
            }
            if b.get(i) != Some(&b']') {
                return None;
            }
            i += 1;
        }
        Some(i)
    }

    /// Strict RFC 5424 §6 header check; returns (HOSTNAME, APP-NAME, PROCID, MSG).
    fn strict_rfc5424(line: &str) -> (String, String, String, String) {
        let rest = line.strip_prefix('<').unwrap_or_else(|| panic!("{line:?}"));
        let (pri, rest) = rest.split_once(">1 ").unwrap_or_else(|| panic!("{line:?}"));
        assert!(
            !pri.is_empty() && pri.len() <= 3 && pri.bytes().all(|c| c.is_ascii_digit()),
            "{line:?}"
        );
        let mut parts = rest.splitn(6, ' ');
        let mut next = || {
            parts
                .next()
                .unwrap_or_else(|| panic!("short header: {line:?}"))
        };
        let (_ts, host, app, procid, msgid, tail) =
            (next(), next(), next(), next(), next(), next());
        for (tok, max) in [(host, 255), (app, 48), (procid, 128), (msgid, 32)] {
            assert!(
                tok == "-"
                    || (!tok.is_empty()
                        && tok.len() <= max
                        && tok.bytes().all(|c| (0x21..=0x7e).contains(&c))),
                "bad header token {tok:?} in {line:?}"
            );
        }
        let n = sd_len(tail).unwrap_or_else(|| panic!("malformed SD in {line:?}"));
        let msg = tail[n..]
            .strip_prefix(' ')
            .unwrap_or_else(|| panic!("no SP before MSG: {line:?}"));
        (host.into(), app.into(), procid.into(), msg.into())
    }

    #[test]
    fn rfc5424_header_is_valid_for_any_input() {
        use rand::{rngs::StdRng, Rng, SeedableRng};
        const ALPHABET: &[char] = &[
            'a', 'Z', '0', '-', '_', '.', '"', ']', '[', '\\', '=', ':', ' ', '\t', '\n', '\r',
            '\u{0}', '\u{7f}', '\u{a0}', '\u{3000}', 'ร', 'ะ', 'บ', '中', '文', 'é', '🙂',
        ];
        let random_string = |rng: &mut StdRng| -> String {
            let len = rng.gen_range(0..=80);
            (0..len)
                .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())])
                .collect()
        };
        let mut rng = StdRng::seed_from_u64(0x5EED_5424);
        for _ in 0..2000 {
            let app = random_string(&mut rng);
            let host = random_string(&mut rng);
            let pid = random_string(&mut rng);
            let mut ev = fixed_event(Some(&app), "msg");
            ev.hostname = Some(host.clone());
            ev.process_id = Some(pid.clone());
            let line = format_event(&ev, OutputFormat::Rfc5424);
            let (h, a, p, msg) = strict_rfc5424(&line);
            assert_eq!(a, header_token(&app, APP_NAME_MAX), "{line:?}");
            assert_eq!(h, header_token(&host, HOSTNAME_MAX), "{line:?}");
            assert_eq!(p, header_token(&pid, PROCID_MAX), "{line:?}");
            assert_eq!(msg, "msg", "{line:?}");
        }
    }

    #[test]
    fn rfc5424_round_trips_through_our_parser() {
        use crate::config::SyslogFormat;
        for app in [
            "Service Control Manager",
            "Application Error",
            "Microsoft-Windows-Windows Firewall With Advanced Security",
            "Tab\tSeparated",
            "ระบบ บันทึก",
            "Microsoft-Windows-Security-Auditing",
        ] {
            let line = format_event(
                &fixed_event(Some(app), "the message"),
                OutputFormat::Rfc5424,
            );
            let mut back = Event::new("rx", "syslog", "");
            crate::pipeline::parse_syslog_into(&mut back, &line, SyslogFormat::Rfc5424);
            let want = header_token(app, APP_NAME_MAX);
            let want = (want != "-").then(|| want.into_owned());
            assert_eq!(back.application, want, "{line:?}");
            assert_eq!(back.process_id.as_deref(), Some("4321"), "{line:?}");
            assert_eq!(back.hostname.as_deref(), Some("WIN-SRV01"), "{line:?}");
            assert_eq!(back.message, "the message", "{line:?}");
        }
    }

    #[test]
    fn rfc3164_sanitizes_tag_pid_and_host() {
        let mut ev = fixed_event(Some("Service Control Manager"), "msg");
        let line = format_event(&ev, OutputFormat::Rfc3164);
        assert!(
            line.ends_with(" WIN-SRV01 Service_Control_Manager[4321]: msg"),
            "{line}"
        );

        ev.application = Some("Foo:Bar[x]".into()); // delimiters inside TAG
        ev.process_id = Some("12]34".into());
        ev.hostname = Some("my host".into());
        let line = format_event(&ev, OutputFormat::Rfc3164);
        assert!(line.ends_with(" my_host Foo_Bar_x_[12_34]: msg"), "{line}");

        // TAG is deliberately not capped at 32 (would truncate common names).
        ev.application = Some("Microsoft-Windows-Security-Auditing".into());
        ev.process_id = None;
        let line = format_event(&ev, OutputFormat::Rfc3164);
        assert!(
            line.ends_with(" Microsoft-Windows-Security-Auditing: msg"),
            "{line}"
        );
    }

    #[test]
    fn rfc3164_round_trips_through_our_parser() {
        use crate::config::SyslogFormat;
        let ev = fixed_event(Some("Service Control Manager"), "the message");
        let line = format_event(&ev, OutputFormat::Rfc3164);
        let mut back = Event::new("rx", "syslog", "");
        crate::pipeline::parse_syslog_into(&mut back, &line, SyslogFormat::Rfc3164);
        assert_eq!(back.hostname.as_deref(), Some("WIN-SRV01"), "{line:?}");
        assert_eq!(
            back.application.as_deref(),
            Some("Service_Control_Manager"),
            "{line:?}"
        );
        assert_eq!(back.process_id.as_deref(), Some("4321"), "{line:?}");
        assert_eq!(back.message, "the message", "{line:?}");
    }

    #[test]
    fn rfc3164_valid_values_are_byte_identical() {
        // Same pinning idea as the RFC 5424 test: valid names do not change.
        let line = format_event(&fixed_event(Some("EventLog"), "msg"), OutputFormat::Rfc3164);
        assert_eq!(line, "<14>Nov 10 08:58:07 WIN-SRV01 EventLog[4321]: msg");
    }
}
