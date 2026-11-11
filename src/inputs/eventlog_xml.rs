//! Parser for the XML that `EvtRender` produces for a Windows Event Log
//! record (`<Event><System>…</System><EventData>…</EventData></Event>`).
//!
//! Split out of `eventlog.rs` because it is pure string processing with no
//! Windows API: compiled on Windows (used by `eventlog::build_event`) and in
//! test builds on every platform, so its tests run locally and in every CI
//! job, not only `test-windows`. Release builds on other platforms do not
//! include it (see `src/inputs/mod.rs`).

/// Fields pulled out of one event's XML.
///
/// On non-Windows test builds only the tests read these fields, so any field
/// the tests don't happen to read would trip `dead_code` under `-D warnings`.
#[derive(Default)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) struct ParsedEvent {
    pub(super) provider: String,
    pub(super) event_id: Option<u64>,
    pub(super) level: Option<u8>,
    pub(super) time_created: Option<String>,
    pub(super) computer: Option<String>,
    pub(super) record_id: Option<String>,
    pub(super) process_id: Option<String>,
    pub(super) keywords: Option<String>,
    pub(super) data: Vec<(String, String)>,
}

/// Minimal parser for the fixed Event Log XML schema. Pulls System metadata
/// and EventData `Data` items without assuming attribute ordering.
pub(super) fn parse_event_xml(xml: &str) -> ParsedEvent {
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
                // quick-xml 0.41 split BytesText::unescape() (decode + XML
                // entity resolution in one call) into two steps: decode()
                // (bytes -> str) then escape::unescape() (&amp;/&lt;/... ->
                // their characters) - same default entity resolver either
                // way, just no longer bundled onto BytesText itself. Both
                // steps happen inside this match arm (not chained through
                // .and_then) so the unescaped Cow is converted to an owned
                // String before the decoded &str it borrows from goes out
                // of scope.
                let text = match t.decode() {
                    Ok(decoded) => quick_xml::escape::unescape(&decoded)
                        .map(|c| c.into_owned())
                        .unwrap_or_default(),
                    Err(_) => String::new(),
                };
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
}
