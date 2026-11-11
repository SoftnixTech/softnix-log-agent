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
///
/// quick-xml 0.41 reports every entity / character reference (`&amp;`,
/// `&#13;`) as its own `Event::GeneralRef` and splits the text around it
/// into several `Event::Text` events. So an element's value is accumulated
/// across `Text` and `GeneralRef` and assigned once, on its `End` (SYS-9).
pub(super) fn parse_event_xml(xml: &str) -> ParsedEvent {
    use quick_xml::events::Event as Xml;
    use quick_xml::reader::Reader;
    use quick_xml::XmlVersion;

    let mut reader = Reader::from_str(xml);
    let mut p = ParsedEvent::default();
    let mut cur: Vec<u8> = Vec::new(); // current text-bearing element name
    let mut text = String::new(); // accumulated value of `cur`
    let mut cur_data_name = String::new();
    let mut in_event_data = false;

    // Attribute values with references resolved (SYS-8). `normalized_value`,
    // not the deprecated `unescape_value` (which fails `-D warnings`). On a
    // malformed reference fall back to the raw value, so a bad attribute
    // never turns into `None`.
    let attr = |e: &quick_xml::events::BytesStart, name: &[u8]| -> Option<String> {
        e.attributes().flatten().find_map(|a| {
            if a.key.as_ref() == name {
                Some(match a.normalized_value(XmlVersion::Implicit1_0) {
                    Ok(v) => v.into_owned(),
                    Err(_) => String::from_utf8_lossy(&a.value).into_owned(),
                })
            } else {
                None
            }
        })
    };

    loop {
        let event = reader.read_event();
        // A self-closing element (`Empty`) has no text and no `End`, so only
        // a real `Start` becomes the current text-bearing element.
        let opens_element = matches!(event, Ok(Xml::Start(_)));
        match event {
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
                cur = if opens_element { name } else { Vec::new() };
                text.clear();
            }
            Ok(Xml::Text(t)) => {
                // Kept verbatim, whitespace included: whitespace between two
                // references is part of the value. Whitespace-only values are
                // dropped on `End`, as before.
                if let Ok(s) = t.decode() {
                    text.push_str(&s);
                }
            }
            Ok(Xml::GeneralRef(r)) => match r.resolve_char_ref() {
                Ok(Some(c)) => text.push(c),
                Ok(None) => {
                    if let Ok(name) = r.decode() {
                        match quick_xml::escape::resolve_predefined_entity(&name) {
                            Some(v) => text.push_str(v),
                            // Unknown entity (EvtRender emits no DTD, so not
                            // expected): keep it literally, never drop data.
                            None => push_literal_ref(&mut text, &name),
                        }
                    }
                }
                // Invalid character reference such as `&#0;`: keep literally.
                Err(_) => {
                    if let Ok(name) = r.decode() {
                        push_literal_ref(&mut text, &name);
                    }
                }
            },
            Ok(Xml::End(e)) => {
                if !cur.is_empty() && e.name().as_ref() == cur.as_slice() {
                    let value = std::mem::take(&mut text);
                    if !value.trim().is_empty() {
                        if in_event_data && cur.as_slice() == b"Data" {
                            p.data.push((std::mem::take(&mut cur_data_name), value));
                        } else {
                            match cur.as_slice() {
                                b"EventID" => p.event_id = value.trim().parse().ok(),
                                b"Level" => p.level = value.trim().parse().ok(),
                                b"Computer" => p.computer = Some(value),
                                b"EventRecordID" => p.record_id = Some(value),
                                b"Keywords" => p.keywords = Some(value),
                                _ => {}
                            }
                        }
                    }
                }
                if e.name().as_ref() == b"EventData" {
                    in_event_data = false;
                }
                cur.clear();
                text.clear();
            }
            Ok(Xml::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    p
}

/// Re-emit a reference that could not be resolved as `&name;`.
fn push_literal_ref(text: &mut String, name: &str) {
    text.push('&');
    text.push_str(name);
    text.push(';');
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
        <Keywords>0x8020000000000000</Keywords>
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
        assert_eq!(p.keywords.as_deref(), Some("0x8020000000000000"));
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

    /// Minimal event around the given `<EventData>` children.
    fn with_event_data(data: &str) -> String {
        format!(
            "<Event><System><Provider Name='P'/><EventID>1</EventID></System>\
             <EventData>{data}</EventData></Event>"
        )
    }

    fn data_of(data: &str) -> Vec<(String, String)> {
        parse_event_xml(&with_event_data(data)).data
    }

    fn pair(k: &str, v: &str) -> (String, String) {
        (k.to_string(), v.to_string())
    }

    // --- SYS-9: element text must survive entity / character references ---
    //
    // quick-xml 0.41 reports every `&…;` as its own `Event::GeneralRef` and
    // splits the surrounding text into several `Event::Text` events; each
    // test below failed on the parser that handled only `Text`.

    #[test]
    fn data_value_with_entities_is_one_item() {
        assert_eq!(
            data_of(
                "<Data Name='CommandLine'>cmd.exe /c dir &amp;&amp; echo \
                 &quot;done&quot; &gt; out.txt</Data>"
            ),
            vec![pair(
                "CommandLine",
                "cmd.exe /c dir && echo \"done\" > out.txt"
            )]
        );
        assert_eq!(
            data_of("<Data Name='Who'>Tom &amp; Jerry</Data>"),
            vec![pair("Who", "Tom & Jerry")]
        );
    }

    #[test]
    fn data_value_keeps_whitespace_between_refs() {
        assert_eq!(
            data_of("<Data Name='X'>a&amp; &amp;b</Data>"),
            vec![pair("X", "a& &b")]
        );
    }

    #[test]
    fn data_value_that_is_only_an_entity_is_kept() {
        assert_eq!(data_of("<Data Name='X'>&lt;</Data>"), vec![pair("X", "<")]);
    }

    #[test]
    fn numeric_char_refs_are_resolved() {
        assert_eq!(
            data_of("<Data Name='X'>line1&#13;&#10;line2 &#x41;&#66;</Data>"),
            vec![pair("X", "line1\r\nline2 AB")]
        );
    }

    #[test]
    fn unnamed_data_with_entity_stays_one_item() {
        assert_eq!(
            data_of("<Data>first</Data><Data>second &amp; third</Data>"),
            vec![pair("", "first"), pair("", "second & third")]
        );
    }

    #[test]
    fn unknown_entity_is_kept_literally() {
        // EvtRender emits no DTD, so this cannot occur in practice; the rule
        // is defensive: never drop data silently.
        assert_eq!(
            data_of("<Data Name='X'>a &foo; b</Data>"),
            vec![pair("X", "a &foo; b")]
        );
        // Invalid character reference (`&#0;` is not a legal XML char).
        assert_eq!(
            data_of("<Data Name='Z'>a&#0;b</Data>"),
            vec![pair("Z", "a&#0;b")]
        );
    }

    #[test]
    fn system_text_fields_resolve_entities() {
        let p = parse_event_xml(
            "<Event><System><Computer>a&amp;b</Computer>\
             <Keywords>&#x30;x10</Keywords></System></Event>",
        );
        assert_eq!(p.computer.as_deref(), Some("a&b"));
        assert_eq!(p.keywords.as_deref(), Some("0x10"));
    }

    // --- SYS-8: attribute values must be unescaped ---

    #[test]
    fn provider_name_is_unescaped() {
        for (raw, want) in [
            ("Backup &amp; Restore", "Backup & Restore"),
            ("Contoso &quot;Agent&quot;", "Contoso \"Agent\""),
            ("O&apos;Brien Tools", "O'Brien Tools"),
            ("Tab&#9;Name", "Tab\tName"),
        ] {
            let p = parse_event_xml(&format!(
                "<Event><System><Provider Name='{raw}'/></System></Event>"
            ));
            assert_eq!(p.provider, want, "Provider Name='{raw}'");
        }
    }

    #[test]
    fn data_name_attribute_is_unescaped() {
        assert_eq!(
            data_of("<Data Name='A&amp;B'>v</Data>"),
            vec![pair("A&B", "v")]
        );
    }

    #[test]
    fn malformed_attribute_reference_keeps_raw_value() {
        // `normalized_value` returns Err for these; the fallback keeps the
        // raw attribute instead of dropping it (spec Goal 4). Same result
        // as before the fix.
        for raw in ["a&foo;b", "a&#0;b", "a&b"] {
            let p = parse_event_xml(&format!(
                "<Event><System><Provider Name='{raw}'/></System></Event>"
            ));
            assert_eq!(p.provider, raw, "Provider Name='{raw}'");
        }
    }

    // --- Guards: XML without references must parse exactly as before ---

    #[test]
    fn empty_and_whitespace_only_data_are_skipped() {
        assert_eq!(
            data_of(
                "<Data Name='E'></Data><Data Name='S'/><Data Name='W'>   </Data>\
                 <Data Name='N'>v</Data>"
            ),
            vec![pair("N", "v")]
        );
    }

    #[test]
    fn data_value_whitespace_is_preserved() {
        assert_eq!(
            data_of("<Data Name='X'>  alice </Data>"),
            vec![pair("X", "  alice ")]
        );
    }
}
