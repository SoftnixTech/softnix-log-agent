use super::format::format_event;
use crate::config::{Framing, OutputConfig, OutputFormat};
use crate::event::Event;
use anyhow::Result;
use std::borrow::Cow;
use tokio::io::AsyncWriteExt;

pub struct StdoutSink {
    id: String,
    format: OutputFormat,
    framing: Framing,
}

impl StdoutSink {
    pub fn new(cfg: &OutputConfig) -> Self {
        StdoutSink {
            id: cfg.id.clone(),
            format: cfg.format,
            framing: cfg.framing,
        }
    }
}

#[async_trait::async_trait]
impl super::Sink for StdoutSink {
    async fn send_batch(&mut self, events: &[Event]) -> Result<usize> {
        let payload = frame_batch(events, self.format, self.framing);
        let mut out = tokio::io::stdout();
        out.write_all(&payload).await?;
        out.flush().await?;
        Ok(events.len())
    }

    fn id(&self) -> &str {
        &self.id
    }
}

/// Build the wire payload for a batch under the configured format/framing.
/// Shared by `StdoutSink` and `SyslogSink`'s TCP/TLS paths — UDP frames
/// per-datagram instead, see `SyslogSink::send_batch`.
pub(super) fn frame_batch(events: &[Event], format: OutputFormat, framing: Framing) -> Vec<u8> {
    let mut payload = Vec::with_capacity(events.len() * 256);
    for ev in events {
        let line = format_event(ev, format);
        match framing {
            Framing::Newline => {
                payload.extend_from_slice(single_line(&line).as_bytes());
                payload.push(b'\n');
            }
            Framing::OctetCounting => {
                payload.extend_from_slice(format!("{} ", line.len()).as_bytes());
                payload.extend_from_slice(line.as_bytes());
            }
        }
    }
    payload
}

/// Newline framing (RFC 6587 §3.4.2) ends a frame at LF, so it cannot carry a
/// line break inside an event: a multi-line message (a Windows event, or an SD
/// value with CR/LF) would arrive as several header-less frames (SYS-1). Write
/// each `\r\n`, lone `\r` and lone `\n` as one space instead. Lines without
/// CR/LF (and every `json` line, where serde already escapes them) are
/// returned unchanged, without allocating.
fn single_line(line: &str) -> Cow<'_, str> {
    if !line.contains(['\r', '\n']) {
        return Cow::Borrowed(line);
    }
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(' ');
            }
            '\n' => out.push(' '),
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(msg: &str) -> Event {
        let mut e = Event::new("test", "test", msg);
        e.hostname = Some("h".into());
        e.application = Some("app".into());
        e
    }

    fn framed(e: Event, format: OutputFormat, framing: Framing) -> String {
        String::from_utf8(frame_batch(&[e], format, framing)).unwrap()
    }

    // --- SYS-1: newline framing must keep one event in one frame ---

    #[test]
    fn newline_framing_keeps_multiline_event_in_one_frame() {
        let out = framed(
            ev("line one\r\nline two\nline three\rline four"),
            OutputFormat::Rfc5424,
            Framing::Newline,
        );
        assert_eq!(out.matches('\n').count(), 1, "{out:?}");
        assert!(!out.contains('\r'), "{out:?}");
        assert!(
            out.ends_with("line one line two line three line four\n"),
            "{out:?}"
        );
    }

    #[test]
    fn newline_framing_rewrites_breaks_in_sd_values() {
        let mut e = ev("msg");
        e.fields
            .insert("data_X".into(), serde_json::Value::from("a\r\nb"));
        let out = framed(e, OutputFormat::Rfc5424, Framing::Newline);
        assert_eq!(out.matches('\n').count(), 1, "{out:?}");
        assert!(out.contains(r#"data_X="a b""#), "{out:?}");
    }

    // --- Guards: nothing that cannot contain CR/LF changes ---

    #[test]
    fn newline_framing_single_line_is_byte_identical() {
        let e = ev("one line\twith a tab");
        for format in [
            OutputFormat::Rfc5424,
            OutputFormat::Rfc3164,
            OutputFormat::Raw,
            OutputFormat::Json,
        ] {
            let want = format!("{}\n", format_event(&e, format));
            assert_eq!(framed(e.clone(), format, Framing::Newline), want);
        }
    }

    #[test]
    fn octet_counting_is_unchanged() {
        let e = ev("line one\r\nline two");
        let line = format_event(&e, OutputFormat::Rfc5424);
        assert!(line.contains("\r\n"));
        let want = format!("{} {}", line.len(), line);
        assert_eq!(
            framed(e, OutputFormat::Rfc5424, Framing::OctetCounting),
            want
        );
    }

    #[test]
    fn json_format_is_unchanged() {
        let e = ev("line one\r\nline two");
        let want = format!("{}\n", serde_json::to_string(&e).unwrap());
        assert_eq!(want.matches('\n').count(), 1, "serde must escape CR/LF");
        assert_eq!(framed(e, OutputFormat::Json, Framing::Newline), want);
    }
}
