use super::format::format_event;
use crate::config::{Framing, OutputConfig, OutputFormat};
use crate::event::Event;
use anyhow::Result;
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
                payload.extend_from_slice(line.as_bytes());
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
