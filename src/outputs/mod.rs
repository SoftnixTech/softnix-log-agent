//! Output workers: one task per destination, reading from that destination's
//! persistent queue with batch send, retry/backoff and health tracking.
//!
//! `Sink` is the seam every destination protocol implements; `OutputWorker`
//! drives any `Box<dyn Sink>` through the retry/backoff loop, independent of
//! the wire protocol underneath.

mod format;
mod stdout;
mod syslog;
mod worker;

pub use format::format_event;
pub use worker::OutputWorker;

use crate::event::Event;

/// A destination for batches of events. `OutputWorker` drives any `Box<dyn
/// Sink>` through the same retry/backoff loop, independent of the wire
/// protocol underneath — the seam every roadmap output (HTTP, Elasticsearch
/// bulk, Splunk HEC, Kafka) needs, which `enum Sink` + a concrete
/// `OutputWorker` could not hold.
#[async_trait::async_trait]
pub trait Sink: Send {
    /// Deliver a batch. Returning `Ok(n)` acks the first `n` events.
    ///
    /// Both built-in Sinks (`SyslogSink`, `StdoutSink`) only ever return
    /// `Ok(events.len())` on success or `Err` on full failure — matching the
    /// worker's own all-or-nothing-per-batch retry/backoff design. A `Sink`
    /// that returns a genuine partial `n < events.len()` needs to know that
    /// `DiskQueue::ack` always commits the *entire* peeked position
    /// regardless of `n` (it only uses `n` to adjust an in-memory counter) —
    /// so a real partial ack here would silently drop the un-acked tail of
    /// the batch rather than retrying it.
    ///
    /// A partial ack (n < events.len()) is treated by OutputWorker as a full
    /// failure and the whole batch is retried — DiskQueue cannot commit a
    /// partial peek, so this is the only safe way to honor a smaller n.
    async fn send_batch(&mut self, events: &[Event]) -> anyhow::Result<usize>;
    /// Called after a delivery failure and after the worker's backoff delay,
    /// just before the next attempt. A Sink that does real I/O here (e.g. an
    /// eager reconnect) still respects the worker's backoff — this is not
    /// called immediately on failure.
    async fn reconnect(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    fn id(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::DiskQueue;
    use crate::config::BufferConfig;
    use crate::metrics::{Metrics, StatusRegistry};
    use std::sync::Arc;

    struct RecordingSink {
        id: String,
        received: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        fail_next: bool,
    }

    #[async_trait::async_trait]
    impl Sink for RecordingSink {
        async fn send_batch(&mut self, events: &[Event]) -> anyhow::Result<usize> {
            if self.fail_next {
                self.fail_next = false;
                anyhow::bail!("simulated delivery failure");
            }
            let mut got = self.received.lock().unwrap();
            for ev in events {
                got.push(ev.message.clone());
            }
            Ok(events.len())
        }
        fn id(&self) -> &str {
            &self.id
        }
    }

    #[tokio::test]
    async fn a_custom_sink_receives_every_queued_event() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BufferConfig::default();
        let queue = DiskQueue::open(dir.path(), "dest", &cfg).unwrap();
        for i in 0..5 {
            queue
                .push(&Event::new("s", "test", &format!("event-{i}")))
                .unwrap();
        }
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Box::new(RecordingSink {
            id: "dest".to_string(),
            received: received.clone(),
            fail_next: true, // proves the retry path goes through the trait
        });

        let worker = OutputWorker::with_sink("dest", sink, queue);
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = worker.spawn(
            Arc::new(StatusRegistry::default()),
            Arc::new(Metrics::default()),
            cancel.clone(),
        );
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        cancel.cancel();
        let _ = handle.await;

        let got = received.lock().unwrap();
        assert_eq!(
            got.len(),
            5,
            "sink should have received all 5 events, got {got:?}"
        );
    }
}
