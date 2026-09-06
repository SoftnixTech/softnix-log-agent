use super::Sink;
use crate::buffer::DiskQueue;
use crate::config::{OutputConfig, OutputKind, RetryConfig};
use crate::metrics::{Metrics, OutputStatus, StatusRegistry};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// A destination becomes unhealthy after this many consecutive failures
/// (used for failover routing decisions).
const UNHEALTHY_AFTER: u64 = 3;

pub struct OutputWorker {
    id: String,
    kind_label: String,
    detail: String,
    sink: Box<dyn Sink>,
    queue: Arc<DiskQueue>,
    retry: RetryConfig,
}

impl OutputWorker {
    pub fn new(cfg: &OutputConfig, queue: Arc<DiskQueue>) -> anyhow::Result<Self> {
        let sink: Box<dyn Sink> = match cfg.kind {
            OutputKind::Stdout => Box::new(super::stdout::StdoutSink::new(cfg)),
            OutputKind::Syslog => Box::new(super::syslog::SyslogSink::new(cfg)?),
        };
        let kind_label = match cfg.kind {
            OutputKind::Syslog => format!("syslog/{:?}", cfg.protocol).to_lowercase(),
            OutputKind::Stdout => "stdout".to_string(),
        };
        Ok(OutputWorker {
            id: cfg.id.clone(),
            kind_label,
            detail: cfg.address.clone().unwrap_or_default(),
            sink,
            queue,
            retry: cfg.retry.clone(),
        })
    }

    /// Construct a worker around any Sink. Used by tests and by future
    /// outputs that are not built from an OutputConfig.
    pub fn with_sink(id: &str, sink: Box<dyn Sink>, queue: Arc<DiskQueue>) -> Self {
        OutputWorker {
            id: id.to_string(),
            kind_label: "custom".to_string(),
            detail: String::new(),
            sink,
            queue,
            retry: RetryConfig::default(),
        }
    }

    pub fn spawn(
        self,
        status: Arc<StatusRegistry>,
        metrics: Arc<Metrics>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        status.set_output(OutputStatus {
            id: self.id.clone(),
            kind: self.kind_label.clone(),
            detail: self.detail.clone(),
            healthy: true,
            connected: false,
            events_sent: 0,
            retries: 0,
            consecutive_failures: 0,
            last_error: None,
        });
        tokio::spawn(async move { self.run(status, metrics, cancel).await })
    }

    async fn run(
        mut self,
        status: Arc<StatusRegistry>,
        metrics: Arc<Metrics>,
        cancel: CancellationToken,
    ) {
        let id = self.id.clone();
        let mut backoff = self.retry.initial_backoff_ms;

        loop {
            self.queue.wait_data(&cancel).await;
            if cancel.is_cancelled() {
                // Final drain attempt: send whatever is connected & pending, briefly.
                break;
            }

            let batch = match self.queue.peek_batch(self.retry.batch_size) {
                // wait_data can report "data available" while peek_batch returns
                // nothing (all remaining records were skipped as corrupt). Without
                // a floor this becomes a tight loop that pins a core forever.
                Ok(b) if b.is_empty() => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Ok(b) => b,
                Err(e) => {
                    metrics.record_error(format!("output {id}: queue read: {e}"));
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            let outcome: anyhow::Result<usize> = match self.sink.send_batch(&batch).await {
                Ok(n) if n < batch.len() => Err(anyhow::anyhow!(
                    "sink returned partial ack {n}/{} events; DiskQueue cannot partially \
                     ack a peeked batch, retrying the whole batch",
                    batch.len()
                )),
                other => other,
            };

            match outcome {
                Ok(n) => {
                    // See the doc comment on Sink::send_batch in mod.rs: n is
                    // expected to equal batch.len() for every Sink in this
                    // codebase today, since DiskQueue::ack always commits the
                    // whole peeked position regardless of n.
                    if let Err(e) = self.queue.ack(n as u64) {
                        metrics.record_error(format!("output {id}: queue ack: {e}"));
                    }
                    metrics
                        .events_sent
                        .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                    backoff = self.retry.initial_backoff_ms;
                    status.update_output(&id, |s| {
                        s.events_sent += n as u64;
                        s.healthy = true;
                        s.connected = true;
                        s.consecutive_failures = 0;
                        s.last_error = None;
                    });
                }
                Err(e) => {
                    self.queue.reset_peek();
                    metrics
                        .events_failed
                        .fetch_add(batch.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    metrics.record_error(format!("output {id}: {e}"));
                    status.update_output(&id, |s| {
                        s.retries += 1;
                        s.consecutive_failures += 1;
                        s.connected = false;
                        s.healthy = s.consecutive_failures < UNHEALTHY_AFTER;
                        s.last_error = Some(e.to_string());
                    });
                    tracing::warn!("output {id}: send failed ({e}); retrying in {backoff}ms");
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_millis(backoff)) => {}
                        _ = cancel.cancelled() => {
                            // Shutting down: still reset the sink so the
                            // graceful-shutdown flush below (which reuses
                            // this same Sink instance) attempts a fresh
                            // connection instead of reusing the stale one
                            // from this failed send.
                            let _ = self.sink.reconnect().await;
                            break;
                        }
                    }
                    let _ = self.sink.reconnect().await;
                    backoff = (backoff * 2).min(self.retry.max_backoff_ms);
                }
            }
        }

        // Graceful shutdown: one bounded attempt to flush remaining events.
        if let Ok(batch) = self.queue.peek_batch(self.retry.batch_size) {
            if !batch.is_empty() {
                let flush = self.sink.send_batch(&batch);
                if let Ok(Ok(n)) =
                    tokio::time::timeout(std::time::Duration::from_secs(3), flush).await
                {
                    let _ = self.queue.ack(n as u64);
                    metrics
                        .events_sent
                        .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                } else {
                    self.queue.reset_peek();
                }
            }
        }
        status.update_output(&id, |s| s.connected = false);
    }
}
