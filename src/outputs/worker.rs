use super::Sink;
use crate::buffer::DiskQueue;
use crate::config::{OutputConfig, OutputKind, RetryConfig};
use crate::metrics::{Metrics, OutputStatus, StatusRegistry};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// A destination becomes unhealthy after this many consecutive failures
/// (used for failover routing decisions).
const UNHEALTHY_AFTER: u64 = 3;

/// Per-batch byte budget handed to `DiskQueue::peek_batch`.
///
/// `retry.batch_size` bounds a batch by event *count*, which is not a memory
/// bound: a file input can emit events up to 4 MiB each, so the default 200
/// events could materialise ~200 MB of `Event`s here plus a second, equally
/// large wire payload in `frame_batch`. 8 MiB is comfortably above any
/// realistic batch of syslog-sized events and two orders of magnitude below
/// the worst case it removes.
const PEEK_MAX_BYTES: usize = 8 * 1024 * 1024;

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

            // R-2: peek_batch does File::open + metadata + seek + N read_exact
            // + N serde_json::from_slice under the queue mutex. One dispatch
            // per batch keeps that off the runtime's two worker threads.
            let q = std::sync::Arc::clone(&self.queue);
            let max = self.retry.batch_size;
            let peeked =
                tokio::task::spawn_blocking(move || q.peek_batch(max, PEEK_MAX_BYTES)).await;
            let batch = match peeked {
                // wait_data can report "data available" while peek_batch returns
                // nothing (all remaining records were skipped as corrupt). Without
                // a floor this becomes a tight loop that pins a core forever.
                Ok(Ok(b)) if b.is_empty() => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Ok(Ok(b)) => b,
                Ok(Err(e)) => {
                    metrics.record_error(format!("output {id}: queue read: {e}"));
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                Err(e) => {
                    metrics.record_error(format!("output {id}: queue read task: {e}"));
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
                    //
                    // Update events_sent/status before ack, not after: the
                    // destination has already received these n events the
                    // moment send_batch returns Ok, regardless of whether
                    // ack (which only persists the queue's own internal read
                    // cursor) later succeeds or fails. Doing it first also
                    // keeps a real invariant intact: nothing here awaits
                    // between send_batch returning and this update, so any
                    // external observer who sees the data arrive (e.g. a
                    // test reading the far end of the socket) is guaranteed
                    // to see events_sent already reflect it. Moving this
                    // below `ack`'s spawn_blocking await broke that
                    // invariant — the two are unrelated code paths racing
                    // to run first, and a test asserting on events_sent
                    // right after observing delivery could see 0 depending
                    // on which one the scheduler happened to run first.
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
                    // R-1: `ack` fsyncs the cursor twice. Do it on the
                    // blocking pool instead of parking one of the runtime's
                    // two worker threads inside fsync.
                    let q = std::sync::Arc::clone(&self.queue);
                    let acked = n as u64;
                    match tokio::task::spawn_blocking(move || q.ack(acked)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            metrics.record_error(format!("output {id}: queue ack: {e}"));
                        }
                        Err(e) => {
                            metrics.record_error(format!("output {id}: queue ack task: {e}"));
                        }
                    }
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
        let q = std::sync::Arc::clone(&self.queue);
        let max = self.retry.batch_size;
        let final_peek =
            tokio::task::spawn_blocking(move || q.peek_batch(max, PEEK_MAX_BYTES)).await;
        if let Ok(Ok(batch)) = final_peek {
            if !batch.is_empty() {
                let flush = self.sink.send_batch(&batch);
                if let Ok(Ok(n)) =
                    tokio::time::timeout(std::time::Duration::from_secs(3), flush).await
                {
                    // Same ordering as the main loop above: record the send
                    // before awaiting ack, which only persists the queue's
                    // internal cursor and races with nothing an external
                    // observer needs events_sent to reflect promptly.
                    metrics
                        .events_sent
                        .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                    let q = std::sync::Arc::clone(&self.queue);
                    let acked = n as u64;
                    let _ = tokio::task::spawn_blocking(move || q.ack(acked)).await;
                } else {
                    self.queue.reset_peek();
                }
            }
        }
        status.update_output(&id, |s| s.connected = false);
    }
}
