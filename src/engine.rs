//! Engine: wires inputs → pipeline → per-destination queues → outputs.
//! The engine is fully restartable, which is how config reload works.

use crate::buffer::{DiskQueue, PushOutcome};
use crate::config::{Config, FullPolicy, OutputConfig};
use crate::event::Event;
use crate::inputs::{file::FileInput, syslog::SyslogInput};
use crate::metrics::{Metrics, StatusRegistry};
use crate::outputs::OutputWorker;
use crate::pipeline::{eval_condition, CompiledCondition, Enricher, Transformer};
use crate::state::StateManager;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// A fan-out target: an output's config, its pre-compiled `when:` condition
/// (compiled once at engine start rather than re-parsing/re-compiling any
/// `matches` regex on every event), the sender into its router task, and the
/// per-destination "router channel full" shed counter (also held in
/// `EngineShared::router_shed` for `/metrics`).
type RouterEntry = (
    OutputConfig,
    Option<CompiledCondition>,
    mpsc::Sender<Arc<Event>>,
    Arc<AtomicU64>,
);

const CHANNEL_CAPACITY: usize = 8192;
/// Bounds the input→pipeline channel in bytes, not just message count: 8192
/// messages at up to a 64 KB syslog line each is ~512 MB of reachable RSS if
/// the pipeline stalls even briefly while a burst arrives, against an
/// advertised ~12 MB footprint. `EventSender` gates admission with a
/// KB-granularity semaphore sized to this many bytes; `CHANNEL_CAPACITY`
/// remains as a secondary cap on raw message count.
const CHANNEL_BYTES: usize = 64 * 1024 * 1024;
/// Capacity of each per-destination router channel. This exists to absorb
/// transient bursts and, in particular, the brief lock contention between a
/// router's `push`/`push_blocking` and the output worker's `ack`/
/// `peek_batch` on `DiskQueue`'s shared mutex (`ack` holds it across two
/// `fsync` calls per batch) — not to let one slow destination buffer memory
/// unboundedly beyond its own on-disk queue. 4096 gives routine contention
/// generous room to be absorbed (each slot is just an `Arc<Event>` pointer +
/// refcount, not the event body, so the memory cost is small) while still
/// being finite: a destination that is genuinely stuck, not just briefly
/// contended, still sheds beyond this — which is intentional, since that is
/// what makes this task's cross-destination isolation guarantee hold.
const ROUTER_CAPACITY: usize = 4096;

/// The input channel's sender, wrapped with a byte-budget gate so the
/// channel is bounded by actual memory rather than just message count (see
/// `CHANNEL_BYTES`). Permits are counted in KB (`Semaphore::MAX_PERMITS` is
/// large but KB granularity keeps the numbers small and the rounding
/// conservative).
///
/// A permit is acquired before an event is admitted to the channel and is
/// held — not released back to the semaphore — until `run_pipeline` actually
/// dequeues that event (see `ChannelBudget::release`), not merely once it has
/// been handed to the channel buffer. Releasing on admission would only
/// bound the number of concurrent in-flight `send` calls, not the events
/// already sitting in the channel waiting for the pipeline to catch up,
/// which is exactly the burst-stall scenario this type exists to bound.
#[derive(Clone)]
pub struct EventSender {
    tx: mpsc::Sender<Event>,
    budget: Arc<tokio::sync::Semaphore>,
    metrics: Option<Arc<Metrics>>,
}

impl EventSender {
    pub fn with_budget(tx: mpsc::Sender<Event>, bytes: usize) -> Self {
        EventSender {
            tx,
            budget: Arc::new(tokio::sync::Semaphore::new(bytes / 1024)),
            metrics: None,
        }
    }

    /// Attach the metrics registry so `send`/`blocking_send` can keep
    /// `agent_channel_bytes` current. Separate from `with_budget` so the
    /// constructor stays usable in tests that don't care about metrics.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// KB, rounded up, at least 1 — so a tiny event never costs zero
    /// permits. Counts `raw_message` alongside `message`: on the Windows
    /// eventlog path (the only input that populates it) `raw_message` holds
    /// the full event XML — 2-4 KB, well beyond the already-rendered
    /// message — so an event that carries it must be charged for both, or
    /// the real byte ceiling this budget provides sits meaningfully above
    /// the configured `CHANNEL_BYTES`.
    fn permits_for(ev: &Event) -> u32 {
        Self::event_bytes(ev).div_ceil(1024).max(1) as u32
    }

    /// Total byte cost of an event for both the budget (`permits_for`) and
    /// the `agent_channel_bytes` gauge — kept as one source of truth so the
    /// two always move together.
    fn event_bytes(ev: &Event) -> u64 {
        (ev.message.len() + ev.raw_message.as_ref().map_or(0, |r| r.len())) as u64
    }

    /// A handle `run_pipeline` uses to release budget as it drains events.
    pub(crate) fn channel_budget(&self) -> ChannelBudget {
        ChannelBudget {
            budget: self.budget.clone(),
        }
    }

    // `SendError<Event>` is exactly what the wrapped `mpsc::Sender::send`
    // already returns; the point of that error is handing the un-sent event
    // back to the caller, so boxing it here would just relocate the cost
    // rather than remove it.
    #[allow(clippy::result_large_err)]
    pub async fn send(&self, ev: Event) -> Result<(), mpsc::error::SendError<Event>> {
        let n = Self::permits_for(&ev);
        let permit = match Arc::clone(&self.budget).acquire_many_owned(n).await {
            Ok(p) => p,
            Err(_) => return Err(mpsc::error::SendError(ev)),
        };
        let len = Self::event_bytes(&ev);
        // Credit the gauge before the send, not after: on the multi-thread
        // runtime, the instant `tx.send` completes is exactly when a parked
        // `rx.recv()` can wake and run `ChannelBudget::release`'s
        // `fetch_sub` on another thread. Crediting first keeps the add/sub
        // pair correctly ordered instead of racing.
        if let Some(m) = &self.metrics {
            m.channel_bytes.fetch_add(len, Ordering::Relaxed);
        }
        match self.tx.send(ev).await {
            Ok(()) => {
                // Deferred release — see the type doc comment above.
                permit.forget();
                Ok(())
            }
            Err(e) => {
                // Never entered the channel; `permit` drops here, returning
                // the budget. Undo the gauge credit for the same reason —
                // it was never dequeued, so no `release` will ever net it
                // back out.
                if let Some(m) = &self.metrics {
                    m.channel_bytes.fetch_sub(len, Ordering::Relaxed);
                }
                Err(e)
            }
        }
    }

    /// For the `spawn_blocking` eventlog path, which cannot await the async
    /// semaphore directly. Retries acquiring a permit on a short interval
    /// instead: this already runs on a `spawn_blocking` thread, where
    /// blocking is not just legal but already happening — `tx.blocking_send`
    /// itself already parks the thread on the channel's own capacity
    /// whenever it's full, so parking on the budget too is no different in
    /// kind. This keeps the byte bound actually enforced on this path rather
    /// than falling back to admitting events unpermitted once the budget is
    /// exhausted. Only gives up waiting for budget if `cancel` fires first
    /// (mirroring shutdown), in which case it falls through to the plain
    /// channel send so a draining shutdown still completes instead of
    /// hanging on a budget that no `release` may ever come to free.
    #[allow(clippy::result_large_err)] // see `send`'s comment above.
    pub fn blocking_send(
        &self,
        ev: Event,
        cancel: &CancellationToken,
    ) -> Result<(), mpsc::error::SendError<Event>> {
        let n = Self::permits_for(&ev);
        let permit = loop {
            if let Ok(p) = Arc::clone(&self.budget).try_acquire_many_owned(n) {
                break Some(p);
            }
            if cancel.is_cancelled() {
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        let len = Self::event_bytes(&ev);
        if let Some(m) = &self.metrics {
            m.channel_bytes.fetch_add(len, Ordering::Relaxed);
        }
        match self.tx.blocking_send(ev) {
            Ok(()) => {
                if let Some(p) = permit {
                    p.forget(); // deferred release, same as `send`.
                }
                // If `permit` is `None` (cancelled while waiting), this event
                // was admitted without a reservation — the same as `send`'s
                // behavior when the channel itself is the only thing that
                // ever blocked it. There is nothing to forget in that case.
                Ok(())
            }
            Err(e) => {
                // Never entered the channel; `permit` (if any) drops here,
                // returning the budget. Undo the gauge credit for the same
                // reason as `send`.
                if let Some(m) = &self.metrics {
                    m.channel_bytes.fetch_sub(len, Ordering::Relaxed);
                }
                Err(e)
            }
        }
    }
}

/// Handle the pipeline uses to release `EventSender` budget as it dequeues
/// events. Kept separate from `EventSender` itself because `run_pipeline`
/// only ever receives the raw `mpsc::Receiver<Event>` — the channel item
/// type never changes — so this travels alongside it as its own parameter.
#[derive(Clone)]
pub(crate) struct ChannelBudget {
    budget: Arc<tokio::sync::Semaphore>,
}

impl ChannelBudget {
    fn release(&self, ev: &Event, metrics: &Metrics) {
        let n = EventSender::permits_for(ev) as usize;
        self.budget.add_permits(n);
        // `saturating_sub` (via `fetch_update`, since `AtomicU64` has no
        // built-in fetch-saturating-sub) as belt-and-braces: `send` and
        // `blocking_send` now credit this gauge before the send that can
        // race a concurrent `release`'s `fetch_sub` (see their comments), so
        // ordinary operation should never underflow it — but wrapping to
        // ~18 quintillion on any residual edge case would make `/metrics`
        // briefly nonsensical, whereas saturating just clamps to 0.
        let _ = metrics
            .channel_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                Some(cur.saturating_sub(EventSender::event_bytes(ev)))
            });
    }
}

/// Everything the web UI needs to observe a running engine.
pub struct EngineShared {
    pub config: Config,
    pub metrics: Arc<Metrics>,
    pub status: Arc<StatusRegistry>,
    pub queues: HashMap<String, Arc<DiskQueue>>,
    /// Per-destination count of events shed because that destination's
    /// router channel was full (`route_event`'s `try_send` `Full` arm).
    /// Distinct from the aggregate `Metrics::events_dropped`, which mixes in
    /// unrelated causes (disk-queue full/drop policies, transform drops).
    pub router_shed: HashMap<String, Arc<AtomicU64>>,
    pub state: Arc<StateManager>,
}

pub struct Engine {
    pub shared: Arc<EngineShared>,
    cancel: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Engine {
    pub async fn start(cfg: Config) -> Result<Engine> {
        let cancel = CancellationToken::new();
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        match Self::build(cfg, &cancel, &mut tasks).await {
            Ok(shared) => Ok(Engine {
                shared,
                cancel,
                tasks,
            }),
            Err(e) => {
                // A partial start must not leave listeners holding ports or
                // output workers holding a single-writer queue directory.
                tracing::error!(
                    "engine start failed, tearing down {} task(s): {e:#}",
                    tasks.len()
                );
                cancel.cancel();
                for t in &tasks {
                    t.abort();
                }
                for t in tasks {
                    let _ = t.await;
                }
                Err(e)
            }
        }
    }

    async fn build(
        cfg: Config,
        cancel: &CancellationToken,
        tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    ) -> Result<Arc<EngineShared>> {
        let data_dir = &cfg.agent.data_dir;
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("cannot create data dir {}", data_dir.display()))?;
        let state = Arc::new(StateManager::open(data_dir)?);
        let metrics = Arc::new(Metrics::default());
        let status = Arc::new(StatusRegistry::default());

        // Per-destination persistent queues.
        let queue_dir = cfg
            .buffer
            .dir
            .clone()
            .unwrap_or_else(|| data_dir.join("queue"));
        let mut queues: HashMap<String, Arc<DiskQueue>> = HashMap::new();
        for out in &cfg.outputs {
            let mut bcfg = cfg.buffer.clone();
            if let Some(p) = out.full_policy {
                bcfg.full_policy = p;
            }
            let q = DiskQueue::open(&queue_dir, &out.id, &bcfg)
                .with_context(|| format!("cannot open queue for output {}", out.id))?;
            queues.insert(out.id.clone(), q);
        }

        // Output workers.
        for out in &cfg.outputs {
            let worker = OutputWorker::new(out, queues[&out.id].clone())?;
            tasks.push(worker.spawn(status.clone(), metrics.clone(), cancel.child_token()));
        }

        // One router task per destination, each fed by its own small bounded
        // channel. A destination whose queue is full (or whose disk writes are
        // otherwise slow) can only ever stall its own channel, never the
        // pipeline or any other destination.
        let mut routers: Vec<RouterEntry> = Vec::new();
        let mut router_shed: HashMap<String, Arc<AtomicU64>> = HashMap::new();
        for out in &cfg.outputs {
            let (rtx, rrx) = mpsc::channel::<Arc<Event>>(ROUTER_CAPACITY);
            let policy = out.full_policy.unwrap_or(cfg.buffer.full_policy);
            let block = policy == FullPolicy::Block;
            let shed = Arc::new(AtomicU64::new(0));
            router_shed.insert(out.id.clone(), shed.clone());
            tasks.push(tokio::spawn(run_router(
                rrx,
                out.clone(),
                queues[&out.id].clone(),
                block,
                metrics.clone(),
                cancel.child_token(),
            )));
            let when = out
                .when
                .as_ref()
                .map(CompiledCondition::compile)
                .transpose()
                .with_context(|| format!("invalid `when` condition on output {}", out.id))?;
            routers.push((out.clone(), when, rtx, shed));
        }

        // Pipeline task: transform, enrich, fan out to the per-destination
        // routers. It no longer awaits any push itself, so a stuck destination
        // cannot stall delivery to its siblings.
        let (raw_tx, rx) = mpsc::channel::<Event>(CHANNEL_CAPACITY);
        let tx = EventSender::with_budget(raw_tx, CHANNEL_BYTES).with_metrics(metrics.clone());
        let channel_budget = tx.channel_budget();
        let transformer = Transformer::compile(&cfg.pipeline)?;
        let enricher = Enricher::new(&cfg.pipeline.enrich);
        tasks.push(tokio::spawn(run_pipeline(
            rx,
            channel_budget,
            transformer,
            enricher,
            routers,
            status.clone(),
            metrics.clone(),
            cancel.child_token(),
        )));

        // Inputs (binds happen before spawn so startup errors are surfaced).
        for s in &cfg.inputs.syslog {
            let input = SyslogInput::new(s);
            let handle = input
                .spawn(
                    tx.clone(),
                    status.clone(),
                    metrics.clone(),
                    cancel.child_token(),
                )
                .await?;
            tasks.push(handle);
        }
        for f in &cfg.inputs.files {
            let input = FileInput::new(f)?;
            tasks.push(input.spawn(
                tx.clone(),
                state.clone(),
                status.clone(),
                metrics.clone(),
                cancel.child_token(),
            ));
        }
        #[cfg(windows)]
        for e in &cfg.inputs.eventlog {
            let input = crate::inputs::eventlog::EventLogInput::new(e);
            tasks.push(input.spawn(
                tx.clone(),
                state.clone(),
                status.clone(),
                metrics.clone(),
                cancel.child_token(),
            ));
        }
        #[cfg(not(windows))]
        for e in &cfg.inputs.eventlog {
            tracing::warn!(
                "eventlog input {:?} ignored: Windows Event Log is only collected on Windows",
                e.id
            );
        }
        drop(tx); // pipeline exits once all input senders are gone

        // Periodic state flush + cursor pruning.
        {
            let state = state.clone();
            let cancel = cancel.child_token();
            tasks.push(tokio::spawn(async move {
                let mut prune_tick = 0u32;
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                            if let Err(e) = state.flush() {
                                tracing::warn!("state flush failed: {e}");
                            }
                            prune_tick += 1;
                            if prune_tick % 720 == 0 {
                                state.prune(7 * 24 * 3600);
                            }
                        }
                        _ = cancel.cancelled() => return,
                    }
                }
            }));
        }

        tracing::info!(
            "engine started: {} file input(s), {} syslog input(s), {} eventlog input(s), {} output(s)",
            cfg.inputs.files.len(),
            cfg.inputs.syslog.len(),
            cfg.inputs.eventlog.len(),
            cfg.outputs.len()
        );

        Ok(Arc::new(EngineShared {
            config: cfg,
            metrics,
            status,
            queues,
            router_shed,
            state,
        }))
    }

    /// Graceful stop: cancel all tasks, wait briefly, persist state.
    pub async fn stop(self) {
        tracing::info!("stopping engine");
        self.cancel.cancel();
        for t in self.tasks {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(8), t).await;
        }
        if let Err(e) = self.shared.state.flush() {
            tracing::error!("final state flush failed: {e}");
        }
        tracing::info!("engine stopped");
    }
}

/// One routing task per destination. The pipeline hands it an already
/// transformed+enriched event; this task owns the blocking push so a full or
/// slow queue cannot stall any other destination.
async fn run_router(
    mut rx: mpsc::Receiver<Arc<Event>>,
    out: OutputConfig,
    queue: Arc<DiskQueue>,
    block: bool,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
) {
    while let Some(ev) = rx.recv().await {
        let result = if block {
            queue.push_blocking(&ev, &cancel).await.map(|stored| {
                if stored {
                    PushOutcome::Stored { evicted: 0 }
                } else {
                    PushOutcome::Dropped
                }
            })
        } else {
            queue.push(&ev)
        };
        match result {
            // Under drop_oldest, storing a new event may evict older ones to
            // make room; those evictions must be counted so the Overview's
            // dropped total stays consistent with the per-queue Buffer page.
            Ok(PushOutcome::Stored { evicted }) => {
                if evicted > 0 {
                    metrics.events_dropped.fetch_add(evicted, Ordering::Relaxed);
                }
            }
            Ok(PushOutcome::Dropped) | Ok(PushOutcome::Full) => {
                metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                metrics.record_error(format!("queue {} write: {e}", out.id));
            }
        }
    }
}

/// Transform → normalize → enrich → fan out to the per-destination routers.
#[allow(clippy::too_many_arguments)]
async fn run_pipeline(
    mut rx: mpsc::Receiver<Event>,
    budget: ChannelBudget,
    transformer: Transformer,
    enricher: Enricher,
    routers: Vec<RouterEntry>,
    status: Arc<StatusRegistry>,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
) {
    loop {
        let ev = tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => {
                    // Release the channel-budget permit(s) this event was
                    // admitted under now that the pipeline — not just the
                    // channel buffer — actually has it.
                    budget.release(&ev, &metrics);
                    ev
                }
                None => return,
            },
            _ = cancel.cancelled() => {
                // Drain whatever is already in the channel before exiting. This
                // runs on every engine stop, including a routine config reload
                // (SIGHUP / GUI save-and-reload both cancel this same token) —
                // not just final process shutdown — so it must not silently shed
                // events the way the hot path's try_send does. Use the
                // force-deliver path instead: it blocks on each router's channel
                // until there is room, rather than giving up after one attempt.
                //
                // This cannot hang indefinitely: by the time this arm runs,
                // `cancel` (and therefore every router's child token — see
                // `run_router`/`push_blocking` in src/buffer.rs) has already been
                // cancelled, so a router currently parked in `push_blocking`
                // waiting for disk-queue space unblocks and returns immediately
                // via `push_blocking`'s own `_ = cancel.cancelled() => return
                // Ok(false)` arm, instead of waiting for space that may never
                // come. Draining may still take a little wall-clock time (the
                // router has to actually work through its backlog), but every
                // event that was in this channel gets a genuine chance to reach
                // the destination's disk queue rather than being shed on a
                // single non-blocking attempt.
                while let Ok(ev) = rx.try_recv() {
                    budget.release(&ev, &metrics);
                    route_event(ev, &transformer, &enricher, &routers, &status, &metrics, true)
                        .await;
                }
                return;
            }
        };
        route_event(
            ev,
            &transformer,
            &enricher,
            &routers,
            &status,
            &metrics,
            false,
        )
        .await;
    }
}

/// `force_deliver` selects the fan-out strategy for this one event:
/// - `false` (the normal hot path): `try_send` — never blocks, sheds this
///   event for a single saturated destination rather than stalling delivery
///   to its siblings (or the pipeline, or any input). This is the isolation
///   guarantee the per-destination routers exist to provide and must not be
///   reopened.
/// - `true` (the drain arm only, see `run_pipeline`'s cancel branch): a
///   blocking send, so a routine stop/reload does not silently shed
///   already-received events. Safe there, and only there, because cancel has
///   already fired by that point (see the comment on the cancel arm above).
async fn route_event(
    mut ev: Event,
    transformer: &Transformer,
    enricher: &Enricher,
    routers: &[RouterEntry],
    status: &StatusRegistry,
    metrics: &Metrics,
    force_deliver: bool,
) {
    if !transformer.apply(&mut ev) {
        metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    enricher.apply(&mut ev);

    let ev = Arc::new(ev);
    for (out, when, tx, shed) in routers {
        // Standby outputs only receive traffic while their primary is down.
        if let Some(primary) = &out.failover_for {
            if status.output_healthy(primary) {
                continue;
            }
        }
        if let Some(cond) = when {
            if !eval_condition(cond, &ev) {
                continue;
            }
        }
        if force_deliver {
            if tx.send(Arc::clone(&ev)).await.is_err() {
                metrics.record_error(format!("router {} closed", out.id));
            }
            continue;
        }
        // A blocking send here would defeat the whole point of per-destination
        // routers: if THIS destination's channel is full because its router is
        // genuinely parked on a full, block-policy disk queue, blocking on the
        // send would stall every other destination and eventually every input
        // too — the exact bug this fan-out exists to prevent. try_send instead:
        // when the channel is full, the event is dropped for this destination
        // only, counted, and every other destination keeps flowing untouched.
        // Losing this one event does not violate `block`'s "never drop" promise
        // at the persistent-queue layer — a full channel here means the disk
        // queue behind it is already full and would have blocked this exact
        // event anyway; the only difference is that OTHER destinations no
        // longer pay for it.
        match tx.try_send(Arc::clone(&ev)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                // This can also fire during brief, routine lock contention on
                // DiskQueue's mutex (shared with the output worker's ack/
                // peek_batch, which holds it across fsync) — not only when the
                // destination is genuinely stuck. Make it visible without
                // spamming: count it per destination (distinct from the
                // aggregate `events_dropped`, which mixes in unrelated causes)
                // and log only every 100th occurrence for this destination.
                let n = shed.fetch_add(1, Ordering::Relaxed) + 1;
                if n % 100 == 1 {
                    tracing::warn!(
                        destination = %out.id,
                        shed_total = n,
                        "destination router buffer full; shedding event (logged every 100th occurrence)"
                    );
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                metrics.record_error(format!("router {} closed", out.id));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BufferConfig, EnrichConfig, Framing, OutputFormat, OutputKind, PipelineConfig, RetryConfig,
        SyslogProtocol,
    };
    use std::sync::atomic::Ordering;

    fn test_output(id: &str) -> OutputConfig {
        OutputConfig {
            id: id.to_string(),
            kind: OutputKind::Stdout,
            address: None,
            protocol: SyslogProtocol::default(),
            format: OutputFormat::default(),
            framing: Framing::default(),
            tls: None,
            when: None,
            failover_for: None,
            retry: RetryConfig::default(),
            full_policy: None,
        }
    }

    // --- EventSender: channel bounded by bytes, not just message count ---

    /// R-3 regression guard: with a small byte budget and events sized past
    /// it, a third send must not complete until the budget frees up — proof
    /// the channel is actually gated in bytes, not just the (much larger)
    /// message-count capacity of the underlying `mpsc` channel.
    #[tokio::test]
    async fn sender_blocks_once_the_byte_budget_is_exhausted() {
        let (tx, _rx) = mpsc::channel::<Event>(8192);
        // 64 KB budget, 32 KB events => the third send must not complete.
        let sender = EventSender::with_budget(tx, 64 * 1024);
        let body = "x".repeat(32 * 1024);
        sender.send(Event::new("s", "t", &body)).await.unwrap();
        sender.send(Event::new("s", "t", &body)).await.unwrap();
        let blocked = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            sender.send(Event::new("s", "t", &body)),
        )
        .await;
        assert!(
            blocked.is_err(),
            "third send should have been held by the budget"
        );
    }

    /// The budget must be held until the pipeline actually dequeues the
    /// event, not just until it's been handed to the channel buffer —
    /// otherwise `send` releasing on its own completion would only bound
    /// concurrent in-flight sends, not events sitting in the channel.
    /// Proven here by draining exactly one event via `ChannelBudget::release`
    /// (what `run_pipeline` does) and confirming a blocked send then
    /// unblocks.
    #[tokio::test]
    async fn budget_only_frees_once_the_pipeline_drains_the_event() {
        let (tx, mut rx) = mpsc::channel::<Event>(8192);
        let sender = EventSender::with_budget(tx, 64 * 1024);
        let body = "x".repeat(32 * 1024);
        sender.send(Event::new("s", "t", &body)).await.unwrap();
        sender.send(Event::new("s", "t", &body)).await.unwrap();
        // Budget now fully committed (2 x 32 KB == 64 KB); nothing has been
        // dequeued yet, so a third send must still block.
        let still_blocked = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            sender.send(Event::new("s", "t", &body)),
        )
        .await;
        assert!(still_blocked.is_err());

        // Drain exactly one event as `run_pipeline` would.
        let metrics = Metrics::default();
        let budget = sender.channel_budget();
        let drained = rx.recv().await.unwrap();
        budget.release(&drained, &metrics);

        // The freed 32 KB must now let a same-sized send through promptly.
        let unblocked = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            sender.send(Event::new("s", "t", &body)),
        )
        .await;
        assert!(
            unblocked.is_ok() && unblocked.unwrap().is_ok(),
            "send should unblock once the pipeline has drained an event"
        );
    }

    /// FIX A (fix round 1): `blocking_send` (the eventlog `spawn_blocking`
    /// path) cannot await the async semaphore, but it no longer falls back
    /// to admitting an event unpermitted once the budget is exhausted — it
    /// retries acquiring a permit on a short interval instead, the same way
    /// `tx.blocking_send` itself already blocks on the channel's own
    /// capacity. Proven here by exhausting the budget, confirming
    /// `blocking_send` is still waiting a while later, then releasing
    /// budget from a concurrent task and confirming it unblocks and
    /// completes only afterward.
    #[tokio::test]
    async fn blocking_send_retries_until_budget_is_released() {
        let (tx, mut rx) = mpsc::channel::<Event>(8192);
        let sender = EventSender::with_budget(tx, 8 * 1024); // 8 KB budget => 8 permits
        let body = "x".repeat(8 * 1024);

        // Exhaust the budget via the normal async path; this event stays
        // sitting in the channel undrained, so nothing has freed its
        // permits yet.
        sender.send(Event::new("s", "t", &body)).await.unwrap();
        assert_eq!(sender.budget.available_permits(), 0);

        // No permit available; blocking_send must retry rather than admit
        // the event unpermitted. Run it on a real blocking thread (as the
        // eventlog `spawn_blocking` context does) — calling `blocking_send`
        // directly on an async runtime worker thread panics.
        let blocking_sender = sender.clone();
        let ev = Event::new("s", "t", &body);
        let cancel = CancellationToken::new();
        #[allow(clippy::result_large_err)] // see `EventSender::send`'s comment.
        let handle =
            tokio::task::spawn_blocking(move || blocking_sender.blocking_send(ev, &cancel));

        // Still waiting a while later: nothing has freed the budget yet.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !handle.is_finished(),
            "blocking_send must still be retrying while the budget is exhausted"
        );

        // Drain the first event and release its budget, as `run_pipeline`
        // would.
        let metrics = Metrics::default();
        let budget = sender.channel_budget();
        let e1 = rx.recv().await.unwrap();
        budget.release(&e1, &metrics);

        // blocking_send must now unblock and complete successfully.
        tokio::time::timeout(std::time::Duration::from_secs(1), handle)
            .await
            .expect("blocking_send should unblock once budget is released")
            .unwrap()
            .unwrap();
        assert_eq!(
            sender.budget.available_permits(),
            0,
            "blocking_send should have consumed the freed permits, not left them idle"
        );
    }

    /// FIX A (fix round 1): if `cancel` fires while `blocking_send` is
    /// waiting on the budget, it must give up waiting rather than retry
    /// forever, falling through to the channel's own (still blocking) send
    /// instead — mirroring what `run_pipeline`'s drain arm already does on
    /// shutdown, so a cancelled shutdown can't hang on a budget that no
    /// `release` will ever come to free.
    #[tokio::test]
    async fn blocking_send_falls_through_to_channel_send_when_cancelled() {
        let (tx, _rx) = mpsc::channel::<Event>(8192);
        let sender = EventSender::with_budget(tx, 8 * 1024); // 8 KB budget => 8 permits
        let body = "x".repeat(8 * 1024);

        // Exhaust the budget; nothing ever drains it in this test, so a
        // retry-forever loop would hang.
        sender.send(Event::new("s", "t", &body)).await.unwrap();
        assert_eq!(sender.budget.available_permits(), 0);

        let cancel = CancellationToken::new();
        let waiting_cancel = cancel.clone();
        let blocking_sender = sender.clone();
        let ev = Event::new("s", "t", &body);
        #[allow(clippy::result_large_err)] // see `EventSender::send`'s comment.
        let handle =
            tokio::task::spawn_blocking(move || blocking_sender.blocking_send(ev, &waiting_cancel));

        // Give it a moment to enter the retry loop, then cancel.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !handle.is_finished(),
            "should still be retrying before cancellation"
        );
        cancel.cancel();

        tokio::time::timeout(std::time::Duration::from_secs(1), handle)
            .await
            .expect("blocking_send must give up waiting once cancelled, not hang")
            .unwrap()
            .expect(
                "falls through to the channel's own send, which still succeeds \
                 since the channel itself has room",
            );
    }

    /// FIX C (fix round 1): `permits_for` must count `raw_message` alongside
    /// `message`, not just `message` alone — otherwise an event that also
    /// carries a populated `raw_message` (as Windows eventlog does when
    /// `keep_raw_message` is set) is charged for only part of its real
    /// footprint.
    #[test]
    fn permits_for_charges_raw_message_alongside_message() {
        let message_only = Event::new("s", "t", &"x".repeat(200));
        let mut with_raw = Event::new("s", "t", &"x".repeat(200));
        with_raw.raw_message = Some("y".repeat(4000));

        let message_only_permits = EventSender::permits_for(&message_only);
        let with_raw_permits = EventSender::permits_for(&with_raw);

        assert_eq!(message_only_permits, 1, "200 bytes rounds up to 1 KB");
        assert_eq!(
            with_raw_permits,
            (200 + 4000_usize).div_ceil(1024) as u32,
            "must charge for message.len() + raw_message.len() combined, not message alone"
        );
        assert!(
            with_raw_permits > message_only_permits,
            "an event carrying raw_message must cost strictly more permits \
             than the same message without it"
        );
    }

    /// `agent_channel_bytes` must track live channel occupancy: it rises as
    /// `EventSender::send` admits an event and falls back once
    /// `ChannelBudget::release` (the pipeline's dequeue path) drains it.
    #[tokio::test]
    async fn channel_bytes_gauge_tracks_admitted_and_drained_events() {
        let (tx, mut rx) = mpsc::channel::<Event>(8192);
        let metrics = Arc::new(Metrics::default());
        let sender = EventSender::with_budget(tx, 1024 * 1024).with_metrics(metrics.clone());
        let body = "x".repeat(2048);
        sender.send(Event::new("s", "t", &body)).await.unwrap();
        assert_eq!(metrics.channel_bytes.load(Ordering::Relaxed), 2048);

        let budget = sender.channel_budget();
        let ev = rx.recv().await.unwrap();
        budget.release(&ev, &metrics);
        assert_eq!(metrics.channel_bytes.load(Ordering::Relaxed), 0);
    }

    /// Regression guard for the fix-round-2 drain fix: `run_pipeline`'s
    /// cancel arm must force-deliver every already-received event to its
    /// destination's router rather than shedding it on a single
    /// non-blocking `try_send`, the way the normal hot path does. This
    /// simulates a router channel that is momentarily behind (a small
    /// capacity plus a slow consumer — the same "router briefly can't keep
    /// up" shape fix 2's shed counter exists for, just exaggerated so the
    /// test runs fast and deterministically instead of depending on real
    /// disk or network timing) and proves every event handed to
    /// `route_event` with `force_deliver: true` still reaches the
    /// destination's disk queue — none dropped — even though far more
    /// events are sent than the channel can hold at once.
    #[tokio::test]
    async fn drain_force_delivers_every_event_even_past_channel_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let bcfg = BufferConfig {
            dir: None,
            max_size_mb: 64,
            segment_size_mb: 8,
            full_policy: FullPolicy::Block,
        };
        let queue = DiskQueue::open(dir.path(), "dest", &bcfg).unwrap();

        // Capacity 4 (vs. the real ROUTER_CAPACITY of 4096) so a modest
        // burst reliably exceeds it; the consumer drains one event at a time
        // with a small delay, standing in for a router that is momentarily
        // slower than the rate events arrive at.
        let (rtx, mut rrx) = mpsc::channel::<Arc<Event>>(4);
        let consumer = tokio::spawn(async move {
            let mut delivered = 0u64;
            while let Some(ev) = rrx.recv().await {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                queue.push(&ev).unwrap();
                delivered += 1;
            }
            (delivered, queue)
        });

        let out = test_output("dest");
        let metrics = Metrics::default();
        let status = StatusRegistry::default();
        let shed = Arc::new(AtomicU64::new(0));
        // `rtx` is moved in here (not cloned) so dropping `routers` below is
        // what closes the channel and lets the consumer's `recv()` loop end.
        let routers = vec![(out, None, rtx, shed.clone())];
        let transformer = Transformer::compile(&PipelineConfig::default()).unwrap();
        let enricher = Enricher::new(&EnrichConfig::default());

        const N: usize = 50; // well past the channel's capacity of 4
        for i in 0..N {
            let ev = Event::new("test", "raw", &format!("drain-{i}"));
            route_event(
                ev,
                &transformer,
                &enricher,
                &routers,
                &status,
                &metrics,
                true,
            )
            .await;
        }
        drop(routers);
        let (delivered, queue) = consumer.await.unwrap();

        assert_eq!(
            delivered, N as u64,
            "every event handed to the force-deliver drain path must reach the router, \
             not just as many as fit in the channel at once"
        );
        assert_eq!(
            queue.len(),
            N as u64,
            "every drained event must actually land in the destination's disk queue"
        );
        assert_eq!(
            shed.load(Ordering::Relaxed),
            0,
            "the force-deliver path must never shed - that counter is for the \
             non-blocking hot path only"
        );
    }

    /// Contrast case: the normal hot path (`force_deliver: false`) sheds
    /// once the router channel is genuinely full, exactly as round 1 fixed
    /// it to do. This pins that behavior so a future change cannot silently
    /// make the hot path force-deliver too (which would reopen the
    /// isolation bug this whole task exists to prevent).
    #[tokio::test]
    async fn hot_path_still_sheds_on_a_full_channel() {
        // Capacity 1 and no consumer at all: the first send fills the
        // channel, the second must be shed immediately rather than waiting.
        let (rtx, _rrx) = mpsc::channel::<Arc<Event>>(1);
        let out = test_output("dest");
        let metrics = Metrics::default();
        let status = StatusRegistry::default();
        let shed = Arc::new(AtomicU64::new(0));
        let routers = vec![(out, None, rtx, shed.clone())];
        let transformer = Transformer::compile(&PipelineConfig::default()).unwrap();
        let enricher = Enricher::new(&EnrichConfig::default());

        for i in 0..5 {
            let ev = Event::new("test", "raw", &format!("hot-{i}"));
            route_event(
                ev,
                &transformer,
                &enricher,
                &routers,
                &status,
                &metrics,
                false,
            )
            .await;
        }

        assert!(
            shed.load(Ordering::Relaxed) > 0,
            "a full channel must shed on the non-blocking hot path, not wait"
        );
        assert_eq!(
            metrics.events_dropped.load(Ordering::Relaxed),
            shed.load(Ordering::Relaxed),
            "the aggregate dropped counter and the per-destination shed counter \
             must agree when shedding is the only drop cause in play"
        );
    }
}
