//! Engine: wires inputs → pipeline → per-destination queues → outputs.
//! The engine is fully restartable, which is how config reload works.

use crate::buffer::{DiskQueue, PushOutcome};
use crate::config::{Config, FullPolicy, OutputConfig};
use crate::event::Event;
use crate::inputs::{file::FileInput, syslog::SyslogInput};
use crate::metrics::{Metrics, StatusRegistry};
use crate::outputs::OutputWorker;
use crate::pipeline::{eval_condition, Enricher, Transformer};
use crate::state::StateManager;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const CHANNEL_CAPACITY: usize = 8192;
/// Capacity of each per-destination router channel. Small on purpose: it is
/// only meant to absorb transient bursts between the pipeline and a router,
/// not to let one slow destination buffer memory unboundedly on top of its
/// own on-disk queue.
const ROUTER_CAPACITY: usize = 256;

/// Everything the web UI needs to observe a running engine.
pub struct EngineShared {
    pub config: Config,
    pub metrics: Arc<Metrics>,
    pub status: Arc<StatusRegistry>,
    pub queues: HashMap<String, Arc<DiskQueue>>,
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
        let mut routers: Vec<(OutputConfig, mpsc::Sender<Arc<Event>>)> = Vec::new();
        for out in &cfg.outputs {
            let (rtx, rrx) = mpsc::channel::<Arc<Event>>(ROUTER_CAPACITY);
            let policy = out.full_policy.unwrap_or(cfg.buffer.full_policy);
            let block = policy == FullPolicy::Block;
            tasks.push(tokio::spawn(run_router(
                rrx,
                out.clone(),
                queues[&out.id].clone(),
                block,
                metrics.clone(),
                cancel.child_token(),
            )));
            routers.push((out.clone(), rtx));
        }

        // Pipeline task: transform, enrich, fan out to the per-destination
        // routers. It no longer awaits any push itself, so a stuck destination
        // cannot stall delivery to its siblings.
        let (tx, rx) = mpsc::channel::<Event>(CHANNEL_CAPACITY);
        let transformer = Transformer::compile(&cfg.pipeline)?;
        let enricher = Enricher::new(&cfg.pipeline.enrich);
        tasks.push(tokio::spawn(run_pipeline(
            rx,
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
                    metrics
                        .events_dropped
                        .fetch_add(evicted, std::sync::atomic::Ordering::Relaxed);
                }
            }
            Ok(PushOutcome::Dropped) | Ok(PushOutcome::Full) => {
                metrics
                    .events_dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                metrics.record_error(format!("queue {} write: {e}", out.id));
            }
        }
    }
}

/// Transform → normalize → enrich → fan out to the per-destination routers.
async fn run_pipeline(
    mut rx: mpsc::Receiver<Event>,
    transformer: Transformer,
    enricher: Enricher,
    routers: Vec<(OutputConfig, mpsc::Sender<Arc<Event>>)>,
    status: Arc<StatusRegistry>,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
) {
    loop {
        let ev = tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => ev,
                None => return,
            },
            _ = cancel.cancelled() => {
                // Drain whatever is already in the channel before exiting.
                while let Ok(ev) = rx.try_recv() {
                    route_event(ev, &transformer, &enricher, &routers, &status, &metrics).await;
                }
                return;
            }
        };
        route_event(ev, &transformer, &enricher, &routers, &status, &metrics).await;
    }
}

async fn route_event(
    mut ev: Event,
    transformer: &Transformer,
    enricher: &Enricher,
    routers: &[(OutputConfig, mpsc::Sender<Arc<Event>>)],
    status: &StatusRegistry,
    metrics: &Metrics,
) {
    if !transformer.apply(&mut ev) {
        metrics
            .events_dropped
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return;
    }
    enricher.apply(&mut ev);

    let ev = Arc::new(ev);
    for (out, tx) in routers {
        // Standby outputs only receive traffic while their primary is down.
        if let Some(primary) = &out.failover_for {
            if status.output_healthy(primary) {
                continue;
            }
        }
        if let Some(cond) = &out.when {
            if !eval_condition(cond, &ev) {
                continue;
            }
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
                metrics
                    .events_dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                metrics.record_error(format!("router {} closed", out.id));
            }
        }
    }
}
