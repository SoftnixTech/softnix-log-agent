//! Engine: wires inputs → pipeline → per-destination queues → outputs.
//! The engine is fully restartable, which is how config reload works.

use crate::buffer::{DiskQueue, PushOutcome};
use crate::config::{Config, FullPolicy};
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
        let data_dir = &cfg.agent.data_dir;
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("cannot create data dir {}", data_dir.display()))?;
        let state = Arc::new(StateManager::open(data_dir)?);
        let metrics = Arc::new(Metrics::default());
        let status = Arc::new(StatusRegistry::default());
        let cancel = CancellationToken::new();
        let mut tasks = Vec::new();

        // Per-destination persistent queues.
        let queue_dir = cfg
            .buffer
            .dir
            .clone()
            .unwrap_or_else(|| data_dir.join("queue"));
        let mut queues: HashMap<String, Arc<DiskQueue>> = HashMap::new();
        for out in &cfg.outputs {
            let q = DiskQueue::open(&queue_dir, &out.id, &cfg.buffer)
                .with_context(|| format!("cannot open queue for output {}", out.id))?;
            queues.insert(out.id.clone(), q);
        }

        // Output workers.
        for out in &cfg.outputs {
            let worker = OutputWorker::new(out, queues[&out.id].clone())?;
            tasks.push(worker.spawn(status.clone(), metrics.clone(), cancel.child_token()));
        }

        // Pipeline task.
        let (tx, rx) = mpsc::channel::<Event>(CHANNEL_CAPACITY);
        let transformer = Transformer::compile(&cfg.pipeline)?;
        let enricher = Enricher::new(&cfg.pipeline.enrich);
        tasks.push(tokio::spawn(run_pipeline(
            rx,
            transformer,
            enricher,
            cfg.clone(),
            queues.clone(),
            status.clone(),
            metrics.clone(),
            cancel.child_token(),
        )));

        // Inputs (binds happen before spawn so startup errors are surfaced).
        for s in &cfg.inputs.syslog {
            let input = SyslogInput::new(s);
            let handle = input
                .spawn(tx.clone(), status.clone(), metrics.clone(), cancel.child_token())
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

        Ok(Engine {
            shared: Arc::new(EngineShared {
                config: cfg,
                metrics,
                status,
                queues,
                state,
            }),
            cancel,
            tasks,
        })
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

/// Transform → normalize → enrich → route into destination queues.
#[allow(clippy::too_many_arguments)]
async fn run_pipeline(
    mut rx: mpsc::Receiver<Event>,
    transformer: Transformer,
    enricher: Enricher,
    cfg: Config,
    queues: HashMap<String, Arc<DiskQueue>>,
    status: Arc<StatusRegistry>,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
) {
    let block = cfg.buffer.full_policy == FullPolicy::Block;
    loop {
        let ev = tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => ev,
                None => return,
            },
            _ = cancel.cancelled() => {
                // Drain whatever is already in the channel before exiting.
                while let Ok(ev) = rx.try_recv() {
                    route_event(ev, &transformer, &enricher, &cfg, &queues, &status, &metrics, None).await;
                }
                return;
            }
        };
        route_event(
            ev,
            &transformer,
            &enricher,
            &cfg,
            &queues,
            &status,
            &metrics,
            if block { Some(&cancel) } else { None },
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn route_event(
    mut ev: Event,
    transformer: &Transformer,
    enricher: &Enricher,
    cfg: &Config,
    queues: &HashMap<String, Arc<DiskQueue>>,
    status: &StatusRegistry,
    metrics: &Metrics,
    block_cancel: Option<&CancellationToken>,
) {
    if !transformer.apply(&mut ev) {
        metrics
            .events_dropped
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return;
    }
    enricher.apply(&mut ev);

    for out in &cfg.outputs {
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
        let Some(q) = queues.get(&out.id) else { continue };
        let result = match block_cancel {
            Some(cancel) => q.push_blocking(&ev, cancel).await.map(|stored| {
                if stored {
                    PushOutcome::Stored { evicted: 0 }
                } else {
                    PushOutcome::Dropped
                }
            }),
            None => q.push(&ev),
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
