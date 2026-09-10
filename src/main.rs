//! Softnix Log Agent — lightweight, reliable, cross-platform log collector.

use anyhow::{Context, Result};
#[cfg(windows)]
use anyhow::bail;
use clap::{Parser, Subcommand};
use engine::Engine;
use logbuf::{LogBuffer, LogBufferLayer};
use softnix_log_agent::{config, engine, event, logbuf, metrics, service, web};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use web::{AppState, ControlMsg};

#[derive(Parser)]
#[command(
    name = "softnix-log-agent",
    version,
    about = "Softnix Log Agent — lightweight log collector"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent in the foreground (default).
    Run {
        #[arg(short, long, default_value = "agent.yaml")]
        config: PathBuf,
    },
    /// Validate a configuration file and exit.
    Validate {
        #[arg(short, long, default_value = "agent.yaml")]
        config: PathBuf,
    },
    /// Manage the OS service (systemd / Windows Service).
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Internal: entry point used by the Windows Service Control Manager.
    #[command(hide = true)]
    ServiceRun {
        #[arg(short, long, default_value = "agent.yaml")]
        config: PathBuf,
    },
    /// Apply a self-contained update artifact (offline, no network access).
    Upgrade {
        /// Path to a downloaded/copied release artifact (.tar.gz on Linux).
        /// Required unless `--rollback` is passed.
        #[arg(long, required_unless_present = "rollback")]
        from: Option<PathBuf>,
        /// Roll back to the previously retained version instead of applying `--from`.
        #[arg(long)]
        rollback: bool,
        /// Allow installing a version older than the one currently running.
        #[arg(long)]
        allow_downgrade: bool,
        #[arg(short, long, default_value = "agent.yaml")]
        config: PathBuf,
    },
    /// Internal: runs inside the self-relaunched temp copy on Windows to
    /// drive the actual MSI install. Not intended to be run directly:
    /// performs zero verification of its own and trusts `--msi` completely
    /// (verification already happened in the parent process that spawned
    /// this one).
    #[cfg(windows)]
    #[command(hide = true)]
    UpgradeApply {
        #[arg(long)]
        msi: PathBuf,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Install and enable the service.
    Install {
        #[arg(short, long, default_value = "/etc/softnix-log-agent/agent.yaml")]
        config: String,
    },
    /// Stop and remove the service.
    Uninstall,
    Start,
    Stop,
    Restart,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Validate { config }) => validate_cmd(&config),
        Some(Command::Service { action }) => match action {
            ServiceAction::Install { config } => service::install(&config),
            ServiceAction::Uninstall => service::uninstall(),
            ServiceAction::Start => service::start(),
            ServiceAction::Stop => service::stop(),
            ServiceAction::Restart => service::restart(),
        },
        Some(Command::ServiceRun { config }) => run_as_windows_service(config),
        Some(Command::Upgrade {
            from,
            rollback,
            allow_downgrade,
            config,
        }) => upgrade_cmd(from.as_deref(), rollback, allow_downgrade, &config),
        #[cfg(windows)]
        Some(Command::UpgradeApply { msi }) => {
            softnix_log_agent::update::apply_windows::apply_msi(&msi)
        }
        Some(Command::Run { config }) => run_foreground(config),
        None => run_foreground(PathBuf::from("agent.yaml")),
    }
}

fn validate_cmd(path: &Path) -> Result<()> {
    match config::load(path) {
        Ok((_cfg, warnings)) => {
            println!("OK: {} is valid", path.display());
            for w in warnings {
                println!("warning: {w}");
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("INVALID: {e:#}");
            std::process::exit(1);
        }
    }
}

fn upgrade_cmd(from: Option<&Path>, rollback: bool, allow_downgrade: bool, config_path: &Path) -> Result<()> {
    let (cfg, _warnings) = config::load(config_path).context("cannot load config for upgrade")?;
    let live_target = std::env::current_exe().context("cannot resolve the running binary's path")?;

    #[cfg(windows)]
    {
        if rollback {
            bail!("Windows rollback is not yet automated by this CLI; see docs/RELEASE-SIGNING.md's Windows rollback runbook (msiexec /x then /i)");
        }
        let from = from.context("--from is required unless --rollback is passed")?;
        return softnix_log_agent::update::apply_windows::self_relaunch_and_apply(
            from,
            config_path,
            &cfg.agent.data_dir,
            allow_downgrade,
        );
    }

    #[cfg(not(windows))]
    {
        if rollback {
            softnix_log_agent::update::apply::rollback_from_local(&live_target, &cfg.agent.data_dir)
        } else {
            let from = from.context("--from is required unless --rollback is passed")?;
            softnix_log_agent::update::apply::apply_from_local(
                from,
                config_path,
                &cfg.agent.data_dir,
                allow_downgrade,
                &live_target,
            )
        }
    }
}

fn run_foreground(config: PathBuf) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(run_agent(config, None))
}

#[cfg(windows)]
fn run_as_windows_service(config: PathBuf) -> Result<()> {
    use std::sync::Mutex;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    static CONFIG: Mutex<Option<PathBuf>> = Mutex::new(None);
    *CONFIG.lock().unwrap() = Some(config);

    windows_service::define_windows_service!(ffi_service_main, service_main);

    fn service_main(_args: Vec<std::ffi::OsString>) {
        let config = CONFIG.lock().unwrap().clone().unwrap();
        let shutdown = CancellationToken::new();
        let shutdown_for_handler = shutdown.clone();

        let status_handle = service_control_handler::register(
            service::SERVICE_NAME,
            move |control| match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    shutdown_for_handler.cancel();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )
        .expect("cannot register service control handler");

        let running = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        };
        status_handle.set_service_status(running.clone()).ok();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("cannot start runtime");
        let result = runtime.block_on(run_agent(config, Some(shutdown)));

        status_handle
            .set_service_status(ServiceStatus {
                current_state: ServiceState::Stopped,
                exit_code: ServiceExitCode::Win32(u32::from(result.is_err())),
                controls_accepted: ServiceControlAccept::empty(),
                ..running
            })
            .ok();
    }

    windows_service::service_dispatcher::start(service::SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(not(windows))]
fn run_as_windows_service(config: PathBuf) -> Result<()> {
    // On non-Windows, behave like `run` so the hidden command is harmless.
    run_foreground(config)
}

/// Core agent: logging, web server, engine lifecycle, reload/rollback loop.
async fn run_agent(
    config_path: PathBuf,
    external_shutdown: Option<CancellationToken>,
) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let (cfg, warnings) =
        config::load(&config_path).context("configuration error (fix it or run `validate`)")?;
    config::check_config_permissions(&config_path)
        .context("configuration error (fix it or run `validate`)")?;

    // Tracing: stderr + in-memory ring buffer for the web UI.
    let log_buffer = LogBuffer::default();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cfg.agent.log_level));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(LogBufferLayer(log_buffer.clone()))
        .init();

    tracing::info!(
        "Softnix Log Agent v{} starting (config: {})",
        event::AGENT_VERSION,
        config_path.display()
    );
    for w in &warnings {
        tracing::warn!("{w}");
    }

    let shutdown = external_shutdown.unwrap_or_default();
    let (control_tx, mut control_rx) = mpsc::channel::<ControlMsg>(4);
    // DNS rebinding protection: the only hostnames a legitimate browser
    // request for this agent's own GUI can carry in Host/Origin (audit H-1).
    let allowed_hosts = vec![
        format!("{}:{}", cfg.web.bind, cfg.web.port),
        format!("localhost:{}", cfg.web.port),
        format!("127.0.0.1:{}", cfg.web.port),
    ];
    // DNS rebinding requires the real server to actually be on loopback —
    // once an operator explicitly binds non-loopback, `config::validate`
    // already forces a real `web.auth_token`, and that token becomes the
    // security boundary instead of same-origin. `.unwrap_or(false)` is a
    // defensive fallback for a bind value that somehow fails to parse as an
    // IP here; `config::validate` will already have rejected a genuinely
    // invalid `web.bind` before this point in normal operation.
    let host_check_enabled = cfg
        .web
        .bind
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false);
    let app_state = Arc::new(AppState {
        engine: tokio::sync::RwLock::new(None),
        logs: log_buffer,
        config_path: config_path.clone(),
        control: control_tx,
        uptime: metrics::Uptime::default(),
        auth_token: web::resolve_token(&cfg.web, &cfg.agent.data_dir)?,
        allowed_hosts,
        host_check_enabled,
    });

    // Web server lives outside the engine so it survives reloads.
    let web_cancel = shutdown.child_token();
    let mut web_task = None;
    if cfg.web.enabled {
        let st = app_state.clone();
        let web_cfg = cfg.web.clone();
        let cancel = web_cancel.clone();
        web_task = Some(tokio::spawn(async move {
            if let Err(e) = web::serve(web_cfg, st, cancel).await {
                tracing::error!("web server failed: {e:#}");
            }
        }));
    }

    // Start the engine.
    let mut engine = Engine::start(cfg).await.context("engine startup failed")?;
    *app_state.engine.write().await = Some(engine.shared.clone());

    // Control loop: shutdown signals, SIGHUP, and web-triggered reloads.
    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        #[cfg(unix)]
        let term = sigterm.recv();
        #[cfg(not(unix))]
        let term = std::future::pending::<Option<()>>();

        #[cfg(unix)]
        let hup = sighup.recv();
        #[cfg(not(unix))]
        let hup = std::future::pending::<Option<()>>();

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl-C; shutting down");
                break;
            }
            _ = term => {
                tracing::info!("received SIGTERM; shutting down");
                break;
            }
            _ = hup => {
                tracing::info!("received SIGHUP; reloading configuration");
                engine = do_reload(engine, &app_state, &config_path).await?;
            }
            _ = shutdown.cancelled() => {
                tracing::info!("shutdown requested; stopping");
                break;
            }
            msg = control_rx.recv() => {
                match msg {
                    Some(ControlMsg::Reload { resp }) => {
                        let (new_engine, result) = try_reload(engine, &app_state, &config_path).await?;
                        engine = new_engine;
                        let _ = resp.send(result);
                    }
                    Some(ControlMsg::Rollback { resp }) => {
                        let backup = config_path.with_extension("yaml.bak");
                        let result = if backup.is_file() {
                            match std::fs::copy(&backup, &config_path) {
                                Ok(_) => {
                                    let (new_engine, result) = try_reload(engine, &app_state, &config_path).await?;
                                    engine = new_engine;
                                    result
                                }
                                Err(e) => Err(format!("cannot restore backup: {e}")),
                            }
                        } else {
                            Err(format!("no backup found at {}", backup.display()))
                        };
                        let _ = resp.send(result);
                    }
                    None => break,
                }
            }
        }
    }

    // Graceful shutdown.
    *app_state.engine.write().await = None;
    engine.stop().await;
    web_cancel.cancel();
    if let Some(t) = web_task {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), t).await;
    }
    tracing::info!("agent stopped");
    Ok(())
}

/// Reload used by SIGHUP: log failures but keep running on the old config.
async fn do_reload(
    engine: Engine,
    app_state: &Arc<AppState>,
    config_path: &PathBuf,
) -> Result<Engine> {
    let (engine, result) = try_reload(engine, app_state, config_path).await?;
    if let Err(e) = result {
        tracing::error!("reload failed: {e}");
    }
    Ok(engine)
}

/// Stop the engine and restart with the on-disk config. On failure, restore
/// the backup config (if any) and bring the previous configuration back up.
async fn try_reload(
    engine: Engine,
    app_state: &Arc<AppState>,
    config_path: &PathBuf,
) -> Result<(Engine, Result<(), String>)> {
    let old_cfg = engine.shared.config.clone();

    let new_cfg = match config::load(config_path) {
        Ok((cfg, warnings)) => {
            if let Err(e) = config::check_config_permissions(config_path) {
                return Ok((engine, Err(format!("{e:#}"))));
            }
            for w in &warnings {
                tracing::warn!("{w}");
            }
            cfg
        }
        Err(e) => {
            // Config invalid: keep running untouched.
            return Ok((engine, Err(format!("{e:#}"))));
        }
    };

    *app_state.engine.write().await = None;
    engine.stop().await;

    match Engine::start(new_cfg).await {
        Ok(new_engine) => {
            *app_state.engine.write().await = Some(new_engine.shared.clone());
            tracing::info!("configuration reloaded");
            Ok((new_engine, Ok(())))
        }
        Err(e) => {
            tracing::error!("new configuration failed to start: {e:#}; restoring previous config");
            // Restore previous config file from backup if it exists.
            let backup = config_path.with_extension("yaml.bak");
            if backup.is_file() {
                std::fs::copy(&backup, config_path).ok();
            }
            let old_engine = Engine::start(old_cfg)
                .await
                .context("FATAL: could not restart previous configuration")?;
            *app_state.engine.write().await = Some(old_engine.shared.clone());
            Ok((
                old_engine,
                Err(format!("{e:#} (previous configuration restored)")),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_rollback_parses_without_from() {
        let cli = Cli::try_parse_from(["softnix-log-agent", "upgrade", "--rollback"]).unwrap();
        match cli.command {
            Some(Command::Upgrade { from, rollback, .. }) => {
                assert!(from.is_none());
                assert!(rollback);
            }
            _ => panic!("expected Command::Upgrade"),
        }
    }

    #[test]
    fn upgrade_without_from_or_rollback_fails_to_parse() {
        let result = Cli::try_parse_from(["softnix-log-agent", "upgrade"]);
        assert!(result.is_err());
    }
}
