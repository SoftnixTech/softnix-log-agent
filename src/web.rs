//! Minimal web GUI + JSON API. Single embedded HTML page, no frontend
//! framework, no build step — appliance-style.

use crate::config::{self, WebConfig};
use crate::engine::EngineShared;
use crate::event::AGENT_VERSION;
use crate::logbuf::LogBuffer;
use crate::metrics::Uptime;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_util::sync::CancellationToken;

const UI_HTML: &str = include_str!("ui.html");

/// Commands the web UI sends to the main control loop.
pub enum ControlMsg {
    Reload {
        resp: oneshot::Sender<Result<(), String>>,
    },
    Rollback {
        resp: oneshot::Sender<Result<(), String>>,
    },
}

pub struct AppState {
    pub engine: RwLock<Option<Arc<EngineShared>>>,
    pub logs: LogBuffer,
    pub config_path: PathBuf,
    pub control: mpsc::Sender<ControlMsg>,
    pub uptime: Uptime,
    pub auth_token: Option<String>,
}

type S = State<Arc<AppState>>;

pub async fn serve(
    web_cfg: WebConfig,
    state: Arc<AppState>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let addr = format!("{}:{}", web_cfg.bind, web_cfg.port);
    let app = Router::new()
        .route("/", get(ui))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_text))
        .route("/api/status", get(api_status))
        .route("/api/inputs", get(api_inputs))
        .route("/api/outputs", get(api_outputs))
        .route("/api/buffer", get(api_buffer))
        .route("/api/logs", get(api_logs))
        .route("/api/about", get(api_about))
        .route("/api/config", get(api_config_get))
        .route("/api/config/validate", post(api_config_validate))
        .route("/api/config/save", post(api_config_save))
        .route("/api/config/reload", post(api_config_reload))
        .route("/api/config/rollback", post(api_config_rollback))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("web GUI listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await?;
    Ok(())
}

fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    if let Some(token) = &state.auth_token {
        let supplied = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .or_else(|| headers.get("x-auth-token").and_then(|v| v.to_str().ok()));
        if supplied != Some(token.as_str()) {
            return Err(Box::new(
                (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
            ));
        }
    }
    Ok(())
}

async fn ui() -> Html<&'static str> {
    Html(UI_HTML)
}

async fn healthz(State(state): S) -> Response {
    let engine = state.engine.read().await;
    match engine.as_ref() {
        Some(_) => (StatusCode::OK, Json(json!({"status": "ok"}))).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "engine not running"})),
        )
            .into_response(),
    }
}

async fn metrics_text(State(state): S) -> Response {
    let engine = state.engine.read().await;
    let Some(eng) = engine.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "engine not running").into_response();
    };
    let m = eng.metrics.snapshot();
    let mut out = String::new();
    out.push_str(&format!(
        "agent_uptime_seconds {}\n",
        state.uptime.seconds()
    ));
    out.push_str(&format!(
        "agent_events_received_total {}\n",
        m.events_received
    ));
    out.push_str(&format!("agent_events_sent_total {}\n", m.events_sent));
    out.push_str(&format!("agent_events_failed_total {}\n", m.events_failed));
    out.push_str(&format!(
        "agent_events_dropped_total {}\n",
        m.events_dropped
    ));
    out.push_str(&format!("agent_errors_total {}\n", m.errors));
    for (id, q) in &eng.queues {
        out.push_str(&format!(
            "agent_queue_events{{destination=\"{id}\"}} {}\n",
            q.len()
        ));
        out.push_str(&format!(
            "agent_queue_bytes{{destination=\"{id}\"}} {}\n",
            q.bytes()
        ));
        out.push_str(&format!(
            "agent_queue_dropped_total{{destination=\"{id}\"}} {}\n",
            q.dropped()
        ));
    }
    for o in eng.status.outputs_snapshot() {
        out.push_str(&format!(
            "agent_output_healthy{{destination=\"{}\"}} {}\n",
            o.id,
            u8::from(o.healthy)
        ));
    }
    out.into_response()
}

async fn api_status(State(state): S) -> Response {
    let engine = state.engine.read().await;
    let Some(eng) = engine.as_ref() else {
        return Json(json!({"running": false, "version": AGENT_VERSION})).into_response();
    };
    let m = eng.metrics.snapshot();
    let queue_events: u64 = eng.queues.values().map(|q| q.len()).sum();
    let queue_bytes: u64 = eng.queues.values().map(|q| q.bytes()).sum();
    let outputs: Vec<_> = eng
        .status
        .outputs_snapshot()
        .into_iter()
        .map(|o| json!({"id": o.id, "healthy": o.healthy, "connected": o.connected}))
        .collect();
    Json(json!({
        "running": true,
        "version": AGENT_VERSION,
        "uptime_seconds": state.uptime.seconds(),
        "events_received": m.events_received,
        "events_sent": m.events_sent,
        "events_failed": m.events_failed,
        "events_dropped": m.events_dropped,
        "errors": m.errors,
        "last_error": m.last_error,
        "queue_events": queue_events,
        "queue_bytes": queue_bytes,
        "destinations": outputs,
    }))
    .into_response()
}

async fn api_inputs(State(state): S) -> Response {
    let engine = state.engine.read().await;
    match engine.as_ref() {
        Some(eng) => Json(eng.status.inputs_snapshot()).into_response(),
        None => Json(json!([])).into_response(),
    }
}

async fn api_outputs(State(state): S) -> Response {
    let engine = state.engine.read().await;
    match engine.as_ref() {
        Some(eng) => Json(eng.status.outputs_snapshot()).into_response(),
        None => Json(json!([])).into_response(),
    }
}

async fn api_buffer(State(state): S) -> Response {
    let engine = state.engine.read().await;
    let Some(eng) = engine.as_ref() else {
        return Json(json!([])).into_response();
    };
    let mut out = Vec::new();
    let mut ids: Vec<_> = eng.queues.keys().cloned().collect();
    ids.sort();
    for id in ids {
        let q = &eng.queues[&id];
        out.push(json!({
            "destination": id,
            "events": q.len(),
            "bytes": q.bytes(),
            "max_bytes": q.max_bytes(),
            "usage_percent": (q.bytes() as f64 / q.max_bytes() as f64 * 100.0).round(),
            "oldest_event_age_seconds": q.oldest_age_secs(),
            "dropped_events": q.dropped(),
        }));
    }
    Json(out).into_response()
}

#[derive(serde::Deserialize)]
struct LogsQuery {
    #[serde(default)]
    level: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    100
}

async fn api_logs(State(state): S, Query(q): Query<LogsQuery>) -> Response {
    Json(state.logs.recent(q.limit.min(500), q.level.as_deref())).into_response()
}

async fn api_about(State(state): S) -> Response {
    let engine = state.engine.read().await;
    let state_path = engine
        .as_ref()
        .map(|e| e.state.path().display().to_string());
    Json(json!({
        "name": "Softnix Log Agent",
        "version": AGENT_VERSION,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "hostname": hostname::get().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default(),
        "config_path": state.config_path.display().to_string(),
        "state_path": state_path,
        "pid": std::process::id(),
    }))
    .into_response()
}

async fn api_config_get(State(state): S, headers: HeaderMap) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return *r;
    }
    match std::fs::read_to_string(&state.config_path) {
        Ok(text) => Json(json!({"path": state.config_path.display().to_string(), "content": text}))
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct ConfigBody {
    content: String,
}

async fn api_config_validate(
    State(state): S,
    headers: HeaderMap,
    Json(body): Json<ConfigBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return *r;
    }
    match config::parse(&body.content) {
        Ok((_cfg, warnings)) => Json(json!({"valid": true, "warnings": warnings})).into_response(),
        Err(e) => Json(json!({"valid": false, "error": format!("{e:#}")})).into_response(),
    }
}

async fn api_config_save(
    State(state): S,
    headers: HeaderMap,
    Json(body): Json<ConfigBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return *r;
    }
    // Always validate before persisting.
    let warnings = match config::parse(&body.content) {
        Ok((_cfg, w)) => w,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"saved": false, "error": format!("{e:#}")})),
            )
                .into_response();
        }
    };
    // Backup current config, then write the new one.
    let backup = state.config_path.with_extension("yaml.bak");
    if state.config_path.exists() {
        if let Err(e) = std::fs::copy(&state.config_path, &backup) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"saved": false, "error": format!("backup failed: {e}")})),
            )
                .into_response();
        }
    }
    if let Err(e) = std::fs::write(&state.config_path, &body.content) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"saved": false, "error": e.to_string()})),
        )
            .into_response();
    }
    Json(json!({"saved": true, "warnings": warnings, "backup": backup.display().to_string()}))
        .into_response()
}

async fn api_config_reload(State(state): S, headers: HeaderMap) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return *r;
    }
    let (tx, rx) = oneshot::channel();
    if state
        .control
        .send(ControlMsg::Reload { resp: tx })
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, "control channel closed").into_response();
    }
    match rx.await {
        Ok(Ok(())) => Json(json!({"reloaded": true})).into_response(),
        Ok(Err(e)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"reloaded": false, "error": e})),
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "reload did not complete").into_response(),
    }
}

async fn api_config_rollback(State(state): S, headers: HeaderMap) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return *r;
    }
    let (tx, rx) = oneshot::channel();
    if state
        .control
        .send(ControlMsg::Rollback { resp: tx })
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, "control channel closed").into_response();
    }
    match rx.await {
        Ok(Ok(())) => Json(json!({"rolled_back": true})).into_response(),
        Ok(Err(e)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"rolled_back": false, "error": e})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "rollback did not complete",
        )
            .into_response(),
    }
}
