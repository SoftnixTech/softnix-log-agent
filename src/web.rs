//! Minimal web GUI + JSON API. Single embedded HTML page, no frontend
//! framework, no build step — appliance-style.

use crate::config::{self, WebConfig};
use crate::engine::EngineShared;
use crate::event::AGENT_VERSION;
use crate::logbuf::LogBuffer;
use crate::metrics::Uptime;
use anyhow::Context;
use axum::extract::{Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
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
    pub auth_token: String,
}

type S = State<Arc<AppState>>;

pub async fn serve(
    web_cfg: WebConfig,
    state: Arc<AppState>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let addr = format!("{}:{}", web_cfg.bind, web_cfg.port);
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("web GUI listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await?;
    Ok(())
}

/// Build the router. Split out of `serve` so tests can drive it directly.
pub fn router(state: Arc<AppState>) -> Router {
    // /healthz is deliberately outside the auth layer: it is the liveness probe
    // for systemd, Kubernetes and the customer's monitoring, and carries no data.
    let public = Router::new()
        .route("/healthz", get(healthz))
        .with_state(state.clone());

    let guarded = Router::new()
        .route("/", get(ui))
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
        .layer(middleware::from_fn_with_state(state.clone(), auth_layer))
        .with_state(state);

    public.merge(guarded)
}

async fn auth_layer(State(state): S, req: Request, next: Next) -> Response {
    let supplied = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| {
            req.headers()
                .get("x-auth-token")
                .and_then(|v| v.to_str().ok())
        })
        .unwrap_or("");
    if !constant_time_eq(supplied.as_bytes(), state.auth_token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    next.run(req).await
}

/// Length-independent, short-circuit-free comparison (audit L-2).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 32 bytes of OS entropy, hex-encoded.
pub fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The configured token, or a persistent one under the data dir.
pub fn resolve_token(cfg: &WebConfig, data_dir: &std::path::Path) -> anyhow::Result<String> {
    if let Some(t) = &cfg.auth_token {
        return Ok(t.clone());
    }
    let path = data_dir.join("web-token");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let t = existing.trim().to_string();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    let token = generate_token();
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("cannot create data dir {}", data_dir.display()))?;
    crate::fsutil::write_atomic(&path, token.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::warn!(
        "web.auth_token was not configured; generated one and stored it at {} \
         (read it with: cat {})",
        path.display(),
        path.display()
    );
    Ok(token)
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

async fn api_config_get(State(state): S) -> Response {
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

async fn api_config_validate(Json(body): Json<ConfigBody>) -> Response {
    match config::parse(&body.content) {
        Ok((_cfg, warnings)) => Json(json!({"valid": true, "warnings": warnings})).into_response(),
        Err(e) => Json(json!({"valid": false, "error": format!("{e:#}")})).into_response(),
    }
}

async fn api_config_save(State(state): S, Json(body): Json<ConfigBody>) -> Response {
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

async fn api_config_reload(State(state): S) -> Response {
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

async fn api_config_rollback(State(state): S) -> Response {
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state(token: &str) -> Arc<AppState> {
        let (control, _rx) = mpsc::channel(1);
        Arc::new(AppState {
            engine: RwLock::new(None),
            logs: LogBuffer::default(),
            config_path: PathBuf::from("/nonexistent/agent.yaml"),
            control,
            uptime: Uptime::default(),
            auth_token: token.to_string(),
        })
    }

    #[tokio::test]
    async fn healthz_is_the_only_unauthenticated_route() {
        let app = router(test_state("secret-token"));
        let guarded = [
            "/metrics",
            "/api/status",
            "/api/inputs",
            "/api/outputs",
            "/api/buffer",
            "/api/logs",
            "/api/about",
            "/api/config",
        ];
        for path in guarded {
            let res = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{path} was open");
        }
        let res = app
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_ne!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_valid_bearer_token_is_accepted() {
        let app = router(test_state("secret-token"));
        let res = app
            .oneshot(
                Request::get("/api/about")
                    .header("authorization", "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[test]
    fn generated_tokens_are_long_and_unique() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }
}
