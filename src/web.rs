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
    pub allowed_hosts: Vec<String>,
    /// Whether the Host/Origin allowlist below is enforced. DNS rebinding's
    /// entire premise is tricking a browser into treating an attacker's page
    /// as same-origin with a LOOPBACK-bound service — the attack requires the
    /// real server to actually be on loopback. Once an operator explicitly
    /// binds non-loopback, `config::validate` already forces a real
    /// `web.auth_token`, and that token is the actual security boundary, not
    /// same-origin — so the Host/Origin checks are skipped entirely in that
    /// mode rather than 403ing every legitimate remote-admin request.
    pub host_check_enabled: bool,
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
    //
    // / is also public: it serves UI_HTML, a compile-time constant with no
    // server-side interpolation of config, secrets or runtime state. It must be
    // reachable without a token because a browser's plain navigation to
    // /#token=<t> never sends the fragment to the server — the embedded JS that
    // reads the fragment and retries with it can't run if the shell itself 401s.
    // Every route that actually reads or mutates state stays guarded below.
    let public = Router::new()
        .route("/", get(ui))
        .route("/healthz", get(healthz))
        .with_state(state.clone());

    let guarded = Router::new()
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
    // DNS rebinding: an attacker page whose hostname resolves to 127.0.0.1 is
    // same-origin from the browser's point of view, so the Host header is the
    // only thing that distinguishes it from a real local request. Checked
    // before the token compare so a rebound/cross-origin request never even
    // reaches it (audit H-1).
    //
    // Enforced only when `web.bind` is loopback. DNS rebinding requires the
    // real server to actually be on loopback; once an operator explicitly
    // binds non-loopback, `config::validate` already forces a real
    // `web.auth_token`, and that token becomes the security boundary instead
    // — so both checks are skipped entirely rather than 403ing every request
    // from a remote admin whose Host/Origin can never match this allowlist.
    if state.host_check_enabled {
        let host_ok = match req.headers().get("host").and_then(|v| v.to_str().ok()) {
            None => true, // HTTP/2 requests carry :authority instead
            Some(h) => state
                .allowed_hosts
                .iter()
                .any(|a| a.eq_ignore_ascii_case(h)),
        };
        if !host_ok {
            return (StatusCode::FORBIDDEN, "host not allowed").into_response();
        }

        // Cross-site requests: an Origin from anywhere else is never legitimate
        // for this API. A same-origin fetch either omits Origin or matches our
        // host.
        if let Some(origin) = req.headers().get("origin").and_then(|v| v.to_str().ok()) {
            let origin_host = origin
                .split_once("://")
                .map(|(_, rest)| rest)
                .unwrap_or(origin);
            if !state
                .allowed_hosts
                .iter()
                .any(|a| a.eq_ignore_ascii_case(origin_host))
            {
                return (StatusCode::FORBIDDEN, "cross-origin request rejected").into_response();
            }
        }
    }

    // An empty stored token must never authenticate anything, no matter what
    // is (or isn't) supplied — belt and suspenders against the regression
    // class in `resolve_token`/`config::validate` that let a blank
    // `web.auth_token` slip through (audit C-1).
    if state.auth_token.is_empty() {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    // A missing Authorization/X-Auth-Token header must be rejected outright —
    // it must NOT be treated as an empty supplied token, or an empty
    // configured token would compare `"" == ""` and let every request in
    // unauthenticated (audit C-1).
    let Some(supplied) = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| {
            req.headers()
                .get("x-auth-token")
                .and_then(|v| v.to_str().ok())
        })
    else {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    };
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
    // A blank or all-whitespace configured token (e.g. `auth_token: ${WEB_TOKEN:-}`
    // with WEB_TOKEN unset) is treated as NOT configured — fall through to the
    // file-reuse/generate path below, exactly like a blank token file already
    // is. An empty configured token must never be handed back verbatim (audit C-1).
    if let Some(t) = &cfg.auth_token {
        if !t.trim().is_empty() {
            return Ok(t.clone());
        }
    }
    let path = data_dir.join("web-token");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let t = existing.trim().to_string();
        if !t.is_empty() {
            // Don't silently trust the existing file's permissions — re-assert
            // 0600 on it too. No exposure window here: the content already
            // exists, so rewriting permissions is purely a hardening step
            // (audit I-1).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            return Ok(t);
        }
    }
    let token = generate_token();
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("cannot create data dir {}", data_dir.display()))?;
    write_token_file(&path, token.as_bytes())?;
    tracing::warn!(
        "web.auth_token was not configured; generated one and stored it at {} \
         (read it with: cat {})",
        path.display(),
        path.display()
    );
    Ok(token)
}

/// Write the generated token file with mode 0600 set AT CREATION TIME on
/// Unix, so there is no window where the file exists world/group-readable
/// before a follow-up `set_permissions` call (audit I-1). Falls back to the
/// generic atomic writer (default `OpenOptions` mode) on non-Unix targets.
#[cfg(unix)]
fn write_token_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    let tmp = path.with_extension(match path.extension() {
        Some(ext) => format!("{}.tmp", ext.to_string_lossy()),
        None => "tmp".to_string(),
    });
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        // `.mode(0o600)` above only applies when the open call actually
        // creates the file. If a `.tmp` file survives a prior crash,
        // `.create(true).truncate(true)` reopens and truncates THAT file,
        // inheriting whatever (possibly wider) permissions it already had.
        // Re-assert 0600 unconditionally so the guarantee holds regardless
        // of whether this open created the file or reused a stale one.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_token_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    crate::fsutil::write_atomic(path, bytes)
}

async fn ui() -> Html<&'static str> {
    Html(UI_HTML)
}

async fn healthz(State(state): S) -> Response {
    let engine = state.engine.read().await;
    let Some(eng) = engine.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "engine not running"})),
        )
            .into_response();
    };
    let full: Vec<&String> = eng
        .queues
        .iter()
        .filter(|(_, q)| q.is_full())
        .map(|(id, _)| id)
        .collect();
    if full.is_empty() {
        (StatusCode::OK, Json(json!({"status": "ok"}))).into_response()
    } else {
        // A full queue under `block` means the pipeline is stalled and the host
        // is no longer collecting. Returning 200 here is what let this go
        // unnoticed for hours in the field.
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "degraded", "queues_full": full})),
        )
            .into_response()
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
        out.push_str(&format!(
            "agent_queue_full{{output=\"{id}\"}} {}\n",
            u8::from(q.is_full())
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
        test_state_with_host_check(token, true)
    }

    fn test_state_with_host_check(token: &str, host_check_enabled: bool) -> Arc<AppState> {
        let (control, _rx) = mpsc::channel(1);
        Arc::new(AppState {
            engine: RwLock::new(None),
            logs: LogBuffer::default(),
            config_path: PathBuf::from("/nonexistent/agent.yaml"),
            control,
            uptime: Uptime::default(),
            auth_token: token.to_string(),
            allowed_hosts: vec!["127.0.0.1:8080".to_string(), "localhost:8080".to_string()],
            host_check_enabled,
        })
    }

    /// A minimal JSON body for the two POST routes that deserialize one
    /// (`/api/config/validate`, `/api/config/save`). Built via
    /// `http-body-util` rather than `axum::body::Body::from` so the
    /// dev-dependency is actually exercised (audit I-2).
    fn json_body(json: &'static str) -> Body {
        Body::new(http_body_util::Full::new(axum::body::Bytes::from_static(
            json.as_bytes(),
        )))
    }

    /// All 12 guarded routes — the 8 GET reads plus the 4 POST mutation
    /// endpoints (`/api/config/validate`, `/api/config/save`,
    /// `/api/config/reload`, `/api/config/rollback`) — must 401 with no
    /// Authorization header. The 4 POSTs are the most dangerous to leave
    /// untested: they write config to disk or trigger a reload/rollback
    /// (audit I-2). Only `/` and `/healthz` stay public.
    #[tokio::test]
    async fn all_guarded_routes_reject_missing_auth() {
        let app = router(test_state("secret-token"));
        let guarded_get = [
            "/metrics",
            "/api/status",
            "/api/inputs",
            "/api/outputs",
            "/api/buffer",
            "/api/logs",
            "/api/about",
            "/api/config",
        ];
        for path in guarded_get {
            let res = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{path} was open");
        }

        for path in ["/api/config/validate", "/api/config/save"] {
            let res = app
                .clone()
                .oneshot(
                    Request::post(path)
                        .header("content-type", "application/json")
                        .body(json_body(r#"{"content":""}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{path} was open");
        }

        for path in ["/api/config/reload", "/api/config/rollback"] {
            let res = app
                .clone()
                .oneshot(Request::post(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{path} was open");
        }

        for path in ["/", "/healthz"] {
            let res = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_ne!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "{path} should be public"
            );
        }
    }

    /// audit C-1: `web.auth_token: ""` (e.g. from an unset
    /// `${WEB_TOKEN:-}`) must never authenticate a request that carries no
    /// Authorization header at all. The old middleware defaulted a missing
    /// header to `""`, so `"" == ""` let every guarded route through
    /// unauthenticated — this pins the fix.
    #[tokio::test]
    async fn empty_configured_token_still_rejects_requests_with_no_header() {
        let app = router(test_state(""));
        let res = app
            .oneshot(Request::get("/api/about").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    /// The GUI shell (`/`) must load with no Authorization header at all — a
    /// cold browser tab navigating to `/#token=<t>` sends no header, since URL
    /// fragments never reach the server — while every other route, including
    /// `/api/about`, stays guarded. This pins the split to exactly
    /// `{/, /healthz}` public vs. everything else, not an accidental
    /// full bypass.
    #[tokio::test]
    async fn root_is_public_but_api_about_is_not() {
        let app = router(test_state("secret-token"));

        let root_res = app
            .clone()
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_ne!(root_res.status(), StatusCode::UNAUTHORIZED);

        let about_res = app
            .oneshot(Request::get("/api/about").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(about_res.status(), StatusCode::UNAUTHORIZED);
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

    /// audit I-3: a wrong token of the SAME length as the real one must be
    /// rejected by content comparison, not accidentally waved through by the
    /// length-mismatch early return in `constant_time_eq` (every prior test
    /// only exercised a length mismatch).
    #[tokio::test]
    async fn a_same_length_wrong_token_is_rejected() {
        let real = "secret-token";
        let wrong = "secret-tokeN"; // one character flipped, same length
        assert_eq!(real.len(), wrong.len());
        let app = router(test_state(real));
        let res = app
            .oneshot(
                Request::get("/api/about")
                    .header("authorization", format!("Bearer {wrong}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    /// audit H-1: a cross-site `fetch` (e.g. from an attacker's page) that
    /// somehow also carries a valid Authorization header must still be
    /// rejected, because a mismatched Origin is never legitimate for this
    /// local-only API.
    #[tokio::test]
    async fn cross_origin_post_is_rejected() {
        let app = router(test_state("t"));
        let res = app
            .oneshot(
                Request::post("/api/config/reload")
                    .header("authorization", "Bearer t")
                    .header("origin", "https://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    /// audit H-1: DNS rebinding — an attacker's hostname resolving to
    /// 127.0.0.1 makes the browser treat the page as same-origin, so a wrong
    /// Host header is the only signal left to reject on.
    #[tokio::test]
    async fn rebound_host_header_is_rejected() {
        let app = router(test_state("t"));
        let res = app
            .oneshot(
                Request::get("/api/about")
                    .header("authorization", "Bearer t")
                    .header("host", "attacker.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    /// audit H-1: a genuine same-origin request (matching Host and Origin,
    /// both in the allowlist) must not be caught by the new checks. Uses
    /// `/api/about` (not `/api/config/reload`, which returns 500 due to an
    /// unrelated test-harness limitation with the control channel) so a hard
    /// 200 actually proves the request reached the handler.
    #[tokio::test]
    async fn same_origin_post_is_allowed() {
        let app = router(test_state("t"));
        let res = app
            .oneshot(
                Request::get("/api/about")
                    .header("authorization", "Bearer t")
                    .header("origin", "http://127.0.0.1:8080")
                    .header("host", "127.0.0.1:8080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// Fix round: once an operator explicitly binds `web.bind` non-loopback,
    /// `config::validate` already forces a real `web.auth_token`, and that
    /// token becomes the security boundary instead of same-origin — so with
    /// `host_check_enabled: false`, a request with a Host/Origin that could
    /// never match the allowlist (e.g. a remote admin's own IP) must still
    /// reach the handler as long as the token is valid.
    #[tokio::test]
    async fn host_and_origin_checks_are_skipped_when_disabled() {
        let app = router(test_state_with_host_check("t", false));
        let res = app
            .oneshot(
                Request::get("/api/about")
                    .header("authorization", "Bearer t")
                    .header("origin", "http://203.0.113.5:8080")
                    .header("host", "203.0.113.5:8080")
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

    // audit I-3: direct unit tests on the comparison primitive itself, so a
    // future refactor of `constant_time_eq` can't silently break equality or
    // inequality without a test-level signal, independent of the HTTP layer.
    #[test]
    fn constant_time_eq_rejects_a_single_differing_byte() {
        assert!(!constant_time_eq(b"aaaa", b"aaab"));
    }

    #[test]
    fn constant_time_eq_accepts_identical_bytes() {
        assert!(constant_time_eq(b"abc", b"abc"));
    }

    #[test]
    fn resolve_token_falls_through_on_blank_configured_token() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = WebConfig {
            auth_token: Some("   ".to_string()),
            ..WebConfig::default()
        };
        let token = resolve_token(&cfg, dir.path()).unwrap();
        // A blank configured token must not be handed back verbatim; a real
        // generated token (and its backing file) takes its place (audit C-1).
        assert_ne!(token.trim(), "");
        assert!(dir.path().join("web-token").exists());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_token_writes_the_generated_file_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let cfg = WebConfig::default();
        resolve_token(&cfg, dir.path()).unwrap();
        let perms = std::fs::metadata(dir.path().join("web-token"))
            .unwrap()
            .permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "audit I-1: no wide-open window"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_token_reasserts_0600_on_a_reused_token_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-token");
        std::fs::write(&path, b"existing-token-value").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let cfg = WebConfig::default();
        let token = resolve_token(&cfg, dir.path()).unwrap();
        assert_eq!(token, "existing-token-value");

        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "audit I-1: reused file re-chmod'd"
        );
    }

    // Round-2 fix (N1): a `web-token.tmp` left behind by a prior crashed run
    // must not carry its (potentially wider) permissions forward through
    // `write_token_file`'s truncate-and-reuse path. `.mode(0o600)` on
    // `OpenOptions` only applies when the open call *creates* the file, so a
    // pre-existing stale tmp file opened with `.create(true).truncate(true)`
    // would otherwise keep its old mode across the rename onto `web-token`.
    #[cfg(unix)]
    #[test]
    fn resolve_token_fixes_permissions_on_a_stale_tmp_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let tmp_path = dir.path().join("web-token.tmp");
        std::fs::write(&tmp_path, b"leftover-from-a-crashed-run").unwrap();
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let cfg = WebConfig::default();
        resolve_token(&cfg, dir.path()).unwrap();

        let perms = std::fs::metadata(dir.path().join("web-token"))
            .unwrap()
            .permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "a stale, wrongly-permissioned .tmp file must not survive the rename"
        );
    }
}
