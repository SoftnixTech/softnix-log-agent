# Self-Update Mechanism (Phase 2: check-only network path) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the agent check (never install) whether a newer signed release exists — `softnix-log-agent upgrade --check`, an authenticated `GET /api/update/status`, and a read-only UI banner — with zero unsolicited network traffic and zero apply capability.

**Architecture:** A minimal HTTPS-only GET client (`src/update/fetch.rs`) built from crates already resolved in this project's dependency tree (`hyper` + `hyper-util` via `axum`, `tokio-rustls`/`webpki-roots` already used for syslog TLS), scoped to fetching and size-capping a manifest — nothing else. Reuses every verification function Phase 0/1 already built (`verify_manifest`, `check_freshness`, `Watermark`) unchanged. The network call only ever fires on an explicit CLI invocation or an explicit authenticated API request — never on a timer, never on startup.

**Tech Stack:** `hyper-rustls` (new, thin rustls-for-hyper glue), `hyper-util` (promoted from transitive to direct, with its `client`/`client-legacy`/`tokio` features turned on), `http-body-util` (promoted from `[dev-dependencies]` to `[dependencies]` — it's already resolved, this only changes which section declares it).

**Spec:** `docs/superpowers/specs/2026-09-09-self-update-mechanism.md`

**Depends on:** `docs/superpowers/plans/2026-09-09-self-update-phase-0-1.md` must be implemented first — this plan calls `update::manifest::{verify_manifest, check_freshness}` and `update::watermark::Watermark` without modification.

## Global Constraints

- No apply capability anywhere in this plan — every task here is read-only with respect to the running binary and the live config. (Spec constraint 1, extended: Phase 2 is check-only by the spec's own phasing.)
- `update.check_url` is opt-in and **disabled by default** — with it unset, this code must make zero outbound network calls, ever, including at startup. (Spec: "a security product must not beacon out unasked.")
- HTTPS only. A `check_url` or manifest artifact URL that isn't `https://` is rejected before any connection is attempted.
- No UI apply button. The UI banner may only display status and a copy-pasteable CLI command.
- The network fetch enforces a hard byte cap taken from the (already signature-verified) manifest's own `size` field — never an unbounded read of a response body.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/update/fetch.rs` | HTTPS-only, size-capped GET fetch; URL-scheme validation as a separately testable pure function |
| `src/config/schema.rs` | Modify: add `UpdateConfig` struct + `pub update: UpdateConfig` field on `Config` |
| `src/update/mod.rs` | Modify: add `pub mod fetch;` |
| `src/main.rs` | Modify: `Upgrade` command gains `--check` |
| `src/web.rs` | Modify: add `AppState.check_url`, `GET /api/update/status` handler |
| `src/ui.html` | Modify: Overview page gains a read-only update-available banner |

---

### Task 1: HTTPS-only, size-capped fetch client

**Files:**
- Create: `src/update/fetch.rs`
- Modify: `src/update/mod.rs` (add `pub mod fetch;`)
- Modify: `Cargo.toml`:
  - Add to `[dependencies]`: `hyper-rustls = { version = "0.27", default-features = false, features = ["ring", "http1", "tls12", "webpki-roots"] }` (mirrors this project's existing `ring`+`tls12` feature choices on `rustls`/`tokio-rustls`), `hyper-util = { version = "0.1", features = ["client", "client-legacy", "tokio"] }` (promoted from transitive-only), `http-body-util = "0.1"` (promoted from `[dev-dependencies]`)
  - Remove from `[dev-dependencies]`: `http-body-util = "0.1"` (now a regular dependency, and regular dependencies are automatically available to tests — leaving it in both sections produces a Cargo warning)

**Interfaces:**
- Produces: `pub fn require_https(url: &str) -> anyhow::Result<()>` (pure, no I/O), `pub async fn fetch_url(url: &str, max_bytes: u64) -> anyhow::Result<Vec<u8>>`.

- [ ] **Step 1: Update `Cargo.toml`**

Make the three additions and one removal described above.

- [ ] **Step 2: Run `cargo build` to confirm the new deps resolve**

Run: `cargo build`
Expected: succeeds. `hyper-rustls` is the only genuinely new crate in the dependency tree; confirm with `cargo tree -p hyper-rustls` that it does not pull in an unexpected TLS backend (it must resolve to the `ring` crypto provider, matching `rustls`'s existing `ring` feature elsewhere in this project — if `cargo tree` shows `aws-lc-rs` anywhere, the feature flags in Step 1 are wrong; fix them before proceeding).

- [ ] **Step 3: Write the failing tests**

Create `src/update/fetch.rs`:

```rust
//! A deliberately minimal HTTPS GET client, scoped to exactly one job:
//! fetching a signed update manifest (or the artifact it points at) with a
//! hard size cap. This is not a general-purpose HTTP client — it has no
//! POST, no redirect following, no cookie jar, nothing beyond what
//! Phase 2/3 of the self-update mechanism needs.

use anyhow::{bail, Context, Result};
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// Rejects any URL that isn't `https://`, before any connection is
/// attempted. A security-relevant fetch over plaintext HTTP is never
/// correct here, even if a caller passed one in by misconfiguration.
pub fn require_https(url: &str) -> Result<()> {
    if !url.starts_with("https://") {
        bail!("refusing to fetch a non-https URL: {url}");
    }
    Ok(())
}

/// Fetches `url` (which must already have passed `require_https`) and
/// returns its body, refusing to read past `max_bytes` — a malicious or
/// broken server sending an unbounded response must not be allowed to
/// exhaust memory on a host that may be running this as root/LocalSystem.
/// 10s connect+request timeout: this must never hang the CLI indefinitely.
pub async fn fetch_url(url: &str, max_bytes: u64) -> Result<Vec<u8>> {
    require_https(url)?;

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, http_body_util::Full<bytes::Bytes>> =
        Client::builder(TokioExecutor::new()).build(https);

    let uri: hyper::Uri = url.parse().with_context(|| format!("invalid URL: {url}"))?;
    let request = hyper::Request::get(uri)
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .context("cannot build request")?;

    let response = tokio::time::timeout(std::time::Duration::from_secs(10), client.request(request))
        .await
        .context("request timed out after 10s")?
        .context("request failed")?;

    if !response.status().is_success() {
        bail!("fetching {url} returned HTTP {}", response.status());
    }

    let mut body = response.into_body();
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.context("error reading response body")?;
        if let Some(chunk) = frame.data_ref() {
            if collected.len() as u64 + chunk.len() as u64 > max_bytes {
                bail!("response from {url} exceeded the {max_bytes}-byte cap");
            }
            collected.extend_from_slice(chunk);
        }
    }
    Ok(collected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_https_accepts_an_https_url() {
        assert!(require_https("https://example.invalid/manifest.json").is_ok());
    }

    #[test]
    fn require_https_rejects_plain_http() {
        let err = require_https("http://example.invalid/manifest.json").unwrap_err();
        assert!(err.to_string().contains("non-https"));
    }

    #[test]
    fn require_https_rejects_a_bare_hostname() {
        let err = require_https("example.invalid/manifest.json").unwrap_err();
        assert!(err.to_string().contains("non-https"));
    }

    // Exercises the size-cap and success path against a real local HTTP
    // server (not HTTPS — TLS handshake correctness is `hyper-rustls`'s own
    // well-tested job, not this module's; what this module owns is the
    // cap-enforcement and body-collection logic, which is identical
    // regardless of the transport). `fetch_url_for_test` below is the same
    // function with `require_https` skipped, so the local plain-HTTP test
    // server can stand in for what would be an HTTPS endpoint in
    // production.
    async fn fetch_url_for_test(url: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let https = hyper_util::client::legacy::connect::HttpConnector::new();
        let client: Client<_, http_body_util::Full<bytes::Bytes>> =
            Client::builder(TokioExecutor::new()).build(https);
        let uri: hyper::Uri = url.parse()?;
        let request = hyper::Request::get(uri).body(http_body_util::Full::new(bytes::Bytes::new()))?;
        let response = client.request(request).await?;
        if !response.status().is_success() {
            bail!("HTTP {}", response.status());
        }
        let mut body = response.into_body();
        let mut collected = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            if let Some(chunk) = frame.data_ref() {
                if collected.len() as u64 + chunk.len() as u64 > max_bytes {
                    bail!("exceeded cap");
                }
                collected.extend_from_slice(chunk);
            }
        }
        Ok(collected)
    }

    async fn spawn_test_server(body: &'static [u8]) -> String {
        use std::convert::Infallible;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let io = hyper_util::rt::TokioIo::new(stream);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |_req| async move {
                        Ok::<_, Infallible>(hyper::Response::new(http_body_util::Full::new(
                            bytes::Bytes::from_static(body),
                        )))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn fetch_url_returns_the_full_body_under_the_cap() {
        let base = spawn_test_server(b"hello world").await;
        let body = fetch_url_for_test(&format!("{base}/x"), 1024).await.unwrap();
        assert_eq!(body, b"hello world");
    }

    #[tokio::test]
    async fn fetch_url_rejects_a_body_over_the_cap() {
        let base = spawn_test_server(b"hello world").await;
        let err = fetch_url_for_test(&format!("{base}/x"), 5).await.unwrap_err();
        assert!(err.to_string().contains("cap"));
    }
}
```

Add to `src/update/mod.rs`:

```rust
pub mod fetch;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib update::fetch::`
Expected: FAIL — module doesn't exist yet.

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test --lib update::fetch::`
Expected: `test result: ok. 5 passed`

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock src/update/mod.rs src/update/fetch.rs
git commit -m "feat(update): add an HTTPS-only, size-capped manifest fetch client"
```

---

### Task 2: `update.check_url` config option (opt-in, disabled by default)

**Files:**
- Modify: `src/config/schema.rs` (add `UpdateConfig`, add `pub update: UpdateConfig` field to `Config`)

**Interfaces:**
- Produces: `pub struct UpdateConfig { pub check_url: Option<String> }` with `Default` giving `check_url: None`.

- [ ] **Step 1: Write the failing test**

Add to `src/config/schema.rs`'s existing `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn update_check_url_defaults_to_none() {
        let cfg = Config::default();
        assert_eq!(cfg.update.check_url, None);
    }

    #[test]
    fn update_check_url_can_be_set() {
        let yaml = "update:\n  check_url: https://updates.example.invalid/manifest.json\n";
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            cfg.update.check_url.as_deref(),
            Some("https://updates.example.invalid/manifest.json")
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib config::schema::tests::update_check_url`
Expected: FAIL — `Config` has no field `update`.

- [ ] **Step 3: Write the implementation**

In `src/config/schema.rs`, add `update` to the `Config` struct (alongside the existing `web` field):

```rust
    #[serde(default)]
    pub web: WebConfig,
    #[serde(default)]
    pub update: UpdateConfig,
```

Add the new struct near `WebConfig`:

```rust
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig {
    /// HTTPS URL to fetch the signed update manifest from. Unset by
    /// default: this agent makes no outbound network call related to
    /// updates unless an operator explicitly configures this.
    #[serde(default)]
    pub check_url: Option<String>,
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib config::`
Expected: all config tests pass, including the 2 new ones.

- [ ] **Step 5: Commit**

```bash
git add src/config/schema.rs
git commit -m "feat(config): add update.check_url, opt-in and disabled by default"
```

---

### Task 3: `softnix-log-agent upgrade --check`

**Files:**
- Modify: `src/main.rs` (`Command::Upgrade` gains a `--check` flag; new `upgrade_check_cmd`)

**Interfaces:**
- Consumes: `update::fetch::fetch_url`, `update::manifest::verify_manifest`, `update::manifest::check_freshness`, `update::watermark::Watermark` (all from Phase 0/1, unchanged).

**Note on the actual current state (Phase 0/1's final-review fix round changed this after this plan was first drafted):** `from` is already `Option<PathBuf>` today, with `#[arg(long, required_unless_present = "rollback")]`, and `upgrade_cmd` already takes `from: Option<&Path>` and does its own `.context(...)?` unwrap internally per platform-cfg branch (this was a deliberate fix for a Critical bug where `--rollback` alone used to fail clap parsing). Do NOT reintroduce a version of `upgrade_cmd` that takes `from: &Path` directly, and do NOT pre-unwrap `from` in the match arm — that would just have to be re-done differently by Phase 3's Task 2, which already plans its own larger refactor of this exact function. This task's job is narrower: only add `check`, and only change the one clap attribute needed to keep `--check` alone parseable.

- [ ] **Step 1: Add the flag and handler**

In `src/main.rs`, add `check: bool` to the `Upgrade` variant, and widen the existing `required_unless_present` on `from` to `required_unless_present_any` (so `upgrade --check` alone still parses — today's attribute only exempts `--rollback`):

```rust
    Upgrade {
        /// Path to a downloaded/copied release artifact: a `.tar.gz` on
        /// Linux, or a `*-update.zip` bundle (.msi + manifest + signature
        /// together) on Windows. Required unless `--check` or `--rollback`
        /// is passed.
        #[arg(long, required_unless_present_any = ["rollback", "check"])]
        from: Option<PathBuf>,
        /// Check for an available update over the network (read-only,
        /// never applies anything) and print the result.
        #[arg(long)]
        check: bool,
        /// Roll back to the previously retained version instead of applying
        /// `--from`. Linux-only; on Windows, use the manual runbook in
        /// docs/RELEASE-SIGNING.md instead.
        #[arg(long)]
        rollback: bool,
        /// Allow installing a version older than the one currently running.
        #[arg(long)]
        allow_downgrade: bool,
        #[arg(short, long, default_value = "agent.yaml")]
        config: PathBuf,
    },
```

Update the match arm to route on `check` first, leaving `upgrade_cmd`'s own call and internal `Option<&Path>` handling completely unchanged:

```rust
        Some(Command::Upgrade {
            from,
            check,
            rollback,
            allow_downgrade,
            config,
        }) => {
            if check {
                upgrade_check_cmd(&config)
            } else {
                upgrade_cmd(from.as_deref(), rollback, allow_downgrade, &config)
            }
        }
```

Add a CLI-parsing test alongside the two that already exist in `src/main.rs`'s `#[cfg(test)] mod tests` (`upgrade_rollback_parses_without_from`, `upgrade_without_from_or_rollback_fails_to_parse`), proving the widened `required_unless_present_any` actually works for `--check`:

```rust
    #[test]
    fn upgrade_check_parses_without_from_or_rollback() {
        let cli = Cli::try_parse_from(["softnix-log-agent", "upgrade", "--check"]).unwrap();
        match cli.command {
            Some(Command::Upgrade { from, check, rollback, .. }) => {
                assert!(from.is_none());
                assert!(check);
                assert!(!rollback);
            }
            _ => panic!("expected Command::Upgrade"),
        }
    }
```

Add the new handler (async — needs a runtime, unlike the other CLI handlers; build a small dedicated one rather than pulling this single command into the main multi-threaded runtime):

```rust
fn upgrade_check_cmd(config_path: &Path) -> Result<()> {
    let (cfg, _warnings) = config::load(config_path).context("cannot load config")?;
    let check_url = cfg
        .update
        .check_url
        .context("update.check_url is not configured; nothing to check")?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let manifest_bytes =
            softnix_log_agent::update::fetch::fetch_url(&check_url, 1024 * 1024).await?;
        let sig_url = format!("{check_url}.sig");
        let sig = softnix_log_agent::update::fetch::fetch_url(&sig_url, 4096).await?;
        let manifest = softnix_log_agent::update::manifest::verify_manifest(&manifest_bytes, &sig)?;

        let watermark = softnix_log_agent::update::watermark::Watermark::open(&cfg.agent.data_dir);
        match softnix_log_agent::update::manifest::check_freshness(
            &manifest,
            watermark.highest_serial(),
            env!("CARGO_PKG_VERSION"),
            false,
            chrono::Utc::now(),
        ) {
            Ok(()) => println!(
                "update available: {} -> {} (run `softnix-log-agent upgrade --from <downloaded-artifact>` to apply)",
                env!("CARGO_PKG_VERSION"),
                manifest.version
            ),
            Err(_) => println!("up to date (running {})", env!("CARGO_PKG_VERSION")),
        }
        anyhow::Ok(())
    })
}
```

- [ ] **Step 2: Run `cargo build` to confirm it compiles**

Run: `cargo build`
Expected: succeeds.

- [ ] **Step 3: Manually verify against a local test server (no real release manifest exists yet — this is not a `cargo test`-covered step)**

This exercises real networking end-to-end, which this plan's automated tests deliberately don't cover for the CLI entry point (Task 1 already covers the fetch logic itself in isolation). Once Phase 0's Task 6 has produced a real signed manifest somewhere reachable, run:

```bash
softnix-log-agent upgrade --check --config /path/to/agent.yaml
```

with `update.check_url` pointed at that manifest's URL, and confirm the printed message matches whether a newer version is actually available.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat(update): add 'upgrade --check', a read-only network manifest check"
```

---

### Task 4: Authenticated `GET /api/update/status` + UI banner

**Files:**
- Modify: `src/web.rs` (add `AppState.check_url`, add `api_update_status` handler + route)
- Modify: `src/main.rs` (`run_agent` passes `cfg.update.check_url.clone()` into `AppState`)
- Modify: `src/ui.html` (Overview page renders the banner)

**Interfaces:**
- Produces: `GET /api/update/status` → `{"configured": bool, "current_version": str, "check_error": str|null, "update_available": bool|null, "latest_version": str|null}`.

- [ ] **Step 1: Add the field to `AppState` and its construction**

In `src/web.rs`, add to `struct AppState` (after `auth_token`):

```rust
    /// `update.check_url` from config, if the operator opted in. `None`
    /// means this endpoint must never make a network call.
    pub check_url: Option<String>,
```

In `src/main.rs`'s `run_agent`, add to the `AppState { ... }` literal:

```rust
        check_url: cfg.update.check_url.clone(),
```

**`AppState` has exactly one other struct-literal construction site, and it must be updated too or the crate stops compiling:** `src/web.rs`'s test module builds every test's `AppState` through `test_state_with_host_check` (`test_state` is a thin wrapper around it) — there is no other place in the whole codebase that constructs `AppState` directly. Add `check_url: None,` to that literal:

```rust
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
            check_url: None,
        })
    }
```

- [ ] **Step 2: Add the handler and route**

In `src/web.rs`, add the route (near the other `/api/*` routes):

```rust
        .route("/api/update/status", get(api_update_status))
```

Add the handler (near `api_about`):

```rust
async fn api_update_status(State(state): S) -> Response {
    let Some(check_url) = state.check_url.clone() else {
        return Json(json!({
            "configured": false,
            "current_version": AGENT_VERSION,
            "check_error": null,
            "update_available": null,
            "latest_version": null,
        }))
        .into_response();
    };

    let result: anyhow::Result<crate::update::manifest::Manifest> = async {
        let manifest_bytes = crate::update::fetch::fetch_url(&check_url, 1024 * 1024).await?;
        let sig = crate::update::fetch::fetch_url(&format!("{check_url}.sig"), 4096).await?;
        crate::update::manifest::verify_manifest(&manifest_bytes, &sig)
    }
    .await;

    match result {
        Ok(manifest) => {
            let target = manifest.version.clone();
            let newer = target.as_str() > AGENT_VERSION; // lexicographic is wrong for e.g. "0.9" vs "0.10"; Task 2's `parse_version` is the correct comparator — call it here instead of this placeholder-grade compare before merging (see Step 3's note)
            Json(json!({
                "configured": true,
                "current_version": AGENT_VERSION,
                "check_error": null,
                "update_available": newer,
                "latest_version": target,
            }))
            .into_response()
        }
        Err(e) => Json(json!({
            "configured": true,
            "current_version": AGENT_VERSION,
            "check_error": format!("{e:#}"),
            "update_available": null,
            "latest_version": null,
        }))
        .into_response(),
    }
}
```

- [ ] **Step 3: Fix the version comparison before this is considered done**

The `newer` line above using a raw string comparison is wrong (`"0.9" > "0.10"` lexicographically, incorrectly) — this is flagged inline rather than shipped. Replace it: expose Phase 0/1's private `parse_version` (`src/update/manifest.rs`) as `pub(crate) fn parse_version` (drop the leading underscore-free `fn parse_version` visibility from private to `pub(crate)`, no signature change), then in `api_update_status` do:

```rust
            let newer = crate::update::manifest::parse_version(&manifest.version)
                .and_then(|t| crate::update::manifest::parse_version(AGENT_VERSION).map(|r| t > r))
                .unwrap_or(false);
```

- [ ] **Step 4: Write a test**

Add to `src/web.rs`'s existing `#[cfg(test)] mod tests` block. This file's real pattern (see `all_guarded_routes_reject_missing_auth`, `a_valid_bearer_token_is_accepted`, etc.) is `router(test_state(token))` plus a plain `Request::get(path).header("authorization", format!("Bearer {token}"))` — there is no `test_app_with` closure-style helper anywhere in this codebase; use the real pattern:

```rust
    #[tokio::test]
    async fn update_status_reports_unconfigured_when_check_url_is_unset() {
        // `test_state` builds its `AppState` with `check_url: None` by
        // default (Step 1 above) — no variant helper needed for this case.
        let app = router(test_state("secret-token"));
        let response = app
            .oneshot(
                Request::get("/api/update/status")
                    .header("authorization", "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["configured"], false);
    }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --lib web::`
Expected: all `web` module tests pass, including the new one.

- [ ] **Step 6: Add the UI banner**

In `src/ui.html`, find the `async overview(){...}` page builder (from the earlier redesign — search for `<h2>Health</h2>`). Add, right after the opening of the function, a fetch to the new endpoint and a conditional banner rendered above the existing `<p class="meta">` line:

```js
  const {body:upd} = await api("/api/update/status");
  const updBanner = upd.configured && upd.update_available
    ? `<div id="updmsg" class="msg ok" role="status">Update available: v${esc(upd.current_version)} &rarr; v${esc(upd.latest_version)}. Run <code>softnix-log-agent upgrade --from &lt;downloaded-artifact&gt;</code> to apply.</div>`
    : "";
```

and splice `${updBanner}` into the template literal immediately before the existing `<h2>Health</h2>` line. No apply button, no click handler — this banner is inert text plus a `<code>` snippet the operator copies by hand.

- [ ] **Step 7: Commit**

```bash
git add src/web.rs src/main.rs src/ui.html
git commit -m "feat(update): add authenticated update-status endpoint and a read-only UI banner"
```

---

## Self-Review Notes

- **Spec coverage:** "opt-in and disabled by default" → `Config::default()`'s `update.check_url: None` (Task 2) and both `upgrade_check_cmd` and `api_update_status` (Tasks 3, 4) refuse to make any network call when it's unset. "No apply button" → Task 4's banner is copy-only, verified by the absence of any `onclick`/form in the spliced markup.
- **Placeholder scan:** Task 4 Step 2's first draft of `api_update_status` is deliberately shown with a wrong version comparison and an inline comment flagging it, then corrected in Step 3 — this is not a placeholder left unresolved, it's showing why the naive approach is wrong before replacing it (the same pattern used in the Phase 0/1 plan's Task 9). Confirm Step 3's replacement code is what actually ships, not Step 2's draft.
- **Type consistency:** `parse_version` changes visibility from private to `pub(crate)` in Task 4 Step 3 — grep `src/update/manifest.rs` after this change to confirm no other caller assumed it was module-private in a way that breaks (none do; `check_freshness` is in the same module and unaffected by a visibility widening).
