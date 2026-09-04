//! Configuration loading, environment expansion and validation.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub inputs: InputsConfig,
    #[serde(default)]
    pub pipeline: PipelineConfig,
    #[serde(default)]
    pub buffer: BufferConfig,
    #[serde(default)]
    pub outputs: Vec<OutputConfig>,
    #[serde(default)]
    pub web: WebConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Base directory for state and queue data.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Agent self-log level: trace|debug|info|warn|error
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            data_dir: default_data_dir(),
            log_level: default_log_level(),
        }
    }
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("data")
}
fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct InputsConfig {
    #[serde(default)]
    pub files: Vec<FileInputConfig>,
    #[serde(default)]
    pub syslog: Vec<SyslogInputConfig>,
    /// Windows Event Log channels. Collected natively on Windows; on other
    /// platforms a configured eventlog input is ignored with a warning.
    #[serde(default)]
    pub eventlog: Vec<EventLogInputConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileInputConfig {
    pub id: String,
    /// Glob patterns: /var/log/*.log, /app/logs/**/*.log, C:\Logs\*.log
    pub paths: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Poll interval for file changes and discovery, in milliseconds.
    #[serde(default = "default_poll_ms")]
    pub poll_interval_ms: u64,
    /// Read existing file content from the beginning on first start.
    #[serde(default)]
    pub read_from_start: bool,
    #[serde(default)]
    pub parser: ParserConfig,
    /// Override the source_type assigned to events (default: "file").
    #[serde(default)]
    pub source_type: Option<String>,
}

fn default_poll_ms() -> u64 {
    500
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyslogProtocol {
    #[default]
    Udp,
    Tcp,
    Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFormat {
    /// Try RFC5424, then RFC3164, then JSON, fall back to raw.
    #[default]
    Auto,
    Rfc3164,
    Rfc5424,
    Json,
    Raw,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogInputConfig {
    pub id: String,
    #[serde(default)]
    pub protocol: SyslogProtocol,
    #[serde(default = "default_bind_all")]
    pub bind: String,
    pub port: u16,
    #[serde(default)]
    pub format: SyslogFormat,
    /// Required when protocol = tls.
    #[serde(default)]
    pub tls: Option<TlsServerOptions>,
    #[serde(default)]
    pub source_type: Option<String>,
    /// Keep the original wire line (PRI, timestamp, hostname, tag included)
    /// in `raw_message`. Unlike file input's `parser.mode: raw`, syslog's
    /// `message` (parsed body) and `raw_message` (full line) genuinely
    /// differ, so this is real information loss when off. Doubles memory,
    /// queue usage and wire size per event; off by default.
    #[serde(default)]
    pub keep_raw_message: bool,
}

fn default_bind_all() -> String {
    "0.0.0.0".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventLogInputConfig {
    pub id: String,
    /// Event Log channels to subscribe to, e.g. "Application", "System",
    /// "Security", "Microsoft-Windows-Sysmon/Operational".
    pub channels: Vec<String>,
    /// XPath query applied to each channel; "*" selects all events. Example:
    /// "*[System[(Level=1 or Level=2 or Level=3)]]" for critical/error/warning.
    #[serde(default = "default_eventlog_query")]
    pub query: String,
    /// On first run (no saved bookmark), read existing events from the oldest
    /// record. Default: only events arriving after the agent starts.
    #[serde(default)]
    pub read_existing: bool,
    /// Override the source_type assigned to events (default: "eventlog").
    #[serde(default)]
    pub source_type: Option<String>,
    /// Keep the full rendered Event XML (2-4 KB) in `raw_message`. Off by
    /// default; `message` already carries the human-readable text.
    #[serde(default)]
    pub keep_raw_message: bool,
}

fn default_eventlog_query() -> String {
    "*".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsServerOptions {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// CA bundle for client certificate verification (enables mTLS).
    #[serde(default)]
    pub client_ca: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TlsClientOptions {
    /// CA bundle used to verify the server (default: system webpki roots).
    #[serde(default)]
    pub ca: Option<PathBuf>,
    /// Client certificate for mTLS.
    #[serde(default)]
    pub cert: Option<PathBuf>,
    #[serde(default)]
    pub key: Option<PathBuf>,
    /// Disable server certificate verification (NOT recommended).
    #[serde(default = "default_true")]
    pub verify: bool,
    /// Override SNI / certificate hostname.
    #[serde(default)]
    pub server_name: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ParserMode {
    #[default]
    Raw,
    Json,
    Kv,
    Regex,
    Syslog,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParserConfig {
    #[serde(default)]
    pub mode: ParserMode,
    /// Regex with named capture groups (mode = regex).
    #[serde(default)]
    pub pattern: Option<String>,
    /// Key-value pair separator (mode = kv), default whitespace.
    #[serde(default = "default_pair_sep")]
    pub pair_separator: String,
    /// Key/value separator (mode = kv), default '='.
    #[serde(default = "default_kv_sep")]
    pub kv_separator: String,
    /// chrono format string used to parse a captured `timestamp` group.
    #[serde(default)]
    pub timestamp_format: Option<String>,
    /// Keep the pre-parse body in `raw_message`. Doubles memory, queue usage
    /// and wire size per event; off by default.
    #[serde(default)]
    pub keep_raw_message: bool,
}

impl Default for ParserConfig {
    fn default() -> Self {
        ParserConfig {
            mode: ParserMode::default(),
            pattern: None,
            pair_separator: default_pair_sep(),
            kv_separator: default_kv_sep(),
            timestamp_format: None,
            keep_raw_message: false,
        }
    }
}

fn default_pair_sep() -> String {
    " ".to_string()
}
fn default_kv_sep() -> String {
    "=".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PipelineConfig {
    #[serde(default)]
    pub transforms: Vec<TransformStep>,
    #[serde(default)]
    pub enrich: EnrichConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransformStep {
    AddField {
        field: String,
        value: serde_json::Value,
        #[serde(default)]
        when: Option<Condition>,
    },
    RemoveField {
        field: String,
        #[serde(default)]
        when: Option<Condition>,
    },
    RenameField {
        from: String,
        to: String,
        #[serde(default)]
        when: Option<Condition>,
    },
    Convert {
        field: String,
        /// int | float | string | bool
        to: String,
        #[serde(default)]
        when: Option<Condition>,
    },
    Mask {
        field: String,
        pattern: String,
        #[serde(default = "default_mask")]
        replacement: String,
        #[serde(default)]
        when: Option<Condition>,
    },
    /// Drop events matching the condition.
    Drop { when: Condition },
    /// Keep only events matching the condition.
    Keep { when: Condition },
}

fn default_mask() -> String {
    "****".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub field: String,
    /// eq | ne | contains | matches | exists | not_exists | gt | lt
    pub op: String,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EnrichConfig {
    #[serde(default = "default_true")]
    pub hostname: bool,
    #[serde(default = "default_true")]
    pub os_info: bool,
    #[serde(default = "default_true")]
    pub agent_version: bool,
    #[serde(default)]
    pub local_ip: bool,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub site: Option<String>,
    #[serde(default)]
    pub tenant: Option<String>,
    #[serde(default)]
    pub customer: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FullPolicy {
    #[default]
    Block,
    DropOldest,
    DropNewest,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BufferConfig {
    /// Queue directory (default: <data_dir>/queue).
    #[serde(default)]
    pub dir: Option<PathBuf>,
    /// Maximum on-disk size per destination, in MB.
    #[serde(default = "default_max_mb")]
    pub max_size_mb: u64,
    /// Segment file size, in MB.
    #[serde(default = "default_seg_mb")]
    pub segment_size_mb: u64,
    #[serde(default)]
    pub full_policy: FullPolicy,
}

impl Default for BufferConfig {
    fn default() -> Self {
        BufferConfig {
            dir: None,
            max_size_mb: default_max_mb(),
            segment_size_mb: default_seg_mb(),
            full_policy: FullPolicy::default(),
        }
    }
}

fn default_max_mb() -> u64 {
    1024
}
fn default_seg_mb() -> u64 {
    8
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputKind {
    Syslog,
    Stdout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    #[default]
    Rfc5424,
    Rfc3164,
    Json,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Framing {
    #[default]
    Newline,
    OctetCounting,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetryConfig {
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,
    /// Events per send batch.
    #[serde(default = "default_batch")]
    pub batch_size: usize,
}

impl Default for RetryConfig {
    fn default() -> Self {
        RetryConfig {
            initial_backoff_ms: default_initial_backoff_ms(),
            max_backoff_ms: default_max_backoff_ms(),
            batch_size: default_batch(),
        }
    }
}

fn default_initial_backoff_ms() -> u64 {
    500
}
fn default_max_backoff_ms() -> u64 {
    30_000
}
fn default_batch() -> usize {
    200
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: OutputKind,
    /// host:port for syslog outputs.
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub protocol: SyslogProtocol,
    #[serde(default)]
    pub format: OutputFormat,
    #[serde(default)]
    pub framing: Framing,
    #[serde(default)]
    pub tls: Option<TlsClientOptions>,
    /// Only route events matching this condition.
    #[serde(default)]
    pub when: Option<Condition>,
    /// Route events here only when the named output is unhealthy.
    #[serde(default)]
    pub failover_for: Option<String>,
    #[serde(default)]
    pub retry: RetryConfig,
    /// Overrides buffer.full_policy for this destination only.
    #[serde(default)]
    pub full_policy: Option<FullPolicy>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_web_bind")]
    pub bind: String,
    #[serde(default = "default_web_port")]
    pub port: u16,
    /// Optional bearer token required for all API requests.
    #[serde(default)]
    pub auth_token: Option<String>,
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            enabled: true,
            bind: default_web_bind(),
            port: default_web_port(),
            auth_token: None,
        }
    }
}

fn default_web_bind() -> String {
    "127.0.0.1".to_string()
}
fn default_web_port() -> u16 {
    8080
}

/// Expand `${VAR}` and `${VAR:-default}` references. Returns the expanded text
/// plus every value that came from a *real environment variable* (not a literal
/// `:-default`, which isn't a secret pulled from the environment), so error
/// messages can be scrubbed of them — a validation error that echoes an
/// expanded value turns /api/config/validate into an oracle for reading the
/// root process's environment.
pub fn expand_env(raw: &str) -> Result<(String, Vec<String>)> {
    let re = regex::Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}").unwrap();
    let mut missing = Vec::new();
    let mut secrets = Vec::new();
    let out = re
        .replace_all(raw, |caps: &regex::Captures| {
            let var = &caps[1];
            match std::env::var(var) {
                Ok(v) => {
                    if !v.is_empty() {
                        secrets.push(v.clone());
                    }
                    v
                }
                Err(_) => match caps.get(2) {
                    Some(d) => d.as_str().to_string(),
                    None => {
                        missing.push(var.to_string());
                        String::new()
                    }
                },
            }
        })
        .into_owned();
    if !missing.is_empty() {
        bail!(
            "undefined environment variable(s) referenced in config: {}",
            missing.join(", ")
        );
    }
    Ok((out, secrets))
}

/// Replace every substituted env value in an error message with `***`.
fn redact(msg: String, secrets: &[String]) -> String {
    let mut msg = msg;
    for s in secrets {
        if s.len() >= 2 {
            msg = msg.replace(s.as_str(), "***");
        }
    }
    msg
}

/// Parse and validate config text. Returns the config plus non-fatal warnings.
pub fn parse(raw: &str) -> Result<(Config, Vec<String>)> {
    let (expanded, secrets) = expand_env(raw)?;
    parse_expanded(&expanded).map_err(|e| anyhow::anyhow!(redact(format!("{e:#}"), &secrets)))
}

fn parse_expanded(expanded: &str) -> Result<(Config, Vec<String>)> {
    let cfg: Config = serde_yaml::from_str(expanded).map_err(|e| {
        anyhow::anyhow!(
            "YAML parse error: {e}\nHint: check field names and indentation; run `softnix-log-agent validate` for details"
        )
    })?;
    let warnings = validate(&cfg)?;
    Ok((cfg, warnings))
}

pub fn load(path: &Path) -> Result<(Config, Vec<String>)> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read config file {}", path.display()))?;
    parse(&raw).with_context(|| format!("invalid configuration in {}", path.display()))
}

/// Structural validation with helpful error messages.
pub fn validate(cfg: &Config) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    let mut ids: HashSet<&str> = HashSet::new();

    for f in &cfg.inputs.files {
        if f.id.trim().is_empty() {
            bail!("inputs.files: every file input requires a non-empty `id`");
        }
        if !ids.insert(&f.id) {
            bail!("duplicate input/output id: {}", f.id);
        }
        if f.paths.is_empty() {
            bail!("inputs.files[{}]: `paths` must not be empty", f.id);
        }
        for p in &f.paths {
            glob::Pattern::new(&p.replace('\\', "/"))
                .with_context(|| format!("inputs.files[{}]: invalid glob pattern {p}", f.id))?;
        }
        for p in &f.exclude {
            globset::Glob::new(&p.replace('\\', "/"))
                .with_context(|| format!("inputs.files[{}]: invalid exclude pattern {p}", f.id))?;
        }
        if f.poll_interval_ms < 50 {
            bail!(
                "inputs.files[{}]: poll_interval_ms must be >= 50 (got {})",
                f.id,
                f.poll_interval_ms
            );
        }
        validate_parser(&f.parser, &format!("inputs.files[{}]", f.id))?;
    }

    for s in &cfg.inputs.syslog {
        if s.id.trim().is_empty() {
            bail!("inputs.syslog: every syslog input requires a non-empty `id`");
        }
        if !ids.insert(&s.id) {
            bail!("duplicate input/output id: {}", s.id);
        }
        s.bind.parse::<IpAddr>().with_context(|| {
            format!(
                "inputs.syslog[{}]: `bind` must be an IP address (got {:?})",
                s.id, s.bind
            )
        })?;
        if s.port == 0 {
            bail!("inputs.syslog[{}]: port must be 1-65535", s.id);
        }
        match s.protocol {
            SyslogProtocol::Tls => {
                let tls = s.tls.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "inputs.syslog[{}]: protocol `tls` requires a `tls:` section with cert and key",
                        s.id
                    )
                })?;
                require_file(&tls.cert, &format!("inputs.syslog[{}].tls.cert", s.id))?;
                require_file(&tls.key, &format!("inputs.syslog[{}].tls.key", s.id))?;
                if let Some(ca) = &tls.client_ca {
                    require_file(ca, &format!("inputs.syslog[{}].tls.client_ca", s.id))?;
                }
            }
            _ => {
                if s.tls.is_some() {
                    warnings.push(format!(
                        "inputs.syslog[{}]: `tls` section is ignored for protocol {:?}",
                        s.id, s.protocol
                    ));
                }
            }
        }
    }

    for e in &cfg.inputs.eventlog {
        if e.id.trim().is_empty() {
            bail!("inputs.eventlog: every eventlog input requires a non-empty `id`");
        }
        if !ids.insert(&e.id) {
            bail!("duplicate input/output id: {}", e.id);
        }
        if e.channels.is_empty() {
            bail!(
                "inputs.eventlog[{}]: `channels` must list at least one channel",
                e.id
            );
        }
        if e.query.trim().is_empty() {
            bail!(
                "inputs.eventlog[{}]: `query` must not be empty (use \"*\")",
                e.id
            );
        }
        if !cfg!(windows) {
            warnings.push(format!(
                "inputs.eventlog[{}]: Windows Event Log input is only collected on Windows; ignored on this platform",
                e.id
            ));
        }
    }

    for t in &cfg.pipeline.transforms {
        validate_transform(t)?;
    }

    if cfg.outputs.is_empty() {
        warnings.push("no outputs configured: events will be discarded".to_string());
    }
    let output_ids: HashSet<&str> = cfg.outputs.iter().map(|o| o.id.as_str()).collect();
    for o in &cfg.outputs {
        if o.id.trim().is_empty() {
            bail!("outputs: every output requires a non-empty `id`");
        }
        if !ids.insert(&o.id) {
            bail!("duplicate input/output id: {}", o.id);
        }
        match o.kind {
            OutputKind::Syslog => {
                let addr = o.address.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "outputs[{}]: syslog output requires `address: host:port`",
                        o.id
                    )
                })?;
                if !addr.contains(':') {
                    bail!(
                        "outputs[{}]: `address` must be host:port (got {addr:?})",
                        o.id
                    );
                }
                if o.protocol == SyslogProtocol::Tls {
                    if let Some(tls) = &o.tls {
                        if let Some(ca) = &tls.ca {
                            require_file(ca, &format!("outputs[{}].tls.ca", o.id))?;
                        }
                        match (&tls.cert, &tls.key) {
                            (Some(c), Some(k)) => {
                                require_file(c, &format!("outputs[{}].tls.cert", o.id))?;
                                require_file(k, &format!("outputs[{}].tls.key", o.id))?;
                            }
                            (None, None) => {}
                            _ => bail!(
                                "outputs[{}]: mTLS requires both `tls.cert` and `tls.key`",
                                o.id
                            ),
                        }
                        if !tls.verify {
                            warnings.push(format!(
                                "outputs[{}]: TLS certificate verification is DISABLED",
                                o.id
                            ));
                        }
                    }
                }
            }
            OutputKind::Stdout => {}
        }
        if let Some(w) = &o.when {
            validate_condition(w, &format!("outputs[{}].when", o.id))?;
        }
        if let Some(f) = &o.failover_for {
            if !output_ids.contains(f.as_str()) {
                bail!(
                    "outputs[{}]: failover_for references unknown output {f:?}",
                    o.id
                );
            }
            if f == &o.id {
                bail!("outputs[{}]: failover_for cannot reference itself", o.id);
            }
        }
        if o.retry.batch_size == 0 {
            bail!("outputs[{}]: retry.batch_size must be >= 1", o.id);
        }
    }

    if cfg.buffer.max_size_mb < 1 {
        bail!("buffer.max_size_mb must be >= 1");
    }
    if cfg.buffer.segment_size_mb < 1 || cfg.buffer.segment_size_mb > cfg.buffer.max_size_mb {
        bail!("buffer.segment_size_mb must be between 1 and buffer.max_size_mb");
    }

    if cfg.web.enabled {
        let ip: IpAddr =
            cfg.web.bind.parse().with_context(|| {
                format!("web.bind must be an IP address (got {:?})", cfg.web.bind)
            })?;
        if !ip.is_loopback() {
            let is_blank = cfg.web.auth_token.is_none()
                || cfg.web.auth_token.as_deref().map(str::trim) == Some("");
            if is_blank {
                bail!(
                    "web.bind is {} (not loopback) but web.auth_token is not set — \
                     refusing to expose an unauthenticated config API. Set web.auth_token \
                     or bind to 127.0.0.1.",
                    cfg.web.bind
                );
            }
            warnings.push(format!(
                "SECURITY WARNING: web GUI is bound to {} and reachable from the network; \
                 restrict access with a firewall",
                cfg.web.bind
            ));
        }
    }

    match cfg.agent.log_level.as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => {}
        other => {
            bail!("agent.log_level must be one of trace|debug|info|warn|error (got {other:?})")
        }
    }

    Ok(warnings)
}

fn validate_parser(p: &ParserConfig, ctx: &str) -> Result<()> {
    if p.mode == ParserMode::Regex {
        let pat = p
            .pattern
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("{ctx}: parser mode `regex` requires `pattern`"))?;
        regex::Regex::new(pat).with_context(|| format!("{ctx}: invalid parser pattern"))?;
    }
    if p.mode == ParserMode::Kv && (p.pair_separator.is_empty() || p.kv_separator.is_empty()) {
        bail!("{ctx}: kv parser separators must not be empty");
    }
    Ok(())
}

fn validate_condition(c: &Condition, ctx: &str) -> Result<()> {
    match c.op.as_str() {
        "eq" | "ne" | "contains" | "gt" | "lt" => {
            if c.value.is_none() {
                bail!("{ctx}: op {:?} requires `value`", c.op);
            }
        }
        "matches" => {
            let v = c
                .value
                .as_ref()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("{ctx}: op `matches` requires a string `value`"))?;
            regex::Regex::new(v).with_context(|| format!("{ctx}: invalid regex in condition"))?;
        }
        "exists" | "not_exists" => {}
        other => bail!(
            "{ctx}: unknown condition op {other:?} (expected eq|ne|contains|matches|exists|not_exists|gt|lt)"
        ),
    }
    Ok(())
}

fn validate_transform(t: &TransformStep) -> Result<()> {
    match t {
        TransformStep::Mask { pattern, .. } => {
            regex::Regex::new(pattern).context("pipeline.transforms: invalid mask pattern")?;
        }
        TransformStep::Convert { to, .. } => match to.as_str() {
            "int" | "float" | "string" | "bool" => {}
            other => bail!(
                "pipeline.transforms: convert `to` must be int|float|string|bool (got {other:?})"
            ),
        },
        _ => {}
    }
    let when = match t {
        TransformStep::AddField { when, .. }
        | TransformStep::RemoveField { when, .. }
        | TransformStep::RenameField { when, .. }
        | TransformStep::Convert { when, .. }
        | TransformStep::Mask { when, .. } => when.as_ref(),
        TransformStep::Drop { when } | TransformStep::Keep { when } => Some(when),
    };
    if let Some(w) = when {
        validate_condition(w, "pipeline.transforms.when")?;
    }
    Ok(())
}

fn require_file(p: &Path, ctx: &str) -> Result<()> {
    if !p.is_file() {
        bail!("{ctx}: file not found: {}", p.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
agent:
  data_dir: /tmp/snx-test
inputs:
  files:
    - id: app
      paths: ["/var/log/*.log"]
  syslog:
    - id: rsyslog
      protocol: udp
      port: 5514
outputs:
  - id: console
    type: stdout
"#;

    #[test]
    fn parses_sample() {
        let (cfg, _w) = parse(SAMPLE).unwrap();
        assert_eq!(cfg.inputs.files.len(), 1);
        assert_eq!(cfg.inputs.syslog[0].port, 5514);
    }

    #[test]
    fn env_expansion() {
        std::env::set_var("SNX_TEST_PORT", "6601");
        let (s, _secrets) = expand_env("port: ${SNX_TEST_PORT}\nx: ${SNX_NOPE:-fallback}").unwrap();
        assert!(s.contains("6601"));
        assert!(s.contains("fallback"));
        assert!(expand_env("y: ${SNX_DEFINITELY_MISSING}").is_err());
    }

    /// H-3: `/api/config/validate` must never echo the raw substituted value
    /// of an env-referenced field back in an error message — that turns the
    /// endpoint into an oracle for reading the root process's environment
    /// one variable at a time.
    #[test]
    fn parse_errors_never_echo_expanded_env_values() {
        std::env::set_var("SNX_TEST_SECRET", "hunter2-super-secret");
        let yaml = "agent:\n  log_level: \"${SNX_TEST_SECRET}\"\n";
        let err = parse(yaml).expect_err("must reject the log level");
        let msg = format!("{err:#}");
        std::env::remove_var("SNX_TEST_SECRET");
        assert!(
            !msg.contains("hunter2-super-secret"),
            "error leaked the env value: {msg}"
        );
        assert!(msg.contains("***"), "expected a redaction marker: {msg}");
    }

    #[test]
    fn rejects_duplicate_ids() {
        let bad = r#"
inputs:
  files:
    - id: a
      paths: ["/x/*.log"]
  syslog:
    - id: a
      port: 514
"#;
        assert!(parse(bad).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(parse("agent:\n  bogus_key: 1\n").is_err());
    }

    #[test]
    fn warns_on_public_bind_with_token_set() {
        let s = r#"
web:
  bind: 0.0.0.0
  auth_token: some-secret-token
outputs:
  - id: console
    type: stdout
"#;
        let (_c, w) = parse(s).unwrap();
        assert!(w.iter().any(|x| x.contains("SECURITY WARNING")));
    }

    #[test]
    fn errors_on_public_bind_without_token() {
        let s = r#"
web:
  bind: 0.0.0.0
outputs:
  - id: console
    type: stdout
"#;
        let err = parse(s).unwrap_err();
        assert!(format!("{err:#}").contains("auth_token"));
    }

    /// audit C-1: `auth_token: ""` (e.g. from `${WEB_TOKEN:-}` with WEB_TOKEN
    /// unset) must be treated the same as an absent token on a non-loopback
    /// bind — a blank string must not sail past this hard-error gate.
    #[test]
    fn errors_on_public_bind_with_blank_token() {
        let s = r#"
web:
  bind: 0.0.0.0
  auth_token: ""
outputs:
  - id: console
    type: stdout
"#;
        let err = parse(s).unwrap_err();
        assert!(format!("{err:#}").contains("auth_token"));
    }

    /// Regression for the shipped `examples/agent.yaml`: `expand_env` runs
    /// over the raw file text before YAML parsing and is not comment-aware,
    /// so a `${VAR}` reference left inside a `#`-prefixed comment still fails
    /// the whole file to expand when `VAR` is unset. `parses_sample` above
    /// only exercises an inline string constant, so it never caught this —
    /// load the actual example file here, with the env vars it might
    /// reference guaranteed unset, and run only `expand_env` on it.
    ///
    /// This deliberately does NOT call `parse()`/`load()`, since those also
    /// run `validate()`'s file-existence checks (e.g. the TLS certificate
    /// paths referenced by the shipped example), which is an unrelated,
    /// separate, pre-existing concern this test is not about.
    #[test]
    fn loads_shipped_example_env_expansion_with_no_env_vars_set() {
        // Defensive: env vars are process-global and test execution order
        // isn't guaranteed, so another test in this binary could otherwise
        // have left one of these set.
        std::env::remove_var("WEB_TOKEN");

        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/agent.yaml");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        expand_env(&raw).unwrap_or_else(|e| {
            panic!(
                "examples/agent.yaml's auth_token placeholder must not reference an \
                 undefined env var (a new user hasn't configured any yet); got error: {e:#}"
            )
        });
    }
}
