//! Configuration schema: the on-disk `Config` structure, its defaults, and
//! IP/CIDR parsing shared with validation.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;

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
    /// How long a file cursor may go untouched before it is pruned from
    /// state.json (rotated-away files). Default 24h.
    #[serde(default = "default_state_retention_hours")]
    pub state_retention_hours: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            data_dir: default_data_dir(),
            log_level: default_log_level(),
            state_retention_hours: default_state_retention_hours(),
        }
    }
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("data")
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_state_retention_hours() -> u64 {
    24
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
    /// Poll interval for tailing already-discovered files, in milliseconds.
    #[serde(default = "default_poll_ms")]
    pub poll_interval_ms: u64,
    /// Interval between filesystem discovery passes (the glob walk that
    /// finds new/removed files), in milliseconds. Kept separate from, and
    /// much slower than, `poll_interval_ms`: the glob walk is the expensive
    /// part, and re-running it on every tail tick does needless I/O for no
    /// benefit on hosts with many globbed files.
    #[serde(default = "default_discovery_ms")]
    pub discovery_interval_ms: u64,
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

fn default_discovery_ms() -> u64 {
    30_000
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
    /// Maximum number of concurrently open TCP/TLS connections (UDP is
    /// connectionless and ignores this). Caps how many idle or slow senders
    /// can pin file descriptors before legitimate senders and the agent's
    /// own outbound connections start starving.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Close a TCP/TLS connection that has sent no complete line for this
    /// long, in seconds. Prevents a slowloris-style idle hold from pinning a
    /// connection-limit slot and a file descriptor indefinitely.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    /// Abandon a TLS handshake that has not completed within this many
    /// seconds. TCP only (plain TCP has no handshake).
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    /// Allowlist of source IPs/CIDRs permitted to send to this input, e.g.
    /// ["10.0.0.0/8", "192.168.1.5"]. Empty (the default) allows any sender,
    /// preserving pre-existing behavior.
    #[serde(default)]
    pub allowed_senders: Vec<String>,
}

fn default_bind_all() -> String {
    "0.0.0.0".to_string()
}

fn default_max_connections() -> usize {
    512
}

fn default_idle_timeout_secs() -> u64 {
    300
}

fn default_handshake_timeout_secs() -> u64 {
    10
}

/// Parse one `allowed_senders` entry as an `ipnet::IpNet`. `ipnet::IpNet`'s
/// `FromStr` requires an explicit prefix (e.g. "10.0.0.0/8") and rejects a
/// bare IP address, so a bare IP is widened to a host route (`/32` for IPv4,
/// `/128` for IPv6) before being treated as an error.
pub fn parse_ip_net(s: &str) -> Result<ipnet::IpNet> {
    if let Ok(net) = s.parse::<ipnet::IpNet>() {
        return Ok(net);
    }
    let addr: IpAddr = s
        .parse()
        .with_context(|| format!("invalid IP or CIDR: {s:?}"))?;
    let prefix_len = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    Ok(ipnet::IpNet::new(addr, prefix_len).expect("prefix_len is valid for the address family"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_net_accepts_bare_ips_and_cidrs() {
        assert!(parse_ip_net("10.0.0.1").is_ok());
        assert!(parse_ip_net("10.0.0.0/8").is_ok());
        assert!(parse_ip_net("::1").is_ok());
        assert!(parse_ip_net("2001:db8::/32").is_ok());
        assert!(parse_ip_net("not-an-ip").is_err());
        assert!(parse_ip_net("10.0.0.0/99").is_err());
    }

    #[test]
    fn parse_ip_net_bare_ipv4_matches_only_itself() {
        let net = parse_ip_net("10.0.0.1").unwrap();
        assert!(net.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!net.contains(&"10.0.0.2".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(crate::config::parse("agent:\n  bogus_key: 1\n").is_err());
    }
}
