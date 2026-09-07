//! Configuration: the on-disk schema, environment expansion, and validation.
//!
//! Split by responsibility so that adding a field (schema.rs) and adding a
//! rule about that field (validate.rs) are separate diffs.

mod env;
mod schema;
mod validate;

pub use env::expand_env;
pub use schema::*;
pub use validate::validate;

#[cfg(unix)]
use anyhow::bail;
use anyhow::{Context, Result};
use std::path::Path;

/// Parse and validate config text. Returns the config plus non-fatal warnings.
pub fn parse(raw: &str) -> Result<(Config, Vec<String>)> {
    let (expanded, secrets) = expand_env(raw)?;
    parse_expanded(&expanded).map_err(|e| anyhow::anyhow!(env::redact(format!("{e:#}"), &secrets)))
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

/// Refuse a config file that non-administrators can write. The agent runs as
/// root/LocalSystem and its config decides which files it reads and where it
/// ships them, so a writable config is a privilege-escalation primitive.
pub fn check_config_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o022 != 0 {
            bail!(
                "config {} is group- or world-writable (mode {:o}); \
                 run: chmod 600 {}",
                path.display(),
                mode & 0o777,
                path.display()
            );
        }
    }
    #[cfg(windows)]
    {
        // Windows ACLs are enforced by the installer (icacls, inheritance
        // broken). A full DACL walk needs windows-acl; log a warning if the
        // file is not under a protected directory.
        tracing::debug!(path = %path.display(), "config permission check: relying on installer ACLs");
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
        assert_eq!(cfg.inputs.files[0].discovery_interval_ms, 30_000);
        assert_eq!(cfg.inputs.syslog[0].port, 5514);
    }

    /// H-5: connection-cap/timeout/allowlist knobs default to safe values
    /// when a syslog input doesn't set them, preserving pre-existing
    /// behavior (unlimited senders) while still bounding connections.
    #[test]
    fn syslog_input_defaults_for_new_knobs() {
        let (cfg, _w) = parse(SAMPLE).unwrap();
        let s = &cfg.inputs.syslog[0];
        assert_eq!(s.max_connections, 512);
        assert_eq!(s.idle_timeout_secs, 300);
        assert_eq!(s.handshake_timeout_secs, 10);
        assert!(s.allowed_senders.is_empty());
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
