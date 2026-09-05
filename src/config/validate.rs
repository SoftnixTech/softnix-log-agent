//! Structural validation of a parsed [`Config`](super::Config): id
//! uniqueness, cross-field rules, and the conditions/transforms DSL.

use super::schema::*;
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

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
        if f.discovery_interval_ms < 50 {
            bail!(
                "inputs.files[{}]: discovery_interval_ms must be >= 50 (got {})",
                f.id,
                f.discovery_interval_ms
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
        // `0` is exactly the value an operator would reach for to mean
        // "unlimited"/"disabled", but it actually breaks the listener: a
        // zero-sized semaphore rejects every connection, and a zero
        // `Duration` timeout elapses instantly, closing every connection or
        // handshake as soon as it starts. 1 is a legitimate (if extreme)
        // value for all three; 0 never is.
        if s.max_connections == 0 {
            bail!(
                "inputs.syslog[{}]: `max_connections` must be >= 1 (got 0)",
                s.id
            );
        }
        if s.idle_timeout_secs == 0 {
            bail!(
                "inputs.syslog[{}]: `idle_timeout_secs` must be >= 1 (got 0)",
                s.id
            );
        }
        if s.handshake_timeout_secs == 0 {
            bail!(
                "inputs.syslog[{}]: `handshake_timeout_secs` must be >= 1 (got 0)",
                s.id
            );
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
        for entry in &s.allowed_senders {
            parse_ip_net(entry).with_context(|| {
                format!(
                    "inputs.syslog[{}]: `allowed_senders` entry {:?} is not a valid IP or CIDR",
                    s.id, entry
                )
            })?;
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
    use crate::config::{check_config_permissions, parse};

    #[test]
    fn accepts_valid_allowed_senders() {
        let yaml = r#"
inputs:
  syslog:
    - id: rsyslog
      protocol: udp
      port: 5514
      allowed_senders: ["10.0.0.0/8", "192.168.1.5", "::1"]
outputs:
  - id: console
    type: stdout
"#;
        let (cfg, _w) = parse(yaml).unwrap();
        assert_eq!(cfg.inputs.syslog[0].allowed_senders.len(), 3);
    }

    #[test]
    fn rejects_invalid_allowed_senders_entry() {
        let yaml = r#"
inputs:
  syslog:
    - id: rsyslog
      protocol: udp
      port: 5514
      allowed_senders: ["10.0.0.0/8", "not-an-ip-or-cidr"]
outputs:
  - id: console
    type: stdout
"#;
        let err = parse(yaml).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("rsyslog"), "expected input id in error: {msg}");
        assert!(
            msg.contains("not-an-ip-or-cidr"),
            "expected the bad entry in error: {msg}"
        );
    }

    /// H-5 fix round 1: `0` for these knobs isn't "unlimited"/"disabled" —
    /// it breaks the listener (a zero-sized semaphore rejects every
    /// connection; a zero timeout elapses instantly) — so `validate()` must
    /// reject it rather than silently accepting a config that drops 100% of
    /// traffic.
    #[test]
    fn rejects_zero_max_connections() {
        let yaml = r#"
inputs:
  syslog:
    - id: rsyslog
      protocol: tcp
      port: 5514
      max_connections: 0
outputs:
  - id: console
    type: stdout
"#;
        let err = parse(yaml).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("rsyslog"), "expected input id in error: {msg}");
        assert!(
            msg.contains("max_connections"),
            "expected field name in error: {msg}"
        );
    }

    #[test]
    fn rejects_zero_idle_timeout_secs() {
        let yaml = r#"
inputs:
  syslog:
    - id: rsyslog
      protocol: tcp
      port: 5514
      idle_timeout_secs: 0
outputs:
  - id: console
    type: stdout
"#;
        let err = parse(yaml).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("rsyslog"), "expected input id in error: {msg}");
        assert!(
            msg.contains("idle_timeout_secs"),
            "expected field name in error: {msg}"
        );
    }

    #[test]
    fn rejects_zero_handshake_timeout_secs() {
        let yaml = r#"
inputs:
  syslog:
    - id: rsyslog
      protocol: tcp
      port: 5514
      handshake_timeout_secs: 0
outputs:
  - id: console
    type: stdout
"#;
        let err = parse(yaml).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("rsyslog"), "expected input id in error: {msg}");
        assert!(
            msg.contains("handshake_timeout_secs"),
            "expected field name in error: {msg}"
        );
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

    /// Fix round 1, FIX 2: `tokio::time::interval` panics on a zero period,
    /// and this crate's release profile sets `panic = "abort"`, so an
    /// unvalidated `discovery_interval_ms: 0` would abort the whole agent
    /// process. `poll_interval_ms` already has this floor; discovery_interval_ms
    /// must get the same one.
    #[test]
    fn rejects_zero_discovery_interval_ms() {
        let bad = r#"
inputs:
  files:
    - id: a
      paths: ["/x/*.log"]
      discovery_interval_ms: 0
outputs:
  - id: console
    type: stdout
"#;
        let err = parse(bad).unwrap_err();
        assert!(
            format!("{err:#}").contains("discovery_interval_ms"),
            "expected a discovery_interval_ms error, got: {err:#}"
        );
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

    #[test]
    fn a_world_writable_config_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent.yaml");
        std::fs::write(&p, "agent: {}\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        #[cfg(unix)]
        assert!(check_config_permissions(&p).is_err());
    }

    #[test]
    fn a_private_config_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent.yaml");
        std::fs::write(&p, "agent: {}\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(check_config_permissions(&p).is_ok());
    }
}
