use crate::config::EnrichConfig;
use crate::event::Event;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Enrichment
// ---------------------------------------------------------------------------

/// Static enrichment values resolved once at engine start.
pub struct Enricher {
    hostname: Option<String>,
    os: Option<String>,
    local_ip: Option<String>,
    environment: Option<String>,
    site: Option<String>,
    tenant: Option<String>,
    customer: Option<String>,
    tags: Vec<String>,
    fields: serde_json::Map<String, Value>,
}

impl Enricher {
    pub fn new(cfg: &EnrichConfig) -> Self {
        Enricher {
            hostname: if cfg.hostname {
                hostname::get()
                    .ok()
                    .map(|h| h.to_string_lossy().into_owned())
            } else {
                None
            },
            os: if cfg.os_info {
                Some(format!(
                    "{} {}",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                ))
            } else {
                None
            },
            local_ip: if cfg.local_ip {
                detect_local_ip()
            } else {
                None
            },
            environment: cfg.environment.clone(),
            site: cfg.site.clone(),
            tenant: cfg.tenant.clone(),
            customer: cfg.customer.clone(),
            tags: cfg.tags.clone(),
            fields: cfg.fields.clone(),
        }
    }

    pub fn apply(&self, ev: &mut Event) {
        if ev.hostname.is_none() {
            ev.hostname = self.hostname.clone();
        }
        if let Some(os) = &self.os {
            ev.fields
                .entry("os".to_string())
                .or_insert_with(|| Value::String(os.clone()));
        }
        if let Some(ip) = &self.local_ip {
            ev.fields
                .entry("local_ip".to_string())
                .or_insert_with(|| Value::String(ip.clone()));
        }
        for (key, val) in [
            ("environment", &self.environment),
            ("site", &self.site),
            ("tenant", &self.tenant),
            ("customer", &self.customer),
        ] {
            if let Some(v) = val {
                ev.fields
                    .entry(key.to_string())
                    .or_insert_with(|| Value::String(v.clone()));
            }
        }
        if !self.tags.is_empty() {
            ev.fields.entry("tags".to_string()).or_insert_with(|| {
                Value::Array(self.tags.iter().cloned().map(Value::String).collect())
            });
        }
        for (k, v) in &self.fields {
            ev.fields.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
}

/// Best-effort local IP discovery without extra dependencies: a UDP "connect"
/// (no packets sent) reveals the kernel-chosen source address.
fn detect_local_ip() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ParserConfig;
    use crate::pipeline::parser::Parser;

    fn raw_parser() -> Parser {
        Parser::compile(&ParserConfig::default()).unwrap()
    }

    #[test]
    fn enrichment_applies() {
        let cfg: EnrichConfig = serde_yaml::from_str(
            r#"
environment: production
tags: [edge, th]
fields:
  rack: r12
"#,
        )
        .unwrap();
        let e = Enricher::new(&cfg);
        let mut ev = raw_parser().parse("hello", "f", "file");
        e.apply(&mut ev);
        assert_eq!(ev.fields["environment"], Value::String("production".into()));
        assert_eq!(ev.fields["rack"], Value::String("r12".into()));
        assert!(ev.hostname.is_some());
    }
}
