//! `${VAR}` / `${VAR:-default}` environment expansion, and redaction of the
//! values it substitutes.

use anyhow::{bail, Result};

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
pub(crate) fn redact(msg: String, secrets: &[String]) -> String {
    let mut msg = msg;
    for s in secrets {
        if s.len() >= 2 {
            msg = msg.replace(s.as_str(), "***");
        }
    }
    msg
}


#[cfg(test)]
mod tests {
    use super::*;

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
        let err = crate::config::parse(yaml).expect_err("must reject the log level");
        let msg = format!("{err:#}");
        std::env::remove_var("SNX_TEST_SECRET");
        assert!(
            !msg.contains("hunter2-super-secret"),
            "error leaked the env value: {msg}"
        );
        assert!(msg.contains("***"), "expected a redaction marker: {msg}");
    }
}
