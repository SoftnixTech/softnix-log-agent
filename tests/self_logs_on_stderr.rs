//! The agent's own log lines go to stderr, so stdout carries only what
//! a `type: stdout` output writes. The tracing subscriber is installed inside
//! the binary, so this spawns the real executable.

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const MARKER: &str = "SELF-LOGS-EVENT";

#[test]
fn self_logs_go_to_stderr_not_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("in.jsonl");
    std::fs::write(&input, format!("{{\"message\":\"{MARKER}\"}}\n")).unwrap();
    let config = dir.path().join("agent.yaml");
    std::fs::write(
        &config,
        format!(
            "agent:\n  data_dir: '{data}'\n  log_level: info\n\
             web:\n  enabled: false\n\
             inputs:\n  files:\n    - id: f\n      paths: ['{input}']\n      read_from_start: true\n      poll_interval_ms: 100\n      parser:\n        mode: json\n\
             outputs:\n  - id: out\n    type: stdout\n    format: json\n",
            data = dir.path().join("data").display(),
            input = input.display(),
        ),
    )
    .unwrap();
    // `check_config_permissions` refuses a group- or world-writable config.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_softnix-log-agent"))
        .arg("run")
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Read stdout on a thread, so the wait below can time out.
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stdout_lines = Vec::new();
    let mut saw_event = false;
    while !saw_event {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(line) => {
                saw_event = line.contains(MARKER);
                stdout_lines.push(line);
            }
            Err(_) => break,
        }
    }

    child.kill().unwrap();
    child.wait().unwrap();
    // The reader thread ends when the pipe closes: collect what is left.
    stdout_lines.extend(rx.iter());
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();

    assert!(
        saw_event,
        "the event never reached stdout.\nstdout: {stdout_lines:#?}\nstderr: {stderr}"
    );
    for line in stdout_lines.iter().filter(|l| !l.trim().is_empty()) {
        assert!(
            serde_json::from_str::<serde_json::Value>(line).is_ok(),
            "stdout must carry only events, but got this line: {line}"
        );
    }
    assert!(
        stderr.contains("Softnix Log Agent v"),
        "the startup log line must be on stderr, got: {stderr}"
    );
}
