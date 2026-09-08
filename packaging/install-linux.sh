#!/usr/bin/env bash
#
# Softnix Log Agent — Linux installer
#
# Checks every dependency, builds (or uses a prebuilt binary), installs the
# binary + config + systemd service, validates, starts, and health-checks.
#
# Usage:
#   sudo ./install-linux.sh                  # build from source and install
#   sudo ./install-linux.sh --binary <path>  # install a prebuilt binary
#   sudo ./install-linux.sh --no-start       # install but don't start
#   sudo ./install-linux.sh --uninstall      # remove service + binary
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Constants & helpers
# ---------------------------------------------------------------------------
NAME="softnix-log-agent"
BIN_DST="/usr/local/bin/${NAME}"
CONF_DIR="/etc/softnix-log-agent"
CONF="${CONF_DIR}/agent.yaml"
DATA_DIR="/var/lib/softnix-log-agent"
UNIT="/etc/systemd/system/${NAME}.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MIN_RUST_MINOR=80          # requires Rust 1.80+

BINARY=""                  # --binary <path>
START=1                    # --no-start
ASSUME_YES=0               # --yes
UNINSTALL=0

if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; BLD=$'\033[1m'; RST=$'\033[0m'
else
  RED=""; GRN=""; YLW=""; BLD=""; RST=""
fi
info()  { echo "${GRN}[ok]${RST}    $*"; }
step()  { echo "${BLD}==>${RST} $*"; }
warn()  { echo "${YLW}[warn]${RST}  $*"; }
fail()  { echo "${RED}[error]${RST} $*" >&2; exit 1; }

confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  read -r -p "$1 [Y/n] " ans
  case "${ans:-Y}" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

usage() { sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --binary)    BINARY="$2"; shift 2 ;;
    --no-start)  START=0; shift ;;
    --yes|-y)    ASSUME_YES=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --help|-h)   usage ;;
    *) fail "unknown option: $1 (try --help)" ;;
  esac
done

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
step "Checking environment"

[ "$(id -u)" -eq 0 ] || fail "must run as root: sudo $0 $*"

[ "$(uname -s)" = "Linux" ] || fail "this installer is for Linux (detected $(uname -s)); see docs/INSTALL-WINDOWS.md for Windows"

command -v systemctl >/dev/null 2>&1 || fail "systemd is required (systemctl not found)"
[ -d /run/systemd/system ] || fail "systemd is not the active init system on this host"
info "systemd detected"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|aarch64|arm64) info "architecture: ${ARCH}" ;;
  *) warn "untested architecture: ${ARCH} — continuing" ;;
esac

# ---------------------------------------------------------------------------
# Uninstall path
# ---------------------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
  step "Uninstalling ${NAME}"
  systemctl stop "$NAME" 2>/dev/null || true
  systemctl disable "$NAME" 2>/dev/null || true
  rm -f "$UNIT"; systemctl daemon-reload
  rm -f "$BIN_DST"
  info "service and binary removed"
  echo "  kept (remove manually if desired):"
  echo "    config: ${CONF_DIR}"
  echo "    state/queues: ${DATA_DIR}"
  exit 0
fi

# ---------------------------------------------------------------------------
# Obtain the binary: prebuilt or build from source
# ---------------------------------------------------------------------------
if [ -n "$BINARY" ]; then
  step "Using prebuilt binary"
  [ -f "$BINARY" ] || fail "binary not found: $BINARY"
  [ -x "$BINARY" ] || chmod +x "$BINARY" || fail "binary is not executable: $BINARY"
  # Show the loader's actual complaint (e.g. "version `GLIBC_2.34' not
  # found") instead of swallowing it - that one line is the whole diagnosis.
  if ! PROBE="$("$BINARY" --version 2>&1)"; then
    fail "$BINARY does not run on this host (wrong arch or libc?):
${PROBE}
  arch: $(uname -m)   libc: $(ldd --version 2>&1 | head -1)"
  fi
  info "binary OK: ${PROBE}"
else
  step "Building from source"
  [ -f "${REPO_DIR}/Cargo.toml" ] || fail "run this script from the repository (Cargo.toml not found in ${REPO_DIR}); or pass --binary <path>"

  # --- C compiler & linker (needed by the `ring` crate) -------------------
  if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    warn "no C compiler found (required to build TLS support)"
    PKG=""
    if   command -v apt-get >/dev/null 2>&1; then PKG="apt-get install -y build-essential pkg-config"
    elif command -v dnf     >/dev/null 2>&1; then PKG="dnf install -y gcc make"
    elif command -v yum     >/dev/null 2>&1; then PKG="yum install -y gcc make"
    elif command -v zypper  >/dev/null 2>&1; then PKG="zypper install -y gcc make"
    elif command -v apk     >/dev/null 2>&1; then PKG="apk add build-base"
    fi
    [ -n "$PKG" ] || fail "install a C compiler (gcc) manually, then re-run"
    confirm "Install C compiler via: ${PKG}?" || fail "C compiler is required"
    sh -c "$PKG" || fail "compiler installation failed"
  fi
  info "C compiler: $(cc --version 2>/dev/null | head -1 || gcc --version | head -1)"

  # --- Rust toolchain ------------------------------------------------------
  # Find cargo for the invoking user (rustup installs per-user).
  REAL_USER="${SUDO_USER:-root}"
  REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
  export PATH="${REAL_HOME}/.cargo/bin:${PATH}"

  if ! command -v cargo >/dev/null 2>&1; then
    warn "Rust toolchain not found"
    command -v curl >/dev/null 2>&1 || fail "curl is required to install Rust (or install Rust manually from https://rustup.rs)"
    confirm "Install Rust (stable, minimal profile) via rustup for user ${REAL_USER}?" || fail "Rust 1.${MIN_RUST_MINOR}+ is required"
    if [ "$REAL_USER" = "root" ]; then
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
    else
      su - "$REAL_USER" -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal"
    fi
    export PATH="${REAL_HOME}/.cargo/bin:${PATH}"
    command -v cargo >/dev/null 2>&1 || fail "cargo still not found after installation"
  fi

  RUST_MINOR="$(rustc --version | sed -E 's/rustc 1\.([0-9]+).*/\1/')"
  [ "$RUST_MINOR" -ge "$MIN_RUST_MINOR" ] 2>/dev/null \
    || fail "Rust 1.${MIN_RUST_MINOR}+ required (found $(rustc --version)); run: rustup update stable"
  info "Rust toolchain: $(rustc --version)"

  # --- Build ---------------------------------------------------------------
  step "Compiling release binary (this takes a few minutes on first build)"
  if [ "$REAL_USER" != "root" ] && [ -O "${REPO_DIR}/Cargo.toml" ]; then
    cargo build --release --manifest-path "${REPO_DIR}/Cargo.toml"
  else
    su - "$REAL_USER" -c "cd '${REPO_DIR}' && '${REAL_HOME}/.cargo/bin/cargo' build --release" 2>/dev/null \
      || cargo build --release --manifest-path "${REPO_DIR}/Cargo.toml"
  fi
  BINARY="${REPO_DIR}/target/release/${NAME}"
  [ -f "$BINARY" ] || fail "build did not produce ${BINARY}"

  # --- Tests (quick safety net; skippable) ---------------------------------
  if confirm "Run the automated test suite before installing (recommended)?"; then
    cargo test --release --manifest-path "${REPO_DIR}/Cargo.toml" >/dev/null \
      && info "all tests passed" \
      || fail "tests failed — aborting install"
  fi
fi

# ---------------------------------------------------------------------------
# Install files
# ---------------------------------------------------------------------------
step "Installing files"

if systemctl is-active --quiet "$NAME" 2>/dev/null; then
  warn "service is running — stopping for upgrade"
  systemctl stop "$NAME"
fi

install -m 755 "$BINARY" "$BIN_DST"
info "binary    -> ${BIN_DST} ($("$BIN_DST" --version 2>/dev/null || echo installed))"

mkdir -p "$CONF_DIR" "$DATA_DIR"
chmod 700 "$DATA_DIR"

if [ -f "$CONF" ]; then
  info "config    -> ${CONF} (existing config kept)"
else
  if [ -f "${REPO_DIR}/examples/agent.yaml" ]; then
    SRC_CONF="${REPO_DIR}/examples/agent.yaml"
  else
    SRC_CONF=""
  fi
  if [ -n "$SRC_CONF" ] && "$BIN_DST" validate --config "$SRC_CONF" >/dev/null 2>&1; then
    install -m 600 "$SRC_CONF" "$CONF"
  else
    # Safe minimal default that always validates. Every section below that
    # is active (uncommented) is enough on its own to run; everything
    # commented out documents an option this agent supports, so this file
    # doubles as a quick-start reference without needing to go find
    # examples/agent.yaml. Full reference: examples/agent.yaml in the
    # source repository, or docs/CONFIGURATION.md.
    cat > "$CONF" <<EOF
# Softnix Log Agent configuration
# Full reference for every option: examples/agent.yaml in the source
# repository, or docs/CONFIGURATION.md.

agent:
  # Where state (file offsets) and the persistent queue live.
  data_dir: ${DATA_DIR}
  # Agent self-log level: trace|debug|info|warn|error
  log_level: info

inputs:
  files:
    - id: system-logs
      paths:
        - /var/log/*.log
      # exclude:
      #   - /var/log/lastlog
      #   - "**/*.gz"
      # poll_interval_ms: 500        # default; how often to re-read tailed files
      # read_from_start: false       # default: skip pre-existing content on first run
      # source_type: linux-syslog    # overrides the default "file" source_type
      # parser:
      #   mode: raw                  # raw | json | kv | regex | syslog

  # Listen for syslog directly, instead of (or alongside) tailing files.
  # syslog:
  #   - id: udp514
  #     protocol: udp                # udp | tcp | tls
  #     bind: 0.0.0.0
  #     port: 514
  #     format: auto                 # auto | rfc3164 | rfc5424 | json | raw
  #   - id: tls6514
  #     protocol: tls
  #     bind: 0.0.0.0
  #     port: 6514
  #     tls:
  #       cert: /etc/softnix-log-agent/tls/server.crt
  #       key: /etc/softnix-log-agent/tls/server.key

# pipeline:
#   transforms:
#     - type: add_field
#       field: team
#       value: platform
#     - type: mask
#       field: message
#       pattern: '\b\d{13,16}\b'
#       replacement: "[REDACTED]"
#     - type: drop
#       when: { field: message, op: contains, value: "health-check" }
#   enrich:
#     hostname: true
#     os_info: true
#     agent_version: true
#     environment: production
#     tags: [edge]

# buffer:
#   max_size_mb: 1024               # per destination, default
#   segment_size_mb: 8              # default
#   full_policy: block              # block | drop_oldest | drop_newest

outputs:
  # Replace with your real destination, e.g. syslog over TLS:
  # - id: siem
  #   type: syslog
  #   protocol: tls
  #   address: siem.example.com:6514
  #   format: rfc5424               # rfc5424 | rfc3164 | json | raw
  #   tls:
  #     ca: /etc/softnix-log-agent/tls/siem-ca.crt
  #     cert: /etc/softnix-log-agent/tls/agent.crt   # mTLS client cert
  #     key: /etc/softnix-log-agent/tls/agent.key
  #   retry:
  #     initial_backoff_ms: 500     # default
  #     max_backoff_ms: 30000       # default
  #     batch_size: 200             # default
  #   failover_for: siem-primary    # use this destination only while another is unhealthy
  #   when: { field: severity, op: lt, value: 4 }   # route only matching events here
  - id: console
    type: stdout
    format: json

web:
  enabled: true
  bind: 127.0.0.1                  # localhost-only by default
  port: 8080
  # Required, not just recommended: if you change bind above to 0.0.0.0 (or
  # any non-loopback address) without setting this, the agent refuses to
  # start at all rather than expose the config API unauthenticated.
  # auth_token: replace-with-a-long-random-secret
EOF
    chmod 600 "$CONF"
  fi
  info "config    -> ${CONF} (new)"
fi

step "Validating configuration"
"$BIN_DST" validate --config "$CONF" || fail "configuration is invalid — fix ${CONF} and re-run"

# ---------------------------------------------------------------------------
# systemd service
# ---------------------------------------------------------------------------
step "Installing systemd service"
cat > "$UNIT" <<EOF
[Unit]
Description=Softnix Log Agent
Documentation=https://www.softnix.co.th
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DST} run --config ${CONF}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=${DATA_DIR}
LimitNOFILE=65536
MemoryMax=512M
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$NAME" >/dev/null 2>&1
info "unit      -> ${UNIT} (enabled at boot)"

# ---------------------------------------------------------------------------
# Start & verify
# ---------------------------------------------------------------------------
if [ "$START" = 1 ]; then
  step "Starting service"
  systemctl start "$NAME"
  sleep 2
  systemctl is-active --quiet "$NAME" \
    || { journalctl -u "$NAME" -n 20 --no-pager || true; fail "service failed to start (log above)"; }
  info "service is active"

  WEB_PORT="$(sed -n 's/^[[:space:]]*port:[[:space:]]*\([0-9]\+\).*/\1/p' "$CONF" | tail -1)"
  WEB_PORT="${WEB_PORT:-8080}"
  if command -v curl >/dev/null 2>&1; then
    if curl -sf "http://127.0.0.1:${WEB_PORT}/healthz" >/dev/null 2>&1; then
      info "health check passed: http://127.0.0.1:${WEB_PORT}/healthz"
    else
      warn "health endpoint not reachable on port ${WEB_PORT} (web GUI may be disabled)"
    fi
  fi
else
  warn "skipped start (--no-start); start later with: systemctl start ${NAME}"
fi

echo
echo "${BLD}${GRN}Softnix Log Agent installed successfully.${RST}"
echo
echo "  config:   ${CONF}"
echo "  state:    ${DATA_DIR}"
echo "  web GUI:  http://127.0.0.1:${WEB_PORT:-8080} (localhost only)"
echo "  logs:     journalctl -u ${NAME} -f"
echo "  reload:   systemctl kill -s HUP ${NAME}"
echo "  manage:   systemctl start|stop|restart ${NAME}"
echo "  remove:   sudo $0 --uninstall"
