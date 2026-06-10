# Linux installation guide

## Quick install (recommended)

One script checks every dependency (systemd, C compiler, Rust — offering to install what's missing), builds or takes a prebuilt binary, installs config + hardened systemd unit, validates, starts, and health-checks:

```bash
sudo ./packaging/install-linux.sh             # build from source + install
sudo ./packaging/install-linux.sh --binary ./softnix-log-agent   # prebuilt binary
sudo ./packaging/install-linux.sh --yes       # non-interactive (CI / fleet rollout)
sudo ./packaging/install-linux.sh --no-start  # install only
sudo ./packaging/install-linux.sh --uninstall # remove service + binary (config/state kept)
```

The script is idempotent: re-running upgrades the binary, keeps an existing config, and restarts the service. Verified end-to-end on Ubuntu 24.04 (install → ingest → SIGHUP reload → uninstall).

The sections below describe the same steps manually.

## Build

Requirements: Rust 1.80+ (`curl https://sh.rustup.rs -sSf | sh`). No system libraries needed (TLS is rustls, statically linked).

```bash
cargo build --release
# binary: target/release/softnix-log-agent  (~4 MB)
```

For a fully static binary (recommended for heterogeneous fleets):

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Install as a systemd service

```bash
sudo install -m 755 target/release/softnix-log-agent /usr/local/bin/
sudo mkdir -p /etc/softnix-log-agent /var/lib/softnix-log-agent
sudo cp examples/agent.yaml /etc/softnix-log-agent/agent.yaml
sudo $EDITOR /etc/softnix-log-agent/agent.yaml

# always validate before starting
sudo softnix-log-agent validate --config /etc/softnix-log-agent/agent.yaml

# writes /etc/systemd/system/softnix-log-agent.service and enables it
sudo softnix-log-agent service install --config /etc/softnix-log-agent/agent.yaml
sudo softnix-log-agent service start          # or: systemctl start softnix-log-agent
systemctl status softnix-log-agent
```

The generated unit applies least-privilege hardening (`NoNewPrivileges`, `ProtectSystem=full`, `PrivateTmp`, `MemoryMax=512M`). A reference copy is in [packaging/softnix-log-agent.service](../packaging/softnix-log-agent.service); adjust `ReadWritePaths` if you change `agent.data_dir`.

Note: binding ports below 1024 (e.g. syslog 514) requires root or
`sudo setcap cap_net_bind_service=+ep /usr/local/bin/softnix-log-agent`,
or add `AmbientCapabilities=CAP_NET_BIND_SERVICE` to the unit.

## Manage

```bash
sudo softnix-log-agent service start|stop|restart
sudo softnix-log-agent service uninstall
sudo systemctl kill -s HUP softnix-log-agent     # config reload without restart
journalctl -u softnix-log-agent -f               # agent logs
```

State and queues live in `agent.data_dir` (default `/var/lib/softnix-log-agent`): `state.json` plus one queue directory per output. Removing them resets read positions and discards buffered events.

## Upgrade

```bash
sudo softnix-log-agent service stop
sudo install -m 755 target/release/softnix-log-agent /usr/local/bin/
sudo softnix-log-agent service start
```

State and queue formats are versionless JSON/segments; offsets and buffered events survive upgrades.
