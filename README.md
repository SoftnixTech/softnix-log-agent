# Softnix Log Agent

A lightweight, reliable, cross-platform log collector agent written in Rust — in the spirit of NXLog / Fluent Bit / Vector, but optimized for simplicity, low resource usage and operational clarity.

```
Inputs (files, syslog UDP/TCP/TLS, Windows Event Log)
  → Parse (raw / JSON / key-value / regex / syslog)
  → Transform (add/remove/rename/convert/mask/filter)
  → Normalize (common event schema)
  → Enrich (host, OS, environment, tenant, tags, …)
  → Route (conditional, failover)
  → Persistent disk queue (per destination, crash-safe)
  → Outputs (syslog UDP/TCP/TLS, stdout)
```

**Measured footprint** (release build, macOS arm64): 4.1 MB binary, ~12 MB RSS, <1% CPU while ingesting 5,000 events.

## Features

- **File collection** — single paths, wildcards (`/var/log/*.log`), recursive globs (`/app/logs/**/*.log`), Windows paths (`C:\Logs\*.log`), include/exclude patterns, dynamic discovery of new files.
- **Rotation-safe tailing** — rename rotation, copy-truncate, truncation, recreation; files identified by inode (Linux) / file identity (Windows); offsets persisted so reads resume exactly where they stopped after a restart.
- **Syslog receiver** — UDP, TCP and TLS (incl. mutual TLS) listeners on any port/binding, multiple listeners, RFC3164 + RFC5424 + JSON + raw parsing with auto-detection.
- **Windows Event Log** (Windows-only) — native `wevtapi` collection from any channel (`Application`, `System`, `Security`, custom/Sysmon), XPath filtering, publisher-rendered messages, bookmark checkpointing for at-least-once resume after restart.
- **Processing pipeline** — modular parse → transform → normalize → enrich → route stages; conditions (`eq/ne/contains/matches/gt/lt/exists`) on any field.
- **Reliability** — per-destination persistent disk queue (CRC-checked segment files), at-least-once delivery, exponential backoff retry, configurable full-queue policy (`block` / `drop_oldest` / `drop_newest`), graceful shutdown, crash recovery.
- **Outputs** — syslog UDP/TCP/TLS (RFC5424, RFC3164, JSON or raw; newline or octet-counting framing), stdout; multiple destinations, conditional routing, health-based failover destinations.
- **Security** — TLS and mTLS on inputs and outputs, certificate validation by default, data masking transform, web GUI bound to localhost by default with explicit warning when exposed.
- **Web GUI** — minimal appliance-style page (single embedded HTML file, no framework): overview, inputs, outputs, buffer, config edit with validate/save/reload/rollback, recent agent logs, about.
- **Service integration** — systemd (Linux) and Windows Service, with `install/uninstall/start/stop/restart` subcommands.
- **Observability** — `/healthz`, Prometheus-style `/metrics`, JSON status API, in-memory ring buffer of agent logs.

## Installation

### Linux

**ติดตั้งด้วย shell script (แนะนำ)**

สคริปต์ตรวจสอบ dependency ทุกรายการ (systemd, C compiler, Rust 1.80+) และเสนอติดตั้งให้อัตโนมัติก่อนดำเนินการ

```bash
# Build จาก source + ติดตั้ง
sudo ./packaging/install-linux.sh

# ใช้ binary ที่ build ไว้แล้ว (ข้ามขั้นตอน Rust/build)
sudo ./packaging/install-linux.sh --binary ./softnix-log-agent

# ติดตั้งแบบ non-interactive (CI / fleet rollout)
sudo ./packaging/install-linux.sh --yes

# ติดตั้งโดยไม่ start service
sudo ./packaging/install-linux.sh --no-start

# ถอนการติดตั้ง (เก็บ config และ state ไว้)
sudo ./packaging/install-linux.sh --uninstall
```

สคริปต์ทำงานแบบ idempotent: รันซ้ำเพื่ออัปเกรดได้เลย — binary จะถูกเปลี่ยน config ที่มีอยู่แล้วจะถูกเก็บไว้ และ service จะถูก restart ให้

**ขั้นตอนหลังติดตั้ง:**

```bash
# ตรวจสอบ service ทำงานปกติ
systemctl status softnix-log-agent

# ดู agent logs
journalctl -u softnix-log-agent -f

# เปิด web GUI
open http://127.0.0.1:8080

# health check endpoint
curl -sf http://127.0.0.1:8080/healthz
```

**แก้ไข config:**

```bash
sudo nano /etc/softnix-log-agent/agent.yaml

# validate ก่อน reload เสมอ
sudo softnix-log-agent validate --config /etc/softnix-log-agent/agent.yaml

# reload โดยไม่ต้อง restart (Linux)
sudo systemctl kill -s HUP softnix-log-agent
```

**อัปเกรด:**

```bash
sudo softnix-log-agent service stop
sudo install -m 755 softnix-log-agent-new /usr/local/bin/softnix-log-agent
sudo softnix-log-agent service start
```

หรือรัน `install-linux.sh` ซ้ำเพื่ออัปเกรดอัตโนมัติ

---

### Windows

**ติดตั้งด้วย MSI (แนะนำ)**

ไฟล์ MSI พร้อมใช้งานที่ `dist/softnix-log-agent-0.1.0-x64.msi` ติดตั้ง binary ไปที่ `C:\Program Files\Softnix\LogAgent` และลงทะเบียน Windows service (auto start, LocalSystem) ให้อัตโนมัติ

```powershell
# ติดตั้งแบบ interactive
msiexec /i softnix-log-agent-0.1.0-x64.msi

# ติดตั้งแบบ silent (fleet / GPO / Intune)
msiexec /i softnix-log-agent-0.1.0-x64.msi /qn

# อัปเกรด (ติดตั้งทับ version เก่า — config ที่แก้ไขไว้จะถูกเก็บ)
msiexec /i softnix-log-agent-<new-version>-x64.msi /qn

# ถอนการติดตั้ง (config และ state ถูกเก็บไว้)
msiexec /x softnix-log-agent-0.1.0-x64.msi /qn
```

**ขั้นตอนหลังติดตั้ง:**

```powershell
# ตรวจสอบ service ทำงานปกติ
Get-Service softnix-log-agent

# ดู event log
Get-EventLog -LogName Application -Source softnix-log-agent -Newest 20

# health check
Invoke-WebRequest http://127.0.0.1:8080/healthz

# เปิด web GUI
Start-Process http://127.0.0.1:8080
```

**แก้ไข config:**

```powershell
notepad C:\ProgramData\Softnix\LogAgent\agent.yaml

# validate
& "C:\Program Files\Softnix\LogAgent\softnix-log-agent.exe" validate `
    --config C:\ProgramData\Softnix\LogAgent\agent.yaml

# reload (Windows ต้องใช้ restart)
Restart-Service softnix-log-agent
# หรือผ่าน web GUI: http://127.0.0.1:8080 → Configuration → Save & Reload
```

**ติดตั้งด้วย PowerShell script (ทางเลือก)**

```powershell
# จาก elevated PowerShell ในโฟลเดอร์ที่มี softnix-log-agent.exe
powershell -ExecutionPolicy Bypass -File packaging\windows\install-windows.ps1

# ถอนการติดตั้ง
powershell -ExecutionPolicy Bypass -File packaging\windows\install-windows.ps1 -Uninstall
```

**อนุญาต Firewall (ถ้ารับ syslog จากเครื่องอื่น):**

```powershell
New-NetFirewallRule -DisplayName "Softnix Log Agent syslog UDP" `
    -Direction Inbound -Protocol UDP -LocalPort 514 -Action Allow
New-NetFirewallRule -DisplayName "Softnix Log Agent syslog TCP" `
    -Direction Inbound -Protocol TCP -LocalPort 514 -Action Allow
```

**Build MSI ใหม่จาก source:**

```bash
# ต้องการ: msitools (brew install msitools / apt install msitools)
# และ mingw-w64 สำหรับ cross-compile
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
./packaging/windows/build-msi.sh
# output: dist/softnix-log-agent-<version>-x64.msi
```

---

### รายละเอียดเพิ่มเติม

| แพลตฟอร์ม | ไฟล์ | เนื้อหา |
|---|---|---|
| Linux | [docs/INSTALL-LINUX.md](docs/INSTALL-LINUX.md) | manual steps, systemd hardening, musl static build |
| Windows | [docs/INSTALL-WINDOWS.md](docs/INSTALL-WINDOWS.md) | manual steps, Windows Service, MSI rebuild |

## Quick start (development)

```bash
cargo build --release
cp examples/minimal.yaml agent.yaml
mkdir -p demo
./target/release/softnix-log-agent run --config agent.yaml &
echo "hello" >> demo/app.log          # appears on stdout as JSON
open http://127.0.0.1:8080            # web GUI
```

## CLI

```
softnix-log-agent run        --config <file>    # run in foreground (default cmd)
softnix-log-agent validate   --config <file>    # validate config and exit
softnix-log-agent service install --config <path>
softnix-log-agent service uninstall | start | stop | restart
```

Environment variables can be referenced in the config as `${VAR}` or `${VAR:-default}` (expansion happens on the raw file, including comments — use the `:-` form for optional variables). Send `SIGHUP` (Linux) or use the web GUI to reload configuration; reloads are validated first and automatically roll back on failure.

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Architecture overview and design decisions |
| [docs/INSTALL-LINUX.md](docs/INSTALL-LINUX.md) | Linux build + installation guide (systemd) |
| [docs/INSTALL-WINDOWS.md](docs/INSTALL-WINDOWS.md) | Windows build + installation guide (Windows Service) |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | **Configuration manual** — every section, option and default explained (TH: [คู่มือภาษาไทย](docs/CONFIGURATION.th.md)) |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Operational guide: config, reload, monitoring, troubleshooting |
| [docs/TESTING.md](docs/TESTING.md) | Testing guide |
| [examples/agent.yaml](examples/agent.yaml) | Full reference configuration |
| [examples/minimal.yaml](examples/minimal.yaml) | Minimal configuration |
| [examples/windows.yaml](examples/windows.yaml) | Windows configuration |

## Known limitations

- **Windows file identity** uses creation time **plus a hash of the file's first line** (stable Rust lacks volume/file-index metadata). The first-line fingerprint disambiguates files created in the same 100 ns tick so concurrent logs are tracked independently; residual collision needs two files created in the same tick *and* with an identical first line.
- **Copy-truncate race**: if a file is truncated *and* regrows past its previous size within one poll interval (default 500 ms), the `size < offset` check alone cannot see the truncation. On Unix the agent additionally compares the file's first-line fingerprint between polls (stable for appends, changes on truncate+rewrite) and resets the offset, so the common case is recovered. Residual edge case: a truncated-and-regrown file whose new first line is byte-identical to the old first line is not detected. Prefer rename rotation where possible.
- **Rename-rotation tail loss**: bytes written to a file *after* the final poll before it is rotated out of the glob's scope are not read. Keep poll intervals short or have rotated files still match a pattern.
- `raw_message` retains the original line, but a `mask` transform targeting `message` now applies the same masking to `raw_message` automatically, so secrets do not leak through it on field-emitting outputs (e.g. `json`).
- **At-least-once**, not exactly-once: after a crash the last un-acked batch (≤ `retry.batch_size` events) may be re-sent.
- TCP syslog input uses newline framing only (no RFC5425 octet-counted *input*; octet-counting is supported on *output*).
- No multiline aggregation (stack traces arrive as separate events).
- Config reload restarts the engine (sub-second); listener sockets are closed and reopened, so in-flight UDP datagrams during the reload window can be lost.
- **Windows Event Log**: reading the `Security` channel requires the agent to run with sufficient privilege (the Windows Service runs as LocalSystem, which satisfies this). If a publisher's message DLL is unavailable, the human-readable message falls back to the joined `EventData`; the full event XML is always preserved in `raw_message`.

## Recommended future enhancements

- Octet-counted and length-prefixed framing on TCP/TLS inputs; multiline aggregation.
- Additional outputs (HTTP/HTTPS bulk, Kafka, file archive) behind the existing `OutputWorker` trait-object seam.
- journald input; ETW (Event Tracing for Windows) input.
- Per-input rate limiting and backpressure metrics; queue compression.
- Native package artifacts (deb/rpm/MSI) and signed release pipeline.
