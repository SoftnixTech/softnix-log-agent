# Windows installation guide

## Quick install — MSI (recommended)

A ready-to-run MSI installer is built to `dist/softnix-log-agent-<version>-x64.msi`. It installs the binary to `C:\Program Files\Softnix\LogAgent`, a default config to `C:\ProgramData\Softnix\LogAgent\agent.yaml`, and registers + starts the **softnix-log-agent** Windows service (auto start, LocalSystem).

```powershell
# interactive
msiexec /i softnix-log-agent-0.1.0-x64.msi
# silent (fleet deployment / GPO / Intune)
msiexec /i softnix-log-agent-0.1.0-x64.msi /qn
# uninstall (config and state are preserved)
msiexec /x softnix-log-agent-0.1.0-x64.msi /qn
```

After install, edit `C:\ProgramData\Softnix\LogAgent\agent.yaml` and reload via the web GUI (`http://127.0.0.1:8080`) or `Restart-Service softnix-log-agent`. Upgrades: just run the newer MSI — a modified config is kept.

Rebuild the MSI from source (works on Windows with WiX, or on Linux/macOS with `msitools` + a cross-compiled exe):

```bash
./packaging/windows/build-msi.sh
```

## Quick install — PowerShell script (alternative)

If MSI distribution isn't convenient, `packaging/windows/install-windows.ps1` performs the same install with full pre-flight checks (elevation, OS version, binary runs, config validation) and a post-install health check:

```powershell
# from a folder containing softnix-log-agent.exe (elevated PowerShell)
powershell -ExecutionPolicy Bypass -File install-windows.ps1
powershell -ExecutionPolicy Bypass -File install-windows.ps1 -Uninstall
```

The sections below describe the manual steps.

## Build

Requirements: Rust 1.80+ (rustup-init.exe from https://rustup.rs) with the MSVC toolchain (Visual Studio Build Tools). No OpenSSL or other system libraries are required.

```powershell
cargo build --release
# binary: target\release\softnix-log-agent.exe
```

Cross-compiling from Linux/macOS is also possible:

```bash
rustup target add x86_64-pc-windows-gnu   # needs mingw-w64
cargo build --release --target x86_64-pc-windows-gnu
```

## Install as a Windows Service

Run an **elevated** (Administrator) PowerShell:

```powershell
New-Item -ItemType Directory -Force "C:\Program Files\Softnix\LogAgent","C:\ProgramData\Softnix\LogAgent" | Out-Null
Copy-Item target\release\softnix-log-agent.exe "C:\Program Files\Softnix\LogAgent\"
Copy-Item examples\windows.yaml "C:\ProgramData\Softnix\LogAgent\agent.yaml"
notepad C:\ProgramData\Softnix\LogAgent\agent.yaml   # edit to taste

cd "C:\Program Files\Softnix\LogAgent"
.\softnix-log-agent.exe validate --config C:\ProgramData\Softnix\LogAgent\agent.yaml

# registers service "softnix-log-agent" (LocalSystem, auto start)
.\softnix-log-agent.exe service install --config C:\ProgramData\Softnix\LogAgent\agent.yaml
.\softnix-log-agent.exe service start
```

The service entry point is `softnix-log-agent.exe service-run --config <path>`, registered automatically by `service install`. Stop/Shutdown control requests trigger the same graceful shutdown path as SIGTERM on Linux (queues flushed, state persisted).

## Manage

```powershell
.\softnix-log-agent.exe service start
.\softnix-log-agent.exe service stop
.\softnix-log-agent.exe service restart
.\softnix-log-agent.exe service uninstall
# or use sc.exe / services.msc — the service name is "softnix-log-agent"
```

Configuration reload on Windows: use the web GUI (`http://127.0.0.1:8080` → Configuration → Save & Reload) or `service restart`.

If receiving syslog on UDP/TCP 514 or running the web GUI beyond localhost, allow it through Windows Firewall, e.g.:

```powershell
New-NetFirewallRule -DisplayName "Softnix Log Agent syslog" -Direction Inbound -Protocol UDP -LocalPort 514 -Action Allow
```

State and queues live in `agent.data_dir` (recommended: `C:\ProgramData\Softnix\LogAgent`).
