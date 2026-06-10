<#
.SYNOPSIS
  Softnix Log Agent - scripted Windows installer (alternative to the MSI).

.DESCRIPTION
  Checks prerequisites, installs the binary and default configuration,
  registers and starts the Windows service, then runs a health check.
  Run from an elevated PowerShell in a folder containing softnix-log-agent.exe
  (and optionally agent-default.yaml).

.PARAMETER BinaryPath
  Path to softnix-log-agent.exe (default: .\softnix-log-agent.exe)

.PARAMETER NoStart
  Install but do not start the service.

.PARAMETER Uninstall
  Stop and remove the service and binary (config/state are kept).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File install-windows.ps1
#>
[CmdletBinding()]
param(
    [string]$BinaryPath = ".\softnix-log-agent.exe",
    [switch]$NoStart,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ServiceName = "softnix-log-agent"
$InstallDir  = "$env:ProgramFiles\Softnix\LogAgent"
$DataDir     = "$env:ProgramData\Softnix\LogAgent"
$ConfigPath  = "$DataDir\agent.yaml"
$ExePath     = "$InstallDir\softnix-log-agent.exe"

function Step($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)    { Write-Host "[ok]    $msg" -ForegroundColor Green }
function Warn2($msg) { Write-Host "[warn]  $msg" -ForegroundColor Yellow }
function Fail($msg)  { Write-Host "[error] $msg" -ForegroundColor Red; exit 1 }

# --- Pre-flight -------------------------------------------------------------
Step "Checking environment"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "must run as Administrator (right-click PowerShell -> Run as administrator)"
}
Ok "running elevated"

if ([Environment]::OSVersion.Version.Major -lt 10) {
    Warn2 "Windows 10 / Server 2016 or newer is recommended (detected $([Environment]::OSVersion.VersionString))"
} else {
    Ok "Windows version: $([Environment]::OSVersion.VersionString)"
}

# --- Uninstall path ----------------------------------------------------------
if ($Uninstall) {
    Step "Uninstalling $ServiceName"
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") { Stop-Service $ServiceName -Force; Ok "service stopped" }
        sc.exe delete $ServiceName | Out-Null
        Ok "service removed"
    } else {
        Warn2 "service not registered"
    }
    if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir; Ok "removed $InstallDir" }
    Write-Host ""
    Write-Host "Kept (remove manually if desired): $DataDir (config, state, queued events)"
    exit 0
}

# --- Locate binary -----------------------------------------------------------
Step "Checking installer payload"
if (-not (Test-Path $BinaryPath)) {
    Fail "binary not found: $BinaryPath  (build with 'cargo build --release' or pass -BinaryPath)"
}
$ver = & $BinaryPath --version 2>$null
if ($LASTEXITCODE -ne 0) { Fail "$BinaryPath does not run on this system (wrong architecture?)" }
Ok "binary OK: $ver"

# --- Stop existing service for upgrade ---------------------------------------
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Warn2 "service is running - stopping for upgrade"
    Stop-Service $ServiceName -Force
}

# --- Install files -----------------------------------------------------------
Step "Installing files"
New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null
Copy-Item -Force $BinaryPath $ExePath
Ok "binary    -> $ExePath"

if (Test-Path $ConfigPath) {
    Ok "config    -> $ConfigPath (existing config kept)"
} else {
    $defaultCfg = Join-Path (Split-Path -Parent $BinaryPath) "agent-default.yaml"
    if (-not (Test-Path $defaultCfg)) { $defaultCfg = Join-Path $PSScriptRoot "agent-default.yaml" }
    if (Test-Path $defaultCfg) {
        Copy-Item $defaultCfg $ConfigPath
    } else {
        @"
agent:
  data_dir: 'C:\ProgramData\Softnix\LogAgent'
  log_level: info
inputs:
  files:
    - id: app-logs
      paths: ['C:\Logs\*.log']
outputs:
  - id: console
    type: stdout
    format: json
web:
  enabled: true
  bind: 127.0.0.1
  port: 8080
"@ | Set-Content -Encoding UTF8 $ConfigPath
    }
    Ok "config    -> $ConfigPath (new)"
}

Step "Validating configuration"
& $ExePath validate --config $ConfigPath
if ($LASTEXITCODE -ne 0) { Fail "configuration is invalid - fix $ConfigPath and re-run" }

# --- Register service ---------------------------------------------------------
Step "Registering Windows service"
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    & $ExePath service install --config $ConfigPath
    if ($LASTEXITCODE -ne 0) { Fail "service registration failed" }
    Ok "service registered (auto start)"
} else {
    Ok "service already registered"
}

# --- Start & verify -----------------------------------------------------------
if (-not $NoStart) {
    Step "Starting service"
    Start-Service $ServiceName
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $ServiceName
    if ($svc.Status -ne "Running") { Fail "service failed to start - check Event Viewer / agent logs" }
    Ok "service is running"

    try {
        $health = Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 "http://127.0.0.1:8080/healthz"
        if ($health.StatusCode -eq 200) { Ok "health check passed: http://127.0.0.1:8080/healthz" }
    } catch {
        Warn2 "health endpoint not reachable (web GUI may be disabled or on another port)"
    }
} else {
    Warn2 "skipped start (-NoStart); start later with: Start-Service $ServiceName"
}

Write-Host ""
Write-Host "Softnix Log Agent installed successfully." -ForegroundColor Green
Write-Host ""
Write-Host "  config:   $ConfigPath"
Write-Host "  state:    $DataDir"
Write-Host "  web GUI:  http://127.0.0.1:8080 (localhost only)"
Write-Host "  manage:   Start-Service / Stop-Service $ServiceName"
Write-Host "  remove:   install-windows.ps1 -Uninstall"
