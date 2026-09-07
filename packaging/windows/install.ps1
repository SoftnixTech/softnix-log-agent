<#
.SYNOPSIS
  Softnix Log Agent - one-line remote installer (Windows)

.DESCRIPTION
  Downloads the latest GitHub release MSI and installs it silently.

.PARAMETER Interactive
  Run the MSI installer interactively instead of silently.

.EXAMPLE
  irm https://raw.githubusercontent.com/SoftnixTech/softnix-log-agent/main/packaging/windows/install.ps1 | iex
#>
[CmdletBinding()]
param(
    [switch]$Interactive
)

$ErrorActionPreference = "Stop"
$Repo = "SoftnixTech/softnix-log-agent"

function Step($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)    { Write-Host "[ok]    $msg" -ForegroundColor Green }
function Fail($msg)  { Write-Host "[error] $msg" -ForegroundColor Red; exit 1 }

Step "Checking environment"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "must run as Administrator (right-click PowerShell -> Run as administrator)"
}
Ok "running elevated"

Step "Fetching latest release"
try {
    $release = Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$Repo/releases/latest"
} catch {
    Fail "could not reach the GitHub releases API: $($_.Exception.Message)"
}
$asset = $release.assets | Where-Object { $_.name -like "*.msi" } | Select-Object -First 1
if (-not $asset) { Fail "no MSI asset found in the latest release - check https://github.com/$Repo/releases" }
Ok "found: $($asset.name)"

$msiPath = Join-Path $env:TEMP $asset.name
Step "Downloading"
Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $msiPath

Step "Installing"
$msiArgs = @("/i", "`"$msiPath`"", "/norestart")
if (-not $Interactive) { $msiArgs += "/qn" }
$proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
Remove-Item $msiPath -ErrorAction SilentlyContinue
if ($proc.ExitCode -ne 0) {
    Fail "msiexec exited with code $($proc.ExitCode) - see Event Viewer > Application for details"
}
Ok "installed"

Write-Host ""
Write-Host "Softnix Log Agent installed successfully." -ForegroundColor Green
Write-Host ""
Write-Host "  service:  Get-Service softnix-log-agent"
Write-Host "  config:   C:\ProgramData\Softnix\LogAgent\agent.yaml"
Write-Host "  web GUI:  http://127.0.0.1:8080 (localhost only; first visit needs the"
Write-Host "            token from C:\ProgramData\Softnix\LogAgent\web-token)"
Write-Host "  remove:   msiexec /x $($asset.name) /qn"
