# AIDefender installer for Windows (PowerShell).
Set-StrictMode -Version Latest
Set-Location $PSScriptRoot

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Write-Error "Python 3.9+ is required."; exit 1 }

python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
try { .\.venv\Scripts\python.exe -m pip install -e ".[full]" } catch { "(optional deps skipped)" }

Write-Host ""
Write-Host "Installed. Run with:"
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  aidefender status"
Write-Host "  aidefender scan $HOME\Downloads"
Write-Host "  aidefender service install"
Write-Host "  aidefender protect --auto-quarantine"
