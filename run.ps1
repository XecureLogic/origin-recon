#!/usr/bin/env pwsh
#
# Origin Recon - one-command launcher for Windows (PowerShell).
# Mirrors run.sh so the project runs natively on both Linux and Windows.
#
#   .\run.ps1          start everything and open the UI (single port :8000)
#   .\run.ps1 -Dev     development mode: hot-reload UI (:5173) + backend (:8000)
#
# First run installs dependencies automatically. Ctrl+C stops everything.
# Optional API keys are loaded from .env (project root) or backend\.env if present.
#
[CmdletBinding()]
param([switch]$Dev)

$ErrorActionPreference = "Stop"
$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
$BACKEND_PORT = 8000
$FRONTEND_PORT = 5173

function Require-Cmd($name, $hint) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Write-Host "error: '$name' is required but was not found on PATH." -ForegroundColor Red
        if ($hint) { Write-Host "       install it from: $hint" -ForegroundColor Red }
        exit 1
    }
}
Require-Cmd python "https://www.python.org/downloads/ (check 'Add to PATH')"
Require-Cmd node   "https://nodejs.org/"
Require-Cmd npm    "https://nodejs.org/"

# --- backend venv (treat as ready only if its interpreter can import uvicorn) ---
$VenvPy = Join-Path $ROOT "backend\.venv\Scripts\python.exe"
function Venv-Ready {
    if (-not (Test-Path $VenvPy)) { return $false }
    & $VenvPy -c "import uvicorn" 2>$null
    return $?
}
Set-Location (Join-Path $ROOT "backend")
if (-not (Venv-Ready)) {
    Write-Host "[setup] creating Python venv and installing backend dependencies..."
    if (Test-Path ".venv") { Remove-Item -Recurse -Force ".venv" }
    python -m venv .venv
    if (-not (Test-Path $VenvPy)) {
        Write-Host "error: could not create the Python venv." -ForegroundColor Red
        exit 1
    }
    & $VenvPy -m pip install -q --upgrade pip
    & $VenvPy -m pip install -q -r requirements.txt
}

# --- load optional API keys (KEY=VALUE or 'export KEY=VALUE' lines) ---
foreach ($envfile in @((Join-Path $ROOT ".env"), (Join-Path $ROOT "backend\.env"))) {
    if (Test-Path $envfile) {
        Get-Content $envfile | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
                $line = $line -replace "^\s*export\s+", ""
                $k, $v = $line -split "=", 2
                [Environment]::SetEnvironmentVariable($k.Trim(), $v.Trim(), "Process")
            }
        }
        Write-Host "[env] loaded API keys from $envfile"
    }
}

# --- start backend ---
Write-Host "[backend] starting on http://localhost:$BACKEND_PORT"
$backend = Start-Process -FilePath $VenvPy `
    -ArgumentList @("-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "$BACKEND_PORT") `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput (Join-Path $ROOT "backend.log") `
    -RedirectStandardError  (Join-Path $ROOT "backend.err.log")

$frontend = $null
function Stop-All {
    foreach ($p in @($frontend, $backend)) {
        if ($p -and -not $p.HasExited) {
            try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
}

# --- wait for health; fail fast if uvicorn already died (import error etc.) ---
# Probe 127.0.0.1, not "localhost": on Windows "localhost" resolves to IPv6 ::1
# first, but uvicorn --host 0.0.0.0 binds IPv4 only, so a localhost probe would
# get connection-refused even though the backend is up.
$up = $false
for ($i = 0; $i -lt 40; $i++) {
    try {
        Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$BACKEND_PORT/api/health" -TimeoutSec 2 | Out-Null
        $up = $true; break
    } catch {}
    if ($backend.HasExited) { break }
    Start-Sleep -Milliseconds 500
}
if (-not $up) {
    Write-Host "error: backend did not become healthy on port $BACKEND_PORT." -ForegroundColor Red
    Write-Host "       last lines of backend.err.log:" -ForegroundColor Red
    if (Test-Path (Join-Path $ROOT "backend.err.log")) { Get-Content (Join-Path $ROOT "backend.err.log") -Tail 20 }
    Stop-All
    exit 1
}

# --- frontend ---
Set-Location (Join-Path $ROOT "frontend")
if (-not (Test-Path "node_modules")) {
    Write-Host "[setup] installing frontend dependencies (first run)..."
    & npm.cmd install --no-audit --no-fund
}

try {
    if ($Dev) {
        Write-Host "[frontend] starting dev server (hot reload) on http://localhost:$FRONTEND_PORT"
        $frontend = Start-Process -FilePath "npm.cmd" -ArgumentList @("run", "dev") `
            -PassThru -NoNewWindow `
            -RedirectStandardOutput (Join-Path $ROOT "frontend.log") `
            -RedirectStandardError  (Join-Path $ROOT "frontend.err.log")
        Start-Process "http://localhost:$FRONTEND_PORT"
        Write-Host ""
        Write-Host "Origin Recon is running:"
        Write-Host "  UI:      http://localhost:$FRONTEND_PORT"
        Write-Host "  Backend: http://localhost:$BACKEND_PORT"
        Write-Host "  Logs:    backend.log / frontend.log     (Ctrl+C stops both)"
    } else {
        Write-Host "[frontend] building UI..."
        & npm.cmd run build *> (Join-Path $ROOT "frontend-build.log")
        if ($LASTEXITCODE -ne 0) {
            Write-Host "error: frontend build failed. See frontend-build.log" -ForegroundColor Red
            Stop-All; exit 1
        }
        Start-Process "http://localhost:$BACKEND_PORT"
        Write-Host ""
        Write-Host "Origin Recon is running -> http://localhost:$BACKEND_PORT"
        Write-Host "  (backend serves the built UI; Ctrl+C stops it)"
    }
    Wait-Process -Id $backend.Id
} finally {
    Write-Host "`nStopping Origin Recon..."
    Stop-All
}
