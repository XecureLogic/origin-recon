#!/usr/bin/env bash
#
# Origin Recon — one-command local launcher.
#
#   ./run.sh          start everything and open the UI (single port :8000)
#   ./run.sh --dev    development mode: hot-reload UI (:5173) + backend (:8000)
#
# First run installs dependencies automatically. Ctrl+C stops everything.
# Optional API keys are loaded from backend/.env if that file exists.
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_PORT=8000
FRONTEND_PORT=5173
MODE="serve"
[[ "${1:-}" == "--dev" ]] && MODE="dev"

command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required"; exit 1; }
command -v node    >/dev/null 2>&1 || { echo "error: node is required"; exit 1; }
command -v npm     >/dev/null 2>&1 || { echo "error: npm is required"; exit 1; }

PIDS=()
cleanup() {
  echo
  echo "Stopping Origin Recon..."
  for pid in "${PIDS[@]:-}"; do
    pkill -P "$pid" 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

open_browser() {
  local url="$1"
  ( sleep 1
    if   command -v xdg-open >/dev/null 2>&1; then xdg-open "$url"
    elif command -v open     >/dev/null 2>&1; then open "$url"
    elif command -v wslview  >/dev/null 2>&1; then wslview "$url"
    fi ) >/dev/null 2>&1 &
}

cd "$ROOT/backend"
if [[ ! -d .venv ]]; then
  echo "[setup] creating Python venv and installing backend dependencies..."
  python3 -m venv .venv
  ./.venv/bin/pip install -q --upgrade pip
  ./.venv/bin/pip install -q -r requirements.txt
fi
PY="$ROOT/backend/.venv/bin/python"

# Load optional API keys. Project-root .env is preferred; backend/.env still works.
for envfile in "$ROOT/.env" "$ROOT/backend/.env"; do
  if [[ -f "$envfile" ]]; then
    set -a
    # shellcheck disable=SC1090
    . "$envfile"
    set +a
    echo "[env] loaded API keys from ${envfile#"$ROOT/"}"
  fi
done

echo "[backend] starting on http://localhost:${BACKEND_PORT}"
"$PY" -m uvicorn app.main:app --host 0.0.0.0 --port "$BACKEND_PORT" >"$ROOT/backend.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 40); do
  curl -fsS "http://localhost:${BACKEND_PORT}/api/health" >/dev/null 2>&1 && break
  sleep 0.5
done

cd "$ROOT/frontend"
if [[ ! -d node_modules ]]; then
  echo "[setup] installing frontend dependencies (first run)..."
  npm install --no-audit --no-fund
fi

if [[ "$MODE" == "dev" ]]; then
  echo "[frontend] starting dev server (hot reload) on http://localhost:${FRONTEND_PORT}"
  npm run dev >"$ROOT/frontend.log" 2>&1 &
  PIDS+=($!)
  open_browser "http://localhost:${FRONTEND_PORT}"
  echo
  echo "Origin Recon is running:"
  echo "  UI:      http://localhost:${FRONTEND_PORT}"
  echo "  Backend: http://localhost:${BACKEND_PORT}"
  echo "  Logs:    backend.log / frontend.log     (Ctrl+C stops both)"
else
  echo "[frontend] building UI..."
  npm run build >"$ROOT/frontend-build.log" 2>&1
  open_browser "http://localhost:${BACKEND_PORT}"
  echo
  echo "Origin Recon is running -> http://localhost:${BACKEND_PORT}"
  echo "  (backend serves the built UI; Ctrl+C stops it)"
fi

wait
