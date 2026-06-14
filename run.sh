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

require() {
  command -v "$1" >/dev/null 2>&1 && return
  echo "error: '$1' is required but was not found on PATH." >&2
  [[ -n "${2:-}" ]] && echo "       install it with: $2" >&2
  exit 1
}
require python3 "sudo apt install python3"
require node    "sudo apt install nodejs"
require npm     "sudo apt install npm"

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
# A directory existing is not the same as a working venv. A run that was
# interrupted (or hit a missing python3-venv package) can leave a partial
# .venv behind; treat the venv as ready only if its interpreter can import
# uvicorn — the thing we actually launch — and rebuild it otherwise.
venv_ready() { [[ -x .venv/bin/python ]] && ./.venv/bin/python -c 'import uvicorn' >/dev/null 2>&1; }
if ! venv_ready; then
  echo "[setup] creating Python venv and installing backend dependencies..."
  rm -rf .venv
  python3 -m venv .venv || {
    echo "error: could not create the Python venv." >&2
    echo "       on Debian/Kali/Ubuntu install the venv package, e.g.:" >&2
    echo "         sudo apt install python3-venv   # or python3.13-venv to match your python3" >&2
    exit 1
  }
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
BACKEND_PID=$!
PIDS+=("$BACKEND_PID")

backend_up=false
for _ in $(seq 1 40); do
  if curl -fsS "http://localhost:${BACKEND_PORT}/api/health" >/dev/null 2>&1; then
    backend_up=true; break
  fi
  # Fail fast if uvicorn already exited (e.g. an import error) instead of
  # waiting out the full 20s only to claim success for a dead backend.
  kill -0 "$BACKEND_PID" 2>/dev/null || break
  sleep 0.5
done

if [[ "$backend_up" != true ]]; then
  echo "error: backend did not become healthy on port ${BACKEND_PORT}." >&2
  echo "       last lines of backend.log:" >&2
  tail -n 20 "$ROOT/backend.log" >&2 || true
  exit 1
fi

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
