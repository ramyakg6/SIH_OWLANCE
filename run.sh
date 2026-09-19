#!/usr/bin/env bash
#
# OwLance — start backend and frontend together.
#
#   ./run.sh
#
# Backend  -> http://127.0.0.1:8000   (API docs at /docs)
# Frontend -> http://localhost:5173
#
# Ctrl-C stops both.

set -euo pipefail
cd "$(dirname "$0")"

PIDS=()
cleanup() {
  echo ""
  echo "Shutting down..."
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ---------- backend ----------
echo "==> Starting backend on http://127.0.0.1:8000"
(
  cd backend
  if [ ! -d .venv ]; then
    echo "    creating virtualenv..."
    python3 -m venv .venv
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
  pip install -q -r requirements.txt
  exec uvicorn app.main:app --host 127.0.0.1 --port 8000
) &
PIDS+=($!)

# Wait for the backend to answer before starting the UI, so the health
# probe on first paint sees a live server instead of a connection refusal.
echo -n "    waiting for backend"
for _ in $(seq 1 40); do
  if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
    echo " — up."
    break
  fi
  echo -n "."
  sleep 1
done

# ---------- frontend ----------
echo "==> Starting frontend on http://localhost:5173"
if [ ! -d node_modules ]; then
  echo "    installing npm packages..."
  npm install --no-audit --no-fund
fi
npm run dev -- --host &
PIDS+=($!)

wait
