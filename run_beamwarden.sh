#!/usr/bin/env bash
# Beam Warden — one-click launcher.
# Starts the dashboard/Command Center and opens it in the browser.
# All mode/source selection happens IN the app (Replay a file, or Connect to router).
# Also runnable from a terminal: ./run_beamwarden.sh
set -euo pipefail

# repo root = this script's directory (resolves symlinks so the .desktop icon works)
ROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
cd "$ROOT"

PORT="${BEAMWARDEN_PORT:-8080}"
URL="http://localhost:${PORT}"
PY="$ROOT/.venv/bin/python"

if [[ ! -x "$PY" ]]; then
  echo "Beam Warden: venv not found at $PY" >&2
  echo "Create it first (python -m venv .venv && .venv/bin/pip install -r requirements.txt)" >&2
  read -rp "Press Enter to close..." _ || true
  exit 1
fi

echo "== Beam Warden =="
echo "starting dashboard on ${URL} ..."

# start the server (no --mode: the source is chosen in the app)
"$PY" tools/dashboard.py --port "$PORT" &
SERVER=$!
# stop the server when this launcher exits (window closed / Ctrl+C)
trap 'kill "$SERVER" 2>/dev/null || true' EXIT INT TERM

# wait until it answers, then open the browser
for _ in $(seq 1 60); do
  if curl -sf "$URL" >/dev/null 2>&1; then break; fi
  sleep 0.25
done
xdg-open "$URL" >/dev/null 2>&1 || echo "open ${URL} in your browser"

echo "dashboard running. close this window (or Ctrl+C) to stop."
wait "$SERVER"
