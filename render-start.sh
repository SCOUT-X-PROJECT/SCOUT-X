#!/usr/bin/env bash
set -e

python -m simulation.ground_control.receiver &
RECEIVER_PID=$!

trap 'kill "$RECEIVER_PID" 2>/dev/null || true' EXIT

uvicorn dashboard.server:app --host 0.0.0.0 --port "${PORT:-8000}"
