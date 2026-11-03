#!/usr/bin/env bash
set -e

python -m simulation.ground_control.receiver &
RECEIVER_PID=$!

shutdown() {
    trap - EXIT INT TERM
    if kill -0 "$RECEIVER_PID" 2>/dev/null; then
        kill "$RECEIVER_PID" 2>/dev/null || true
    fi
    if [ -n "${DASHBOARD_PID:-}" ] && kill -0 "$DASHBOARD_PID" 2>/dev/null; then
        kill "$DASHBOARD_PID" 2>/dev/null || true
    fi
    wait "$RECEIVER_PID" 2>/dev/null || true
    if [ -n "${DASHBOARD_PID:-}" ]; then
        wait "$DASHBOARD_PID" 2>/dev/null || true
    fi
}

trap shutdown EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -n "${PORT:-}" ]; then
    export SCOUTX_DASHBOARD__PORT="$PORT"
    export SCOUTX_DASHBOARD__HOST="0.0.0.0"
    export SCOUTX_DASHBOARD__PUBLIC_BIND="true"
fi

python -m dashboard.server &
DASHBOARD_PID=$!
set +e
wait -n "$RECEIVER_PID" "$DASHBOARD_PID"
STATUS=$?
exit "$STATUS"
