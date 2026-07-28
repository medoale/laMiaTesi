#!/usr/bin/env bash
# Stop the background vulnRadar run cleanly: SIGINT triggers its own
# KeyboardInterrupt handler (logs "exiting"); falls back to SIGTERM if needed.
cd "$(dirname "$0")"

if [ ! -f run.pid ]; then
    echo "No run.pid found. Running processes:"
    pgrep -af 'python3 main.py' || echo "  (none found)"
    exit 0
fi

PID=$(cat run.pid)
if kill -0 "$PID" 2>/dev/null; then
    echo "Stopping vulnRadar (PID $PID)..."
    kill -INT "$PID"                       # SIGINT -> clean shutdown
    for _ in $(seq 1 15); do
        kill -0 "$PID" 2>/dev/null || break
        sleep 1
    done
    if kill -0 "$PID" 2>/dev/null; then
        echo "Still running, forcing..."
        kill "$PID"
    fi
else
    echo "Process $PID is not running."
fi

rm -f run.pid
echo "Stopped."
