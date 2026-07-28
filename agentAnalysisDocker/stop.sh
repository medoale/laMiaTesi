#!/usr/bin/env bash
# Stop a background run cleanly: signal main.py (which then removes its own
# containers and rebuilds the results), then force-remove any leftover agent
# container as a safety net — so nothing keeps hitting the shared cluster.
cd "$(dirname "$0")"

if [ -f run.pid ]; then
    PID=$(cat run.pid)
    if kill -0 "$PID" 2>/dev/null; then
        echo "Stopping main.py (PID $PID)..."
        kill "$PID"                       # SIGTERM -> main.py cleans up
        for _ in $(seq 1 15); do
            kill -0 "$PID" 2>/dev/null || break
            sleep 1
        done
    fi
fi

# Safety net: remove any agent containers that are still alive.
LEFT=$(docker ps -q --filter label=tool=agentAnalysisDocker)
if [ -n "$LEFT" ]; then
    echo "Removing leftover agent container(s)..."
    docker rm -f $LEFT >/dev/null
fi

echo "Stopped."
