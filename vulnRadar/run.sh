#!/usr/bin/env bash
# Launch vulnRadar in the background, detached from this terminal.
# In daemon mode (DAILY_RUN_HOUR_UTC set) it runs now and then daily; output
# goes to run.log and the run survives closing the terminal (nohup).
# Follow it with:  tail -f run.log      Stop it with:  ./stop.sh
cd "$(dirname "$0")"

# Pick an interpreter that actually has the dependencies, instead of whatever
# `python3` happens to mean in the calling shell: launched from a terminal with
# a virtualenv active, a bare `python3` resolves to that venv — which does not
# have `requests` — and the run dies immediately with ModuleNotFoundError.
# Override with:  PYTHON=/path/to/python ./run.sh
PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
    for CANDIDATE in /usr/bin/python3 python3; do
        if command -v "$CANDIDATE" >/dev/null && "$CANDIDATE" -c 'import requests' 2>/dev/null; then
            PYTHON="$CANDIDATE"; break
        fi
    done
fi
[ -n "$PYTHON" ] || { echo "ERROR: no python3 with 'requests' installed found."; exit 1; }

# -u = unbuffered output, so run.log updates live and shows exactly what you
# would normally see on the terminal.
nohup "$PYTHON" -u main.py > run.log 2>&1 &
echo $! > run.pid
echo "Started in background (PID $!) using $PYTHON."
echo "  follow: tail -f run.log"
echo "  stop:   ./stop.sh"
