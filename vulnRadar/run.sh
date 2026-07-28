#!/usr/bin/env bash
# Launch vulnRadar in the background, detached from this terminal.
# In daemon mode (DAILY_RUN_HOUR_UTC set) it runs now and then daily; output
# goes to run.log and the run survives closing the terminal (nohup).
# Follow it with:  tail -f run.log      Stop it with:  ./stop.sh
cd "$(dirname "$0")"
# -u = unbuffered output, so run.log updates live and shows exactly what you
# would normally see on the terminal.
nohup python3 -u main.py > run.log 2>&1 &
echo $! > run.pid
echo "Started in background (PID $!)."
echo "  follow: tail -f run.log"
echo "  stop:   ./stop.sh"
