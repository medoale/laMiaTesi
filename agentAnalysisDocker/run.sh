#!/usr/bin/env bash
# Launch the pipeline in the background, detached from this terminal.
# Output goes to run.log; the run survives closing the terminal (nohup).
# Follow it with:  tail -f run.log      Stop it with:  ./stop.sh
cd "$(dirname "$0")"
# -u = unbuffered output, so run.log updates live and shows exactly what you
# would normally see on the terminal (progress lines, statuses, errors).
nohup python3 -u main.py > run.log 2>&1 &
echo "Started in background (PID $!)."
echo "  follow: tail -f run.log"
echo "  stop:   ./stop.sh"
