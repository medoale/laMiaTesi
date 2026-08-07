#!/usr/bin/env bash
# Launch the pipeline in the background, detached from this terminal.
# Output goes to run.log; the run survives closing the terminal (nohup).
# Follow it with:  tail -f run.log      Stop it with:  ./stop.sh
cd "$(dirname "$0")"
# -u = unbuffered output, so run.log updates live and shows exactly what you
# would normally see on the terminal (progress lines, statuses, errors).
#
# --skip-completed-errors: relaunching after a stop picks up only what was never
# run or was cut short. A run that reached the end without a parseable verdict
# keeps its answer in log.jsonl and is NOT repeated — rerunning it would spend
# ~4 minutes to get the same text back. Drop the flag to retry those too (e.g.
# after changing the prompt or the required format).
nohup python3 -u main.py --skip-completed-errors "$@" > run.log 2>&1 &
echo "Started in background (PID $!)."
echo "  follow: tail -f run.log"
echo "  stop:   ./stop.sh"
