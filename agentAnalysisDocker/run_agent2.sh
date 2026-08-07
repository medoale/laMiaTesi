#!/usr/bin/env bash
# Re-run ONLY agent2, overwriting its existing answers, detached from the
# terminal (same idea as run.sh, which is left untouched and still runs the
# full set).
#
#   --agents agent2  restricts the run to agent2; agent1 and agent3 keep their
#                    current results and are not touched.
#   --force          ignores the "already ok" state, so all of agent2 is
#                    re-executed instead of only the failed ones. The new
#                    answers overwrite the files on disk, and results.jsonl is
#                    rebuilt from the log with the newest record winning.
#
# Output goes to its own run_agent2.log, so a previous run.log is preserved.
# Follow it with:  tail -f run_agent2.log      Stop it with:  ./stop.sh
cd "$(dirname "$0")"

# One run at a time: two would share run.pid and the egress network/proxy
# (fixed names), and each one's cleanup would tear down the other's containers.
if [ -f run.pid ] && kill -0 "$(cat run.pid 2>/dev/null)" 2>/dev/null; then
    echo "ERROR: a run is already in progress (PID $(cat run.pid)). Stop it first: ./stop.sh"
    exit 1
fi

# -u = unbuffered, so the log updates live instead of in blocks.
nohup python3 -u main.py --agents agent2 --force > run_agent2.log 2>&1 &
echo "Started in background (PID $!): agent2 only, --force"
echo "  model:  $(python3 -c 'import config; print(config.OPENCODE_MODEL)')"
echo "  follow: tail -f $(pwd)/run_agent2.log"
echo "  stop:   ./stop.sh"
