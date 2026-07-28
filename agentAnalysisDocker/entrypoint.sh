#!/bin/sh
# Runs INSIDE the OpenCode container. Executes OpenCode headlessly on the
# mounted workspace and writes the final answer + full transcript to /output,
# which is bind-mounted to the host — so both survive the container's removal.
#
# Contract with the host (see sandbox.py / main.py):
#   /work              the workspace the agent explores (read-only)
#   /output/PROMPT.txt the instruction for this run (written by the host)
#   /output/...        where we drop answer.txt, opencode.log, the transcript
set -u

# Keep OpenCode's session/transcript data under /output so it lands on the host.
export XDG_DATA_HOME=/output/opencode-data
mkdir -p "$XDG_DATA_HOME"

PROMPT="$(cat /output/PROMPT.txt)"

# Open OpenCode on the workspace and run one prompt non-interactively.
# --dangerously-skip-permissions: headless mode needs this to auto-approve the
# agent's own tool use (read/bash); without it OpenCode does not act and exits
# with an empty answer. It is safe here: the container is throwaway, the repo
# is mounted read-only, and the network is locked to the model API only.
cd /work 2>/dev/null || cd /
# --agent reviewer: the agent defined in opencode.json (tools, permissions,
# maxSteps=200 tool-round cap, webfetch/websearch denied). --dangerously-skip-
# permissions is kept as a belt so headless never stalls on a permission prompt.
opencode run -m "$OPENCODE_MODEL" --agent reviewer \
    --dangerously-skip-permissions --print-logs "$PROMPT" \
    >/output/answer.txt 2>/output/opencode.log
echo "$?" >/output/exit_code.txt
