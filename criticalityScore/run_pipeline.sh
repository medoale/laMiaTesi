#!/usr/bin/env bash
# Runs the official OpenSSF criticality_score pipeline to produce a fresh,
# ranked snapshot of "the most critical/most used" GitHub repositories.
#
# Two stages (the third official tool, `scorer`, is not needed: `criticality_score`
# already computes the score itself in the same pass):
#   1. enumerate_github  -> list of repo URLs with at least MIN_STARS stars
#   2. criticality_score -> scores each repo, deps.dev dependent-count included
#      (pike_depsdev.yml weights it at 4, the highest weight in the config —
#      it is the strongest available signal of real-world usage)
#
# Meant to be run occasionally (see README) to refresh the local snapshot that
# task_talkers.py will read — NOT part of the daily vulnRadar pipeline itself,
# same relationship CVEfixes.db has with the collect_projects.py script.
#
# RESUMABLE: a run that gets interrupted (network blip, closed terminal, a
# single failed repo) can be restarted with the same command and picks up
# where it left off, at both stages:
#   - Stage 1 only commits its output under its final name once
#     enumerate_github exits successfully (temp file + rename-on-success), so
#     an interrupted stage 1 is simply redone from scratch on the next run —
#     a partial candidate list is never mistaken for a complete one.
#   - Stage 2 keeps a stable, un-dated working file (scored_in_progress.csv)
#     that candidates are appended to. On restart, candidates already present
#     in that file are skipped (diffed out before the next criticality_score
#     call), so only what's left gets processed with -append.
#   - Only once ALL candidates are scored is the working file copied to a
#     dated final snapshot AND the working state is deleted — so the next
#     periodic refresh (weeks/months later) starts genuinely fresh instead of
#     "resuming" a run that actually finished.
set -euo pipefail
cd "$(dirname "$0")"

# --- Tunable parameters ------------------------------------------------------
MIN_STARS=3000          # candidate pool: how popular a repo must be to be scored
WORKERS=1                # 1 worker per GitHub token (see tool's own README)
CVEFIXES_INI="/home/medo/.CVEfixes.ini"

DATA_DIR="Data"
CANDIDATES_FILE="$DATA_DIR/candidates.txt"           # final name: only exists once complete
CANDIDATES_TMP="$DATA_DIR/candidates.txt.partial"     # written to during stage 1
SCORED_WIP="$DATA_DIR/scored_in_progress.csv"         # stable across resumed runs
REMAINING_FILE="$DATA_DIR/candidates_remaining.txt"   # stage-2 input on a resumed run

mkdir -p "$DATA_DIR"

# --- Prerequisites ------------------------------------------------------------
command -v go >/dev/null || { echo "ERROR: Go is not installed. See README.md."; exit 1; }
command -v gcloud >/dev/null || { echo "ERROR: gcloud SDK is not installed. See README.md."; exit 1; }
gcloud auth application-default print-access-token >/dev/null 2>&1 || {
    echo "ERROR: not authenticated with GCP. Run: gcloud auth login --update-adc"
    exit 1
}

# The GitHub token lives in CVEfixes.ini (same source every other script in
# this project uses); the Go tools only read it from an environment variable.
TOKEN=$(python3 -c "
from configparser import ConfigParser
cfg = ConfigParser()
cfg.read('$CVEFIXES_INI')
tok = cfg.get('GitHubVulnRadar', 'token', fallback=None) or cfg.get('GitHub', 'token', fallback=None)
print(tok or '')
")
[ -n "$TOKEN" ] || { echo "ERROR: no GitHub token found in $CVEFIXES_INI"; exit 1; }
export GITHUB_TOKEN="$TOKEN"

cd criticality_score

# --- Stage 1: enumerate candidate repos ---------------------------------------
# Reused as-is if a PREVIOUS run already completed it (final name exists).
# An interrupted stage 1 never leaves the final name behind, only the .partial
# file, so it is redone from scratch rather than resumed from a partial list.
if [ -s "../$CANDIDATES_FILE" ]; then
    echo "=== Stage 1/2: reusing existing candidate list (already completed) ==="
else
    echo "=== Stage 1/2: enumerating repos with >= $MIN_STARS stars ==="
    go run ./cmd/enumerate_github \
        -min-stars="$MIN_STARS" \
        -workers="$WORKERS" \
        -out="../$CANDIDATES_TMP" \
        -force
    mv "../$CANDIDATES_TMP" "../$CANDIDATES_FILE"   # only reached on success
fi

N_CANDIDATES=$(wc -l < "../$CANDIDATES_FILE")
echo "  -> $N_CANDIDATES candidate repos"

# --- Stage 2: score every candidate, resumable ---------------------------------
if [ -s "../$SCORED_WIP" ]; then
    echo "  found partial results from a previous interrupted run, resuming..."
    python3 -c "
import csv

# Defensive: if criticality_score's -append ever repeats a header line, don't
# let it be mistaken for a scored repo (its 'repo.url' cell would literally
# read 'repo.url').
done = set()
with open('../$SCORED_WIP') as f:
    for row in csv.DictReader(f):
        url = row.get('repo.url')
        if url and url != 'repo.url':
            done.add(url)

with open('../$CANDIDATES_FILE') as f:
    all_urls = [line.strip() for line in f if line.strip()]

remaining = [u for u in all_urls if u not in done]
with open('../$REMAINING_FILE', 'w') as f:
    f.write('\n'.join(remaining) + ('\n' if remaining else ''))

print(f'  {len(done)} already scored, {len(remaining)} remaining')
"
    INPUT_FILE="../$REMAINING_FILE"
    APPEND_OR_FORCE="-append"
else
    INPUT_FILE="../$CANDIDATES_FILE"
    APPEND_OR_FORCE="-force"
fi

N_REMAINING=$(wc -l < "$INPUT_FILE" 2>/dev/null || echo 0)
if [ "$N_REMAINING" -eq 0 ]; then
    echo "=== Stage 2/2: nothing left to score ==="
else
    echo "=== Stage 2/2: scoring $N_REMAINING repos (~2.5s each with 1 worker) ==="
    go run ./cmd/criticality_score \
        -workers="$WORKERS" \
        -format=csv \
        -scoring-config=config/scorer/pike_depsdev.yml \
        -out="../$SCORED_WIP" \
        "$APPEND_OR_FORCE" \
        "$INPUT_FILE"
fi

cd ..

# --- Finalize: only reached once every candidate has been scored ---------------
FINAL_FILE="$DATA_DIR/scored_$(date -u +%Y-%m-%d).csv"
python3 -c "
import csv

# Write the final snapshot with exactly one header row, dropping any stray
# duplicate header lines a resumed -append run might have introduced.
with open('$SCORED_WIP') as f:
    reader = csv.reader(f)
    header = next(reader)
    rows = [r for r in reader if r and r != header]

with open('$FINAL_FILE', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(header)
    w.writerows(rows)

score_col = [c for c in header if c.endswith('_score')][0]
idx_score, idx_url = header.index(score_col), header.index('repo.url')
rows.sort(key=lambda r: float(r[idx_score] or 0), reverse=True)
print(f'Finalized snapshot: $FINAL_FILE ({len(rows)} repos)')
print('Top 5 by score:')
for r in rows[:5]:
    print(f'  {float(r[idx_score]):.3f}  {r[idx_url]}')
"

# Clean up working state so the NEXT periodic refresh starts genuinely fresh
# instead of thinking there is a run to resume.
rm -f "$CANDIDATES_FILE" "$SCORED_WIP" "$REMAINING_FILE"
echo "Working state cleared — next run will start a fresh enumeration."
