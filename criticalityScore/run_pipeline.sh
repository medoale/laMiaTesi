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
set -euo pipefail
cd "$(dirname "$0")"

# --- Tunable parameters ------------------------------------------------------
MIN_STARS=3000          # candidate pool: how popular a repo must be to be scored
WORKERS=1                # 1 worker per GitHub token (see tool's own README)
CVEFIXES_INI="/home/medo/.CVEfixes.ini"

DATE_TAG=$(date -u +%Y-%m-%d)
DATA_DIR="Data"
CANDIDATES_FILE="$DATA_DIR/candidates_${DATE_TAG}.txt"
SCORED_FILE="$DATA_DIR/scored_${DATE_TAG}.csv"

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
echo "=== Stage 1/2: enumerating repos with >= $MIN_STARS stars ==="
go run ./cmd/enumerate_github \
    -min-stars="$MIN_STARS" \
    -workers="$WORKERS" \
    -out="../$CANDIDATES_FILE" \
    -force

N_CANDIDATES=$(wc -l < "../$CANDIDATES_FILE")
echo "  -> $N_CANDIDATES candidate repos"

# --- Stage 2: score every candidate --------------------------------------------
echo "=== Stage 2/2: scoring $N_CANDIDATES repos (~2.5s each with 1 worker) ==="
go run ./cmd/criticality_score \
    -workers="$WORKERS" \
    -format=csv \
    -scoring-config=config/scorer/pike_depsdev.yml \
    -out="../$SCORED_FILE" \
    -force \
    "../$CANDIDATES_FILE"

echo
echo "Done. Scored snapshot: $SCORED_FILE"
echo "Top 5 by score:"
python3 -c "
import csv
with open('$SCORED_FILE') as f:
    rows = list(csv.DictReader(f))
score_col = [c for c in rows[0] if c.endswith('_score')][0]
rows.sort(key=lambda r: float(r[score_col] or 0), reverse=True)
for r in rows[:5]:
    print(f\"  {float(r[score_col]):.3f}  {r['repo.url']}\")
"
