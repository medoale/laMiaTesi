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
# single failed repo, GitHub rate-limiting) can be restarted with the same
# command and picks up where it left off, at both stages:
#   - Stage 1 enumerates one YEAR at a time (2008 is old enough that a single
#     enumerate_github call spanning it all can run for over an hour — losing
#     all of it to one failed retry, as happened in practice, defeats the
#     point of being "resumable"). Each year's chunk is written to its own
#     temp file and only appended to the growing candidate list once that
#     specific `enumerate_github` call has exited successfully; the year is
#     then recorded in a small "done" marker file. On restart, years already
#     marked done are skipped — an interruption costs at most one year of
#     re-work, not the whole 2008-to-now range.
#   - Stage 2 keeps a stable, un-dated working file (scored_in_progress.csv)
#     that candidates are appended to. On restart, candidates already present
#     in that file are skipped (diffed out before the next criticality_score
#     call), so only what's left gets processed with -append.
#   - Only once ALL candidates are scored is the working file copied to a
#     dated final snapshot AND the working state (both stages') is deleted —
#     so the next periodic refresh (weeks/months later) starts genuinely
#     fresh instead of "resuming" a run that actually finished.
set -euo pipefail
cd "$(dirname "$0")"

# --- Tunable parameters ------------------------------------------------------
MIN_STARS=3000          # candidate pool: how popular a repo must be to be scored
WORKERS=1                # 1 worker per GitHub token (see tool's own README)
START_YEAR=2008          # enumerate_github's own earliest supported date is 2008-01-01
# BigQuery "sandbox" projects (no billing account linked, no credit card
# needed) cap table expiration at 60 days — criticality_score defaults to no
# expiration at all, which sandbox projects reject outright. This just needs
# to stay under 60*24=1440 hours; the tables in question are BigQuery-side
# working state for the deps.dev lookup, not our output, so letting them
# expire costs nothing since this pipeline only runs occasionally anyway.
DEPSDEV_TABLE_EXPIRATION_HOURS=1400
# Candidate paths for CVEfixes.ini, tried in order so the same script runs
# unmodified on the local machine or the cluster.
CVEFIXES_INI_CANDIDATES=(
    "/home/medo/.CVEfixes.ini"
    "/home/students/s346086/AlessandroMedvescek/CVEfixes.ini"
)

DATA_DIR="Data"
CANDIDATES_FILE="$DATA_DIR/candidates.txt"           # final name: only exists once complete
CANDIDATES_TMP="$DATA_DIR/candidates.txt.partial"     # growing list across completed year-chunks
CHUNK_TMP="$DATA_DIR/candidates_chunk.txt.partial"    # single year currently being enumerated
CHUNKS_DONE_FILE="$DATA_DIR/enumerate_chunks_done.txt"  # one completed year per line
SCORED_WIP="$DATA_DIR/scored_in_progress.csv"         # stable across resumed runs
REMAINING_FILE="$DATA_DIR/candidates_remaining.txt"   # stage-2 input on a resumed run
FAILED_FILE="$DATA_DIR/failed_repos.txt"              # repos that error out every time, skipped for good
STDERR_LOG="$DATA_DIR/criticality_score_stderr.log"   # captured per attempt, to find WHICH repo just failed

mkdir -p "$DATA_DIR"

# --- Prerequisites ------------------------------------------------------------
command -v go >/dev/null || { echo "ERROR: Go is not installed. See README.md."; exit 1; }
command -v gcloud >/dev/null || { echo "ERROR: gcloud SDK is not installed. See README.md."; exit 1; }
gcloud auth application-default print-access-token >/dev/null 2>&1 || {
    echo "ERROR: not authenticated with GCP. Run: gcloud auth login --update-adc"
    exit 1
}

# criticality_score's deps.dev/BigQuery collector cannot always auto-detect
# the project to bill against — read it from the active gcloud config
# instead of hardcoding it, so this works on any machine without editing.
GCP_PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
[ -n "$GCP_PROJECT_ID" ] || {
    echo "ERROR: no active GCP project. Run: gcloud config set project <PROJECT_ID>"
    exit 1
}

# The GitHub token lives in CVEfixes.ini (same source every other script in
# this project uses); the Go tools only read it from an environment variable.
CVEFIXES_INI_PY_LIST=$(printf "'%s', " "${CVEFIXES_INI_CANDIDATES[@]}")
TOKEN=$(python3 -c "
from configparser import ConfigParser
cfg = ConfigParser()
cfg.read([$CVEFIXES_INI_PY_LIST])
tok = cfg.get('GitHubVulnRadar', 'token', fallback=None) or cfg.get('GitHub', 'token', fallback=None)
print(tok or '')
")
[ -n "$TOKEN" ] || { echo "ERROR: no GitHub token found in any of: ${CVEFIXES_INI_CANDIDATES[*]}"; exit 1; }
export GITHUB_TOKEN="$TOKEN"

cd criticality_score

# --- Stage 1: enumerate candidate repos, one year at a time --------------------
# Reused as-is if a PREVIOUS run already completed it (final name exists).
if [ -s "../$CANDIDATES_FILE" ]; then
    echo "=== Stage 1/2: reusing existing candidate list (already completed) ==="
else
    echo "=== Stage 1/2: enumerating repos with >= $MIN_STARS stars, year by year ==="
    touch "../$CHUNKS_DONE_FILE"
    CURRENT_YEAR=$(date -u +%Y)
    TODAY=$(date -u +%Y-%m-%d)

    for YEAR in $(seq "$CURRENT_YEAR" -1 "$START_YEAR"); do
        if grep -qxF "$YEAR" "../$CHUNKS_DONE_FILE"; then
            echo "  $YEAR already enumerated, skipping"
            continue
        fi

        CHUNK_START="${YEAR}-01-01"
        # The current year isn't over yet — asking enumerate_github for dates
        # beyond today doesn't make sense (and there is nothing there yet).
        if [ "$YEAR" -eq "$CURRENT_YEAR" ]; then
            CHUNK_END="$TODAY"
        else
            CHUNK_END="${YEAR}-12-31"
        fi

        echo "  enumerating $CHUNK_START to $CHUNK_END..."
        go run ./cmd/enumerate_github \
            -start="$CHUNK_START" \
            -end="$CHUNK_END" \
            -min-stars="$MIN_STARS" \
            -workers="$WORKERS" \
            -out="../$CHUNK_TMP" \
            -force

        # Reached only if the year's enumeration succeeded: fold it into the
        # growing candidate list and record the year as done, so a failure on
        # the NEXT year never re-does this one.
        cat "../$CHUNK_TMP" >> "../$CANDIDATES_TMP"
        rm -f "../$CHUNK_TMP"
        echo "$YEAR" >> "../$CHUNKS_DONE_FILE"
    done

    mv "../$CANDIDATES_TMP" "../$CANDIDATES_FILE"   # only reached once every year succeeded
    rm -f "../$CHUNKS_DONE_FILE"
fi

N_CANDIDATES=$(wc -l < "../$CANDIDATES_FILE")
echo "  -> $N_CANDIDATES candidate repos"

# --- Stage 2: score every candidate, resumable ---------------------------------
touch "../$FAILED_FILE"   # repos already known to always fail (see the retry loop below)

# Remaining = candidates minus (already scored) minus (known to always fail).
# Both sets can grow WHILE stage 2 runs (criticality_score writes rows to
# SCORED_WIP incrementally, and the retry loop below adds to FAILED_FILE), so
# this is a function, re-run after every attempt — not just computed once —
# otherwise a retry would re-process (and duplicate) repos that were already
# written to SCORED_WIP earlier in the SAME crashed attempt.
recompute_remaining() {
    python3 -c "
import csv

done = set()
try:
    with open('../$SCORED_WIP') as f:
        for row in csv.DictReader(f):
            url = row.get('repo.url')
            # Defensive: if criticality_score's -append ever repeats a header
            # line, don't let it be mistaken for a scored repo (its 'repo.url'
            # cell would literally read 'repo.url').
            if url and url != 'repo.url':
                done.add(url)
except FileNotFoundError:
    pass

with open('../$FAILED_FILE') as f:
    failed = {line.strip() for line in f if line.strip()}

with open('../$CANDIDATES_FILE') as f:
    all_urls = [line.strip() for line in f if line.strip()]

remaining = [u for u in all_urls if u not in done and u not in failed]
with open('../$REMAINING_FILE', 'w') as f:
    f.write('\n'.join(remaining) + ('\n' if remaining else ''))

print(f'  {len(done)} already scored, {len(failed)} permanently failed (skipped), '
      f'{len(remaining)} remaining')
"
}

if [ -s "../$SCORED_WIP" ]; then
    echo "  found partial results from a previous interrupted run, resuming..."
    APPEND_OR_FORCE="-append"
else
    APPEND_OR_FORCE="-force"   # only for the very first invocation, to create the file
fi
recompute_remaining
INPUT_FILE="../$REMAINING_FILE"

N_REMAINING=$(wc -l < "$INPUT_FILE" 2>/dev/null || echo 0)
if [ "$N_REMAINING" -eq 0 ]; then
    echo "=== Stage 2/2: nothing left to score ==="
else
    echo "=== Stage 2/2: scoring $N_REMAINING repos (~2.5s each with 1 worker) ==="

    # A single repo whose signal collection errors out (e.g. a contributor
    # whose GitHub login is a bot like "Copilot", unresolvable by the GraphQL
    # query criticality_score uses for org-diversity) crashes the tool's
    # ENTIRE process — it does not skip and continue on its own. So: on
    # failure, find which repo just failed from its own JSON error log, add
    # it to the permanent skip-list, recompute what's left (dropping both
    # that failure AND whatever was already written to SCORED_WIP before the
    # crash), and retry — until a run succeeds or nothing is left to try.
    while true; do
        go run ./cmd/criticality_score \
            -workers="$WORKERS" \
            -format=csv \
            -scoring-config=config/scorer/pike_depsdev.yml \
            -gcp-project-id="$GCP_PROJECT_ID" \
            -depsdev-expiration="$DEPSDEV_TABLE_EXPIRATION_HOURS" \
            -out="../$SCORED_WIP" \
            "$APPEND_OR_FORCE" \
            "$INPUT_FILE" 2>&1 | tee "../$STDERR_LOG" && break

        BAD_URL=$(grep -o '"url": "[^"]*"' "../$STDERR_LOG" | tail -1 | sed -E 's/"url": "(.*)"/\1/')
        if [ -z "$BAD_URL" ]; then
            echo "ERROR: criticality_score failed and no repo URL could be found in its error output — see above, aborting."
            exit 1
        fi
        echo "  $BAD_URL always fails signal collection (see error above) — skipping it for good and retrying"
        echo "$BAD_URL" >> "../$FAILED_FILE"
        APPEND_OR_FORCE="-append"   # SCORED_WIP now has a header + rows from this attempt
        recompute_remaining
        N_REMAINING=$(wc -l < "$INPUT_FILE" 2>/dev/null || echo 0)
        if [ "$N_REMAINING" -eq 0 ]; then
            echo "  no candidates left after removing failures."
            break
        fi
    done
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
# instead of thinking there is a run to resume. CHUNKS_DONE_FILE is already
# removed right after stage 1 succeeds; included here too as a safety net.
rm -f "$CANDIDATES_FILE" "$SCORED_WIP" "$REMAINING_FILE" "$CHUNKS_DONE_FILE"
echo "Working state cleared — next run will start a fresh enumeration."
