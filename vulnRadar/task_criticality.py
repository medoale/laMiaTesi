"""
Task 3 — Criticality:
Track the most critical open-source repositories, as ranked by the OpenSSF
`criticality_score` tool: the projects the wider ecosystem actually depends on
(the dependent count from deps.dev carries the highest weight in the scoring
config), so a vulnerability in any of them has the widest blast radius.

Unlike the other tasks this one is STATIC and makes no API calls: it reads the
ranked snapshot produced offline by criticalityScore/run_pipeline.sh and
returns its top MAX_REPOS entries. That snapshot is expensive to build (it
enumerates and scores thousands of repositories against the GitHub and
deps.dev APIs) and changes very slowly — the most depended-upon projects are
the same from one week to the next — so recomputing it daily would spend a lot
of GitHub quota to obtain the same list. Re-run that pipeline when a fresher
ranking is wanted; this task picks up the newest snapshot automatically.
"""
import csv
import logging
from pathlib import Path

logger = logging.getLogger('vulnRadar')

# How many of the top-ranked repositories to track.
MAX_REPOS = 30

# Where run_pipeline.sh writes its dated snapshots, and the columns to read.
# The score column is named after the scoring config in use (pike_depsdev.yml).
SNAPSHOT_DIR = Path(__file__).resolve().parent.parent / 'criticalityScore' / 'Data'
SCORE_COLUMN = 'pike_depsdev_score'
URL_COLUMN = 'repo.url'


def latest_snapshot() -> Path | None:
    """The newest scored_*.csv, or None if the pipeline has not produced one
    yet. Names are dated (scored_YYYY-MM-DD.csv), so sorting by name works."""
    snapshots = sorted(SNAPSHOT_DIR.glob('scored_*.csv'))
    return snapshots[-1] if snapshots else None


def run(client=None) -> list[dict]:
    """The top-MAX_REPOS repositories of the latest snapshot.

    `client` is accepted and ignored: the pipeline hands every task a GitHub
    client, but this one needs no network access at all."""
    snapshot = latest_snapshot()
    if snapshot is None:
        logger.warning(f'TASK 3 (criticality) — no snapshot in {SNAPSHOT_DIR}; '
                       'run criticalityScore/run_pipeline.sh to produce one. '
                       'Selected 0 repos.')
        return []

    logger.info(f'TASK 3 (criticality) — reading ranked snapshot {snapshot.name}')
    scored: list[tuple[float, str]] = []
    with open(snapshot, newline='') as f:
        for row in csv.DictReader(f):
            url = (row.get(URL_COLUMN) or '').strip()
            if not url:
                continue
            try:
                score = float(row.get(SCORE_COLUMN) or 0)
            except ValueError:
                continue   # unscored row: skip rather than rank it as zero
            scored.append((score, url))

    scored.sort(reverse=True)
    selected: list[dict] = []
    for score, url in scored[:MAX_REPOS]:
        full_name = url.replace('https://github.com/', '').strip('/')
        selected.append({
            'full_name': full_name,
            'url':       url,
            'score':     round(score, 3),
            'reason':    f'criticality score {score:.3f} ({snapshot.name})',
        })

    logger.info(f'TASK 3 (criticality) — selected {len(selected)} repos '
                f'out of {len(scored)} ranked')
    return selected
