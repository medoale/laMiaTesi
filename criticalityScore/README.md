# criticalityScore

Vendored copy of the official [OpenSSF criticality_score](https://github.com/ossf/criticality_score)
tool (`criticality_score/`, cloned as-is — same relationship `cveFixes/CVEfixes/`
has with the upstream CVEfixes tool), plus `run_pipeline.sh`, a script that
runs it to produce a ranked snapshot of the most important/most used
repositories on GitHub.

## Why

`task_talkers.py` (in `vulnRadar/`) needs a starting pool of "the repositories
that genuinely matter" before it measures their current commit/issue activity.
A plain GitHub search sorted by stars is easy but naive — it only measures
notoriety. `criticality_score` is OpenSSF's own methodology for this exact
problem: it combines stars, contributor count, organizational diversity,
commit/release/issue cadence, and (optionally) how many *other* packages
depend on the project — dependents being the strongest available signal of
genuine, technical usage, not just popularity.

## Why it's a separate, occasional step

Unlike `cveFixes`'s `collect_projects.py`, this is not something vulnRadar
runs itself. `criticality_score` does not discover important repos on its
own — it only scores a list you give it — and "importance" changes slowly, so
there is no reason to run this daily. `run_pipeline.sh` is meant to be run
occasionally (weekly/monthly, at your discretion) to refresh a local snapshot.
**Once we've looked at the results, that snapshot will be wired into
`task_talkers.py`** — that integration hasn't happened yet.

## Prerequisites (one-time setup)

1. **Go** (the tool is written in Go):
   ```bash
   # see https://go.dev/doc/install for your platform
   ```
2. **Google Cloud SDK**, for the dependent-count signal (`deps.dev`, queried
   via BigQuery — free tier is sufficient for this tool's usage):
   ```bash
   # see https://cloud.google.com/sdk/docs/install
   gcloud auth login --update-adc
   ```
   You'll need a GCP project (any free-tier project works); if
   `criticality_score` can't auto-detect one, pass `-gcp-project-id` in
   `run_pipeline.sh`.
3. **GitHub token** — already covered: the script reads it from
   `[GitHub]`/`[GitHubVulnRadar]` in the same `.CVEfixes.ini` every other tool
   in this project uses. Nothing to configure here.

## Running it

```bash
cd criticalityScore
./run_pipeline.sh
```

The command **returns immediately**: the script re-execs itself under `setsid`,
in its own session with no controlling terminal, and keeps running after you
close the terminal that launched it. This is not a convenience — a full run
takes hours, and while it is resumable, stage 1 only checkpoints once per year,
so a run killed by a closing terminal (VSCode's integrated terminal, an ssh
session, a JupyterHub pod) threw away up to a year's worth of GitHub queries
every time and never reached the end.

Output therefore goes to `run.log` (appended across runs, so earlier attempts
stay on record) rather than to the console:

```bash
tail -f run.log            # Ctrl+C closes only the tail, not the run
kill $(cat run.pid)        # stop the run
CRITICALITY_NO_DETACH=1 ./run_pipeline.sh   # foreground instead, for debugging
```

Launching while a run is already in progress is refused: two copies would write
the same state files and destroy each other's resume state.

Two stages:

1. `enumerate_github` — lists every repo with at least `MIN_STARS` stars
   (default **3000**, tunable at the top of the script) into
   `Data/candidates_<date>.txt`. Note it queries GitHub **one calendar day at a
   time**, so the whole 2008-to-now range is ~7,000 GraphQL queries against a
   5,000/hour budget: expect stage 1 alone to stall waiting for the rate limit
   to reset.
2. `criticality_score` — scores each candidate (~2.5s/repo with one worker;
   expect on the order of an hour for a few thousand candidates) using
   `pike_depsdev.yml`, the config that includes the dependent-count signal,
   into `Data/scored_<date>.csv`.

The script prints the top 5 by score at the end as a sanity check.

## Output

`Data/scored_<date>.csv` — one row per repo, comma-separated, with all raw
signals plus a `default_score` column (0–1, higher = more critical). Not
pre-sorted by the tool for you beyond the script's own top-5 preview — sort by
`default_score` descending to get the full ranking.

## Adjusting the candidate pool

`MIN_STARS` is the main lever: lower it to widen the pool (slower —
`enumerate_github` itself takes longer, and every extra candidate costs
~2.5s in stage 2), raise it to narrow to only the most famous projects. 3000
was chosen as a starting point to keep the whole run to roughly an hour;
adjust based on how the first run goes.
