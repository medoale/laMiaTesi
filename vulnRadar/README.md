# vulnRadar

A daily scanner that selects which GitHub repositories to **keep an eye on** because they're more likely to be the subject of a future CVE. Three independent selection tasks run in parallel, and after each run the system cross-references its historical selections against newly published CVEs to see whether it "predicted" any of them.

## Quick start — run as a daemon in the background

```bash
cd /home/medo/laMiaTesi/vulnRadar
nohup python3 main.py >> radar.log 2>&1 &
```

The pipeline runs immediately and then re-runs once a day. Watch the log with `tail -f radar.log`. Stop the daemon with `pkill -f "python3 main.py"`.

---

## How it works

Three tasks run **in parallel** (one thread each), each producing up to `MAX_REPOS_PER_TASK` repositories (default **100**):

### Task 1 — Official (NVD-driven, product-aware)
Queries the **NVD API** for CVEs published in the last 30 days and extracts every distinct `(vendor, product)` pair from CPE strings (a single CVE that lists 5 different versions of the same product still counts once for that pair). Pairs are then ranked by frequency.

For each top pair, the task tries to find the actual GitHub repository hosting that product, in this order:

1. `/repos/{vendor}/{product}` — direct lookup
2. `/repos/{mapped_vendor}/{product}` — if the NVD vendor name needs mapping (e.g. `nvidia` → `NVIDIA`, `cisco` → `cisco-open-source`)
3. `/search/repositories?q={product} in:name org:{vendor}` — search by repo name within the vendor's org

A global fuzzy search is intentionally avoided to prevent false positives on forks and unrelated projects. Resolved pairs are cached in-process, so a `(vendor, product)` that recurs across many CVEs costs only one API call.

### Task 2 — Hot (security-keyword commits + silent patch signals)
Searches GitHub for **commits authored in the last 7 days** whose messages contain security-related keywords (`CVE`, `vulnerability`, `exploit`, `injection`, `XSS`, `overflow`, `RCE`, `sanitize`, `auth bypass`, `credential`, `patch`, …). Up to 3 pages (300 commits) per keyword are paginated, and commits are deduplicated by SHA so a single commit matching multiple keywords is counted only once.

Each candidate is then enriched with two **silent-patch signals**:

```
keyword_score    = #unique_commits + 2 × #distinct_keywords
commit_factor    = commits_last_week × W_COMMITS        (default 0.5)
download_factor  = log10(total_release_downloads + 1) × W_DOWNLOADS  (default 3.0)

score = keyword_score + commit_factor + download_factor
```

So a repo with very few security-keyword commits but a sudden burst of activity (silent fix) and a wide user base (high release downloads) still ranks high. Weights `W_COMMITS` and `W_DOWNLOADS` are tunable at the top of `task_hot.py`.

### Task 3 — Talkers (most active repos right now)
Counts **issues created + commits authored in the last 7 days** across GitHub via the search API (paginated up to 1000 results each). Repos are ranked by:

```
score = W_ISSUES × #recent_issues + W_COMMITS × #recent_commits
                  (default 1.0)             (default 1.5)
```

Commits are weighted slightly more — coordinated developer activity is a stronger signal of an exposed surface than user chatter. Weights are at the top of `task_talkers.py`.

---

## CVE matching

After the three tasks finish, vulnRadar fetches CVEs from NVD published since the last run and looks for `github.com/owner/repo` URLs in their `references` field. If any URL points to a repo we have **ever** selected, we record a match in `cve_matches` with the number of days between selection and CVE publication.

Two important guarantees:

- **No false predictions** — matches are only counted when the CVE was published *on or after* the day the repo was first selected. CVEs that pre-date the selection are skipped (logged as `skipped_pre_selection`).
- **No silent data loss** — the NVD client splits long ranges into ≤119-day windows (NVD's hard limit) and returns the upper bound of the most recent window that succeeded. The `last_check` cursor is advanced only to that point, never to `now()`. If a window fails mid-fetch, the missing tail will be retried on the next run.

The URL extraction also filters out reserved GitHub paths (`advisories/`, `orgs/`, `sponsors/`, `marketplace/`, `pulls/`, `issues/`, …) that look like `owner/repo` but are not real repositories.

---

## Database schema

| Table | Description |
|-------|-------------|
| `tracked_repos` | One row per (repo, date, task) selection. Includes the selection score and a human-readable reason. The same repo can appear multiple times across days/tasks. |
| `cve_matches`   | A repo we previously selected has been mentioned in a new CVE. Includes `days_until_cve` (always ≥ 0). Rows are never deleted (`INSERT OR IGNORE`). |
| `last_check`    | Bookkeeping: timestamp of the upper bound of the last successful NVD fetch, so we only fetch new CVEs each run. |

---

## Configuration

All tunable parameters live at the top of `config.py`:

```python
MAX_REPOS_PER_TASK    = 100   # cap per task per run
NVD_LOOKBACK_DAYS     = 30    # window for the Official task
HOT_LOOKBACK_DAYS     = 7     # window for the Hot task
TALKERS_LOOKBACK_DAYS = 7     # window for the Talkers task
SECURITY_KEYWORDS     = [...]  # keywords used by the Hot task
```

Per-task tuning:

- `task_hot.py` → `W_COMMITS`, `W_DOWNLOADS`, `ENRICH_MULTIPLIER`, `SEARCH_PAGES_PER_KEYWORD`
- `task_talkers.py` → `W_ISSUES`, `W_COMMITS`

### Credentials (`.CVEfixes.ini`)

The GitHub token is read from the same `.CVEfixes.ini` file used by the other tools. Optionally, an NVD API key can be added to make NVD calls **10× faster** (sleep drops from 6s to 0.6s between pages):

```ini
[GitHub]
token = ghp_xxxxxxxxxxxxxxxxxxxx

[NVD]
api_key = your-nvd-api-key   # optional, request free at https://nvd.nist.gov/developers/request-an-api-key
```

---

## Usage

```bash
cd /home/medo/laMiaTesi/vulnRadar
python3 main.py
```

By default the program runs in **daemon mode**: it executes the full pipeline immediately and then loops forever, triggering one full pipeline per day at the hour set in `config.DAILY_RUN_HOUR_UTC` (default `6` = 06:00 UTC). Press `Ctrl+C` to stop the loop. If a single run fails it is logged and the daily schedule continues — a transient API outage will not kill the daemon.

To run it just once and exit (e.g. for ad-hoc analysis or external scheduling), set `DAILY_RUN_HOUR_UTC = None` in `config.py`.

Run it as a background process so it survives logout:

```bash
nohup python3 main.py >> radar.log 2>&1 &
```

Or as a systemd service for automatic restart on reboot.

---

## File structure

```
vulnRadar/
├── main.py            ← entry point, runs the three tasks in parallel
├── config.py          ← tunable parameters + .CVEfixes.ini reader
├── github_client.py   ← thread-safe GitHub HTTP client (rate limit aware)
├── nvd_client.py      ← NVD client: 119-day windowing, robust pagination, partial-failure safe
├── database.py        ← SQLite schema and insert helpers
├── task_official.py   ← Task 1 — NVD vendor/product analysis with caching
├── task_hot.py        ← Task 2 — security keyword commit search + silent-patch signals
├── task_talkers.py    ← Task 3 — most active repos right now
└── cve_matcher.py     ← cross-reference selections vs new CVEs (no false predictions)
```
