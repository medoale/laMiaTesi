# vulnRadar

A daily scanner that selects which GitHub repositories to **keep an eye on** because they're more likely to be the subject of a future CVE. Three independent selection tasks run in parallel, and after each run the system cross-references its historical selections against newly published CVEs to see whether it "predicted" any of them.

## Quick start — run as a daemon in the background

```bash
cd /home/medo/laMiaTesi/vulnRadar
./run.sh          # start detached from the terminal
tail -f run.log   # watch it live
./stop.sh         # stop it cleanly
```

The pipeline runs immediately and then re-runs once a day. `run.sh` detaches the process (`nohup`, unbuffered) so it survives closing the terminal and mirrors into `run.log` exactly what you would see on screen; `stop.sh` signals it to shut down cleanly.

---

## How it works

Four tasks run **in parallel** (one thread each), each producing up to `MAX_REPOS_PER_TASK` repositories (default **30**):

### Task 1 — Official (NVD-driven, product-aware)
Queries the **NVD API** for CVEs published in the last 30 days and extracts every distinct `(vendor, product)` pair from CPE strings (a single CVE that lists 5 different versions of the same product still counts once for that pair). Pairs are then ranked by frequency.

For each top pair, the task resolves the actual GitHub repository hosting that product — **the repo name is never guessed** — in this order:

1. `/repos/{vendor}/{product}` — direct lookup
2. the `github.com/owner/repo` URLs that the CVEs of that product list in their own `references`, most-referenced first, accepted only when at least `MIN_REFERENCE_HITS` (default 2) **distinct CVEs** point to the same repo (a repo linked by a single CVE is often the reporter's proof-of-concept). This recovers the products whose GitHub org differs from the NVD vendor name (`openwebui` → `open-webui/open-webui`, `linuxfoundation/nats-server` → `nats-io/nats-server`): the CVE itself names the repo.

A product that resolves to neither is **dropped**. Usually it is simply not hosted on GitHub (Chrome, Windows, macOS, …) — and those are exactly the products with the most CVEs, so the previous approach (a static vendor→org map plus a name search inside the org) used to fill the top of the ranking with false positives such as `google/coding-with-chrome` for `google/chrome`. A global fuzzy search remains intentionally avoided. Resolved pairs are cached in-process, so a `(vendor, product)` that recurs across many CVEs costs only one API call.

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

### Task 4 — OSV (OSV.dev-driven, package-aware)
The same idea as Task 1, sourced from **OSV.dev** instead of NVD: an independent vulnerability database, so a package that NVD has not indexed yet can still surface here. Every distinct `(ecosystem, package)` pair found in recent OSV entries is ranked by how many vulnerabilities affect it.

The repo name is **never guessed**; a pair resolves in this order:

1. **direct lookup**, when the package name already *is* a GitHub path — the OSV counterpart of Task 1's `/repos/{vendor}/{product}`. This is the norm in the Go ecosystem, where the package name is literally the module import path (`github.com/gin-gonic/gin`), and simply does not apply to ecosystems whose names are not path-shaped.
2. the `github.com/owner/repo` URLs the vulnerabilities of that package list in their own `references`, accepted only when at least `MIN_REFERENCE_HITS` distinct vulnerabilities agree — the same rule, and the same shared extractor, as Task 1.

A package that resolves to neither is **dropped**, exactly as Task 1 drops Chrome or Windows.

OSV has no date-range query, so instead of a time window the task streams the newest `MAX_ENTRIES_TO_CHECK` entries (default **5000**) from OSV's reverse-chronological feed and re-samples them fresh every run. The size matters: the feed is dominated by Linux distro and container advisories (Debian, Ubuntu, Chainguard, …), whose references point at the distro's own tracker rather than at GitHub, so the window must be wide enough to also reach the GitHub-backed ecosystems (GHSA, Go, PyPI, npm). Detail fetches run concurrently, keeping the whole task to roughly two minutes per run.

---

## CVE matching

After the four tasks finish, vulnRadar fetches vulnerabilities published since the last run and looks for `github.com/owner/repo` URLs in their `references` field. If any URL points to a repo we have **ever** selected, we record a match in `cve_matches` with the number of days between selection and CVE publication.

Two **independent sources** are queried for the same kind of evidence, and a repo is matched if **either** finds it (logical OR), so a vulnerability indexed by only one of the two is not missed:

- **NVD** — date-range API, `last_check` cursor `nvd_last_check`.
- **OSV.dev** — streamed reverse-chronological feed, capped per run, cursor `osv_last_check`. Its cursor advances only once the whole window has actually been covered, never on a partial fetch. When a vulnerability carries a real CVE ID among its aliases that ID is used, so the same issue found by both sources lands under one `cve_id` and the `UNIQUE(repo, cve_id)` constraint recognises it as a single match.

Two important guarantees:

- **No false predictions** — a match is counted only when the CVE was published **after the exact moment** the repo was first selected (`selected_at`, full timestamp): a CVE published a few hours *before* the daily run — typically one of the very CVEs that caused the selection — is skipped (logged as `skipped_pre_selection`). Rows written before the `selected_at` column existed only carry a date and are conservatively treated as selected at the *end* of that day, so their same-day CVEs are discarded too. Repo comparison is **case-insensitive** (GitHub URLs are), and matches are recorded under the canonical tracked name.
- **No silent data loss** — the NVD client splits long ranges into ≤119-day windows (NVD's hard limit) and returns the upper bound of the most recent window that succeeded. The `last_check` cursor is advanced only to that point, never to `now()`. If a window fails mid-fetch, the missing tail will be retried on the next run.

The URL extraction also filters out reserved GitHub paths (`advisories/`, `orgs/`, `sponsors/`, `marketplace/`, `pulls/`, `issues/`, …) that look like `owner/repo` but are not real repositories.

---

## Database schema

| Table | Description |
|-------|-------------|
| `tracked_repos` | One row per (repo, date, task) selection. Includes the selection score, a human-readable reason and the exact selection timestamp (`selected_at`, added by automatic migration; NULL on rows that pre-date it). The same repo can appear multiple times across days/tasks. |
| `cve_matches`   | A repo we previously selected has been mentioned in a new CVE. See fields below. Rows are never deleted (`INSERT OR IGNORE`). |
| `last_check`    | Bookkeeping: one cursor per source (`nvd_last_check`, `osv_last_check`) holding the upper bound of the last successful fetch, so each run only looks at what is new. |

**`cve_matches` columns**:

| Column | Meaning |
|--------|---------|
| `repo_full_name`        | The matched repository (`owner/repo`). |
| `cve_id`                | The CVE that mentions it. |
| `cve_published_date`    | When NVD published the CVE. |
| `first_selected_date`   | When vulnRadar first selected this repo. |
| `days_until_cve`        | `cve_published_date − first_selected_date` (always ≥ 0). |
| `severity`              | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` (CVSS v3.1 → v3.0 → v2 fallback). |
| `cvss_score`            | Numeric CVSS base score (0.0–10.0). |
| `exploitability_score`  | NVD exploitability sub-score. |
| `cwe_ids`               | Comma-separated list of CWE IDs (e.g. `CWE-79, CWE-89`). |
| `matched_at`            | When the match was recorded by vulnRadar. |

The schema migrates automatically: if the DB pre-dates the severity / CVSS / CWE columns, they are added in place via `ALTER TABLE ADD COLUMN` on the next run.

---

## Configuration

All tunable parameters live at the top of `config.py`:

```python
MAX_REPOS_PER_TASK    = 30    # cap per task per run
NVD_LOOKBACK_DAYS     = 30    # window for the Official task
HOT_LOOKBACK_DAYS     = 7     # window for the Hot task
TALKERS_LOOKBACK_DAYS = 7     # window for the Talkers task
OSV_LOOKBACK_DAYS     = 30    # window for the OSV task
SECURITY_KEYWORDS     = [...]  # keywords used by the Hot task
```

Per-task tuning:

- `task_official.py` → `MIN_REFERENCE_HITS`
- `task_hot.py` → `W_COMMITS`, `W_DOWNLOADS`, `ENRICH_MULTIPLIER`, `SEARCH_PAGES_PER_KEYWORD`
- `task_talkers.py` → `W_ISSUES`, `W_COMMITS`
- `task_osv.py` → `MAX_ENTRIES_TO_CHECK`, `MIN_REFERENCE_HITS`

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

To run it detached so it survives logout, use the helper scripts (see Quick start):

```bash
./run.sh     # background, logs to run.log
./stop.sh    # clean shutdown
```

Or install it as a systemd service for automatic restart on reboot.

---

## File structure

```
vulnRadar/
├── main.py            ← entry point, runs the four tasks in parallel
├── config.py          ← tunable parameters + .CVEfixes.ini reader
├── github_client.py   ← thread-safe GitHub HTTP client (rate limit aware)
├── nvd_client.py      ← NVD client: 119-day windowing, robust pagination, partial-failure safe
├── osv_client.py      ← OSV.dev client: reverse-chronological feed, concurrent detail fetches
├── database.py        ← SQLite schema, automatic migrations and insert helpers
├── task_official.py   ← Task 1 — NVD vendor/product analysis (direct lookup + CVE references)
├── task_hot.py        ← Task 2 — security keyword commit search + silent-patch signals
├── task_talkers.py    ← Task 3 — most active repos right now
├── task_osv.py        ← Task 4 — OSV ecosystem/package analysis (direct lookup + references)
├── cve_matcher.py     ← cross-reference selections vs new CVEs from NVD and OSV (no false predictions)
├── vulnRadar_results_analysis.ipynb  ← analysis notebook on the collected matches
└── Data/vulnRadar.db  ← SQLite database with selections and matches
```
