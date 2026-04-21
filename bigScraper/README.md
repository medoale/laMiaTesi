# bigScraper

A tool that monitors the **largest and most popular GitHub repositories** and detects unusual spikes in commit activity compared to their historical baseline.

It targets repositories from major vendors (Linux kernel, Linux distros, Microsoft, Google, Meta, Amazon, and more), plus the **top 10 most starred repositories on GitHub globally**, for a total of **200 repositories** per run.

Results are stored in a local SQLite database and printed to the terminal at the end of each run.

---

## How it works

1. **Repo collection** — fetches the most starred public repositories from ~45 curated vendor organisations (e.g. `torvalds`, `microsoft`, `kubernetes`, `rust-lang`, …) plus a global search for the 10 most starred repos on GitHub. Duplicates are removed and the final list is trimmed to the top 200 by star count.

2. **Commit activity** — for each repository, the GitHub endpoint `GET /repos/{owner}/{repo}/stats/commit_activity` returns **52 weeks** of weekly commit totals.

3. **Spike score computation** — see section below.

4. **Recent commits** — the last 14 days of individual commits (up to 100 per repo) are fetched and stored with their SHA, author, date, and subject line.

5. **Output** — a ranked table of the top 20 spikes is printed to the terminal; all data is persisted in SQLite for further analysis.

---

## Spike Score

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║               total commits in the last 2 weeks                  ║
║  score  =  ──────────────────────────────────────────────────    ║
║            average weekly commits over the previous 20 weeks × 2 ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

The denominator (`baseline_avg × 2`) converts the weekly average into the
expected 2-week count, so the score stays anchored to 1.0 = normal activity.

| Score | Meaning |
|------:|---------|
| `1.0` | Activity is exactly at the historical average — no spike |
| `2.0` | Twice as many commits as usual over the past 2 weeks |
| `5.0` | Five times the normal rate — significant spike |
| `10.0+` | Exceptional spike, likely a major release, incident, or coordinated effort |

### Why these windows?

- **Recent window — last 2 weeks**: wide enough to capture a multi-day burst without being thrown off by a single unusually busy day.
- **Baseline window — previous 20 weeks (~5 months)**: covers enough release cycles and quiet periods to give a stable, representative average without going so far back that the repo's activity level has fundamentally changed.

### Exclusion rules

A score is **not computed** if:
- fewer than 4 of the 20 baseline weeks had any commits (repo is too inactive to have a meaningful baseline);
- the baseline average is below `0.5` commits/week (effectively dormant).

---

## Database schema

| Table | Description |
|-------|-------------|
| `repos` | Metadata for each monitored repository (name, stars, language, vendor) |
| `commit_activity` | 52 weeks of weekly commit counts per repository |
| `spike_analysis` | Daily spike score per repository (recent commits, baseline avg/std, score) |
| `recent_commits` | Individual commits from the last 14 days (SHA, author, date, subject line) |

The database is written to the path configured in `.CVEfixes.ini` under `database_path`, as `bigScraper.db`.

---

## Configuration

Uses the same `.CVEfixes.ini` file as CVEfixes. The relevant fields are:

```ini
[CVEfixes]
database_path = /path/to/data/directory

[GitHub]
token = ghp_your_personal_access_token
```

A GitHub personal access token is strongly recommended — without it the rate limit is 60 requests/hour, which is not enough to process 200 repositories.

---

## Usage

```bash
python3 main.py
```

---

## File structure

```
bigScraper/
├── main.py          ← entry point, run this
├── config.py        ← reads .CVEfixes.ini
├── github_client.py ← HTTP client with rate-limit handling and retry logic
├── vendors.py       ← curated list of vendor organisations
├── database.py      ← SQLite schema and all insert/upsert operations
├── analysis.py      ← spike computation, repo and commit fetching
└── display.py       ← terminal output
```
