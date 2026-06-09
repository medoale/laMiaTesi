---
student: Alessandro
date: 2026-05-19
session_type: weekly-update
relates_to_milestones: [SG1, SG2, SG3]
---

# Progress — 2026-05-19

## What I did this week

- Collected and analysed the CVEfixes dataset (ground truth for SG2 and future AI agent evaluation).
  The database covers **9,016 vulnerability-fixing commits** across 4,249 open-source projects for 11,873 CVEs.
  Of these, **1,079 (12%)** have both `code_before` and `code_after` extracted . The subset directly usable
  to evaluate AI agents on real fix pairs. The remaining 88% have no code (unreachable repos,
  deleted commits) but show the same severity distribution.

- Ran vulnRadar for the first time end-to-end and validated the **temporal signal** (SG2).
  The system runs daily at 06:00 UTC, selects up to 30 GitHub repositories per task, and cross-references
  selections against CVEs published afterwards on NVD.
  Three independent tasks run in parallel, each selecting up to 30 repos per run:

  - **Official** — queries NVD for CVEs published in the last 30 days, extracts every distinct
    `(vendor, product)` pair from CPE strings, and ranks pairs by frequency. For each top pair it
    tries to locate the GitHub repository via direct lookup (`/repos/{vendor}/{product}`),
    vendor-name mapping, or an org-scoped name search. A global fuzzy search is intentionally avoided
    to prevent false positives on forks and unrelated projects. Repos are ranked by how many distinct
    CVEs reference their `(vendor, product)` pair in the lookback window.

  - **Hot** — searches GitHub for commits authored in the last 7 days whose messages contain
    security-related keywords (`CVE`, `exploit`, `XSS`, `RCE`, `overflow`, `auth bypass`, …).
    Up to 300 commits per keyword are collected and deduplicated by SHA. Each candidate repo is scored as:

    ```
    score = (unique_commits + 2 × distinct_keywords)
            + commits_last_week × 0.5
            + log10(release_downloads + 1) × 3.0
    ```

    A high download count with a sudden security-keyword burst is treated as a silent-patch signal.

  - **Talkers** — counts issues created and commits authored in the last 7 days across GitHub
    (up to 1,000 results each via the search API). Repos are ranked by:

    ```
    score = 1.0 × recent_issues + 1.5 × recent_commits
    ```

    Commits are weighted higher because coordinated developer activity is a stronger signal of an
    exposed surface than user chatter.

- Obtained **31 CVE matches across 8 distinct repositories**, all from the Official task,
  with a lead time of **+3 to +9 days** between selection and CVE publication.
  The strongest case: ChurchCRM/CRM selected on 05/05, then hit by 2 CRITICAL CVEs (CVSS 10.0 and 9.6)
  on 12/05 (7 days later).

## What I'm working on next

- Investigate why the Hot and Talkers tasks produced zero matches.
  Apply stricter selection filters and rerun to check whether match rate improves.
- Continue letting vulnRadar run daily to accumulate more match data and build a longer time series
  for SG3 analysis (CVE rate over time, lead time distribution).

## Blockers and open questions

- **Hot and Talkers tasks: zero CVE matches.** The most likely cause is noise in repository selection:
  both tasks cast a wide net over GitHub activity and pick up many small, unrelated, or spam repos.
  The NVD cross-reference finds no hits because few of these repos are ever mentioned in a real CVE.
  Two directions to explore:
  1. **Stricter filters** : minimum star/fork thresholds, minimum contributor count, require a recent release.
  2. **Multi-source verification** : A repo appearing in multiple databases is a much stronger signal.

- **88% of CVEfixes commits have no extracted code.** This limits the usable training set for AI agents
  to roughly 1 in 8 real fixes. Worth flagging as a dataset limitation in any paper or evaluation that
  relies on `code_before / code_after` pairs.
## Deviation from plan

The temporal-signal validation (SG2) is working for the Official task
but not yet for Hot and Talkers; those two require filter tuning before they contribute reliable signals.

## Things I don't yet understand

- What is the acceptable false-positive rate for SG1? If Hot/Talkers select 30 repos per day and
  zero match CVEs, does that count as a high false-positive rate or just low sensitivity?
