# cveFixes — thesis layer

Custom scripts and analyses built **on top of** the official
[CVEfixes](https://github.com/secureIT-project/CVEfixes) collection tool.
The upstream tool lives untouched in `CVEfixes/` — see `CVEfixes/README.md`
for its own documentation. This file documents only our additions.

## The database

`CVEfixes/Code/Data/CVEfixes.db` (~7 GB) is **not in git**. Regenerate it with
`CVEfixes/Code/collect_projects.py` or copy it from the cluster.

Two copies exist:

- **local** — a partial simulation: the `file_change` table (which holds
  `code_before`, `code_after`, `diff` per modified file) is missing and
  `method_change` is empty. Enough to develop queries against `cve`, `fixes`,
  `commits`, `repository`.
- **cluster** — the complete database, produced by a full collection run.
  Everything that needs `file_change` runs there.

## Our scripts

### `query_utili.py`

Interactive menu of ready-made queries (table counts, CVEs per repo, top
CWEs, severity distributions, …). Run it from this folder:
`python3 query_utili.py`.

### `CVEfixes/Code/Data/cveFixes_repo_size_analyzer.py`

Measures how big each repository was **just before** each vulnerability fix.

- **Selection** (SQL on `commits ⋈ fixes ⋈ cve`): non-merge commits with a
  parent, linked to CVEs published in `CVE_YEAR` (2026). Non-merge + parent
  means before/after/diff are recoverable from git.
- **Measure**: one full clone per repo (temporary, always deleted), then for
  every qualifying commit a `git checkout` of the **parent** (pre-fix)
  version; counts every file (`.git` excluded), their lines, and the disk
  size of the whole clone (`.git` included).
- **Output**: `repo_analysis_v2.csv`, one row per `(repo_url, commit)`:
  `repo_url, commit, parent, n_files, total_lines, avg_lines_per_file,
  clone_size_mb, status`.
- **Resumable**: on restart, pairs already present in the CSV are skipped.
- The script sits next to the database because its paths are relative to its
  own location. The GitHub token is read from the ini file pointed to by the
  `CVEFIXES_INI` constant (adjust it per machine).

Note on `clone_size_mb`: it is dominated by `.git`, i.e. by the repo's whole
history — snapshots of the same repo have nearly identical values, and it is
not comparable with the per-commit file/line counts.

### `CVEfixes/Code/Data/cvefixes_analysis.ipynb`

Analysis notebook (run it from the `Data/` folder so the relative paths
work). Sections:

1. dataset overview with a `YEAR_FILTER` (CVEs, fixes, file/method changes);
2. commits-per-repository distributions;
3. **Repository size at fix time** — reads `repo_analysis_v2.csv`, collapses
   the snapshots of each repo to their **median**, and plots four log-scale
   distributions: files per repo, mean lines per file, lines per repo, clone
   size in MB.

Run the notebook top to bottom: the later cells reuse the imports and the
`YEAR_FILTER` defined in the first cells.

## Downstream

`repo_analysis_v2.csv` is also the input of `../agentAnalysis/` (the LLM
agents that analyze the fix commits): its rows define which (repo, commit)
pairs the agents are run on.
