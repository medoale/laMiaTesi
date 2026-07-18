# laMiaTesi

Thesis project on software vulnerabilities: collecting CVE fix commits, monitoring
GitHub repositories at risk, and testing whether LLM agents can recognize the
vulnerabilities that a commit fixes.

## Repository layout

```
laMiaTesi/
├── cveFixes/        CVEfixes dataset (CVE ↔ fix commits) + analysis scripts
├── vulnRadar/       daily scanner that predicts which repos will get a CVE
├── bigScraper/      commit-activity anomaly monitor for major GitHub repos
└── agentAnalysis/   the three LLM agents that analyze fix commits
```

Each tool has its own README (vulnRadar, bigScraper) or is documented below.

## cveFixes/

Wraps the [CVEfixes](https://github.com/secureIT-project/CVEfixes) collection
tool. The SQLite database (`CVEfixes/Code/Data/CVEfixes.db`, ~7 GB) is **not in
git**: regenerate it with `CVEfixes/Code/collect_projects.py` or copy it from
the cluster. The local copy may be a partial simulation; the complete one
(including the `file_change` table with `code_before` / `code_after` / `diff`)
lives on the cluster.

- `query_utili.py` — interactive menu of useful queries on the database.
- `CVEfixes/Code/Data/cveFixes_repo_size_analyzer.py` — for every non-merge
  commit with a parent linked to a CVE published in 2026, clones the repo,
  checks out the **parent** (pre-fix) version and measures files, lines and
  clone size. Output: `repo_analysis_v2.csv` (one row per repo/commit pair,
  resumable run).
- `CVEfixes/Code/Data/cvefixes_analysis.ipynb` — analysis notebook: dataset
  overview, commits per repo, and the repository-size distributions built
  from `repo_analysis_v2.csv`.

## vulnRadar/

Daily scanner that selects GitHub repositories likely to receive a future CVE
(three selection tasks) and then matches newly published CVEs against the
historically tracked repos. See `vulnRadar/README.md` for the full design.
Results live in `vulnRadar/Data/vulnRadar.db`; the analysis notebook is
`vulnRadar/vulnRadar_results_analysis.ipynb`.

## bigScraper/

Monitors ~200 major repositories for unusual spikes in commit activity against
their historical baseline. See `bigScraper/README.md`.

## agentAnalysis/

Sends the fix commits selected in `repo_analysis_v2.csv` to an OpenRouter
agent under three different information regimes, to measure how much context
an LLM needs to recognize the vulnerability fixed by a commit:

| agent | receives | repo access |
|---|---|---|
| `agent1` | `code_before` + `code_after` + `diff` of the commit | none |
| `agent2` | same code sections | full clone, navigable via tools |
| `agent3` | nothing | full clone, navigable via tools |

Key properties:

- **Stateless by construction** — every call starts a brand-new conversation:
  no agent ever sees another agent's prompt, or a previous commit.
- **Blind prompts** — no repo names, file paths or CVE metadata in the text;
  files are only numbered.
- **Navigation via tool calling** — agents 2 and 3 explore the clone through
  `list_dir` / `read_file` tools, sandboxed inside the repo and with `.git`
  hidden (the history contains the fix itself and would leak the answer).
  The clone is checked out at the **parent** commit, i.e. the still-vulnerable
  version, and deleted after each row.

Files:

- `main.py` — orchestrator: reads the CSV, fetches before/after/diff from
  `CVEfixes.db`, clones once per row, runs the three agents, writes output.
  Contains the `filter_rows()` placeholder for selecting which CSV rows to run.
- `agent1.py` / `agent2.py` / `agent3.py` — one per agent: its prompt
  placeholder (`PROMPT_1/2/3`) and its `run()` entry point.
- `common.py` — shared machinery: OpenRouter calls, tool schemas, sandboxed
  filesystem tools, tool-calling loop. The `MODEL` constant lives here
  (agents 2 and 3 need a model that supports tool calling).

Output:

- `agent_responses.jsonl` — raw log, one line per agent call. Resumable:
  on restart, calls already answered `ok` are skipped, errors are retried.
- `results.jsonl` — consumable view, rebuilt from the log at the end of each
  run: one line per (repo, version) with `repo_name`, `commit`, `parent`
  first, then the three agent results together (`null` if not yet run).

To run on the cluster: fill the three prompts and `filter_rows()`, set a
tool-capable `MODEL`, adjust `CVEFIXES_INI` in `common.py`, then
`python3 main.py` from the `agentAnalysis/` folder.

## Configuration

All credentials live in a single ini file outside the repo (default
`~/.CVEfixes.ini`, absolute path in the scripts' constants):

```ini
[CVEfixes]        # database path/name, sample limit, logging
[GitHub]          # token used by CVEfixes and for cloning
[GitHubVulnRadar] # optional separate token for vulnRadar
[NVD]             # api_key for faster NVD queries
[OpenRouter]      # api_key for the agentAnalysis agents
```

Tokens are never committed; scripts fail with a clear error (or fall back to
anonymous access where possible) when a key is missing.
