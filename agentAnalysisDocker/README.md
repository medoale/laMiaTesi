# agentAnalysisDocker

A self-contained variant of `agentAnalysis` that runs each agent as **OpenCode
inside a throwaway Docker container**, instead of a hand-written tool loop.

The host (this machine) does all the orchestration — ground truth, cloning,
workspace prep, collecting results — and each agent instance runs in its own
container that is created, used, and destroyed. The container gives the agent
full read access to explore the code, and its answer + full transcript are
saved back on this machine.

## The three agents

| Agent | Sees |
|-------|------|
| agent1 | only the commit's code changes (`_CHANGES/`), no repository |
| agent2 | the repository (checked out before the fix) **and** the changes |
| agent3 | only the repository, no changes, no hint (zero-day style) |

The repository is always mounted **without `.git`**, so the agent cannot read
history and discover the fix. The CWE answer key (ground_truth.csv) is never
shown to any agent — it is only used afterwards to score the answers.

## Files

| File | Role |
|------|------|
| `config.py` | all paths, the Docker image, the model, the OpenRouter key, and the **internet-block placeholder** |
| `build_ground_truth.py` | (re)generates `ground_truth.csv` from `repo_analysis_v2.csv` + the database |
| `ground_truth.csv` | local copy — the sample the agents actually run on |
| `data.py` | host-side inputs: code changes (from the DB) and the parent-commit clone |
| `prompts.py` | the three agent prompts (all end with the shared verdict block) |
| `sandbox.py` | builds and runs one `docker run`, then it auto-removes |
| `network_rules.py` | egress isolation: an internal network + an allowlist proxy so the agent reaches ONLY the model API |
| `proxy_server.py` | the tiny CONNECT proxy that runs inside the proxy container |
| `entrypoint.sh` | runs INSIDE the container: OpenCode headless → answer + transcript |
| `main.py` | the orchestrator loop (resumable) |
| `verdict.py` | the required answer format and its parser |

## Requirements

- Docker, with the OpenCode sandbox image: `docker pull docker/sandbox-templates:opencode`
- The CVEfixes database at the path in `config.DB_PATH` (the one external
  dependency — too large to copy).
- An OpenRouter key under `[OpenRouter]` in the `.ini` (same as the rest of the
  project).

## Run

```bash
python3 build_ground_truth.py   # once, or when the sample changes
python3 main.py                 # runs the agents; safe to stop and re-run (resumes)
```

Everything is split per model, under `outputs/<model>/`:
- `log.jsonl` — the raw log, one line per agent run (drives the resume).
- `results.jsonl` — the grouped result, one line per (repo, commit) with the
  three agents together, rebuilt from the log at the end of each run.
- `<repo>/<commit>/<agent>/` — the per-run files: `answer.txt`, `opencode.log`,
  `exit_code.txt`, and `opencode-data/` (the full transcript).

## Internet isolation

`network_rules.py` puts each agent on a Docker `--internal` network (no route
to the internet) and routes it through an allowlist proxy that only tunnels to
`config.ALLOWED_EGRESS_HOSTS` (openrouter.ai). So the agent can talk to the
model API and nothing else — it cannot look up the CVE or the fix online.
Toggle with `config.ISOLATE_NETWORK` (set False only to test OpenCode without
the proxy). To point at Gemini instead, change the allowlisted host.

## Still to verify (needs Docker, on your machine)

- **OpenCode invocation**: `entrypoint.sh` assumes `opencode run -m <model>
  "<prompt>"` and that the model string is `openrouter/openai/gpt-oss-20b:free`
  (`config.OPENCODE_MODEL`). Verify both against your OpenCode version on the
  first run — the most likely spot to need a small adjustment.
- **Proxy honoured**: confirm OpenCode uses `HTTPS_PROXY`. Even if it did not,
  the `--internal` network leaves no other route out, so the agent stays
  contained; it just would fail to reach the API rather than leak.
