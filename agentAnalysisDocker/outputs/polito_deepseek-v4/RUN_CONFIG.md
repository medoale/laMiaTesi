# Run configuration — deepseek-v4

Reference configuration of the results in this folder. Started **2026-08-07,
09:40 CEST** (07:40 UTC), 50 commits × 3 agents = 150 runs.

This is the **final protocol**: one attempt per run, no delegation, no
interactive fallback. Any other result folder produced before this date used a
different configuration and is not directly comparable.

---

## Model

| | |
|---|---|
| Model | `deepseek-v4` |
| Endpoint | `https://llm.polito.it/v1` (LiteLLM proxy, OpenAI-compatible) |
| Declared as | `polito/deepseek-v4` |
| Temperature | `0` |
| Context window | 131,072 tokens (a hard limit of the model — see *Known limitations*) |

## Agent (`reviewer` in `opencode.json`)

| Setting | Value | Why |
|---|---|---|
| `mode` | `primary` | |
| `maxSteps` | **200** | tool-round ceiling, **one single pass**: no run may ever receive more rounds than another |
| `read`, `glob`, `grep`, `bash` | allowed | the agent explores the workspace on its own |
| `write`, `edit` | **disabled** | the agent analyses, it must never modify the code it is examining (the same clone is later handed to another agent) |
| `external_directory` | allowed | agent2's material is mounted outside the workspace (`/changes`); without this the agent cannot read its own input |
| **`task`** | **denied, as tool and as permission** | **no sub-agents** — see below |
| `webfetch`, `websearch` | denied | no web access |
| `question` | denied | no interactive questions |
| `lsp` | denied | not needed |

### Why sub-agents are forbidden

A sub-agent does not inherit this configuration: it runs under OpenCode's
built-in `general` profile, with tools and permissions **we never declared**.
Part of the analysis would then happen outside the stated protocol, and could
not be reproduced or audited. This was observed directly: delegated sub-agents
lacked the `external_directory` permission granted here and stalled on it.

It also matters for the comparison between models: a model that delegates is
coordinating assistants, while one that does not is working alone. Forbidding
delegation puts every model on the same footing.

The choice has a measurable cost, reported under *Known limitations*.

## Prompt

The three agents differ only in the material they receive. Every prompt ends
with the same shared block (`verdict.py`), which states the operating
conditions and the required answer format:

> You are running headless: there is no user, and no question of yours can ever
> be answered. Never ask whether to continue or what to focus on — decide by
> yourself and carry on until the analysis is done. Take all the time and tool
> calls you need, then commit to a conclusion: stopping to ask something is the
> one thing that makes this run useless.
>
> […] you MUST end your entire answer with exactly this block […]
>
> ```
> VULNERABILITY_FOUND: yes or no
> CWE_ID: the CWE identifier(s) […] or "none"
> CWE_NAME: the matching short CWE name(s) […] or "none"
> ```

The headless notice is part of the **initial** prompt, delivered identically to
every agent and every model. It is a description of the operating conditions,
not a hint about the answer, and nothing is injected mid-run: a model that ends
without a verdict is left as it is, because resuming the session would hand a
second chance only to the models that struggle — precisely what the comparison
is meant to measure.

## What each agent sees

| Agent | Workspace | Material |
|---|---|---|
| agent1 | `/work` = `_CHANGES` only | code before / after / diff of the commit, no repository |
| agent2 | `/work` = repository, `/changes` = the same material | both |
| agent3 | `/work` = repository only | no diff, no hint (zero-day setting) |

The repository is always checked out at the **parent** of the fix commit (the
still-vulnerable version) and mounted **read-only with `.git` removed**, so the
history — which contains the fix — cannot be read.

## Isolation

- One **throwaway container per agent** (`docker run --rm`): no state survives
  between runs, so no agent can inherit anything from another.
- **Network**: the container sits on a Docker `--internal` network with no route
  to the internet and reaches the model API only through an allowlist proxy
  (`llm.polito.it`). Even with `bash` available, the agent cannot look the
  vulnerability up online.
- The answer key (`ground_truth.csv`, and the CVE/CWE tables of the database) is
  never mounted, never passed, and never mentioned in a prompt.
- Container timeout: 1800 s.

## Sample

50 commits, one per repository, from `ground_truth.csv` — the repositories whose
size is closest to the dataset mean, each with its most recent qualifying fix
commit. Every commit has a known CVE and CWE, used only to score the answers
afterwards.

---

## Known limitations of this configuration

**Context exhaustion on agent3.** With delegation forbidden, the agent reads
every file itself, and on large repositories the accumulated context passes the
model's 131,072-token limit (`ContextWindowExceededError`). OpenCode's own
compaction step fires but is not sufficient, since compacting itself requires a
call carrying the oversized context. In the affected runs the agent often still
states a conclusion, but in free form rather than in the required block.

This is a direct consequence of forbidding sub-agents: delegation was how the
model kept its context small, by having a separate agent read the files and
return only a summary. It affects agent3 far more than the others, which read a
bounded amount of material.

**Answers outside the required format.** The model frequently writes its verdict
as prose, a markdown heading or a JSON block instead of the requested lines.
Those runs are logged as errors, but the full text is preserved in `log.jsonl`,
so the verdict can be recovered afterwards without re-running anything.

## Files

| File | Content |
|---|---|
| `log.jsonl` | one line per agent run: status, full answer, model, timestamp |
| `results.jsonl` | one line per commit, the three agents grouped |
| `<repo>/<commit>/<agent>/` | `answer.txt`, `opencode.log`, `exit_code.txt`, `opencode-data/` (full transcript), `PROMPT.txt` |
