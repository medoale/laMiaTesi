"""Orchestrator (host side).

For every sampled (repo, commit) in ground_truth.csv, runs the three agents,
each in its own throwaway OpenCode container:

  agent1 — sees ONLY the commit's code changes (a _CHANGES folder), no repo.
  agent2 — sees the repository (checked out before the fix) AND the _CHANGES.
  agent3 — sees ONLY the repository, no changes, no hint (zero-day style).

Everything except the agent itself happens here on this machine: reading the
ground truth, fetching the code changes from the database, cloning the repo at
the parent commit (with .git stripped), preparing each workspace, launching the
container, and collecting its answer + transcript. Nothing about the CWE answer
key is ever put in front of an agent.

Resumable: one JSON line per agent run is appended to log.jsonl; on restart,
(repo, commit, agent) triples already marked 'ok' are skipped.
"""
import csv
import json
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import config
import data
import network_rules
import sandbox
from prompts import PROMPTS
from verdict import parse_verdict

AGENTS = ['agent1', 'agent2', 'agent3']

OUT_DIR = config.OUTPUTS_DIR / config.model_slug()
# Raw log: one JSON line per single agent run (what makes resume possible).
LOG = OUT_DIR / 'log.jsonl'
# Consumable result: one JSON line per (repo, commit) with the three agents
# grouped together, rebuilt from the log at the end of every run. Same split
# per model as the log (both live under outputs/<model>/).
RESULTS = OUT_DIR / 'results.jsonl'


def load_ground_truth():
    """Unique (repo_name, repo_url, commit) from the ground truth, in order.
    The CWE columns are deliberately ignored — agents never see them."""
    seen, rows = set(), []
    with open(config.GROUND_TRUTH_CSV, newline='') as f:
        for r in csv.DictReader(f):
            key = (r['repo_url'], r['commit'])
            if key not in seen:
                seen.add(key)
                rows.append({'repo_name': r['repo_name'],
                             'repo_url': r['repo_url'], 'commit': r['commit']})
    return rows


def load_done():
    """(repo_url, commit, agent) triples already completed with status 'ok'."""
    done = set()
    if LOG.exists():
        with open(LOG) as f:
            for line in f:
                rec = json.loads(line)
                if rec['status'] == 'ok':
                    done.add((rec['repo_url'], rec['commit'], rec['agent']))
    return done


def write_changes(dest_dir, changes):
    """Write the commit's code changes as files the agent can read:
    dest_dir/file_01/{before,after,diff}.txt, one folder per changed file.
    Blind: files are only numbered, no real paths or names."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    for i, (before, after, diff) in enumerate(changes, 1):
        d = dest_dir / f'file_{i:02d}'
        d.mkdir()
        (d / 'before.txt').write_text(before)
        (d / 'after.txt').write_text(after)
        (d / 'diff.txt').write_text(diff)


def run_one(agent, output_dir, api_key, changes, repo_dir, workdir, net_args):
    """Prepare the workspace for one agent and run it. `workdir` is a scratch
    dir for this instance's mounts; `net_args` are the network-isolation
    `docker run` flags. Returns (status, response)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / 'PROMPT.txt').write_text(PROMPTS[agent])

    # Build the read-only mounts that make up /work for this agent.
    if agent == 'agent1':
        # Only the changes, under _CHANGES, no repository.
        ws = workdir / 'ws'
        write_changes(ws / '_CHANGES', changes)
        mounts = [(str(ws), '/work', 'ro')]
    elif agent == 'agent2':
        # The repo as /work, and the changes in a SEPARATE /changes (not nested
        # inside /work — Docker cannot create a mountpoint inside a read-only
        # bind mount, which failed with exit 125).
        chg = workdir / '_CHANGES'
        write_changes(chg, changes)
        mounts = [(str(repo_dir), '/work', 'ro'),
                  (str(chg), '/changes', 'ro')]
    else:  # agent3
        mounts = [(str(repo_dir), '/work', 'ro')]

    exit_code, docker_out = sandbox.run_agent(mounts, str(output_dir), api_key, net_args)
    # Keep docker's own output too, so a failure to even start the container
    # (e.g. a bad mount -> exit 125) is diagnosable, not just a bare code.
    (output_dir / 'docker.log').write_text(docker_out or '')

    answer_file = output_dir / 'answer.txt'
    response = answer_file.read_text() if answer_file.exists() else ''
    found, _, _ = parse_verdict(response)
    if exit_code == 0 and found is not None:
        return 'ok', response
    # No usable verdict (empty answer, refusal, crash): record as error so it is
    # retried on the next run, keeping the raw output for inspection.
    reason = 'no valid verdict' if exit_code == 0 else f'container exit {exit_code}'
    return f'error: {reason}', response


def build_grouped_results():
    """Rebuild results.jsonl from the raw log: one line per (repo, commit) with
    the three agents grouped together. The log may hold several lines for the
    same (repo, commit, agent) — e.g. an error later retried — so reading in
    order and overwriting means THE LAST RECORD WINS (the most recent outcome).
    Agents not yet run appear as null, so every line has the same shape."""
    if not LOG.exists():
        return
    grouped, names = {}, {}
    with open(LOG) as f:
        for line in f:
            rec = json.loads(line)
            key = (rec['repo_url'], rec['commit'])
            grouped.setdefault(key, {})[rec['agent']] = {
                'status': rec['status'], 'response': rec['response'],
                'output_dir': rec.get('output_dir'),
            }
            names[key] = rec['repo_name']
    with open(RESULTS, 'w') as out:
        for (repo_url, commit), agents in grouped.items():
            out.write(json.dumps({
                'repo_name': names[(repo_url, commit)],
                'repo_url': repo_url, 'commit': commit,
                'agent1': agents.get('agent1'),
                'agent2': agents.get('agent2'),
                'agent3': agents.get('agent3'),
            }, ensure_ascii=False) + '\n')
    print(f'Grouped results written to {RESULTS} ({len(grouped)} entries)')


def main():
    api_key = config.read_openrouter_key()
    if not api_key:
        sys.exit(f'ERROR: no [OpenRouter] api_key in {config.CVEFIXES_INI_CANDIDATES}')
    if not config.DB_PATH.exists():
        sys.exit(f'ERROR: database not found at {config.DB_PATH}')

    rows = load_ground_truth()
    done = load_done()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    total = len(rows) * len(AGENTS)
    print(f'{len(rows)} commits x {len(AGENTS)} agents = {total} runs '
          f'({len(done)} already done)')

    # Network isolation: bring up the egress proxy once (agents can then reach
    # only the model API), and always tear it down at the end.
    net_args = []
    if config.ISOLATE_NETWORK:
        network_rules.setup()
        net_args = network_rules.agent_docker_args()

    n = 0
    try:
        with open(LOG, 'a') as log:

            def record(repo, commit, agent, status, response, out_path):
                nonlocal n
                n += 1
                log.write(json.dumps({
                    'repo_name': repo['repo_name'], 'repo_url': repo['repo_url'],
                    'commit': commit, 'agent': agent, 'model': config.OPENCODE_MODEL,
                    'status': status, 'response': response,
                    'output_dir': str(out_path),
                    'created_at': datetime.now(timezone.utc).isoformat(),
                }, ensure_ascii=False) + '\n')
                log.flush()
                print(f'[{n}/{total}] {repo["repo_name"]} @{commit[:9]} {agent}: {status}')

            for repo in rows:
                commit = repo['commit']
                todo = [a for a in AGENTS if (repo['repo_url'], commit, a) not in done]
                if not todo:
                    n += len(AGENTS)
                    continue

                repo_slug = repo['repo_name'].replace('/', '__')
                base_out = OUT_DIR / repo_slug / commit[:12]

                # Inputs shared by the agents of this commit, prepared once.
                changes = data.fetch_changes(commit) if {'agent1', 'agent2'} & set(todo) else []
                repo_dir = None
                clone_error = None
                if {'agent2', 'agent3'} & set(todo):
                    parent = data.parent_hash(commit)
                    if not parent:
                        clone_error = 'no parent commit in database'
                    else:
                        try:
                            repo_dir = data.clone_at_parent(repo['repo_url'], parent)
                        except Exception as e:
                            clone_error = f'clone failed: {type(e).__name__}'

                try:
                    for agent in todo:
                        out_path = base_out / agent
                        # Guard: an agent cannot run without its required input.
                        if agent in ('agent1', 'agent2') and not changes:
                            record(repo, commit, agent, 'error: no code changes', '', out_path)
                            continue
                        if agent in ('agent2', 'agent3') and repo_dir is None:
                            record(repo, commit, agent, f'error: {clone_error}', '', out_path)
                            continue

                        workdir = Path(tempfile.mkdtemp(prefix='ws_'))
                        try:
                            status, response = run_one(agent, out_path, api_key,
                                                       changes, repo_dir, workdir, net_args)
                        finally:
                            shutil.rmtree(workdir, ignore_errors=True)
                        record(repo, commit, agent, status, response, out_path)
                finally:
                    if repo_dir is not None:
                        shutil.rmtree(repo_dir, ignore_errors=True)
    finally:
        if config.ISOLATE_NETWORK:
            network_rules.teardown()

    # Rebuild the grouped, consumable result from the raw log.
    build_grouped_results()
    print(f'\nDone. Log: {LOG}  |  Results: {RESULTS}')


if __name__ == '__main__':
    main()
