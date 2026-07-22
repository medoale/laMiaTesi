"""Orchestrator: runs the three agents on every selected row of the CSV.

For each (repo, commit) row of repo_analysis_v2.csv:
  agent1 — gets the before/after/diff of the commit (from CVEfixes.db);
  agent2 — gets before/after/diff AND a temporary clone of the repository,
           checked out at the parent commit (pre-fix), to navigate;
  agent3 — gets ONLY the clone, no code sections at all.

Each agent call is completely independent: no conversation, file or variable
is shared between agents or between rows — memory ends with each call.

The repository is cloned ONCE per row, used by agents 2 and 3, then deleted.
Answers are appended to agent_responses.jsonl (one JSON line per agent call);
on restart, calls already answered with status 'ok' are skipped.
"""
import csv
import json
import re
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from configparser import ConfigParser
from datetime import datetime, timezone
from pathlib import Path

import agent1
import agent2
import agent3
from common import CVEFIXES_INI_CANDIDATES, MODEL, parse_verdict, read_api_key

# ---------------------------------------------------------------------------
# Paths. This folder lives in laMiaTesi/agentAnalysis/, the data lives in the
# cveFixes tree: both are resolved relative to this file, so the layout works
# unchanged on any machine that has the same repository structure.
# ---------------------------------------------------------------------------
DATA_DIR = Path(__file__).resolve().parent.parent / 'cveFixes' / 'CVEfixes' / 'Code' / 'Data'
DB = DATA_DIR / 'CVEfixes.db'
CSV_PATH = DATA_DIR / 'repo_analysis_v2.csv'

# All outputs of one model go in their own folder outputs/<model>/, so
# switching MODEL starts a fresh set of output files automatically instead
# of silently mixing runs from different models under one "already done" log
# (load_already_done only checks repo/commit/agent, not model). MODEL_SLUG is
# a filesystem-safe version of MODEL (e.g. 'openai/gpt-oss-20b:free' ->
# 'openai_gpt-oss-20b_free').
MODEL_SLUG = re.sub(r'[^A-Za-z0-9._-]+', '_', MODEL)
OUTPUT_DIR = Path(__file__).resolve().parent / 'outputs' / MODEL_SLUG
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Raw log: one JSON line per single agent call, appended as soon as the call
# ends. This is what makes fine-grained resume possible.
OUT_JSONL = OUTPUT_DIR / 'agent_responses.jsonl'

# Consumable output: one JSON line per (repo, version) with the repo name and
# version FIRST, then the three agent results together. Rebuilt from the raw
# log at the end of every run.
RESULTS_JSONL = OUTPUT_DIR / 'results.jsonl'

# Maximum seconds for cloning one repository before marking it as failed.
CLONE_TIMEOUT = 1800

# Courtesy pause between agent calls, to be gentle with API rate limits.
SLEEP_BETWEEN_CALLS = 1


# How many repositories the sample keeps (see filter_rows).
SAMPLE_SIZE = 30


def filter_rows(rows):
    """Sample selection: the SAMPLE_SIZE repositories whose size (total_lines,
    at the pre-fix parent commit) is closest to the mean repo size in the
    whole dataset — the same computation as repo_size in
    cveFixes/CVEfixes/Code/Data/cvefixes_analysis.ipynb (section "Repository
    size at fix time"):

      1) collapse each repo's snapshots to their MEDIAN total_lines (a repo
         with several qualifying commits must not weigh more than one with a
         single commit — matches the notebook's per-repo aggregation);
      2) take the mean of those medians across all repos;
      3) rank repos by |median - mean| and keep the closest SAMPLE_SIZE.

    Only the MOST RECENT commit of each selected repo is kept (see
    most_recent_commit_per_repo) — one agent run per repo, to keep a first
    test run small rather than one run per qualifying commit.
    """
    by_repo: dict[str, list[float]] = {}
    for r in rows:
        by_repo.setdefault(r['repo_url'], []).append(r['total_lines'])

    medians = {repo: statistics.median(sizes) for repo, sizes in by_repo.items()}
    mean_of_medians = statistics.mean(medians.values())

    closest_repos = sorted(medians, key=lambda repo: abs(medians[repo] - mean_of_medians))
    selected_repos = set(closest_repos[:SAMPLE_SIZE])

    selected_rows = [r for r in rows if r['repo_url'] in selected_repos]
    return most_recent_commit_per_repo(selected_rows)


def most_recent_commit_per_repo(rows):
    """Keep only the row with the latest commit (by committer_date, from
    CVEfixes.db's commits table — repo_analysis_v2.csv itself carries no
    date) for each repo_url."""
    conn = sqlite3.connect(str(DB))
    try:
        dates = {}
        for r in rows:
            found = conn.execute(
                'SELECT committer_date FROM commits WHERE hash = ?', (r['commit'],)
            ).fetchone()
            dates[r['commit']] = found[0] if found else ''
    finally:
        conn.close()

    best_per_repo = {}
    for r in rows:
        current_best = best_per_repo.get(r['repo_url'])
        if current_best is None or dates[r['commit']] > dates[current_best['commit']]:
            best_per_repo[r['repo_url']] = r
    return list(best_per_repo.values())


def load_csv_rows():
    """Rows of the CSV that were measured successfully. The parent hash is
    kept because agents 2 and 3 need the pre-fix checkout; total_lines is
    kept for filter_rows' size-based sampling (not used past that point)."""
    with open(CSV_PATH, newline='') as f:
        return [{'repo_url': r['repo_url'],
                 'commit': r['commit'],
                 'parent': r['parent'],
                 'total_lines': float(r['total_lines'])}
                for r in csv.DictReader(f) if r['status'] == 'ok']


def fetch_file_changes(conn, commit_hash):
    """(code_before, code_after, diff) of every file touched by the commit,
    keeping only files where all three are present."""
    return conn.execute("""
        SELECT code_before, code_after, diff
        FROM file_change
        WHERE hash = ?
          AND code_before IS NOT NULL AND code_before != ''
          AND code_after  IS NOT NULL AND code_after  != ''
          AND diff        IS NOT NULL AND diff        != ''
    """, (commit_hash,)).fetchall()


def read_github_token():
    """[GitHub] token from the same ini, used only to authenticate clones
    (private/rate-limited repos). None -> anonymous clones."""
    config = ConfigParser()
    if config.read(CVEFIXES_INI_CANDIDATES):
        token = config.get('GitHub', 'token', fallback=None)
        if token and token != 'None':
            return token
    return None


def url_with_token(repo_url, token):
    """Inject the token into the clone URL, only for repos on github.com."""
    if token and repo_url.startswith('https://github.com/'):
        return repo_url.replace('https://', f'https://x-access-token:{token}@', 1)
    return repo_url


def git(*args, cwd, timeout=300):
    """Run one git command silently; raises CalledProcessError on failure.
    GIT_TERMINAL_PROMPT=0 prevents git from hanging on a credential prompt."""
    import os
    subprocess.run(
        ['git', *args], cwd=cwd, check=True, timeout=timeout,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},
    )


def clone_at_parent(repo_url, parent, token):
    """Full clone of the repo in a temp dir, checked out at the parent
    commit (the pre-fix snapshot). Returns the Path of the clone.
    The caller is responsible for deleting it."""
    tmp = Path(tempfile.mkdtemp(prefix='agent_repo_'))
    try:
        git('clone', '-q', url_with_token(repo_url, token), str(tmp),
            cwd='/', timeout=CLONE_TIMEOUT)
        git('checkout', '-q', '--force', parent, cwd=str(tmp))
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)   # never leave clones behind
        raise
    return tmp


def load_already_done():
    """(repo_url, commit, agent) triples already answered successfully.
    Errors are NOT included, so they are retried on the next run."""
    done = set()
    if OUT_JSONL.exists():
        with open(OUT_JSONL) as f:
            for line in f:
                rec = json.loads(line)
                if rec['status'] == 'ok':
                    done.add((rec['repo_url'], rec['commit'], rec['agent']))
    return done


def repo_name_from_url(repo_url):
    """Clean 'owner/repo' name: scheme, host and trailing .git removed.
    E.g. 'https://github.com/1Panel-dev/MaxKB.git' -> '1Panel-dev/MaxKB'."""
    from urllib.parse import urlparse
    name = urlparse(repo_url).path.strip('/')
    return name[:-4] if name.endswith('.git') else name


def build_grouped_results():
    """Rebuild RESULTS_JSONL from the raw log: one line per (repo, commit),
    with the repo name and version first, then the three agent results.

    The raw log may contain several lines for the same (repo, commit, agent)
    — e.g. an error later retried successfully. Reading the log in order and
    overwriting means THE LAST RECORD WINS, which is the most recent outcome.
    Agents not yet run for a row appear as null, so every line always has
    the same shape."""
    if not OUT_JSONL.exists():
        return
    grouped = {}   # (repo_url, commit) -> {agent: {...}}, insertion-ordered
    parents = {}
    with open(OUT_JSONL) as f:
        for line in f:
            rec = json.loads(line)
            key = (rec['repo_url'], rec['commit'])
            grouped.setdefault(key, {})[rec['agent']] = {
                'status': rec['status'],
                'response': rec['response'],
            }
            parents[key] = rec.get('parent')

    with open(RESULTS_JSONL, 'w') as out:
        for (repo_url, commit), agents in grouped.items():
            entry = {
                # Reference first: which repo and which version.
                'repo_name': repo_name_from_url(repo_url),
                'repo_url': repo_url,
                'commit': commit,            # the fix commit
                'parent': parents[(repo_url, commit)],   # version cloned for agents 2/3
                # Then the three results, always all present.
                'agent1': agents.get('agent1'),
                'agent2': agents.get('agent2'),
                'agent3': agents.get('agent3'),
            }
            out.write(json.dumps(entry, ensure_ascii=False) + '\n')
    print(f'Grouped results written to {RESULTS_JSONL} ({len(grouped)} entries)')


def main():
    api_key = read_api_key()
    if not api_key:
        print(f'ERROR: no [OpenRouter] api_key found in any of {CVEFIXES_INI_CANDIDATES}')
        sys.exit(1)
    if not DB.exists():
        print(f'ERROR: database not found at {DB}')
        sys.exit(1)

    token = read_github_token()
    rows = filter_rows(load_csv_rows())
    already_done = load_already_done()
    agent_names = ['agent1', 'agent2', 'agent3']
    total = len(rows) * len(agent_names)
    print(f'CSV rows selected: {len(rows)} -> {total} agent calls, '
          f'already done: {len(already_done)}')

    conn = sqlite3.connect(str(DB))
    done = 0
    with open(OUT_JSONL, 'a') as out:

        def write(record):
            """Append one JSON line and flush, so progress survives a crash."""
            out.write(json.dumps(record, ensure_ascii=False) + '\n')
            out.flush()
            print(f'[{done}/{total}] {record["repo_url"]} '
                  f'@{record["commit"][:9]} {record["agent"]}: {record["status"]}')

        for row in rows:
            repo_url, commit, parent = row['repo_url'], row['commit'], row['parent']
            todo = [a for a in agent_names
                    if (repo_url, commit, a) not in already_done]
            if not todo:
                done += len(agent_names)
                continue

            def base_record(agent_name):
                """Common fields of every JSONL line."""
                return {'repo_url': repo_url, 'commit': commit,
                        'parent': parent, 'agent': agent_name, 'model': MODEL,
                        'created_at': datetime.now(timezone.utc).isoformat()}

            # --- Gather the inputs needed by the pending agents ------------
            # before/after/diff: needed by agent1 and agent2.
            changes = None
            if 'agent1' in todo or 'agent2' in todo:
                changes = fetch_file_changes(conn, commit)

            # Clone at the parent commit: needed by agent2 and agent3.
            # One clone per row, shared by both, deleted at the end.
            repo_dir = None
            clone_error = None
            if 'agent2' in todo or 'agent3' in todo:
                try:
                    repo_dir = clone_at_parent(repo_url, parent, token)
                except (subprocess.CalledProcessError,
                        subprocess.TimeoutExpired, OSError) as e:
                    clone_error = f'clone error: {type(e).__name__}'

            # --- Run each pending agent, independently of the others -------
            try:
                for agent_name in todo:
                    done += 1
                    record = base_record(agent_name)

                    # Decide whether this agent can run at all.
                    if agent_name in ('agent1', 'agent2') and not changes:
                        record.update(status='skipped: no file changes',
                                      response=None)
                        write(record)
                        continue
                    if agent_name in ('agent2', 'agent3') and repo_dir is None:
                        record.update(status=clone_error or 'clone error',
                                      response=None)
                        write(record)
                        continue

                    # Dispatch. Each run() builds its own fresh conversation:
                    # nothing is carried over between these calls.
                    try:
                        if agent_name == 'agent1':
                            response = agent1.run(api_key, changes)
                        elif agent_name == 'agent2':
                            response = agent2.run(api_key, changes, repo_dir)
                        else:
                            response = agent3.run(api_key, repo_dir)
                        # A response with no parseable verdict (empty, or the
                        # model ignored the format) must NOT be stored as 'ok'
                        # — 'ok' is never retried, so it would be a permanent
                        # gap. Recorded as an error instead, to be retried on
                        # the next run; the raw text is kept for inspection.
                        found, _, _ = parse_verdict(response)
                        if found is None:
                            record.update(status='error: no valid verdict in response',
                                          response=response)
                        else:
                            record.update(status='ok', response=response)
                    except Exception as e:
                        # Broad on purpose: one malformed API response must
                        # fail only this call, never crash an unattended run.
                        record.update(status=f'error: {type(e).__name__}: {e}',
                                      response=None)

                    write(record)
                    time.sleep(SLEEP_BETWEEN_CALLS)
            finally:
                # The clone is temporary by contract: always delete it, even
                # on Ctrl-C or unexpected errors.
                if repo_dir is not None:
                    shutil.rmtree(repo_dir, ignore_errors=True)

    conn.close()

    # Regenerate the grouped, consumable output from the raw log.
    build_grouped_results()
    print(f'\nDone. Raw log in {OUT_JSONL}')


if __name__ == '__main__':
    main()
