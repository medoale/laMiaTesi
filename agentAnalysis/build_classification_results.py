"""Classification-results CSV: for each sampled (repo, commit), each agent's
verdict (found a vulnerability? which CWE?) extracted from results.jsonl.

Uses parse_verdict (common.py) against each agent's raw response text, so all
three agents are parsed by the exact same rule regardless of how much
free-text reasoning precedes their VERDICT_FORMAT block.

Output: classification_results.csv, one row per (repo, commit), same key
shape as ground_truth.csv (repo_name, repo_url, commit) so the two can be
joined to check the agents' answers against the real vulnerability.
"""
import csv
import json

from common import parse_verdict
from main import MODEL_SLUG, RESULTS_JSONL

OUT_CSV = f'classification_results_{MODEL_SLUG}.csv'
AGENT_NAMES = ['agent1', 'agent2', 'agent3']


def verdict_fields(agent_result):
    """(found, cwe_id, cwe_name) for one agent's entry in results.jsonl.
    None entries — agent not yet run, or a non-'ok' status (skipped/error) —
    yield all-None rather than a misleading guess."""
    if not agent_result or agent_result.get('status') != 'ok':
        return None, None, None
    return parse_verdict(agent_result.get('response'))


def main():
    if not RESULTS_JSONL.exists():
        print(f'ERROR: {RESULTS_JSONL} not found — run main.py first')
        return

    out_rows = []
    with open(RESULTS_JSONL) as f:
        for line in f:
            rec = json.loads(line)
            row = {
                'repo_name': rec['repo_name'],
                'repo_url': rec['repo_url'],
                'commit': rec['commit'],
            }
            for agent in AGENT_NAMES:
                found, cwe_id, cwe_name = verdict_fields(rec.get(agent))
                row[f'{agent}_found'] = found
                row[f'{agent}_cwe_id'] = cwe_id
                row[f'{agent}_cwe_name'] = cwe_name
            out_rows.append(row)

    fieldnames = ['repo_name', 'repo_url', 'commit']
    for agent in AGENT_NAMES:
        fieldnames += [f'{agent}_found', f'{agent}_cwe_id', f'{agent}_cwe_name']

    with open(OUT_CSV, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(out_rows)

    print(f'{len(out_rows)} rows written to {OUT_CSV}')


if __name__ == '__main__':
    main()
