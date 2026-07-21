"""Ground-truth reference for the sampled commits, used to check the agents'
answers against the real vulnerability each commit fixed.

Uses the SAME selection as main.py (filter_rows/load_csv_rows are imported,
not reimplemented) so this file always matches exactly the commits the agents
were actually run on.

For each selected (repo_url, commit), looks up in CVEfixes.db:
  - every CVE the commit fixes (a commit can fix more than one CVE);
  - for each CVE, its CWE classification(s) (a CVE can carry more than one).

Output: ground_truth.csv, one row per (repo_url, commit, cve_id) — not
collapsed further, so each vulnerability the commit addresses is its own row,
straightforward to check one at a time against an agent's answer.
"""
import csv
import sqlite3

from main import DB, filter_rows, load_csv_rows, repo_name_from_url

OUT_CSV = 'ground_truth.csv'


def fetch_cves(conn, commit_hash):
    """Every CVE this commit fixes, per the CVEfixes 'fixes' table."""
    rows = conn.execute(
        'SELECT DISTINCT cve_id FROM fixes WHERE hash = ?', (commit_hash,)
    ).fetchall()
    return [r[0] for r in rows]


def fetch_cwes(conn, cve_id):
    """(cwe_id, cwe_name) pairs for one CVE, sorted by id — a CVE can carry
    more than one CWE classification."""
    return conn.execute("""
        SELECT cc.cwe_id, cw.cwe_name
        FROM cwe_classification cc
        LEFT JOIN cwe cw ON cw.cwe_id = cc.cwe_id
        WHERE cc.cve_id = ?
        ORDER BY cc.cwe_id
    """, (cve_id,)).fetchall()


def main():
    rows = filter_rows(load_csv_rows())
    repos = {r['repo_url'] for r in rows}
    print(f'Selected sample: {len(rows)} commits across {len(repos)} repositories')

    conn = sqlite3.connect(str(DB))
    out_rows = []
    for row in rows:
        cve_ids = fetch_cves(conn, row['commit'])
        if not cve_ids:
            # Shouldn't happen (rows come from repo_analysis_v2.csv, itself
            # derived from `fixes`), but never silently drop a sampled commit.
            out_rows.append({
                'repo_name': repo_name_from_url(row['repo_url']),
                'repo_url': row['repo_url'],
                'commit': row['commit'],
                'cve_id': None,
                'cwe_ids': None,
                'cwe_names': None,
            })
            continue
        for cve_id in cve_ids:
            cwes = fetch_cwes(conn, cve_id)
            out_rows.append({
                'repo_name': repo_name_from_url(row['repo_url']),
                'repo_url': row['repo_url'],
                'commit': row['commit'],
                'cve_id': cve_id,
                'cwe_ids': ', '.join(c[0] for c in cwes) or None,
                'cwe_names': ', '.join(c[1] for c in cwes if c[1]) or None,
            })
    conn.close()

    with open(OUT_CSV, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=[
            'repo_name', 'repo_url', 'commit', 'cve_id', 'cwe_ids', 'cwe_names',
        ])
        w.writeheader()
        w.writerows(out_rows)

    print(f'{len(out_rows)} rows written to {OUT_CSV} '
         f'({sum(1 for r in out_rows if r["cve_id"] is None)} commits with no CVE found)')


if __name__ == '__main__':
    main()
