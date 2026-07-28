"""(Re)generate ground_truth.csv, self-contained in this folder.

Reproduces the exact sample of the old agentAnalysis tool so this folder does
not depend on it:
  1. from repo_analysis_v2.csv, take the SAMPLE_SIZE repositories whose size
     (median total_lines across their snapshots) is closest to the dataset
     mean — the same computation as the cvefixes size analysis;
  2. keep only the MOST RECENT commit of each of those repos (by committer_date
     from the database), one commit per repo;
  3. for each selected (repo, commit), look up in the database every CVE it
     fixes and the CWE(s) of each CVE.

Output: ground_truth.csv (repo_name, repo_url, commit, cve_id, cwe_ids,
cwe_names). This is the ANSWER KEY — it is never shown to the agents; the
pipeline only reads its (repo, commit) keys.

Run:  python3 build_ground_truth.py
"""
import csv
import sqlite3
import statistics
from urllib.parse import urlparse

import config

# How many repositories the ground truth contains (one commit each). This is
# the knob for the ground-truth size — change it and re-run this script.
SAMPLE_SIZE = 10


def repo_name_from_url(repo_url):
    """'https://github.com/1Panel-dev/MaxKB.git' -> '1Panel-dev/MaxKB'."""
    name = urlparse(repo_url).path.strip('/')
    return name[:-4] if name.endswith('.git') else name


def load_csv_rows():
    """Measured rows of repo_analysis_v2.csv (status 'ok'). total_lines drives
    the size sampling; parent is unused here but kept for parity."""
    with open(config.REPO_ANALYSIS_CSV, newline='') as f:
        return [{'repo_url': r['repo_url'], 'commit': r['commit'],
                 'parent': r['parent'], 'total_lines': float(r['total_lines'])}
                for r in csv.DictReader(f) if r['status'] == 'ok']


def most_recent_commit_per_repo(rows, conn):
    """Keep, per repo, the row with the latest commit by committer_date."""
    dates = {}
    for r in rows:
        found = conn.execute('SELECT committer_date FROM commits WHERE hash = ?',
                             (r['commit'],)).fetchone()
        dates[r['commit']] = found[0] if found else ''
    best = {}
    for r in rows:
        cur = best.get(r['repo_url'])
        if cur is None or dates[r['commit']] > dates[cur['commit']]:
            best[r['repo_url']] = r
    return list(best.values())


def sample_rows(rows, conn):
    """The SAMPLE_SIZE repos closest to the mean size, one (latest) commit each."""
    by_repo = {}
    for r in rows:
        by_repo.setdefault(r['repo_url'], []).append(r['total_lines'])
    medians = {repo: statistics.median(sizes) for repo, sizes in by_repo.items()}
    mean_of_medians = statistics.mean(medians.values())
    closest = sorted(medians, key=lambda repo: abs(medians[repo] - mean_of_medians))
    selected = set(closest[:SAMPLE_SIZE])
    return most_recent_commit_per_repo([r for r in rows if r['repo_url'] in selected], conn)


def fetch_cves(conn, commit_hash):
    return [r[0] for r in conn.execute(
        'SELECT DISTINCT cve_id FROM fixes WHERE hash = ?', (commit_hash,)).fetchall()]


def fetch_cwes(conn, cve_id):
    return conn.execute("""
        SELECT cc.cwe_id, cw.cwe_name
        FROM cwe_classification cc
        LEFT JOIN cwe cw ON cw.cwe_id = cc.cwe_id
        WHERE cc.cve_id = ?
        ORDER BY cc.cwe_id
    """, (cve_id,)).fetchall()


def main():
    conn = sqlite3.connect(str(config.DB_PATH))
    rows = sample_rows(load_csv_rows(), conn)
    print(f'Sample: {len(rows)} commits across {len({r["repo_url"] for r in rows})} repos')

    out = []
    for row in rows:
        cve_ids = fetch_cves(conn, row['commit'])
        base = {'repo_name': repo_name_from_url(row['repo_url']),
                'repo_url': row['repo_url'], 'commit': row['commit']}
        if not cve_ids:
            out.append({**base, 'cve_id': None, 'cwe_ids': None, 'cwe_names': None})
            continue
        for cve_id in cve_ids:
            cwes = fetch_cwes(conn, cve_id)
            out.append({**base, 'cve_id': cve_id,
                        'cwe_ids': ', '.join(c[0] for c in cwes) or None,
                        'cwe_names': ', '.join(c[1] for c in cwes if c[1]) or None})
    conn.close()

    with open(config.GROUND_TRUTH_CSV, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['repo_name', 'repo_url', 'commit',
                                          'cve_id', 'cwe_ids', 'cwe_names'])
        w.writeheader()
        w.writerows(out)
    print(f'{len(out)} rows written to {config.GROUND_TRUTH_CSV}')


if __name__ == '__main__':
    main()
