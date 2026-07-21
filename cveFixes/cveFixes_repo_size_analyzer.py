"""Analyze the CVEfixes database repositories with CVEs published in 2026.

A single query selects all "complete" commits (non-merge and with a parent,
hence with before/after/diff recoverable from git) linked to a CVE published
in 2026. For each repository the script makes a temporary full clone and, for
each of its qualifying commits, checks out the parent (pre-fix) version and
counts all files and their lines. The clone is deleted as soon as it is done.

The GitHub token is read from CVEfixes.ini (same paths as the tool).

Output: repo_analysis_v2.csv, one row per (repo_url, commit) pair with number of
files, total lines, average lines per file and the size on disk of the whole
clone. If the execution is interrupted, the next run skips the pairs already
present in the CSV.
"""
import ast
import csv
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from configparser import ConfigParser
from pathlib import Path

# Path relative to this script — assumes the script sits next to CVEfixes.db
# (e.g. .../cveFixes/CVEfixes/Code/Data/), works on any machine.
DB = Path(__file__).resolve().parent / 'CVEfixes.db'
OUT_CSV = Path(__file__).resolve().parent / 'repo_analysis_v2.csv'

# Publication year of the CVEs to consider.
CVE_YEAR = '2026'

# Maximum seconds for cloning a repository before marking it as failed.
CLONE_TIMEOUT = 1800

# Candidate paths of the CVEfixes.ini file holding the [GitHub] token, tried
# in order so the same code runs unmodified on the local machine or the
# cluster; ConfigParser.read() silently skips any path that doesn't exist.
CVEFIXES_INI_CANDIDATES = [
    '/home/medo/.CVEfixes.ini',
    '/home/students/s346086/AlessandroMedvescek/CVEfixes.ini',
]


def read_github_token():
    """Read [GitHub] token from CVEFIXES_INI_CANDIDATES. Returns None if absent."""
    config = ConfigParser()
    if config.read(CVEFIXES_INI_CANDIDATES):
        token = config.get('GitHub', 'token', fallback=None)
        if token and token != 'None':
            return token
    return None


def commits_to_analyze():
    """Return {repo_url: [(hash, parent_hash), ...]} with all qualifying
    commits: non-merge, with a parent, linked to CVEs published in CVE_YEAR."""
    if not DB.exists():
        print(f'ERROR: database not found at {DB}')
        sys.exit(1)
    c = sqlite3.connect(str(DB))
    rows = c.execute("""
        SELECT DISTINCT co.repo_url, co.hash, co.parents
        FROM commits co
        JOIN fixes f  ON f.hash    = co.hash
        JOIN cve   cv ON cv.cve_id = f.cve_id
        WHERE cv.published_date LIKE ? || '%'
          AND co.merge = 'False'
          AND co.parents IS NOT NULL AND co.parents != '' AND co.parents != '[]'
        ORDER BY co.repo_url, co.committer_date
    """, (CVE_YEAR,)).fetchall()
    c.close()

    per_repo = {}
    for repo_url, hash_, parents_s in rows:
        try:
            parent = ast.literal_eval(parents_s)[0]
        except (ValueError, SyntaxError, IndexError):
            continue
        per_repo.setdefault(repo_url, []).append((hash_, parent))
    return per_repo


def url_with_token(repo_url, token):
    """Inject the token into the URL, only for repos on github.com."""
    if token and repo_url.startswith('https://github.com/'):
        return repo_url.replace('https://', f'https://x-access-token:{token}@', 1)
    return repo_url


def git(*args, cwd, timeout=300):
    subprocess.run(
        ['git', *args], cwd=cwd, check=True, timeout=timeout,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},  # never prompt for credentials
    )


def count_files_and_lines(root):
    """Count every file in the directory (excluding .git) and their lines.
    Returns (number of files, total lines)."""
    n_files = 0
    total_lines = 0
    for p in root.rglob('*'):
        if '.git' in p.parts or p.is_symlink() or not p.is_file():
            continue
        n_files += 1
        with open(p, 'rb') as f:
            total_lines += sum(1 for _ in f)
    return n_files, total_lines


def clone_size_mb(root):
    """Size on disk of the whole clone, in MB, .git history included.

    Unlike the file and line counts, this is dominated by .git, which depends on
    the repository's entire history rather than on the commit checked out: two
    snapshots of the same repo differ only by their working tree."""
    total_bytes = 0
    for p in root.rglob('*'):
        if p.is_symlink() or not p.is_file():
            continue
        total_bytes += p.stat().st_size
    return round(total_bytes / (1024 * 1024), 2)


def main():
    token = read_github_token()
    print('GitHub token:', 'found' if token else 'NOT found (anonymous clones)')

    per_repo = commits_to_analyze()
    n_commits = sum(len(v) for v in per_repo.values())
    print(f'Qualifying repos (CVEs published in {CVE_YEAR}): {len(per_repo)}, '
          f'commits to analyze: {n_commits}')

    # Resume: skip the (repo, commit) pairs already analyzed in previous runs.
    already_done = set()
    if OUT_CSV.exists():
        with open(OUT_CSV, newline='') as f:
            already_done = {(r['repo_url'], r['commit']) for r in csv.DictReader(f)}
        print(f'Already analyzed (skipped): {len(already_done)}')

    is_new = not OUT_CSV.exists()
    done = 0
    with open(OUT_CSV, 'a', newline='') as f_out:
        w = csv.writer(f_out)
        if is_new:
            w.writerow(['repo_url', 'commit', 'parent', 'n_files', 'total_lines',
                        'avg_lines_per_file', 'clone_size_mb', 'status'])

        for repo_url, commits in per_repo.items():
            todo = [(h, p) for h, p in commits
                    if (repo_url, h) not in already_done]
            if not todo:
                done += len(commits)
                continue

            # A single clone per repo, then one checkout per commit.
            tmp = tempfile.mkdtemp(prefix='cvefixes_repo_')
            try:
                try:
                    git('clone', '-q', url_with_token(repo_url, token), tmp,
                        cwd='/', timeout=CLONE_TIMEOUT)
                except (subprocess.CalledProcessError,
                        subprocess.TimeoutExpired, OSError) as e:
                    for hash_, parent in todo:
                        done += 1
                        w.writerow([repo_url, hash_, parent, '', '', '', '',
                                    f'clone error: {type(e).__name__}'])
                    print(f'[{done}/{n_commits}] {repo_url}: CLONE ERROR '
                          f'({type(e).__name__})')
                    continue

                for hash_, parent in todo:
                    done += 1
                    try:
                        git('checkout', '-q', '--force', parent, cwd=tmp)
                        n_files, lines = count_files_and_lines(Path(tmp))
                        avg = round(lines / n_files, 1) if n_files else 0
                        size_mb = clone_size_mb(Path(tmp))
                        w.writerow([repo_url, hash_, parent,
                                    n_files, lines, avg, size_mb, 'ok'])
                        print(f'[{done}/{n_commits}] {repo_url} @{parent[:9]}: '
                              f'{n_files} files, {lines} lines, {size_mb} MB')
                    except (subprocess.CalledProcessError,
                            subprocess.TimeoutExpired, OSError) as e:
                        w.writerow([repo_url, hash_, parent, '', '', '', '',
                                    f'checkout error: {type(e).__name__}'])
                        print(f'[{done}/{n_commits}] {repo_url} @{parent[:9]}: '
                              f'CHECKOUT ERROR ({type(e).__name__})')
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
                f_out.flush()

    print(f'\nDone. Results in {OUT_CSV}')


if __name__ == '__main__':
    main()
