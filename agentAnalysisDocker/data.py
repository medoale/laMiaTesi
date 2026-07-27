"""Host-side data preparation: the two things the agents need as input, both
built on this machine before any container starts.

  - fetch_changes: the code before/after/diff of a commit, from the database
    (agent 1 and 2).
  - clone_at_parent: a clone of the repository checked out at the commit's
    PARENT (the still-vulnerable version), with .git removed so the agent
    cannot read the history and discover the fix (agent 2 and 3).
"""
import ast
import shutil
import subprocess
import sqlite3
import tempfile
from pathlib import Path

import config


def fetch_changes(commit_hash):
    """(code_before, code_after, diff) for every file the commit touched, keeping
    only files where all three are present. Read-only DB access."""
    conn = sqlite3.connect(str(config.DB_PATH))
    try:
        return conn.execute("""
            SELECT code_before, code_after, diff
            FROM file_change
            WHERE hash = ?
              AND code_before IS NOT NULL AND code_before != ''
              AND code_after  IS NOT NULL AND code_after  != ''
              AND diff        IS NOT NULL AND diff        != ''
        """, (commit_hash,)).fetchall()
    finally:
        conn.close()


def parent_hash(commit_hash):
    """The commit's first parent, from the database `commits` table. None if
    unknown (a root commit, or the commit is missing).

    The `parents` column stores a stringified Python list, e.g.
    "['hash1', 'hash2']" (merge commits have several); we take the first."""
    conn = sqlite3.connect(str(config.DB_PATH))
    try:
        row = conn.execute('SELECT parents FROM commits WHERE hash = ?',
                           (commit_hash,)).fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return None
    try:
        parents = ast.literal_eval(row[0])
    except (ValueError, SyntaxError):
        return None
    return str(parents[0]) if parents else None


def _git(*args, cwd, timeout=300):
    """Run one git command silently; raise on failure. GIT_TERMINAL_PROMPT=0
    stops git from hanging on a credential prompt."""
    import os
    subprocess.run(['git', *args], cwd=cwd, check=True, timeout=timeout,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'})


def clone_at_parent(repo_url, parent):
    """Full clone in a temp dir, checked out at `parent`, with .git REMOVED so
    the mounted workspace is just the source tree (no history to leak the fix).
    Returns the Path; the caller must delete it when done."""
    tmp = Path(tempfile.mkdtemp(prefix='docker_repo_'))
    try:
        _git('clone', '-q', repo_url, str(tmp), cwd='/', timeout=config.CLONE_TIMEOUT)
        _git('checkout', '-q', '--force', parent, cwd=str(tmp))
        shutil.rmtree(tmp / '.git', ignore_errors=True)   # no history in the workspace
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)            # never leave clones behind
        raise
    return tmp
