import sqlite3
from datetime import datetime, timezone


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS repos (
            full_name   TEXT PRIMARY KEY,
            owner       TEXT NOT NULL,
            name        TEXT NOT NULL,
            stars       INTEGER,
            language    TEXT,
            description TEXT,
            url         TEXT,
            vendor      TEXT,
            fetched_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS commit_activity (
            repo_full_name  TEXT NOT NULL,
            week_ts         INTEGER NOT NULL,
            week_date       TEXT NOT NULL,
            commit_count    INTEGER NOT NULL,
            PRIMARY KEY (repo_full_name, week_ts)
        );

        CREATE TABLE IF NOT EXISTS spike_analysis (
            repo_full_name      TEXT NOT NULL,
            analysis_date       TEXT NOT NULL,
            recent_2w_commits INTEGER,
            baseline_avg        REAL,
            baseline_std        REAL,
            spike_score         REAL,
            PRIMARY KEY (repo_full_name, analysis_date)
        );

        CREATE TABLE IF NOT EXISTS recent_commits (
            repo_full_name  TEXT NOT NULL,
            sha             TEXT NOT NULL,
            author          TEXT,
            committed_date  TEXT,
            message         TEXT,
            PRIMARY KEY (repo_full_name, sha)
        );
    """)
    conn.commit()


def upsert_repo(conn: sqlite3.Connection, repo: dict, vendor: str) -> None:
    conn.execute("""
        INSERT INTO repos (full_name, owner, name, stars, language, description, url, vendor, fetched_at)
        VALUES (:full_name, :owner, :name, :stars, :language, :description, :url, :vendor, :fetched_at)
        ON CONFLICT(full_name) DO UPDATE SET
            stars=excluded.stars,
            fetched_at=excluded.fetched_at
    """, {
        'full_name':   repo['full_name'],
        'owner':       repo['owner']['login'],
        'name':        repo['name'],
        'stars':       repo.get('stargazers_count', 0),
        'language':    repo.get('language'),
        'description': repo.get('description'),
        'url':         repo.get('html_url'),
        'vendor':      vendor,
        'fetched_at':  datetime.now(timezone.utc).isoformat(),
    })


def insert_commit_activity(conn: sqlite3.Connection, full_name: str, weeks: list) -> None:
    rows = [
        (
            full_name,
            w['week'],
            datetime.fromtimestamp(w['week'], tz=timezone.utc).strftime('%Y-%m-%d'),
            w['total'],
        )
        for w in weeks
    ]
    conn.executemany("""
        INSERT OR REPLACE INTO commit_activity (repo_full_name, week_ts, week_date, commit_count)
        VALUES (?, ?, ?, ?)
    """, rows)


def insert_spike(conn: sqlite3.Connection, full_name: str,
                 recent: int, avg: float, std: float, score: float) -> None:
    conn.execute("""
        INSERT OR REPLACE INTO spike_analysis
            (repo_full_name, analysis_date, recent_2w_commits, baseline_avg, baseline_std, spike_score)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (full_name, datetime.now(timezone.utc).date().isoformat(), recent, avg, std, score))


def insert_recent_commits(conn: sqlite3.Connection, full_name: str, commits: list[dict]) -> None:
    rows = []
    for c in commits:
        sha = c.get('sha', '')
        committed_date = ''
        author_name = ''
        try:
            committed_date = c['commit']['committer']['date']
            author_name = c['commit']['author']['name']
        except (KeyError, TypeError):
            pass
        message = (c.get('commit') or {}).get('message', '')
        subject = message.split('\n', 1)[0].strip()
        rows.append((full_name, sha, author_name, committed_date, subject))

    conn.executemany("""
        INSERT OR IGNORE INTO recent_commits (repo_full_name, sha, author, committed_date, message)
        VALUES (?, ?, ?, ?, ?)
    """, rows)
