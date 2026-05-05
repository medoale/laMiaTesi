import sqlite3
from datetime import datetime, timezone


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS tracked_repos (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name       TEXT NOT NULL,
            url             TEXT NOT NULL,
            selected_date   TEXT NOT NULL,
            task            TEXT NOT NULL,
            score           REAL,
            reason          TEXT,
            UNIQUE (full_name, selected_date, task)
        );

        CREATE INDEX IF NOT EXISTS idx_tracked_repos_full_name ON tracked_repos(full_name);
        CREATE INDEX IF NOT EXISTS idx_tracked_repos_task      ON tracked_repos(task);

        CREATE TABLE IF NOT EXISTS cve_matches (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_full_name      TEXT NOT NULL,
            cve_id              TEXT NOT NULL,
            cve_published_date  TEXT,
            first_selected_date TEXT,
            days_until_cve      INTEGER,
            matched_at          TEXT NOT NULL,
            UNIQUE (repo_full_name, cve_id)
        );

        CREATE TABLE IF NOT EXISTS last_check (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    conn.commit()


def insert_tracked_repos(conn: sqlite3.Connection, repos: list[dict], task: str) -> int:
    today = datetime.now(timezone.utc).date().isoformat()
    rows = [
        (
            r['full_name'],
            r.get('url') or f"https://github.com/{r['full_name']}",
            today,
            task,
            r.get('score'),
            r.get('reason', ''),
        )
        for r in repos
    ]
    cursor = conn.executemany("""
        INSERT OR IGNORE INTO tracked_repos
            (full_name, url, selected_date, task, score, reason)
        VALUES (?, ?, ?, ?, ?, ?)
    """, rows)
    conn.commit()
    return cursor.rowcount


def insert_cve_matches(conn: sqlite3.Connection, matches: list[dict]) -> int:
    now = datetime.now(timezone.utc).isoformat()
    rows = [
        (
            m['repo_full_name'],
            m['cve_id'],
            m.get('cve_published_date'),
            m.get('first_selected_date'),
            m.get('days_until_cve'),
            now,
        )
        for m in matches
    ]
    cursor = conn.executemany("""
        INSERT OR IGNORE INTO cve_matches
            (repo_full_name, cve_id, cve_published_date, first_selected_date, days_until_cve, matched_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, rows)
    conn.commit()
    return cursor.rowcount


def get_last_check(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute('SELECT value FROM last_check WHERE key = ?', (key,)).fetchone()
    return row[0] if row else None


def set_last_check(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("""
        INSERT INTO last_check (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
    """, (key, value))
    conn.commit()


def get_tracked_repo_first_selection(conn: sqlite3.Connection) -> dict[str, str]:
    """Return mapping {full_name: earliest_selected_date} across all tasks."""
    rows = conn.execute("""
        SELECT full_name, MIN(selected_date)
        FROM tracked_repos
        GROUP BY full_name
    """).fetchall()
    return {full_name: date for full_name, date in rows}
