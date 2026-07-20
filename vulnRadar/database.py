import sqlite3
import logging
from datetime import datetime, timezone

logger = logging.getLogger('vulnRadar')

# Columns added after the initial schema. We migrate existing DBs in place
# so new fields (severity, CVSS, CWE…) appear without losing data.
_CVE_MATCHES_EXTRA_COLUMNS = [
    ('severity',             'TEXT'),
    ('cvss_score',           'REAL'),
    ('exploitability_score', 'REAL'),
    ('cwe_ids',              'TEXT'),
    # Which feed found this match: 'nvd' or 'osv'. The same (repo, cve_id)
    # pair is never inserted twice (UNIQUE constraint below) — whichever
    # source's matcher pass runs first wins; the other is silently ignored.
    ('source',               'TEXT'),
]

# Full selection timestamp. `selected_date` alone is not enough to tell a CVE
# published hours BEFORE the selection from one published after it, on the same
# day. Rows written before this migration keep it NULL.
_TRACKED_REPOS_EXTRA_COLUMNS = [
    ('selected_at', 'TEXT'),
]


def _ensure_columns(conn: sqlite3.Connection, table: str,
                    columns: list[tuple[str, str]]) -> None:
    """ALTER TABLE ADD COLUMN for any column not already present."""
    existing = {row[1] for row in conn.execute(f'PRAGMA table_info({table})')}
    for name, sql_type in columns:
        if name not in existing:
            conn.execute(f'ALTER TABLE {table} ADD COLUMN {name} {sql_type}')
            logger.info(f'Migrated DB: added column {table}.{name}')
    conn.commit()


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
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_full_name        TEXT NOT NULL,
            cve_id                TEXT NOT NULL,
            cve_published_date    TEXT,
            first_selected_date   TEXT,
            days_until_cve        INTEGER,
            matched_at            TEXT NOT NULL,
            severity              TEXT,
            cvss_score            REAL,
            exploitability_score  REAL,
            cwe_ids               TEXT,
            UNIQUE (repo_full_name, cve_id)
        );

        CREATE TABLE IF NOT EXISTS last_check (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    conn.commit()
    # Migrate older DBs that pre-date the new columns.
    _ensure_columns(conn, 'cve_matches', _CVE_MATCHES_EXTRA_COLUMNS)
    _ensure_columns(conn, 'tracked_repos', _TRACKED_REPOS_EXTRA_COLUMNS)


def insert_tracked_repos(conn: sqlite3.Connection, repos: list[dict], task: str) -> int:
    now = datetime.now(timezone.utc)
    today = now.date().isoformat()
    rows = [
        (
            r['full_name'],
            r.get('url') or f"https://github.com/{r['full_name']}",
            today,
            now.isoformat(),
            task,
            r.get('score'),
            r.get('reason', ''),
        )
        for r in repos
    ]
    cursor = conn.executemany("""
        INSERT OR IGNORE INTO tracked_repos
            (full_name, url, selected_date, selected_at, task, score, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?)
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
            m.get('severity'),
            m.get('cvss_score'),
            m.get('exploitability_score'),
            m.get('cwe_ids'),
            m.get('source'),
        )
        for m in matches
    ]
    cursor = conn.executemany("""
        INSERT OR IGNORE INTO cve_matches
            (repo_full_name, cve_id, cve_published_date, first_selected_date,
             days_until_cve, matched_at, severity, cvss_score,
             exploitability_score, cwe_ids, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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


def get_tracked_repo_first_selection(conn: sqlite3.Connection) -> dict[str, dict]:
    """Return the earliest selection of each repo across all tasks, as
    {full_name_lower: {'full_name', 'selected_date', 'selected_at'}}.

    Keyed on the lowercased name because GitHub URLs are case-insensitive:
    a CVE referencing github.com/imagemagick/imagemagick must still match the
    repo we tracked as ImageMagick/ImageMagick. `full_name` keeps the original
    casing, so matches are recorded under the canonical name.
    `selected_at` is NULL for rows written before that column existed."""
    rows = conn.execute("""
        SELECT full_name, selected_date, selected_at
        FROM (
            SELECT full_name, selected_date, selected_at,
                   ROW_NUMBER() OVER (
                       PARTITION BY lower(full_name)
                       ORDER BY selected_date, id
                   ) AS rn
            FROM tracked_repos
        )
        WHERE rn = 1
    """).fetchall()
    return {
        full_name.lower(): {
            'full_name':     full_name,
            'selected_date': selected_date,
            'selected_at':   selected_at,
        }
        for full_name, selected_date, selected_at in rows
    }
