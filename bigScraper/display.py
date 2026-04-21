import sqlite3
from datetime import datetime, timezone


def print_top_spikes(conn: sqlite3.Connection, top_n: int = 20) -> None:
    today = datetime.now(timezone.utc).date().isoformat()
    rows = conn.execute("""
        SELECT s.repo_full_name, r.vendor, r.stars,
               s.recent_2w_commits, s.baseline_avg, s.spike_score
        FROM spike_analysis s
        JOIN repos r ON r.full_name = s.repo_full_name
        WHERE s.analysis_date = ?
          AND s.spike_score IS NOT NULL
        ORDER BY s.spike_score DESC
        LIMIT ?
    """, (today, top_n)).fetchall()

    w = 82
    print(f'\n{"─" * w}')
    print(f'  TOP {top_n} COMMIT SPIKES  —  {today}')
    print(f'{"─" * w}')
    print(f'  {"Repo":<37} {"Vendor":<14} {"Stars":>8}  {"Recent":>7}  {"Avg":>7}  {"Score":>7}')
    print(f'{"─" * w}')
    for full_name, vendor, stars, recent, avg, score in rows:
        stars_s = f'{stars:,}' if stars else 'n/a'
        print(f'  {full_name:<37} {(vendor or ""):<14} {stars_s:>8}  {recent:>7}  {avg:>7.1f}  {score:>7.2f}x')
    print(f'{"─" * w}\n')
