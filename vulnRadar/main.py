import sys
import time
import sqlite3
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor

import config
from github_client import GitHubClient
from database import init_db, insert_tracked_repos
import task_official
import task_hot
import task_talkers
import cve_matcher


def _print_results(task_name: str, repos: list[dict], inserted: int) -> None:
    print(f'\n{"─"*78}')
    print(f'  {task_name.upper()}  —  {len(repos)} selected, {inserted} new in DB')
    print(f'{"─"*78}')
    for r in repos[:20]:
        score_s = f'{r.get("score", 0):.1f}' if r.get('score') is not None else 'n/a'
        print(f'  {r["full_name"]:<45} score={score_s}')
        if r.get('reason'):
            print(f'      └─ {r["reason"]}')
    if len(repos) > 20:
        print(f'  … and {len(repos) - 20} more')


PRINT_MATCHES_LIMIT = 30


def _print_all_matches(conn: sqlite3.Connection) -> None:
    total = conn.execute('SELECT COUNT(*) FROM cve_matches').fetchone()[0]
    rows = conn.execute("""
        SELECT cm.repo_full_name, cm.cve_id, cm.cve_published_date,
               cm.first_selected_date, cm.days_until_cve, cm.matched_at,
               GROUP_CONCAT(DISTINCT tr.task) as tasks
        FROM cve_matches cm
        LEFT JOIN tracked_repos tr ON tr.full_name = cm.repo_full_name
        GROUP BY cm.repo_full_name, cm.cve_id
        ORDER BY cm.cve_published_date DESC
        LIMIT ?
    """, (PRINT_MATCHES_LIMIT,)).fetchall()

    suffix = f'  (showing latest {PRINT_MATCHES_LIMIT})' if total > PRINT_MATCHES_LIMIT else ''
    print(f'\n{"─"*100}')
    print(f'  HISTORICAL CVE MATCHES  —  {total} total{suffix}')
    print(f'{"─"*100}')
    if not rows:
        print('  (no matches yet)')
        print(f'{"─"*100}\n')
        return
    print(f'  {"Repo":<35} {"CVE":<18} {"CVE pub date":<22} {"Selected":<12} {"Days":>5}  Task')
    print(f'{"─"*100}')
    for repo, cve_id, pub, sel, days, _matched, tasks in rows:
        days_s = f'{days:>5}' if days is not None else '  n/a'
        pub_s = (pub or '')[:19]
        print(f'  {repo:<35} {cve_id:<18} {pub_s:<22} {(sel or ""):<12} {days_s}  {tasks or ""}')
    print(f'{"─"*100}\n')


def run_pipeline(client: GitHubClient) -> None:
    """One full execution: three tasks in parallel, then CVE matching."""
    # Each iteration uses a fresh connection — long-lived sqlite handles can
    # accumulate locks or stale state across days.
    conn = sqlite3.connect(config.DATABASE)
    try:
        init_db(conn)

        with ThreadPoolExecutor(max_workers=3, thread_name_prefix='task') as pool:
            f_official = pool.submit(task_official.run, client)
            f_hot      = pool.submit(task_hot.run, client)
            f_talkers  = pool.submit(task_talkers.run, client)

            results = {
                'official': f_official.result(),
                'hot':      f_hot.result(),
                'talkers':  f_talkers.result(),
            }

        inserted_counts = {
            task: insert_tracked_repos(conn, repos, task)
            for task, repos in results.items()
        }
        for task, repos in results.items():
            _print_results(task, repos, inserted_counts[task])

        new_matches = cve_matcher.run(conn)
        print(f'\nCVE matcher: {new_matches} new matches recorded.')
        _print_all_matches(conn)
    finally:
        conn.close()


def _seconds_until_next_run(hour_utc: int) -> float:
    now = datetime.now(timezone.utc)
    target = now.replace(hour=hour_utc, minute=0, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds(), target


if __name__ == '__main__':
    config.read_config()
    config.logger.info(f'Database: {config.DATABASE}')
    config.logger.info(f'MAX_REPOS_PER_TASK = {config.MAX_REPOS_PER_TASK}')

    client = GitHubClient(token=config.TOKEN)

    if config.DAILY_RUN_HOUR_UTC is None:
        # one-shot mode
        run_pipeline(client)
        config.logger.info('Done.')
        sys.exit(0)

    # Daemon mode: run immediately, then loop forever waking up daily.
    config.logger.info(
        f'Daemon mode: pipeline will run now and then daily at '
        f'{config.DAILY_RUN_HOUR_UTC:02d}:00 UTC. Press Ctrl+C to stop.'
    )
    while True:
        run_started = datetime.now(timezone.utc)
        config.logger.info(f'═══ Pipeline run started at {run_started.isoformat()} ═══')
        try:
            run_pipeline(client)
        except KeyboardInterrupt:
            config.logger.info('Interrupted by user, exiting.')
            break
        except Exception:
            config.logger.exception('Pipeline run failed; continuing the daily schedule.')

        wait_s, next_run = _seconds_until_next_run(config.DAILY_RUN_HOUR_UTC)
        config.logger.info(
            f'═══ Next run at {next_run.isoformat()} '
            f'(in {wait_s/3600:.1f}h) ═══'
        )
        try:
            time.sleep(wait_s)
        except KeyboardInterrupt:
            config.logger.info('Interrupted by user during sleep, exiting.')
            break
