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


def run_pipeline(client: GitHubClient) -> None:
    """One full execution: three tasks in parallel, then CVE matching.
    Results are stored in the SQLite DB; logs report only summary numbers."""
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

        for task, repos in results.items():
            inserted = insert_tracked_repos(conn, repos, task)
            config.logger.info(
                f'Persisted task={task}: {len(repos)} selected, {inserted} new in DB'
            )

        new_matches = cve_matcher.run(conn)
        total_matches = conn.execute('SELECT COUNT(*) FROM cve_matches').fetchone()[0]
        config.logger.info(
            f'CVE matcher: {new_matches} new matches this run, {total_matches} total to date'
        )
    finally:
        conn.close()


def _next_run_time(hour_utc: int) -> tuple[float, datetime]:
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
        run_pipeline(client)
        config.logger.info('Done.')
        sys.exit(0)

    config.logger.info(
        f'Daemon mode: pipeline runs now and then daily at '
        f'{config.DAILY_RUN_HOUR_UTC:02d}:00 UTC. Ctrl+C to stop.'
    )
    while True:
        config.logger.info(f'=== Pipeline run started at {datetime.now(timezone.utc).isoformat()} ===')
        try:
            run_pipeline(client)
        except KeyboardInterrupt:
            config.logger.info('Interrupted by user, exiting.')
            break
        except Exception:
            config.logger.exception('Pipeline run failed; continuing the daily schedule.')

        wait_s, next_run = _next_run_time(config.DAILY_RUN_HOUR_UTC)
        config.logger.info(
            f'=== Next run at {next_run.isoformat()} (in {wait_s/3600:.1f}h) ==='
        )
        try:
            time.sleep(wait_s)
        except KeyboardInterrupt:
            config.logger.info('Interrupted by user during sleep, exiting.')
            break
