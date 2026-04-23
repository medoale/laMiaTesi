import time
import statistics
import logging
import sqlite3
from datetime import datetime, timezone, timedelta

from github_client import GitHubClient
from vendors import VENDOR_ORGS
from database import (
    upsert_repo,
    insert_commit_activity,
    insert_spike,
    insert_recent_commits,
    insert_issue_activity,
    insert_issue_spike,
    insert_recent_issues,
)

logger = logging.getLogger('bigScraper')


def compute_spike(weeks: list) -> tuple[int, float, float, float] | None:
    """
    Returns (recent_2w_commits, baseline_avg, baseline_std, spike_score).
    Recent  = total commits in the last 2 weeks.
    Baseline = mean weekly commits over the 20 weeks before that.
    Score   = recent_2w / (baseline_avg * 2)  →  1.0 means normal activity.
    Returns None if there is not enough activity to be meaningful.
    """
    if len(weeks) < 22:
        return None
    recent_2w = weeks[-1]['total'] + weeks[-2]['total']
    baseline = [w['total'] for w in weeks[-22:-2]]
    if sum(1 for v in baseline if v > 0) < 4:
        return None
    avg = statistics.mean(baseline)
    if avg < 0.5:
        return None
    std = statistics.stdev(baseline) if len(baseline) > 1 else 0.0
    score = recent_2w / (avg * 2)
    return recent_2w, avg, std, score


def fetch_global_top_repos(client: GitHubClient, n: int = 10) -> list[dict]:
    """Fetch the top N most starred repositories globally, regardless of vendor."""
    logger.info(f'Fetching top {n} most starred repos globally…')
    data = client.get('/search/repositories', params={
        'q': 'stars:>1',
        'sort': 'stars',
        'order': 'desc',
        'per_page': n,
    })
    if not isinstance(data, dict) or 'items' not in data:
        logger.warning('Could not fetch global top repos.')
        return []
    for r in data['items']:
        r.setdefault('_vendor', 'Global Top')
    return data['items']


def fetch_top_repos(client: GitHubClient, org: str, vendor: str, per_page: int) -> list[dict]:
    data = client.get(f'/orgs/{org}/repos', params={'type': 'public', 'sort': 'stargazers', 'per_page': per_page})
    if not isinstance(data, list):
        data = client.get(f'/users/{org}/repos', params={'type': 'public', 'sort': 'stargazers', 'per_page': per_page})
    if not isinstance(data, list):
        logger.warning(f'No repos found for {org}')
        return []
    for r in data:
        r['_vendor'] = vendor
    return data


def collect_repos(client: GitHubClient, target: int = 200) -> list[dict]:
    all_repos: dict[str, dict] = {}
    per_org = max(10, (target // len(VENDOR_ORGS)) + 5)

    # guaranteed inclusions: global top 10 by stars
    for r in fetch_global_top_repos(client, n=10):
        all_repos[r['full_name']] = r
    time.sleep(0.3)

    for org, vendor in VENDOR_ORGS:
        logger.info(f'Fetching repos for {org} ({vendor})…')
        for r in fetch_top_repos(client, org, vendor, per_org):
            fn = r['full_name']
            if fn not in all_repos or r.get('stargazers_count', 0) > all_repos[fn].get('stargazers_count', 0):
                all_repos[fn] = r
        time.sleep(0.3)

    ranked = sorted(all_repos.values(), key=lambda r: r.get('stargazers_count', 0), reverse=True)
    logger.info(f'Collected {len(ranked)} unique repos, keeping top {target}.')
    return ranked[:target]


def fetch_issue_weekly_counts(client: GitHubClient, full_name: str, weeks: int = 22) -> dict:
    """
    Fetch all issues created in the last `weeks` weeks and bin them by ISO week start (Monday).
    Returns a dict {week_date_str: count} with an entry for every week in the range.
    """
    since = (datetime.now(timezone.utc) - timedelta(weeks=weeks)).isoformat()
    all_issues = []
    page = 1
    while True:
        data = client.get(f'/repos/{full_name}/issues', params={
            'state': 'all',
            'since': since,
            'per_page': 100,
            'page': page,
        })
        if not isinstance(data, list) or len(data) == 0:
            break
        # GitHub issues endpoint returns both issues and PRs; exclude PRs
        all_issues.extend(i for i in data if 'pull_request' not in i)
        if len(data) < 100:
            break
        page += 1
        time.sleep(0.2)

    # bin by week start (Monday)
    counts: dict[str, int] = {}
    now = datetime.now(timezone.utc)
    for w in range(weeks):
        week_start = (now - timedelta(weeks=w)).date()
        week_start -= timedelta(days=week_start.weekday())  # back to Monday
        counts[week_start.isoformat()] = 0

    for issue in all_issues:
        created = issue.get('created_at', '')
        if not created:
            continue
        dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
        week_start = dt.date() - timedelta(days=dt.weekday())
        key = week_start.isoformat()
        if key in counts:
            counts[key] += 1

    return counts


def compute_issue_spike(weekly_counts: dict) -> tuple[int, float, float, float] | None:
    """Same spike logic as commits but over weekly issue counts."""
    sorted_weeks = sorted(weekly_counts.keys())
    if len(sorted_weeks) < 22:
        return None
    counts = [weekly_counts[w] for w in sorted_weeks]
    recent_2w = counts[-1] + counts[-2]
    baseline = counts[-22:-2]
    if sum(1 for v in baseline if v > 0) < 4:
        return None
    avg = statistics.mean(baseline)
    if avg < 0.5:
        return None
    std = statistics.stdev(baseline) if len(baseline) > 1 else 0.0
    score = recent_2w / (avg * 2)
    return recent_2w, avg, std, score


def fetch_recent_issues(client: GitHubClient, full_name: str, since_days: int = 14) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(days=since_days)).isoformat()
    data = client.get(f'/repos/{full_name}/issues', params={
        'state': 'all',
        'since': since,
        'per_page': 100,
    })
    if not isinstance(data, list):
        return []
    return [i for i in data if 'pull_request' not in i]


def process_issue_spikes(client: GitHubClient, repos: list[dict], conn: sqlite3.Connection) -> None:
    for i, repo in enumerate(repos, 1):
        full_name = repo['full_name']
        vendor = repo.get('_vendor', '')
        logger.info(f'[{i}/{len(repos)}] {full_name} ({vendor}) — issues spike')

        weekly_counts = fetch_issue_weekly_counts(client, full_name)
        insert_issue_activity(conn, full_name, weekly_counts)

        result = compute_issue_spike(weekly_counts)
        if result is None:
            logger.debug(f'  Not enough issue data for {full_name}.')
        else:
            recent, avg, std, score = result
            insert_issue_spike(conn, full_name, recent, avg, std, score)
            logger.info(f'  issue_spike_score={score:.2f}  recent={recent}  baseline_avg={avg:.1f}')

        issues = fetch_recent_issues(client, full_name)
        insert_recent_issues(conn, full_name, issues)

        conn.commit()
        time.sleep(0.5)


def fetch_recent_commits(client: GitHubClient, full_name: str, since_days: int = 14) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(days=since_days)).isoformat()
    data = client.get(f'/repos/{full_name}/commits', params={'since': since, 'per_page': 100})
    return data if isinstance(data, list) else []


def process_commit_spikes(client: GitHubClient, repos: list[dict], conn: sqlite3.Connection) -> None:
    for i, repo in enumerate(repos, 1):
        full_name = repo['full_name']
        vendor = repo.get('_vendor', '')
        stars = repo.get('stargazers_count', 0)
        logger.info(f'[{i}/{len(repos)}] {full_name} ({vendor}) — stars: {stars}')

        upsert_repo(conn, repo, vendor)

        weeks = client.get(f'/repos/{full_name}/stats/commit_activity')
        if not isinstance(weeks, list) or len(weeks) == 0:
            logger.warning(f'  No commit activity for {full_name}, skipping.')
            conn.commit()
            continue

        insert_commit_activity(conn, full_name, weeks)

        result = compute_spike(weeks)
        if result is None:
            logger.debug(f'  Not enough data to compute spike for {full_name}.')
        else:
            recent, avg, std, score = result
            insert_spike(conn, full_name, recent, avg, std, score)
            logger.info(f'  spike_score={score:.2f}  recent={recent}  baseline_avg={avg:.1f}')

        commits = fetch_recent_commits(client, full_name)
        insert_recent_commits(conn, full_name, commits)

        conn.commit()
        time.sleep(0.5)
