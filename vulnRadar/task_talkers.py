"""
Task 3 — Top talkers:
Find the repos that are most "talked about" on GitHub right now: those with the
highest combined volume of recent issues + recent commits. They are the most
exposed to user attention (and to attackers).

Score = W_ISSUES × #recent_issues + W_COMMITS × #recent_commits

The two activity signals are semantically different (issues = user-facing
attention, commits = developer activity) so the weights are exposed for tuning.
By default we weight commits slightly more — coordinated development is a
stronger signal of an exposed surface than user chatter.
"""
import time
import logging
from collections import Counter
from datetime import datetime, timezone, timedelta

from github_client import GitHubClient
import config

logger = logging.getLogger('vulnRadar')

W_ISSUES  = 1.0
W_COMMITS = 1.5


def _paginate_search(client: GitHubClient, path: str, query: str, max_pages: int = 10) -> list[dict]:
    items = []
    for page in range(1, max_pages + 1):
        data = client.get(path, params={
            'q':        query,
            'sort':     'created',
            'order':    'desc',
            'per_page': 100,
            'page':     page,
        })
        if not isinstance(data, dict) or 'items' not in data:
            break
        items.extend(data['items'])
        if len(data['items']) < 100:
            break
        time.sleep(2)  # search rate limit
    return items


def count_recent_issues(client: GitHubClient, since_date: str) -> Counter:
    logger.info(f'  talkers: counting issues since {since_date}')
    items = _paginate_search(client, '/search/issues',
                             f'is:issue created:>{since_date}', max_pages=10)
    counter: Counter = Counter()
    for it in items:
        url = it.get('repository_url', '')
        # ".../repos/owner/repo"
        parts = url.split('/repos/', 1)
        if len(parts) == 2:
            counter[parts[1]] += 1
    return counter


def count_recent_commits(client: GitHubClient, since_date: str) -> Counter:
    logger.info(f'  talkers: counting commits since {since_date}')
    items = _paginate_search(client, '/search/commits',
                             f'committer-date:>{since_date}', max_pages=10)
    counter: Counter = Counter()
    for it in items:
        repo = it.get('repository', {}).get('full_name')
        if repo:
            counter[repo] += 1
    return counter


def run(client: GitHubClient) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(days=config.TALKERS_LOOKBACK_DAYS)).date().isoformat()
    logger.info(f'TASK 3 (talkers) — looking at activity since {since}')

    issues = count_recent_issues(client, since)
    commits = count_recent_commits(client, since)

    combined: dict[str, float] = {}
    for repo in set(issues) | set(commits):
        combined[repo] = W_ISSUES * issues.get(repo, 0) + W_COMMITS * commits.get(repo, 0)

    ranked = sorted(combined.items(), key=lambda kv: kv[1], reverse=True)

    selected: list[dict] = []
    for repo, score in ranked[:config.MAX_REPOS_PER_TASK]:
        selected.append({
            'full_name': repo,
            'url':       f'https://github.com/{repo}',
            'score':     round(score, 2),
            'reason':    (f'{issues.get(repo, 0)} issues × {W_ISSUES} + '
                          f'{commits.get(repo, 0)} commits × {W_COMMITS} '
                          f'in last {config.TALKERS_LOOKBACK_DAYS}d'),
        })

    logger.info(f'TASK 3 (talkers) — selected {len(selected)} repos')
    return selected
