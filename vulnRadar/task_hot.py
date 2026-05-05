"""
Task 2 — Hot:
Find repos that look "hot" in a security sense, including potential
SILENT PATCHES — fixes pushed without an explicit security-keyword message.

Score combines three components (additive, on comparable scales):

  keyword_score    = #unique_commits + 2 × #distinct_keywords
  commit_factor    = commits_last_week × W_COMMITS
  download_factor  = log10(total_release_downloads + 1) × W_DOWNLOADS

So a repo with no security-keyword commits but a sudden burst of activity
(silent patch signal) and a wide user base (high downloads) still ranks high.
"""
import time
import math
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from github_client import GitHubClient
import config

logger = logging.getLogger('vulnRadar')

# Score component weights — tweak here to re-balance.
W_COMMITS   = 0.5
W_DOWNLOADS = 3.0

# How many candidates to enrich (×MAX_REPOS_PER_TASK). 2× gives the silent-patch
# signals room to re-rank, but caps API cost.
ENRICH_MULTIPLIER = 2

# Pages of /search/commits to read per keyword (each page = 100 results).
# Search API total cap is ~1000 results regardless.
SEARCH_PAGES_PER_KEYWORD = 3


def search_security_commits(client: GitHubClient, since_date: str) -> dict:
    """
    Returns {repo_full_name: {sha → set(matched_keywords)}}.
    Deduplicating by SHA prevents counting the same commit multiple times when
    its message matches several security keywords.
    """
    repo_hits: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for kw in config.SECURITY_KEYWORDS:
        logger.info(f'  hot: searching commits for "{kw}" since {since_date}')
        for page in range(1, SEARCH_PAGES_PER_KEYWORD + 1):
            data = client.get('/search/commits', params={
                'q':        f'{kw} committer-date:>{since_date}',
                'sort':     'committer-date',
                'order':    'desc',
                'per_page': 100,
                'page':     page,
            })
            if not isinstance(data, dict) or not data.get('items'):
                break
            for item in data['items']:
                repo = item.get('repository', {}).get('full_name')
                sha = item.get('sha')
                if repo and sha:
                    repo_hits[repo][sha].add(kw)
            if len(data['items']) < 100:
                break
            time.sleep(2)
        time.sleep(2)  # search API: 30 req/min
    return repo_hits


def keyword_score(commits_by_sha: dict[str, set[str]]) -> tuple[int, int, set[str]]:
    """Return (n_unique_commits, n_distinct_keywords, all_keywords)."""
    n_commits = len(commits_by_sha)
    all_kws: set[str] = set()
    for kws in commits_by_sha.values():
        all_kws.update(kws)
    return n_commits, len(all_kws), all_kws


def get_commits_last_week(client: GitHubClient, full_name: str) -> int:
    weeks = client.get(f'/repos/{full_name}/stats/commit_activity')
    if isinstance(weeks, list) and weeks:
        return int(weeks[-1].get('total', 0))
    return 0


def get_total_downloads(client: GitHubClient, full_name: str, max_releases: int = 30) -> int:
    releases = client.get(f'/repos/{full_name}/releases', params={'per_page': max_releases})
    if not isinstance(releases, list):
        return 0
    total = 0
    for rel in releases:
        for asset in rel.get('assets', []):
            total += int(asset.get('download_count', 0))
    return total


def run(client: GitHubClient) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(days=config.HOT_LOOKBACK_DAYS)).date().isoformat()
    logger.info(f'TASK 2 (hot) — searching security commits since {since}')

    repo_hits = search_security_commits(client, since)
    logger.info(f'  → {len(repo_hits)} repos with at least one security-keyword commit')

    # Pre-rank by keyword score and cap candidates so we don't burn API on long tail.
    pre_scored = []
    for repo, commits_by_sha in repo_hits.items():
        n_commits, n_distinct, all_kws = keyword_score(commits_by_sha)
        kw_sc = n_commits + 2 * n_distinct
        pre_scored.append((repo, kw_sc, n_commits, n_distinct, all_kws))
    pre_scored.sort(key=lambda x: x[1], reverse=True)
    candidates = pre_scored[:config.MAX_REPOS_PER_TASK * ENRICH_MULTIPLIER]

    enriched: list[dict] = []
    for i, (full_name, kw_sc, n_commits, n_distinct, all_kws) in enumerate(candidates, 1):
        commits = get_commits_last_week(client, full_name)
        downloads = get_total_downloads(client, full_name)

        commit_factor = commits * W_COMMITS
        download_factor = math.log10(max(downloads, 1)) * W_DOWNLOADS
        score = kw_sc + commit_factor + download_factor

        kw_list = ', '.join(sorted(all_kws))
        enriched.append({
            'full_name': full_name,
            'url':       f'https://github.com/{full_name}',
            'score':     round(score, 2),
            'reason':    (f'kw_score={kw_sc} ({n_commits}c/{n_distinct}kw: {kw_list}) | '
                          f'commits_last_week={commits} | '
                          f'downloads={downloads}'),
        })
        if i % 10 == 0:
            logger.info(f'  hot: enriched {i}/{len(candidates)} candidates')
        time.sleep(0.3)

    enriched.sort(key=lambda r: r['score'], reverse=True)
    selected = enriched[:config.MAX_REPOS_PER_TASK]
    logger.info(f'TASK 2 (hot) — selected {len(selected)} repos')
    return selected
