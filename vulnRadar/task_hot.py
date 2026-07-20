"""
Task 2 — Hot:
Select repositories that show BEHAVIORAL signs of a silent patch — a security
fix pushed without any announcement — so they can be handed to a deeper,
slower analysis later (this task only picks *where* to look).

This is deliberately NOT a keyword search. A repo that silences a fix on
purpose will not say "security" or "CVE" in the commit message either, so
searching commit messages for those words can only ever find fixes that were
already announced — never a silent one. Instead, every candidate repo is
compared against ITS OWN recent history: three behavioral indicators, each
independent of what the commit message says.

  1) message brevity  — commit messages in the last HOT_LOOKBACK_DAYS are much
     shorter than this repo's own normal length. A rushed, deliberately vague
     fix ("fix issue", "misc updates") reads shorter than routine commits.
  2) merge speed       — pull requests are being merged much faster than this
     repo's own normal pace. An urgent fix often skips the usual review cycle.
  3) author concentration — recent commits come from a much narrower set of
     authors than usual. Security fixes are often handled by a small trusted
     group to limit exposure before disclosure.

Each indicator is a z-score against a BASELINE_DAYS-long window ending where
the recent window begins, so "normal" means "normal for this repo", not some
global average. A repo needs enough baseline history to judge what is normal
for it: too little history and a signal is skipped rather than guessed at.

Candidates are NOT a fixed watchlist. Every run queries GitHub's repository
search for active, non-trivial, non-fork, non-archived repos pushed within
the lookback window — a fresh pool each time, which is what makes this
"real-time": today's run looks at what is happening today, not at a list
someone curated once. Repos are ranked by HOW MANY indicators fire, ties
broken by how strongly.
"""
import logging
import statistics
import time
from datetime import datetime, timezone, timedelta

from github_client import GitHubClient
import config

logger = logging.getLogger('vulnRadar')

# --- Candidate discovery ----------------------------------------------------
# Filters applied by the GitHub repository search itself, to keep the pool to
# repos worth analyzing: enough stars to matter, pushed recently (otherwise
# there is nothing to compare), not a fork (its own history is derivative)
# and not archived (no one is patching it, silently or otherwise).
SEARCH_MIN_STARS = 500
MAX_CANDIDATES_TO_CHECK = 150   # how many search results get the full check
SEARCH_PAGE_SIZE = 100          # GitHub search API max per page

# --- Baseline window ---------------------------------------------------------
# "Normal for this repo" is measured over a fixed BASELINE_DAYS window ending
# where the recent (config.HOT_LOOKBACK_DAYS) window begins. Below this many
# baseline samples, a signal is not statistically meaningful and is skipped
# rather than fired on noise.
BASELINE_DAYS = 90
MIN_BASELINE_COMMITS = 10
MIN_BASELINE_PRS = 5

# --- Pagination caps ----------------------------------------------------------
# Per-repo cost bound: at most this many pages (each 100 items) are fetched
# per repo, covering baseline + recent windows together. A very active repo
# (e.g. the Linux kernel) would otherwise cost hundreds of requests alone.
MAX_COMMIT_PAGES = 5
MAX_PR_PAGES = 3

# --- Indicator thresholds -----------------------------------------------------
# Z-score threshold for the message-brevity and merge-speed signals: the
# recent mean must be at least this many baseline standard deviations BELOW
# the baseline mean (shorter messages / faster merges) to count as anomalous.
Z_THRESHOLD = 2.0

# Author-concentration signal: fires when the recent window's
# distinct-authors-per-commit ratio drops to less than this fraction of the
# repo's own baseline ratio (i.e. recent commits cluster around far fewer
# people than usual for the same amount of activity).
AUTHOR_CONCENTRATION_RATIO = 0.5
MIN_RECENT_COMMITS_FOR_AUTHOR_SIGNAL = 3   # avoid firing on a single commit

# GitHub bot accounts (dependabot, renovate, github-actions, ...) make
# frequent, short, mechanical commits/PRs that would otherwise swamp both the
# baseline and the recent window with noise unrelated to human behavior.
BOT_SUFFIX = '[bot]'


def _is_bot(login_or_name: str | None) -> bool:
    return bool(login_or_name) and login_or_name.endswith(BOT_SUFFIX)


def search_candidate_repos(client: GitHubClient, since_date: str) -> list[str]:
    """Fresh candidate pool for this run: active, non-trivial, non-fork,
    non-archived repos pushed since `since_date`, most recently pushed first.
    Returns up to MAX_CANDIDATES_TO_CHECK full names."""
    names: list[str] = []
    page = 1
    while len(names) < MAX_CANDIDATES_TO_CHECK:
        data = client.get('/search/repositories', params={
            'q': f'stars:>{SEARCH_MIN_STARS} pushed:>{since_date} '
                 f'fork:false archived:false',
            'sort':     'updated',
            'order':    'desc',
            'per_page': SEARCH_PAGE_SIZE,
            'page':     page,
        })
        items = data.get('items') if isinstance(data, dict) else None
        if not items:
            break
        names.extend(item['full_name'] for item in items)
        if len(items) < SEARCH_PAGE_SIZE:
            break
        page += 1
        time.sleep(2)   # search API rate limit
    return names[:MAX_CANDIDATES_TO_CHECK]


def fetch_commits(client: GitHubClient, full_name: str,
                  since: datetime, until: datetime) -> list[dict]:
    """Commits in [since, until], bot authors excluded, capped at
    MAX_COMMIT_PAGES pages. Each entry: {'date': datetime, 'author': str,
    'message_len': int}."""
    commits = []
    for page in range(1, MAX_COMMIT_PAGES + 1):
        data = client.get(f'/repos/{full_name}/commits', params={
            'since':    since.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'until':    until.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'per_page': 100,
            'page':     page,
        })
        if not isinstance(data, list) or not data:
            break
        for item in data:
            author_login = (item.get('author') or {}).get('login')
            commit_author = item.get('commit', {}).get('author', {})
            if _is_bot(author_login) or _is_bot(commit_author.get('name')):
                continue
            date_s = commit_author.get('date')
            message = item.get('commit', {}).get('message', '')
            if not date_s:
                continue
            commits.append({
                'date':        datetime.fromisoformat(date_s.replace('Z', '+00:00')),
                'author':      author_login or commit_author.get('name', 'unknown'),
                'message_len': len(message.strip()),
            })
        if len(data) < 100:
            break
    return commits


def fetch_merged_prs(client: GitHubClient, full_name: str,
                     since: datetime, until: datetime) -> list[dict]:
    """Merged PRs whose merge falls in [since, until], bot authors excluded,
    capped at MAX_PR_PAGES pages (sorted by most-recently-updated first, so
    the cap keeps the most relevant activity). Each entry: {'merged_at':
    datetime, 'hours_to_merge': float}. `merged_at` is kept (not just the
    duration) so the caller can split recent vs. baseline PRs by date, the
    same way fetch_commits' 'date' field is used."""
    prs = []
    for page in range(1, MAX_PR_PAGES + 1):
        data = client.get(f'/repos/{full_name}/pulls', params={
            'state':     'closed',
            'sort':      'updated',
            'direction': 'desc',
            'per_page':  100,
            'page':      page,
        })
        if not isinstance(data, list) or not data:
            break
        for pr in data:
            if _is_bot((pr.get('user') or {}).get('login')):
                continue
            merged_at, created_at = pr.get('merged_at'), pr.get('created_at')
            if not merged_at or not created_at:
                continue
            merged_dt = datetime.fromisoformat(merged_at.replace('Z', '+00:00'))
            if not (since <= merged_dt <= until):
                continue
            created_dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            hours = (merged_dt - created_dt).total_seconds() / 3600
            prs.append({'merged_at': merged_dt, 'hours_to_merge': hours})
        if len(data) < 100:
            break
    return prs


def _zscore(recent_values: list[float], baseline_values: list[float],
           min_baseline: int) -> float | None:
    """How many baseline standard deviations below the baseline mean the
    recent mean sits. None if there is not enough baseline history to judge,
    or the baseline has zero variance (would divide by zero)."""
    if len(baseline_values) < min_baseline or not recent_values:
        return None
    baseline_mean = statistics.mean(baseline_values)
    baseline_std = statistics.pstdev(baseline_values)
    if baseline_std == 0:
        return None
    recent_mean = statistics.mean(recent_values)
    return (recent_mean - baseline_mean) / baseline_std


def evaluate_repo(client: GitHubClient, full_name: str, baseline_start: datetime,
                  recent_start: datetime, until: datetime) -> dict | None:
    """Compute the three indicators for one repo, each recent vs. this repo's
    own baseline. Returns None if none of them fire (the repo is simply not
    anomalous — not "hot"). Otherwise returns the dict `run()` selects from:
    {'full_name', 'url', 'score', 'reason'}."""
    commits = fetch_commits(client, full_name, baseline_start, until)
    prs = fetch_merged_prs(client, full_name, baseline_start, until)

    baseline_commits = [c for c in commits if c['date'] < recent_start]
    recent_commits   = [c for c in commits if c['date'] >= recent_start]
    baseline_prs = [p for p in prs if p['merged_at'] < recent_start]
    recent_prs   = [p for p in prs if p['merged_at'] >= recent_start]

    indicators: list[tuple[str, float, str]] = []   # (name, severity, detail)

    # 1) message brevity: recent messages much shorter than this repo's own norm.
    msg_z = _zscore(
        [c['message_len'] for c in recent_commits],
        [c['message_len'] for c in baseline_commits],
        MIN_BASELINE_COMMITS,
    )
    if msg_z is not None and msg_z <= -Z_THRESHOLD:
        indicators.append(('message_brevity', -msg_z, f'z={msg_z:.1f}'))

    # 2) merge speed: recent PRs merged much faster than usual.
    merge_z = _zscore(
        [p['hours_to_merge'] for p in recent_prs],
        [p['hours_to_merge'] for p in baseline_prs],
        MIN_BASELINE_PRS,
    )
    if merge_z is not None and merge_z <= -Z_THRESHOLD:
        indicators.append(('merge_speed', -merge_z, f'z={merge_z:.1f}'))

    # 3) author concentration: recent activity clustered in far fewer authors
    # than the repo's own baseline rate would predict for this many commits.
    if (len(recent_commits) >= MIN_RECENT_COMMITS_FOR_AUTHOR_SIGNAL
            and len(baseline_commits) >= MIN_BASELINE_COMMITS):
        recent_ratio = len({c['author'] for c in recent_commits}) / len(recent_commits)
        baseline_ratio = len({c['author'] for c in baseline_commits}) / len(baseline_commits)
        if baseline_ratio > 0 and recent_ratio <= baseline_ratio * AUTHOR_CONCENTRATION_RATIO:
            drop = 1 - recent_ratio / baseline_ratio
            indicators.append(('author_concentration', drop * 10, f'-{drop:.0%}'))

    if not indicators:
        return None

    severity = sum(sev for _, sev, _ in indicators)
    detail = ', '.join(f'{name}({d})' for name, _, d in indicators)
    return {
        'full_name': full_name,
        'url':       f'https://github.com/{full_name}',
        'score':     round(len(indicators) * 10 + severity, 2),
        'reason':    f'{len(indicators)}/3 indicators: {detail}',
    }


def run(client: GitHubClient) -> list[dict]:
    """Returns a list of selected repos, capped at MAX_REPOS_PER_TASK."""
    until = datetime.now(timezone.utc)
    recent_start = until - timedelta(days=config.HOT_LOOKBACK_DAYS)
    baseline_start = recent_start - timedelta(days=BASELINE_DAYS)

    logger.info(f'TASK 2 (hot) — searching candidate repos pushed since '
               f'{recent_start.date()}')
    candidates = search_candidate_repos(client, recent_start.date().isoformat())
    logger.info(f'  → {len(candidates)} candidates to check')

    flagged: list[dict] = []
    for i, full_name in enumerate(candidates, 1):
        result = evaluate_repo(client, full_name, baseline_start, recent_start, until)
        if result:
            flagged.append(result)
        if i % 20 == 0:
            logger.info(f'  hot: checked {i}/{len(candidates)} candidates, '
                       f'{len(flagged)} flagged so far')
        time.sleep(0.3)

    flagged.sort(key=lambda r: r['score'], reverse=True)
    selected = flagged[:config.MAX_REPOS_PER_TASK]
    logger.info(f'TASK 2 (hot) — selected {len(selected)} repos')
    return selected
