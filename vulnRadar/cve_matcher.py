"""
After the three tasks have run, fetch new CVEs from NVD published since the
last check and see if any of our historically-tracked repos appear in the
references of those CVEs. Records hits in `cve_matches`.
"""
import re
import sqlite3
import logging
from datetime import datetime, timezone, timedelta

from database import (
    get_last_check,
    set_last_check,
    insert_cve_matches,
    get_tracked_repo_first_selection,
)
from nvd_client import fetch_cves_since

logger = logging.getLogger('vulnRadar')

GITHUB_URL = re.compile(r'https?://github\.com/([^/\s]+)/([^/\s?#)]+)', re.I)
LAST_CHECK_KEY = 'nvd_last_check'

# First path segments under github.com/ that are NOT user/org names but
# reserved GitHub product paths. We must not interpret them as repo owners.
GITHUB_RESERVED_PATHS = {
    'advisories', 'orgs', 'sponsors', 'marketplace', 'topics',
    'search', 'apps', 'notifications', 'settings', 'login',
    'pricing', 'features', 'enterprise', 'security', 'about',
    'collections', 'trending', 'explore', 'codespaces',
    'discussions', 'readme', 'site', 'home', 'contact',
    'pulls', 'issues', 'new', 'organizations', 'users',
    'mobile', 'customer-stories', 'team', 'blog',
}


def extract_github_repos(cve_item: dict) -> set[str]:
    """Find every github.com/owner/repo URL in a CVE's references.
    Skips reserved GitHub paths (advisories, orgs, sponsors, …) that look like
    owner/repo URLs but are not actual repositories."""
    cve = cve_item.get('cve', {})
    repos = set()
    for ref in cve.get('references', []):
        url = ref.get('url', '')
        for m in GITHUB_URL.finditer(url):
            owner, repo = m.group(1), m.group(2)
            if owner.lower() in GITHUB_RESERVED_PATHS:
                continue
            repo = re.sub(r'\.git$|/$', '', repo)
            if not repo:
                continue
            repos.add(f'{owner}/{repo}')
    return repos


def run(conn: sqlite3.Connection) -> int:
    last = get_last_check(conn, LAST_CHECK_KEY)
    if last is None:
        # first run: look back 30 days
        since_dt = datetime.now(timezone.utc) - timedelta(days=30)
    else:
        since_dt = datetime.fromisoformat(last)

    logger.info(f'CVE matcher — fetching NVD CVEs since {since_dt.isoformat()}')
    cves, last_covered = fetch_cves_since(since_dt)
    logger.info(f'  → {len(cves)} new CVEs (range covered up to {last_covered.isoformat()})')

    tracked = get_tracked_repo_first_selection(conn)
    if not tracked:
        logger.info('  → no tracked repos yet, skipping match')
        # Even with no repos to match, advance the cursor only to the period
        # we actually fetched (could be == since_dt if the very first window
        # failed). We don't want to skip CVEs we never actually inspected.
        set_last_check(conn, LAST_CHECK_KEY, last_covered.isoformat())
        return 0

    matches = []
    skipped_pre_selection = 0
    for item in cves:
        cve = item.get('cve', {})
        cve_id = cve.get('id')
        published = cve.get('published')
        for repo in extract_github_repos(item):
            if repo not in tracked:
                continue
            first_selected = tracked[repo]
            try:
                pub_date = datetime.fromisoformat(published.replace('Z', '+00:00')).date()
                sel_date = datetime.fromisoformat(first_selected).date()
                days = (pub_date - sel_date).days
            except (ValueError, AttributeError):
                continue
            # Only count this as a real "prediction" if the CVE was published
            # AFTER (or the same day as) our first selection of the repo.
            if days < 0:
                skipped_pre_selection += 1
                continue
            matches.append({
                'repo_full_name': repo,
                'cve_id': cve_id,
                'cve_published_date': published,
                'first_selected_date': first_selected,
                'days_until_cve': days,
            })

    if skipped_pre_selection:
        logger.info(f'  skipped {skipped_pre_selection} CVEs published before selection date')

    inserted = insert_cve_matches(conn, matches) if matches else 0
    logger.info(f'CVE matcher — {len(matches)} matches found, {inserted} new')

    # Advance the cursor only to the end of the period we successfully fetched.
    # If a window failed mid-way, we will retry the missing tail next run.
    set_last_check(conn, LAST_CHECK_KEY, last_covered.isoformat())
    return inserted
