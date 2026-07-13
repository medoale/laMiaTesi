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


def extract_cve_metrics(cve: dict) -> dict:
    """Extract severity, CVSS score and exploitability score.
    Tries CVSS v3.1 first, falls back to v3.0 then v2."""
    metrics = cve.get('metrics', {}) or {}
    for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        items = metrics.get(key)
        if not items:
            continue
        m = items[0]
        cvss_data = m.get('cvssData', {}) or {}
        severity = (
            cvss_data.get('baseSeverity')   # v3.x
            or m.get('baseSeverity')         # sometimes top-level
            or cvss_data.get('severity')     # v2 fallback
            or m.get('severity')
        )
        return {
            'severity':             severity,
            'cvss_score':           cvss_data.get('baseScore'),
            'exploitability_score': m.get('exploitabilityScore'),
        }
    return {'severity': None, 'cvss_score': None, 'exploitability_score': None}


def parse_dt(value: str) -> datetime | None:
    """Parse an ISO timestamp. NVD publishes naive values that are UTC, so we
    attach UTC when absent — otherwise they cannot be compared with the
    timezone-aware selection timestamps."""
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, AttributeError, TypeError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def selection_moment(info: dict) -> datetime | None:
    """The instant a repo was selected, used as the cut-off for predictions.

    Rows written before `selected_at` existed only carry a date: we do not know
    the hour, so we place them at the END of that day. That discards same-day
    CVEs for those repos, which is the safe choice — a same-day CVE is far more
    likely to be one that triggered the selection than one predicted by it."""
    if info['selected_at']:
        return parse_dt(info['selected_at'])
    day = parse_dt(info['selected_date'])
    return day.replace(hour=23, minute=59, second=59) if day else None


def extract_cwe_ids(cve: dict) -> str | None:
    """Concatenate all CWE-XXX identifiers found in the CVE's weaknesses field."""
    cwes: set[str] = set()
    for w in cve.get('weaknesses', []) or []:
        for d in w.get('description', []) or []:
            value = (d.get('value') or '').strip()
            if value.startswith('CWE-'):
                cwes.add(value)
    return ', '.join(sorted(cwes)) if cwes else None


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
        repos = extract_github_repos(item)
        # Extract metadata once per CVE — same for every matched repo.
        metrics = extract_cve_metrics(cve) if repos else None
        cwe_ids = extract_cwe_ids(cve) if repos else None
        for repo in repos:
            info = tracked.get(repo.lower())
            if info is None:
                continue
            pub_dt = parse_dt(published)
            sel_dt = selection_moment(info)
            if pub_dt is None or sel_dt is None:
                continue
            # Only a real "prediction" if the CVE was published AFTER we picked
            # the repo. Comparing full timestamps (not just dates) is what keeps
            # out the CVEs that caused the selection in the first place: those
            # are published hours before the run, on the same calendar day.
            if pub_dt <= sel_dt:
                skipped_pre_selection += 1
                continue
            days = (pub_dt.date() - sel_dt.date()).days
            matches.append({
                'repo_full_name': info['full_name'],
                'cve_id': cve_id,
                'cve_published_date': published,
                'first_selected_date': info['selected_date'],
                'days_until_cve': days,
                'severity':             metrics['severity'],
                'cvss_score':           metrics['cvss_score'],
                'exploitability_score': metrics['exploitability_score'],
                'cwe_ids':              cwe_ids,
            })

    if skipped_pre_selection:
        logger.info(f'  skipped {skipped_pre_selection} CVEs published before selection date')

    inserted = insert_cve_matches(conn, matches) if matches else 0
    logger.info(f'CVE matcher — {len(matches)} matches found, {inserted} new')

    # Advance the cursor only to the end of the period we successfully fetched.
    # If a window failed mid-way, we will retry the missing tail next run.
    set_last_check(conn, LAST_CHECK_KEY, last_covered.isoformat())
    return inserted
