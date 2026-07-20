"""
After the tasks have run, fetch new vulnerabilities from NVD and OSV published
since each source's last check, and see if any of our historically-tracked
repos appear in their references. Records hits in `cve_matches`.

NVD and OSV are two independent sources of the SAME kind of evidence (a
github.com/owner/repo URL in a vulnerability's own references): a repo is
matched if EITHER source finds it — logical OR. Each source has its own
persistent cursor (`nvd_last_check` / `osv_last_check`), since they are
fetched in completely different ways (NVD: date-range API; OSV: streamed
reverse-chronological file, capped per run — see osv_client.fetch_recent_ids
for why its cursor only advances when the whole window was actually covered).
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
from osv_client import fetch_recent_ids, fetch_vuln

logger = logging.getLogger('vulnRadar')

GITHUB_URL = re.compile(r'https?://github\.com/([^/\s]+)/([^/\s?#)]+)', re.I)
NVD_LAST_CHECK_KEY = 'nvd_last_check'
OSV_LAST_CHECK_KEY = 'osv_last_check'

# How many OSV entries to inspect per run when catching up a stale cursor.
# The modified_id.csv stream is dominated by Linux distro advisories (~99% in
# samples) — same cost rationale as task_osv.MAX_ENTRIES_TO_CHECK, just more
# generous here since matching (a dict lookup) is cheaper than resolving a
# new repo (which costs extra GitHub API calls).
OSV_MAX_ENTRIES_PER_RUN = 2000

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


def extract_github_repos(item: dict) -> set[str]:
    """Find every github.com/owner/repo URL in an item's references.

    Accepts both NVD's shape ({"cve": {"references": [...]}}) and OSV's flat
    shape ({"references": [...]}) — this function is shared by the NVD-sourced
    (official, cve_matcher) and OSV-sourced (osv task, cve_matcher) callers.

    Skips reserved GitHub paths (advisories, orgs, sponsors, …) that look like
    owner/repo URLs but are not actual repositories."""
    references = item.get('cve', {}).get('references') or item.get('references', [])
    repos = set()
    for ref in references:
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
    """Extract severity, CVSS score and exploitability score from an NVD CVE.
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


def extract_cwe_ids(cve: dict) -> str | None:
    """Concatenate all CWE-XXX identifiers found in an NVD CVE's weaknesses
    field."""
    cwes: set[str] = set()
    for w in cve.get('weaknesses', []) or []:
        for d in w.get('description', []) or []:
            value = (d.get('value') or '').strip()
            if value.startswith('CWE-'):
                cwes.add(value)
    return ', '.join(sorted(cwes)) if cwes else None


def nvd_id(item: dict) -> str | None:
    return item.get('cve', {}).get('id')


def nvd_published(item: dict) -> str | None:
    return item.get('cve', {}).get('published')


def nvd_metrics(item: dict) -> dict:
    cve = item.get('cve', {})
    metrics = extract_cve_metrics(cve)
    metrics['cwe_ids'] = extract_cwe_ids(cve)
    return metrics


def osv_id(vuln: dict) -> str | None:
    """Prefer a real CVE ID (from `aliases`) so a vulnerability found by both
    NVD and OSV lands under the same cve_id — letting the UNIQUE(repo, cve_id)
    constraint correctly recognize it as the same match. Falls back to OSV's
    own native ID (GHSA-..., PYSEC-...) for advisories with no CVE assigned."""
    for alias in vuln.get('aliases', []) or []:
        if alias.startswith('CVE-'):
            return alias
    return vuln.get('id')


def osv_published(vuln: dict) -> str | None:
    return vuln.get('published')


def osv_metrics(vuln: dict) -> dict:
    """OSV gives a clean severity string and CWE list only when GitHub has
    reviewed the advisory (most GHSA entries carry `database_specific`); it
    does not give a ready numeric CVSS score without parsing the raw CVSS
    vector string, so cvss_score/exploitability_score are left None here —
    a real capability gap versus NVD, not an oversight."""
    db = vuln.get('database_specific', {}) or {}
    cwe_ids = db.get('cwe_ids') or []
    return {
        'severity':             db.get('severity'),
        'cvss_score':           None,
        'exploitability_score': None,
        'cwe_ids':              ', '.join(sorted(cwe_ids)) if cwe_ids else None,
    }


def parse_dt(value: str) -> datetime | None:
    """Parse an ISO timestamp. NVD/OSV both publish naive-looking values that
    are UTC, so we attach UTC when absent — otherwise they cannot be compared
    with the timezone-aware selection timestamps."""
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


def build_matches(items: list[dict], tracked: dict[str, dict], source: str, *,
                  get_id, get_published, get_metrics) -> tuple[list[dict], int]:
    """Shared match-building loop for any source (NVD or OSV): for each item,
    extract referenced GitHub repos, keep the ones we track, and apply the
    "no false predictions" timing rule (published strictly after selection).

    Only the field-extraction functions differ between NVD's nested shape and
    OSV's flat one (see nvd_* / osv_* functions above); the matching logic
    itself — the actual reason this exists — is identical for both, hence
    a single shared implementation rather than one per source.

    Returns (matches, n_skipped_pre_selection)."""
    matches = []
    skipped = 0
    for item in items:
        item_id = get_id(item)
        published = get_published(item)
        repos = extract_github_repos(item)
        metrics = get_metrics(item) if repos else None
        for repo in repos:
            info = tracked.get(repo.lower())
            if info is None:
                continue
            pub_dt = parse_dt(published)
            sel_dt = selection_moment(info)
            if pub_dt is None or sel_dt is None:
                continue
            # Only a real "prediction" if published AFTER we picked the repo.
            # Comparing full timestamps (not just dates) is what keeps out the
            # CVEs/vulnerabilities that caused the selection in the first
            # place: those are published hours before the run, same calendar day.
            if pub_dt <= sel_dt:
                skipped += 1
                continue
            days = (pub_dt.date() - sel_dt.date()).days
            matches.append({
                'repo_full_name':       info['full_name'],
                'cve_id':               item_id,
                'cve_published_date':   published,
                'first_selected_date':  info['selected_date'],
                'days_until_cve':       days,
                'source':               source,
                'severity':             metrics['severity'],
                'cvss_score':           metrics['cvss_score'],
                'exploitability_score': metrics['exploitability_score'],
                'cwe_ids':              metrics['cwe_ids'],
            })
    return matches, skipped


def run(conn: sqlite3.Connection) -> int:
    # Fetched and the cursors advanced regardless of whether there is anything
    # tracked yet (build_matches simply yields zero matches against an empty
    # dict) — so a cursor is never left frozen just because this happens to
    # run before any task has ever inserted a repo.
    tracked = get_tracked_repo_first_selection(conn)
    if not tracked:
        logger.info('  → no tracked repos yet, will still advance cursors')

    all_matches: list[dict] = []

    # --- NVD ------------------------------------------------------------------
    nvd_last = get_last_check(conn, NVD_LAST_CHECK_KEY)
    nvd_since = datetime.fromisoformat(nvd_last) if nvd_last else \
        datetime.now(timezone.utc) - timedelta(days=30)
    logger.info(f'CVE matcher — fetching NVD CVEs since {nvd_since.isoformat()}')
    cves, nvd_covered = fetch_cves_since(nvd_since)
    logger.info(f'  → {len(cves)} new CVEs (range covered up to {nvd_covered.isoformat()})')

    nvd_matches, nvd_skipped = build_matches(
        cves, tracked, source='nvd',
        get_id=nvd_id, get_published=nvd_published, get_metrics=nvd_metrics,
    )
    all_matches.extend(nvd_matches)
    if nvd_skipped:
        logger.info(f'  NVD: skipped {nvd_skipped} CVEs published before selection date')
    # Advance only to what was actually fetched — a failure mid-window means
    # the missing tail is retried next run, never silently skipped.
    set_last_check(conn, NVD_LAST_CHECK_KEY, nvd_covered.isoformat())

    # --- OSV --------------------------------------------------------------------
    osv_last = get_last_check(conn, OSV_LAST_CHECK_KEY)
    osv_since = datetime.fromisoformat(osv_last) if osv_last else \
        datetime.now(timezone.utc) - timedelta(days=30)
    logger.info(f'CVE matcher — fetching OSV vulnerabilities since {osv_since.isoformat()}')
    osv_ids, osv_new_cursor = fetch_recent_ids(osv_since, OSV_MAX_ENTRIES_PER_RUN)
    vulns = [v for v in (fetch_vuln(i) for i in osv_ids) if v is not None]
    logger.info(f'  → {len(vulns)}/{len(osv_ids)} OSV records fetched')

    osv_matches, osv_skipped = build_matches(
        vulns, tracked, source='osv',
        get_id=osv_id, get_published=osv_published, get_metrics=osv_metrics,
    )
    all_matches.extend(osv_matches)
    if osv_skipped:
        logger.info(f'  OSV: skipped {osv_skipped} vulnerabilities published before selection date')
    if osv_new_cursor is not None:
        set_last_check(conn, OSV_LAST_CHECK_KEY, osv_new_cursor.isoformat())
    else:
        logger.info('  OSV: per-run cap reached before covering the full window — '
                   'cursor left unchanged, retrying the same window next run')

    inserted = insert_cve_matches(conn, all_matches) if all_matches else 0
    logger.info(f'CVE matcher — {len(all_matches)} matches found '
               f'({len(nvd_matches)} nvd, {len(osv_matches)} osv), {inserted} new')
    return inserted
