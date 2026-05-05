"""
Robust NVD client.

Fixes:
  • NVD enforces a 120-day max range per query → we split into ≤119-day windows.
  • Pagination advances by actual page length, breaks on empty page.
  • Returns (cves, last_covered_end) so the caller can only advance its
    `last_check` cursor up to the period that was successfully fetched
    (no silent data loss on partial failure).
"""
import time
import logging
import requests
from datetime import datetime, timezone, timedelta

import config

logger = logging.getLogger('vulnRadar')

NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
NVD_DATE_FMT = '%Y-%m-%dT%H:%M:%S.000'
PAGE_SIZE = 2000          # NVD allows up to 2000
WINDOW_DAYS = 119         # stay safely under the 120-day limit
# With API key: 50 req / 30s → 0.6s sleep is safe.
# Without:       5 req / 30s → 6s sleep needed.
RATE_SLEEP_WITH_KEY = 0.6
RATE_SLEEP_NO_KEY   = 6


def _sleep() -> float:
    return RATE_SLEEP_WITH_KEY if config.NVD_API_KEY else RATE_SLEEP_NO_KEY


def _headers() -> dict:
    return {'apiKey': config.NVD_API_KEY} if config.NVD_API_KEY else {}


def _fetch_window(start: datetime, end: datetime) -> tuple[list[dict], bool]:
    """Fetch one ≤120-day window, paginated. Returns (cves, ok)."""
    cves: list[dict] = []
    start_index = 0
    while True:
        params = {
            'pubStartDate':   start.strftime(NVD_DATE_FMT),
            'pubEndDate':     end.strftime(NVD_DATE_FMT),
            'startIndex':     start_index,
            'resultsPerPage': PAGE_SIZE,
        }
        try:
            r = requests.get(NVD_API, params=params, headers=_headers(), timeout=60)
            r.raise_for_status()
        except requests.RequestException as e:
            logger.warning(f'NVD page failed (startIndex={start_index}): {e}')
            return cves, False

        try:
            data = r.json()
        except ValueError as e:
            logger.warning(f'NVD returned non-JSON response: {e}')
            return cves, False

        page = data.get('vulnerabilities')
        if not isinstance(page, list):
            logger.warning(f'NVD returned malformed payload at startIndex={start_index}')
            return cves, False

        if not page:
            break

        cves.extend(page)
        total = int(data.get('totalResults', 0))
        start_index += len(page)
        logger.info(f'  NVD page: got {len(page)} (total {len(cves)}/{total})')

        if start_index >= total:
            break
        time.sleep(_sleep())

    return cves, True


def fetch_cves_since(since_dt: datetime) -> tuple[list[dict], datetime]:
    """
    Fetch every NVD CVE published between `since_dt` and now, splitting the
    range into ≤119-day windows.

    Returns (cves, last_covered_end). `last_covered_end` is the upper bound of
    the most recent window that was fetched successfully — the caller should
    advance its `last_check` cursor to this datetime, NOT to now(), so a
    failure mid-fetch does not silently skip CVEs.
    """
    end = datetime.now(timezone.utc)
    if since_dt >= end:
        return [], end

    all_cves: list[dict] = []
    last_covered = since_dt
    cursor = since_dt
    window = timedelta(days=WINDOW_DAYS)

    while cursor < end:
        window_end = min(cursor + window, end)
        logger.info(f'  NVD window: {cursor.date()} → {window_end.date()}')
        page_cves, ok = _fetch_window(cursor, window_end)
        all_cves.extend(page_cves)
        if not ok:
            logger.warning(
                f'  NVD fetch failed in window starting {cursor.date()}; '
                f'last_check will only advance to {last_covered.isoformat()}'
            )
            break
        last_covered = window_end
        cursor = window_end
        if cursor < end:
            time.sleep(_sleep())

    return all_cves, last_covered


def fetch_cves_last_n_days(days: int) -> tuple[list[dict], datetime]:
    """Convenience wrapper for callers that just want the last N days."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return fetch_cves_since(since)
