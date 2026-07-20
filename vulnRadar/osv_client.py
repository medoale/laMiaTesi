"""
Minimal OSV.dev client.

OSV.dev is free and requires no API key or authentication — unlike GitHub and
(optionally) NVD, so this client is deliberately simpler than github_client.py
or nvd_client.py: no token, no rate-limit bookkeeping.

There is no "give me vulnerabilities published in the last N days" endpoint
like NVD's date-range query. Instead OSV publishes a single flat file,
`modified_id.csv`, listing every vulnerability ID with its last-modified
timestamp, sorted most-recent first. We stream it from the top and stop once
we have enough recent entries — no need to download the whole multi-million-row
file to get "the last 30 days".
"""
import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger('vulnRadar')

MODIFIED_IDS_URL = 'https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv'
VULN_URL = 'https://api.osv.dev/v1/vulns/{id}'


def fetch_recent_ids(since: datetime, max_ids: int) -> tuple[list[str], datetime | None]:
    """Stream modified_id.csv (reverse-chronological, newest first) and return
    up to `max_ids` vulnerability IDs modified since `since`.

    Returns (ids, new_cursor). `new_cursor` is the newest timestamp seen (the
    file's first line at fetch time) if the WHOLE window down to `since` was
    covered — callers with a persistent cursor should advance it to this
    value. If the cap is hit before reaching `since`, or the request fails,
    `new_cursor` is None: an unknown amount of older, still-unprocessed
    backlog remains, so the caller must NOT advance its cursor — the next
    call retries the same `since` (costs repeated work on high-volume days,
    but never silently skips an entry, mirroring nvd_client's
    partial-failure-safe cursor)."""
    ids: list[str] = []
    newest_ts: datetime | None = None
    try:
        with requests.get(MODIFIED_IDS_URL, stream=True, timeout=60) as r:
            r.raise_for_status()
            for line in r.iter_lines(decode_unicode=True):
                if not line:
                    continue
                ts_str, ecosystem_and_id = line.split(',', 1)
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                if newest_ts is None:
                    newest_ts = ts
                if ts < since:
                    return ids, newest_ts   # whole window covered
                # Each row is "ecosystem/native_id" (e.g. "Echo/ECHO-d46b-865d-7398"),
                # but /v1/vulns/{id} wants only the native ID, without the ecosystem
                # prefix — keeping it would 404 on every single lookup.
                _, vuln_id = ecosystem_and_id.split('/', 1)
                ids.append(vuln_id)
                if len(ids) >= max_ids:
                    return ids, None   # capped: backlog remains, don't advance
    except requests.RequestException as e:
        logger.warning(f'OSV modified_id.csv fetch failed: {e}')
        return ids, None   # partial/failed fetch: don't advance either
    return ids, newest_ts   # reached the end of the file (never happens in practice)


def fetch_vuln(vuln_id: str) -> dict | None:
    """Full record for one vulnerability ID. None on any failure — OSV IDs
    from modified_id.csv occasionally 404 (e.g. withdrawn records)."""
    try:
        r = requests.get(VULN_URL.format(id=vuln_id), timeout=30)
        if r.status_code != 200:
            return None
        return r.json()
    except requests.RequestException as e:
        logger.warning(f'OSV vuln fetch failed for {vuln_id}: {e}')
        return None
