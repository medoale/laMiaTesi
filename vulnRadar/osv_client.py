"""
Minimal OSV.dev client.

OSV.dev is free and requires no API key or authentication — unlike GitHub and
(optionally) NVD, so this client carries no token and no rate-limit budget.
It is NOT, however, unlimited: sustained high concurrency makes api.osv.dev
start dropping connections (SSL EOF, connection resets), so requests go
through a shared session with transport-level retry/backoff (see `_session`)
and fetch_vulns has a circuit breaker that bails out — rather than grinding
for hours — when the network or the API is genuinely down.

There is no "give me vulnerabilities published in the last N days" endpoint
like NVD's date-range query. Instead OSV publishes a single flat file,
`modified_id.csv`, listing every vulnerability ID with its last-modified
timestamp, sorted most-recent first. We stream it from the top and stop once
we have enough recent entries — no need to download the whole multi-million-row
file to get "the last 30 days".
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, CancelledError
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger('vulnRadar')

MODIFIED_IDS_URL = 'https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv'
VULN_URL = 'https://api.osv.dev/v1/vulns/{id}'

# OSV needs no token, so there is no shared rate-limit budget to protect
# (unlike GitHubClient). Concurrency stays modest here on purpose: 20 workers
# hammering /v1/vulns/{id} for hours triggered hundreds of SSL-EOF and
# connection-reset drops in practice, so we pair a smaller pool with
# connection reuse (one shared session) and retries instead.
DEFAULT_MAX_WORKERS = 10

# Circuit breaker: if this many fetches fail back-to-back (in completion
# order) the API/network is almost certainly down for the whole run, not just
# flaking on a few IDs — stop firing the rest instead of grinding through
# thousands of doomed requests (and their retries) for hours.
CIRCUIT_BREAKER_CONSECUTIVE_FAILURES = 50

# A run is only "complete" (safe for the caller to advance its cursor past the
# fetched window) if at least this fraction of the requested IDs came back.
# Below it, too much was lost to network trouble to treat the window as
# covered — mirrors the partial-failure-safe cursor policy in fetch_recent_ids.
FETCH_COMPLETENESS_THRESHOLD = 0.8


# One session shared across the worker pool: connection reuse means far fewer
# TLS handshakes (each handshake is a chance for the SSL-EOF drops we saw), and
# the mounted Retry transparently retries transient connect/read failures and
# 429/5xx with exponential backoff before fetch_vuln ever sees an exception.
_session = requests.Session()
_retry = Retry(
    total=4, connect=4, read=4,
    backoff_factor=0.5,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=frozenset(['GET']),
    raise_on_status=False,
)
_adapter = HTTPAdapter(
    max_retries=_retry,
    pool_connections=DEFAULT_MAX_WORKERS,
    pool_maxsize=DEFAULT_MAX_WORKERS,
)
_session.mount('https://', _adapter)
_session.mount('http://', _adapter)


def fetch_recent_ids(since: datetime, max_ids: int,
                     *, newest_first: bool = True) -> tuple[list[str], datetime | None]:
    """Return up to `max_ids` vulnerability IDs modified since `since`, plus
    the timestamp cursor a persistent caller should advance to.

    `modified_id.csv` is reverse-chronological (newest first). We stream it
    from the top and collect every entry with `since < ts`.

    Two consumers want opposite ends of that window:

    * `newest_first=True` (default, used by task_osv, which has no persistent
      cursor): return the newest `max_ids` entries — the most relevant for
      ranking frequently-affected packages. `new_cursor` is the newest ts seen
      ONLY when the whole window down to `since` fit under the cap; if the cap
      truncated an older tail, `new_cursor` is None (advancing to "newest"
      would silently skip that tail).

    * `newest_first=False` (used by cve_matcher, which keeps a cursor): return
      the OLDEST `max_ids` entries — the block contiguous with `since`. A
      single high-water cursor can only move forward across a block adjacent
      to `since`, so this is the only choice that lets the cursor advance every
      run WITHOUT ever skipping an entry: a large backlog drains oldest-first
      over several runs, and once caught up each run just handles the day's new
      entries. `new_cursor` is the newest ts among the RETURNED ids, and every
      entry sharing that boundary ts is included even if it slightly exceeds
      `max_ids`, so a run can never split one timestamp and skip its tail.

    In both modes `new_cursor` is None when the window is empty or the request
    failed (nothing to advance, and never advance past a failure)."""
    window: list[tuple[datetime, str]] = []
    try:
        with requests.get(MODIFIED_IDS_URL, stream=True, timeout=60) as r:
            r.raise_for_status()
            for line in r.iter_lines(decode_unicode=True):
                if not line:
                    continue
                ts_str, ecosystem_and_id = line.split(',', 1)
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                # Exclusive lower bound: an entry exactly at `since` was the
                # boundary of the previous run — including it would reprocess it.
                if ts <= since:
                    break   # file is newest-first, everything below is older still
                # Each row is "ecosystem/native_id" (e.g. "Echo/ECHO-d46b-865d-7398"),
                # but /v1/vulns/{id} wants only the native ID, without the ecosystem
                # prefix — keeping it would 404 on every single lookup.
                _, vuln_id = ecosystem_and_id.split('/', 1)
                window.append((ts, vuln_id))
                # Fast path for newest-first: the newest `max_ids` are the first
                # `max_ids` streamed, so we can stop without reading the whole
                # (potentially multi-hundred-thousand-row) window into memory.
                if newest_first and len(window) > max_ids:
                    # More than the cap remained newer than `since`: the window
                    # was truncated, so its older tail is unprocessed.
                    return [vid for _, vid in window[:max_ids]], None
    except requests.RequestException as e:
        logger.warning(f'OSV modified_id.csv fetch failed: {e}')
        return [], None

    if not window:
        return [], None

    if newest_first:
        # Whole window fit under the cap: fully covered, advance to the newest.
        newest_ts = window[0][0]
        return [vid for _, vid in window], newest_ts

    # Oldest-first: sort ascending and take the block adjacent to `since`.
    window.sort()
    chosen = window[:max_ids]
    cutoff_ts = chosen[-1][0]
    # Never split a timestamp across runs: pull in any remaining entries that
    # share the cutoff ts so the next run's `> cutoff_ts` can't skip them.
    i = len(chosen)
    while i < len(window) and window[i][0] == cutoff_ts:
        chosen.append(window[i])
        i += 1
    return [vid for _, vid in chosen], cutoff_ts


def fetch_vuln(vuln_id: str) -> dict | None:
    """Full record for one vulnerability ID. None on any failure — OSV IDs
    from modified_id.csv occasionally 404 (e.g. withdrawn records). Transient
    connect/read/5xx failures are already retried with backoff by the shared
    session before an exception reaches here."""
    try:
        r = _session.get(VULN_URL.format(id=vuln_id), timeout=(10, 30))
        if r.status_code != 200:
            return None
        return r.json()
    except requests.RequestException as e:
        logger.warning(f'OSV vuln fetch failed for {vuln_id}: {e}')
        return None


def fetch_vulns(vuln_ids: list[str],
                max_workers: int = DEFAULT_MAX_WORKERS) -> tuple[list[dict], bool]:
    """Fetch many vulnerability records concurrently.

    Returns (records, complete):
      * records  — only the successfully fetched ones (fetch_vuln's None
        failures are dropped here, so callers need no `if v is not None`).
      * complete — False when the circuit breaker tripped OR too many IDs were
        lost (< FETCH_COMPLETENESS_THRESHOLD returned). A caller with a
        persistent cursor MUST NOT advance it when complete is False: the
        window was not fully covered, so the missing IDs are retried next run
        instead of being silently skipped."""
    if not vuln_ids:
        return [], True

    results: list[dict] = []
    consecutive_failures = 0
    aborted = False

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fetch_vuln, vid): vid for vid in vuln_ids}
        for fut in as_completed(futures):
            try:
                v = fut.result()
            except CancelledError:
                continue   # cancelled by the circuit breaker below
            if v is None:
                consecutive_failures += 1
                if (consecutive_failures >= CIRCUIT_BREAKER_CONSECUTIVE_FAILURES
                        and not aborted):
                    aborted = True
                    logger.warning(
                        f'OSV: {consecutive_failures} consecutive fetch failures — '
                        'aborting remaining lookups (network/API likely down)')
                    for f in futures:
                        f.cancel()
            else:
                consecutive_failures = 0
                results.append(v)

    complete = (not aborted) and len(results) >= len(vuln_ids) * FETCH_COMPLETENESS_THRESHOLD
    if not complete:
        logger.warning(
            f'OSV: fetched {len(results)}/{len(vuln_ids)} records — treating the '
            'window as NOT covered (cursor will not advance)')
    return results, complete
