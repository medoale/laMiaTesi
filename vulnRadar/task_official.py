"""
Task 1 — Official:
For each (vendor, product) pair found in recent NVD CVEs, find the most likely
GitHub repository that hosts that product. Score is the number of CVE
occurrences for that pair, so the most-frequently affected products surface
first. We try four resolution strategies in order until we find a real repo.
"""
import time
import logging
from collections import Counter

from github_client import GitHubClient
from nvd_client import fetch_cves_last_n_days
import config

logger = logging.getLogger('vulnRadar')

# Only mappings where the NVD vendor name differs from the GitHub org handle.
# For everything else we try the vendor name directly as an org/user handle.
VENDOR_TO_GH_ORG = {
    'wordpress': 'WordPress',
    'jenkins':   'jenkinsci',
    'gitlab':    'gitlabhq',
    'ibm':       'IBM',
    'nvidia':    'NVIDIA',
    'cisco':     'cisco-open-source',
    'rust':      'rust-lang',
    'go':        'golang',
    'node':      'nodejs',
}


def extract_vendor_products(cves: list[dict]) -> Counter:
    """Count distinct CVEs per (vendor, product) pair.
    Multiple CPE entries within the same CVE that point to the same pair
    (different affected versions) are counted only once."""
    counter: Counter = Counter()
    for item in cves:
        cve = item.get('cve', {})
        seen_in_this_cve: set[tuple[str, str]] = set()
        for conf in cve.get('configurations', []):
            for node in conf.get('nodes', []):
                for cpe in node.get('cpeMatch', []):
                    parts = cpe.get('criteria', '').split(':')
                    if len(parts) > 5:
                        vendor = parts[3].lower()
                        product = parts[4].lower()
                        if vendor and product:
                            seen_in_this_cve.add((vendor, product))
        for pair in seen_in_this_cve:
            counter[pair] += 1
    return counter


_REPO_CACHE: dict[tuple[str, str], dict | None] = {}


def find_repo_for_product(client: GitHubClient, vendor: str, product: str) -> dict | None:
    """Try three strategies to map a (vendor, product) pair to a real GitHub repo.
    Cached per-process to avoid hitting the API for the same pair twice.

    1) /repos/{vendor}/{product}              direct lookup
    2) /repos/{mapped_vendor}/{product}        if vendor needs a mapping
    3) /search/repositories?q=product in:name org:{vendor}   product as repo name in vendor's org

    A global fuzzy search is intentionally NOT used: it produces too many
    false positives (forks and unrelated projects with the same name).
    """
    cache_key = (vendor, product)
    if cache_key in _REPO_CACHE:
        return _REPO_CACHE[cache_key]

    candidates: list[tuple[str, str]] = [(vendor, product)]
    mapped = VENDOR_TO_GH_ORG.get(vendor)
    if mapped and (mapped, product) not in candidates:
        candidates.append((mapped, product))

    # Strategies 1 + 2: direct repo lookup
    for owner, repo_name in candidates:
        repo = client.get(f'/repos/{owner}/{repo_name}')
        if isinstance(repo, dict) and 'full_name' in repo:
            _REPO_CACHE[cache_key] = repo
            return repo

    # Strategy 3: search within the vendor org by repo name
    for owner in (vendor, mapped) if mapped else (vendor,):
        data = client.get('/search/repositories', params={
            'q':        f'{product} in:name org:{owner}',
            'sort':     'stars',
            'order':    'desc',
            'per_page': 1,
        })
        if isinstance(data, dict) and data.get('items'):
            _REPO_CACHE[cache_key] = data['items'][0]
            return data['items'][0]
        time.sleep(2)  # search rate limit

    _REPO_CACHE[cache_key] = None
    return None


def run(client: GitHubClient) -> list[dict]:
    """Returns a list of selected repos, capped at MAX_REPOS_PER_TASK."""
    logger.info(f'TASK 1 (official) — fetching NVD CVEs from last {config.NVD_LOOKBACK_DAYS} days…')
    cves, _ = fetch_cves_last_n_days(config.NVD_LOOKBACK_DAYS)
    logger.info(f'  → got {len(cves)} CVEs from NVD')

    pairs = extract_vendor_products(cves)
    logger.info(f'  → distinct (vendor, product) pairs: {len(pairs)}')

    selected: list[dict] = []
    seen: set[str] = set()
    for (vendor, product), count in pairs.most_common():
        if len(selected) >= config.MAX_REPOS_PER_TASK:
            break
        repo = find_repo_for_product(client, vendor, product)
        if not repo:
            continue
        full_name = repo['full_name']
        if full_name in seen:
            continue
        seen.add(full_name)
        selected.append({
            'full_name': full_name,
            'url':       repo.get('html_url'),
            'score':     float(count),
            'reason':    f'product "{vendor}/{product}" appears in {count} recent CVE CPEs',
        })
        time.sleep(0.2)

    logger.info(f'TASK 1 (official) — selected {len(selected)} repos')
    return selected
