"""
Task 1 — Official:
For each (vendor, product) pair found in recent NVD CVEs, find the GitHub
repository that hosts that product. Score is the number of CVE occurrences for
that pair, so the most-frequently affected products surface first.

The repo name is never guessed. Two resolution strategies, in order:
  1) direct lookup of /repos/{vendor}/{product}
  2) the github.com URLs the CVEs of that product list in their own references

A product that resolves to neither is dropped. Usually it simply is not hosted
on GitHub (Chrome, Windows, macOS…) — and those are exactly the products with
the most CVEs, so guessing a repo name for them used to put false positives at
the very top of the ranking.
"""
import time
import logging
from collections import Counter, defaultdict

from github_client import GitHubClient
from nvd_client import fetch_cves_last_n_days
from cve_matcher import extract_github_repos
import config

logger = logging.getLogger('vulnRadar')

# A repo must be referenced by at least this many distinct CVEs of a product
# before we accept it as that product's repo. A repo linked by a single CVE is
# often the reporter's proof-of-concept, not the affected product itself.
MIN_REFERENCE_HITS = 2


def extract_vendor_products(cves: list[dict]) -> tuple[Counter, dict[tuple[str, str], Counter]]:
    """Count distinct CVEs per (vendor, product) pair, and collect the GitHub
    repos referenced by the CVEs of each pair.

    Multiple CPE entries within the same CVE that point to the same pair
    (different affected versions) are counted only once. Reference hits are
    counted per distinct CVE too, so a repo linked five times by one CVE
    counts once.
    """
    counter: Counter = Counter()
    references: dict[tuple[str, str], Counter] = defaultdict(Counter)
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
        if not seen_in_this_cve:
            continue
        repos = extract_github_repos(item)
        for pair in seen_in_this_cve:
            counter[pair] += 1
            for repo in repos:
                references[pair][repo] += 1
    return counter, references


# Successes only — see the docstring below for why failures are never cached.
_REPO_CACHE: dict[tuple[str, str], dict] = {}


def find_repo_for_product(client: GitHubClient, vendor: str, product: str,
                          referenced: Counter) -> dict | None:
    """Map a (vendor, product) pair to a real GitHub repo, without ever guessing
    the repo name.

    1) /repos/{vendor}/{product} — the product lives under its own vendor name.
    2) the repos the product's own CVEs reference, most-referenced first, keeping
       only those that clear MIN_REFERENCE_HITS. This recovers the cases where
       the GitHub org differs from the NVD vendor name (jenkins → jenkinsci):
       the CVE itself names the repo, so we do not have to invent it.

    Every candidate is confirmed against the API, so a resolved repo always
    exists and carries GitHub's own canonical casing.

    Caching is asymmetric and deliberately so. The process runs as a daemon
    that keeps this cache alive for days, while `referenced` is derived from a
    sliding NVD_LOOKBACK_DAYS window that changes every run. A resolved repo
    never stops being the right answer, so successes are cached forever. An
    unresolved pair can become resolvable later purely because the window
    shifted — e.g. a repo cited by 1 CVE today (below MIN_REFERENCE_HITS) may
    be cited by 3 CVEs once more of them land in the window — so failures are
    retried on every call instead of being cached.
    """
    cache_key = (vendor, product)
    if cache_key in _REPO_CACHE:
        return _REPO_CACHE[cache_key]

    # Strategy 1: direct lookup.
    repo = client.get(f'/repos/{vendor}/{product}')
    if isinstance(repo, dict) and 'full_name' in repo:
        _REPO_CACHE[cache_key] = repo
        return repo

    # Strategy 2: the repos this product's CVEs point at.
    for full_name, hits in referenced.most_common():
        if hits < MIN_REFERENCE_HITS:
            break  # most_common() is sorted, everything below is under threshold
        repo = client.get(f'/repos/{full_name}')
        if isinstance(repo, dict) and 'full_name' in repo:
            _REPO_CACHE[cache_key] = repo
            return repo
        time.sleep(0.2)

    return None   # not cached: see the caching note in the docstring above


def run(client: GitHubClient) -> list[dict]:
    """Returns a list of selected repos, capped at MAX_REPOS_PER_TASK."""
    logger.info(f'TASK 1 (official) — fetching NVD CVEs from last {config.NVD_LOOKBACK_DAYS} days…')
    cves, _ = fetch_cves_last_n_days(config.NVD_LOOKBACK_DAYS)
    logger.info(f'  → got {len(cves)} CVEs from NVD')

    pairs, references = extract_vendor_products(cves)
    logger.info(f'  → distinct (vendor, product) pairs: {len(pairs)}')

    selected: list[dict] = []
    seen: set[str] = set()
    for (vendor, product), count in pairs.most_common():
        if len(selected) >= config.MAX_REPOS_PER_TASK:
            break
        repo = find_repo_for_product(client, vendor, product,
                                     references[(vendor, product)])
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
