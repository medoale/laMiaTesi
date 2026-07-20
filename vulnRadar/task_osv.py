"""
Task — OSV:
Same identical logic as Task 1 (official), sourced from OSV.dev instead of
NVD. For each (ecosystem, package) pair found in recent OSV vulnerabilities,
find the GitHub repository that hosts that package. Score is the number of
vulnerability occurrences for that pair, so the most-frequently affected
packages surface first.

The repo name is never guessed. Two resolution strategies, in order:
  1) direct lookup, when the package name IS already a GitHub path — this is
     the OSV equivalent of official's "/repos/{vendor}/{product}" lookup. It
     works well for the Go ecosystem, where OSV's package name is literally
     the module's import path (e.g. "github.com/gin-gonic/gin"); it simply
     fails harmlessly for ecosystems whose name isn't shaped like a path.
  2) the github.com URLs the vulnerabilities of that package list in their
     own references (extract_github_repos, shared with cve_matcher.py and
     official).

A package that resolves to neither is dropped — most commonly a Linux distro
advisory (Ubuntu, Debian, Alpine...) whose references point at the distro's
own tracker or at a non-GitHub upstream (git.kernel.org, for example), never
at a github.com URL. That is not filtered out on purpose — the same "resolve
or drop" rule applies uniformly regardless of ecosystem, exactly like
official drops Windows/Chrome — it just happens that distro entries rarely
have the reference that would let them resolve.

OSV has no NVD-style date-range query, so the candidate pool is capped at
MAX_ENTRIES_TO_CHECK per run rather than exhausting the whole lookback window
(see osv_client.fetch_recent_ids).
"""
import time
import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta

from github_client import GitHubClient
from osv_client import fetch_recent_ids, fetch_vulns
from cve_matcher import extract_github_repos
import config

logger = logging.getLogger('vulnRadar')

# How many of the most recent OSV entries in config.OSV_LOOKBACK_DAYS to
# actually check — the modified_id.csv stream is dominated by Linux distro
# advisories (~99% in samples), so the window can hold far more entries than
# are worth an API call each; this caps the cost per run.
MAX_ENTRIES_TO_CHECK = 500

# Same threshold and same rationale as official: a repo referenced by a
# single vulnerability is often a proof-of-concept, not the package itself.
MIN_REFERENCE_HITS = 2


def extract_packages(vulns: list[dict]) -> tuple[Counter, dict[tuple[str, str], Counter]]:
    """Count distinct vulnerabilities per (ecosystem, package) pair, and
    collect the GitHub repos referenced by the vulnerabilities of each pair.

    Mirrors official's extract_vendor_products: multiple affected entries
    within the same vulnerability that point to the same pair (different
    version ranges) are counted only once.
    """
    counter: Counter = Counter()
    references: dict[tuple[str, str], Counter] = defaultdict(Counter)
    for vuln in vulns:
        seen_in_this_vuln: set[tuple[str, str]] = set()
        for affected in vuln.get('affected', []):
            pkg = affected.get('package', {})
            ecosystem, name = pkg.get('ecosystem'), pkg.get('name')
            if ecosystem and name:
                seen_in_this_vuln.add((ecosystem, name))
        if not seen_in_this_vuln:
            continue
        repos = extract_github_repos(vuln)
        for pair in seen_in_this_vuln:
            counter[pair] += 1
            for repo in repos:
                references[pair][repo] += 1
    return counter, references


# Successes only — same asymmetric-caching rationale as official: the
# candidate window shifts every run, so a pair below MIN_REFERENCE_HITS today
# may clear it once more vulnerabilities land in the window later.
_REPO_CACHE: dict[tuple[str, str], dict] = {}


def find_repo_for_package(client: GitHubClient, ecosystem: str, name: str,
                          referenced: Counter) -> dict | None:
    """Map an (ecosystem, package) pair to a real GitHub repo, without ever
    guessing the repo name. See official's find_repo_for_product for the
    caching rationale — identical here."""
    cache_key = (ecosystem, name)
    if cache_key in _REPO_CACHE:
        return _REPO_CACHE[cache_key]

    # Strategy 1: the package name is already a GitHub path (Go modules).
    if name.startswith('github.com/'):
        owner_repo = name[len('github.com/'):]
        repo = client.get(f'/repos/{owner_repo}')
        if isinstance(repo, dict) and 'full_name' in repo:
            _REPO_CACHE[cache_key] = repo
            return repo

    # Strategy 2: the repos this package's own vulnerabilities point at.
    for full_name, hits in referenced.most_common():
        if hits < MIN_REFERENCE_HITS:
            break  # most_common() is sorted, everything below is under threshold
        repo = client.get(f'/repos/{full_name}')
        if isinstance(repo, dict) and 'full_name' in repo:
            _REPO_CACHE[cache_key] = repo
            return repo
        time.sleep(0.2)

    return None   # not cached: see the caching note on official's counterpart


def run(client: GitHubClient) -> list[dict]:
    """Returns a list of selected repos, capped at MAX_REPOS_PER_TASK."""
    since = datetime.now(timezone.utc) - timedelta(days=config.OSV_LOOKBACK_DAYS)
    logger.info(f'TASK (osv) — fetching up to {MAX_ENTRIES_TO_CHECK} OSV entries '
               f'from last {config.OSV_LOOKBACK_DAYS} days…')
    ids, _ = fetch_recent_ids(since, MAX_ENTRIES_TO_CHECK)   # cursor not needed here:
    # this task re-samples the most recent window fresh every run, same as
    # official's fresh NVD query every day — no persistent state to advance.
    logger.info(f'  → {len(ids)} candidate vulnerability IDs')

    vulns = fetch_vulns(ids)
    logger.info(f'  → {len(vulns)} vulnerability records fetched')

    pairs, references = extract_packages(vulns)
    logger.info(f'  → distinct (ecosystem, package) pairs: {len(pairs)}')

    selected: list[dict] = []
    seen: set[str] = set()
    for (ecosystem, name), count in pairs.most_common():
        if len(selected) >= config.MAX_REPOS_PER_TASK:
            break
        repo = find_repo_for_package(client, ecosystem, name,
                                     references[(ecosystem, name)])
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
            'reason':    f'package "{ecosystem}/{name}" appears in {count} recent OSV vulnerabilities',
        })
        time.sleep(0.2)

    logger.info(f'TASK (osv) — selected {len(selected)} repos')
    return selected
