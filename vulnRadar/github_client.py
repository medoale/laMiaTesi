import time
import logging
import threading
import requests

logger = logging.getLogger('vulnRadar')


class GitHubClient:
    BASE = 'https://api.github.com'

    def __init__(self, token: str | None) -> None:
        self._session = requests.Session()
        self._session.headers['Accept'] = 'application/vnd.github+json'
        self._session.headers['X-GitHub-Api-Version'] = '2022-11-28'
        if token:
            self._session.headers['Authorization'] = f'Bearer {token}'
        # serialise rate-limit waits across threads
        self._lock = threading.Lock()

    def get(self, path: str, params: dict = None, retries: int = 3) -> dict | list | None:
        """GET with rate-limit awareness and retry on 202 (stats still computing)."""
        url = path if path.startswith('http') else f'{self.BASE}{path}'
        for _ in range(retries):
            try:
                r = self._session.get(url, params=params, timeout=30)
            except requests.RequestException as e:
                logger.warning(f'Request error for {url}: {e}')
                time.sleep(5)
                continue

            if r.status_code == 200:
                self._check_rate_limit(r)
                return r.json()
            elif r.status_code == 202:
                logger.debug(f'202 — stats computing for {url}, retrying in 5s…')
                time.sleep(5)
                continue
            elif r.status_code == 403 and 'rate limit' in r.text.lower():
                self._wait_for_reset(r)
                continue
            elif r.status_code == 422:
                # Search query exhausted (e.g., > 1000 results)
                logger.debug(f'422 (validation) for {url}')
                return None
            elif r.status_code == 404:
                return None
            else:
                logger.warning(f'HTTP {r.status_code} for {url}')
                return None
        return None

    def _check_rate_limit(self, response: requests.Response) -> None:
        remaining = int(response.headers.get('X-RateLimit-Remaining', 9999))
        if remaining < 5:
            self._wait_for_reset(response)

    def _wait_for_reset(self, response: requests.Response) -> None:
        with self._lock:
            reset = int(response.headers.get('X-RateLimit-Reset', time.time() + 60))
            wait = max(reset - int(time.time()), 1)
            logger.warning(f'Rate limit low/hit, sleeping {wait}s…')
            time.sleep(wait)
