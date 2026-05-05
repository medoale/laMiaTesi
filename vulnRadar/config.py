import sys
import logging
from pathlib import Path
from configparser import ConfigParser

# ----------------------------------------------------------------------------
# Tunable parameters — change here to adjust behaviour
# ----------------------------------------------------------------------------
MAX_REPOS_PER_TASK = 100        # max repos selected per task per run
NVD_LOOKBACK_DAYS = 30          # how far back to look in NVD for "official" task
HOT_LOOKBACK_DAYS = 7           # how far back to look for "hot" task
TALKERS_LOOKBACK_DAYS = 7       # how far back to look for "talkers" task

# Daemon mode: when run as `python3 main.py`, the program loops forever and
# triggers a full pipeline once per day at this UTC hour (24-hour clock).
# Set to None to disable the loop and run only once.
DAILY_RUN_HOUR_UTC: int | None = 6

# Security-related keywords used by the "hot" task
SECURITY_KEYWORDS = [
    'CVE', 'vulnerability', 'exploit', 'security',
    'injection', 'XSS', 'CSRF', 'overflow', 'RCE',
    'sanitize', 'auth bypass', 'credential', 'patch',
]

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(threadName)s] %(message)s',
    datefmt='%m/%d/%Y %H:%M:%S',
)
logger = logging.getLogger('vulnRadar')

# ----------------------------------------------------------------------------
# Config from .CVEfixes.ini
# ----------------------------------------------------------------------------
TOKEN: str | None = None        # GitHub personal access token
NVD_API_KEY: str | None = None  # NVD API key (optional; speeds up NVD calls 10×)
DATABASE: Path = Path('Data') / 'vulnRadar.db'


def read_config() -> None:
    global TOKEN, NVD_API_KEY, DATABASE
    cfg = ConfigParser()
    locations = [
        '.CVEfixes.ini',
        Path.home() / '.config' / 'CVEfixes.ini',
        Path.home() / '.CVEfixes.ini',
    ]
    if not cfg.read(locations):
        logger.error('Cannot find .CVEfixes.ini — add GitHub token there.')
        sys.exit(1)
    TOKEN = cfg.get('GitHub', 'token', fallback=None)
    NVD_API_KEY = cfg.get('NVD', 'api_key', fallback=None)
    data_path = Path(cfg.get('CVEfixes', 'database_path', fallback='Data'))
    data_path.mkdir(parents=True, exist_ok=True)
    DATABASE = data_path / 'vulnRadar.db'
    if not TOKEN:
        logger.warning('No GitHub token found — rate limit will be 60 req/hr.')
    if not NVD_API_KEY:
        logger.warning('No NVD API key found — NVD calls will sleep 6s/page (vs 0.6s with key).')
