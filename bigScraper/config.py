import sys
import logging
from pathlib import Path
from configparser import ConfigParser

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%m/%d/%Y %H:%M:%S',
)
logger = logging.getLogger('bigScraper')

TOKEN: str | None = None
DATABASE: Path = Path('Data') / 'bigScraper.db'


def read_config() -> None:
    global TOKEN, DATABASE
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
    data_path = Path(cfg.get('CVEfixes', 'database_path', fallback='Data'))
    data_path.mkdir(parents=True, exist_ok=True)
    DATABASE = data_path / 'bigScraper.db'
    if not TOKEN:
        logger.warning('No GitHub token found — rate limit will be 60 req/hr.')
