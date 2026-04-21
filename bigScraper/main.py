import sqlite3

import config
from github_client import GitHubClient
from database import init_db
from analysis import collect_repos, process_commit_spikes
from display import print_top_spikes

if __name__ == '__main__':
    config.read_config()

    config.logger.info(f'Database: {config.DATABASE}')
    conn = sqlite3.connect(config.DATABASE)
    init_db(conn)

    client = GitHubClient(token=config.TOKEN)

    repos = collect_repos(client, target=200)
    process_commit_spikes(client, repos, conn)

    print_top_spikes(conn, top_n=20)

    conn.close()
    config.logger.info('Done.')
