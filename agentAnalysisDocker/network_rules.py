"""Egress isolation for the agent containers (host side).

Goal: an agent can reach ONLY the model API (config.ALLOWED_EGRESS_HOSTS), and
nothing else on the internet — so agent3/agent2 cannot look up the CVE or the
fix online.

How (the "egress gateway" pattern):
  - a Docker --internal network has NO route to the internet;
  - the agent runs on it, so it cannot reach the internet directly;
  - a small proxy container (proxy_server.py) sits on that internal network AND
    on the normal bridge, and only tunnels (CONNECT) to the allowlisted hosts;
  - the agent is pointed at the proxy via HTTP(S)_PROXY.
The --internal network is the real guarantee: even if the agent ignored the
proxy env vars, it has no other route out.

Usage from main.py:
    network_rules.setup()                    # once, before the run loop
    args = network_rules.agent_docker_args() # add to each agent's `docker run`
    ...
    network_rules.teardown()                 # once, after (in a finally)
"""
import subprocess
import time

import config

NETWORK = 'agentanalysis_egress'     # the internal (no-internet) network
PROXY_NAME = 'agentanalysis_proxy'   # the allowlist proxy container
PROXY_PORT = 8888
PROXY_IMAGE = 'python:3-alpine'      # pullable base; just runs proxy_server.py
PROXY_SCRIPT = config.BASE_DIR / 'proxy_server.py'


def _docker(*args, check=True):
    return subprocess.run(['docker', *args], capture_output=True, text=True, check=check)


def setup():
    """Create the internal network and start the allowlist proxy on it.

    The proxy is started on the default bridge (which has internet) and then
    ALSO connected to the internal network, so it can both reach the model API
    and be reached by the agents by name."""
    teardown()  # remove any leftovers from an interrupted previous run

    # Internal network: containers on it get no external connectivity.
    _docker('network', 'create', '--internal', NETWORK)

    # Proxy container: default bridge (internet) + our CONNECT proxy script.
    allowed = ','.join(config.ALLOWED_EGRESS_HOSTS)
    _docker('run', '-d', '--name', PROXY_NAME,
            '-e', f'ALLOWED_HOSTS={allowed}',
            '-e', f'PROXY_PORT={PROXY_PORT}',
            '-v', f'{PROXY_SCRIPT}:/proxy_server.py:ro',
            PROXY_IMAGE, 'python', '/proxy_server.py')

    # Attach the proxy to the internal network too, so agents can reach it.
    _docker('network', 'connect', NETWORK, PROXY_NAME)

    time.sleep(1)  # let the proxy start listening before the first agent runs
    print(f'Egress isolation on: agents may reach only {config.ALLOWED_EGRESS_HOSTS}')


def agent_docker_args():
    """`docker run` args that isolate one agent: internal network only, with
    HTTP(S)_PROXY pointing at the allowlist proxy (both upper- and lower-case,
    since clients differ on which they read)."""
    proxy_url = f'http://{PROXY_NAME}:{PROXY_PORT}'
    return ['--network', NETWORK,
            '-e', f'HTTP_PROXY={proxy_url}', '-e', f'HTTPS_PROXY={proxy_url}',
            '-e', f'http_proxy={proxy_url}', '-e', f'https_proxy={proxy_url}',
            '-e', 'NO_PROXY=localhost,127.0.0.1',
            '-e', 'no_proxy=localhost,127.0.0.1']


def teardown():
    """Remove the proxy and the internal network (idempotent). Force-removes
    ANY container still attached to the network first — otherwise 'network rm'
    fails with 'network in use' (a stray agent/proxy left by a crashed run),
    the network survives, and the next 'network create' hits 'already exists'
    and aborts the whole run."""
    _docker('rm', '-f', PROXY_NAME, check=False)
    attached = subprocess.run(
        ['docker', 'network', 'inspect', NETWORK, '-f',
         '{{range .Containers}}{{.ID}} {{end}}'],
        capture_output=True, text=True).stdout.split()
    if attached:
        _docker('rm', '-f', *attached, check=False)
    _docker('network', 'rm', NETWORK, check=False)
