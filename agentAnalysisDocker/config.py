"""Central configuration for the Docker/OpenCode agent pipeline.

Everything the pipeline needs to find on the host lives here: the sampled
commits (ground_truth.csv, reused from the old agentAnalysis tool), the
CVEfixes database (for the code changes and the parent commit), the Docker
image, the model, and the OpenRouter key. Keeping it in one place means the
rest of the code never hard-codes a path or a name.
"""
from configparser import ConfigParser
from pathlib import Path

# --- Layout ------------------------------------------------------------------
# This tool lives in laMiaTesi/agentAnalysisDocker/. The data it reuses lives
# in the sibling trees, resolved relative to this file so it works on any
# machine with the same repository layout.
BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent

# Selection of (repo, commit) to run on: the ground truth, kept LOCAL to this
# folder so the tool is self-contained. build_ground_truth.py (re)generates it
# from repo_analysis_v2.csv + the database. We only read its keys here; the CWE
# columns are the answer key and are never shown to the agents.
GROUND_TRUTH_CSV = BASE_DIR / 'ground_truth.csv'

# Input to build_ground_truth.py: the per-commit repository-size measurements
# the sample is drawn from. Read from the ORIGINAL produced by the cveFixes
# size analyzer (authoritative source), not a copy.
REPO_ANALYSIS_CSV = REPO_ROOT / 'cveFixes' / 'CVEfixes' / 'Code' / 'Data' / 'repo_analysis_v2.csv'

# CVEfixes database: the one external dependency (too large to copy, ~9 GB).
# Source of the per-commit code changes (file_change), each commit's parent
# (commits), and, for build_ground_truth.py only, the CVE/CWE answer key.
DB_PATH = REPO_ROOT / 'cveFixes' / 'CVEfixes' / 'Code' / 'Data' / 'CVEfixes.db'

# All outputs (answers + transcripts + the resumable log) are written here, on
# this machine, under a per-model subfolder so different models never mix.
OUTPUTS_DIR = BASE_DIR / 'outputs'

# --- Docker / OpenCode -------------------------------------------------------
# The prebuilt OpenCode sandbox image (see docs.docker.com/ai/sandboxes).
DOCKER_IMAGE = 'docker/sandbox-templates:opencode'

# Label put on every agent container, so an interrupted run can find and kill
# them all — a container keeps running in the Docker daemon after main.py is
# Ctrl+C'd, and would keep hitting the shared cluster until stopped.
CONTAINER_LABEL = 'tool=agentAnalysisDocker'

# The entrypoint script mounted into every container (runs OpenCode headlessly).
ENTRYPOINT_SH = BASE_DIR / 'entrypoint.sh'

# --- Model provider ----------------------------------------------------------
# Switch backend here: OpenRouter (cloud) or Polito (the local LiteLLM proxy on
# the cluster, OpenAI-compatible). Everything else is derived from this: the
# model, the ini section holding the key, the env var OpenCode reads the key
# from, the host the agent may reach, and (for a custom endpoint) the
# opencode.json that defines the provider.
PROVIDER = 'polito'   # 'openrouter' | 'polito'

_PROVIDERS = {
    'openrouter': {
        'model': 'openrouter/openai/gpt-oss-20b:free',
        'ini_section': 'OpenRouter',
        'key_env': 'OPENROUTER_API_KEY',   # OpenCode reads OpenRouter from this
        'allowed_host': 'openrouter.ai',
        'opencode_config': None,           # OpenRouter is built into OpenCode
    },
    'polito': {
        # Models on the proxy: deepseek-v4, gpt-oss-120b, qwen3-235b, gemma-4-31b
        'model': 'polito/gemma-4-31b',
        'ini_section': 'Polito',
        'key_env': 'POLITO_API_KEY',       # referenced by opencode.json
        'allowed_host': 'llm.polito.it',
        'opencode_config': BASE_DIR / 'opencode.json',
    },
}
_P = _PROVIDERS[PROVIDER]
OPENCODE_MODEL = _P['model']
INI_SECTION = _P['ini_section']
KEY_ENV = _P['key_env']
OPENCODE_CONFIG_FILE = _P['opencode_config']

# Seconds a single container may run before we give up and tear it down.
CONTAINER_TIMEOUT = 1800
# Seconds allowed for cloning one repository.
CLONE_TIMEOUT = 1800

# --- Internet access ---------------------------------------------------------
# The agent needs the network to reach the model API, but must NOT be able to
# look up the CVE/fix online (that would let agent3 cheat). network_rules.py
# enforces this with an egress proxy: the agent runs on a Docker --internal
# network and can reach only the hosts below (the model API), nothing else.
#
# ISOLATE_NETWORK toggles it: True in real runs; set False only to test the
# OpenCode container without the proxy (then the agent has full internet).
ISOLATE_NETWORK = True

# Hosts the agent is allowed to reach: only the selected provider's API host.
ALLOWED_EGRESS_HOSTS = [_P['allowed_host']]


# --- Credentials -------------------------------------------------------------
# Same ini files as the rest of the project; the key is under the selected
# provider's section (INI_SECTION). Tried in order so it works on any machine.
CVEFIXES_INI_CANDIDATES = [
    '/home/medo/.CVEfixes.ini',
    '/home/students/s346086/AlessandroMedvescek/CVEfixes.ini',
]


def read_api_key():
    """Read the api_key of the selected provider's section (e.g. [Polito]).
    Returns None if absent."""
    config = ConfigParser()
    if config.read(CVEFIXES_INI_CANDIDATES):
        key = config.get(INI_SECTION, 'api_key', fallback=None)
        if key and key != 'None':
            return key
    return None


def model_slug():
    """Filesystem-safe version of OPENCODE_MODEL, for the output subfolder."""
    import re
    return re.sub(r'[^A-Za-z0-9._-]+', '_', OPENCODE_MODEL)
