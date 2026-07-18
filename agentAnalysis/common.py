"""Shared machinery for the three agents: OpenRouter API calls, the
filesystem tools and the tool-calling loop used to navigate a cloned repo.

Every entry point here is STATELESS across prompts: each call to
`single_completion` or `run_tool_loop` builds a brand-new `messages` array, so
an agent can never see anything from a previous prompt or a previous commit.
"""
import json
import time
from configparser import ConfigParser
from pathlib import Path

import requests

# Absolute path of the ini file that holds the [OpenRouter] api_key.
CVEFIXES_INI = '/home/medo/.CVEfixes.ini'

OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions'

# The model used for every agent. Agents 2 and 3 use tool calling, so the
# model chosen here must support it (most ':free' models do not).
MODEL = 'meta-llama/llama-3.3-70b-instruct:free'

TEMPERATURE = 0        # reproducibility: same input -> same output as far as possible
REQUEST_TIMEOUT = 600  # seconds to wait for a single completion
MAX_RETRIES = 3        # attempts per API call before giving up

# Safety limits for the navigation tools. MAX_TOOL_TURNS caps how many
# request/response rounds an agent may use before being forced to answer;
# READ_FILE_MAX_CHARS truncates huge files so a single read cannot blow up
# the context window.
MAX_TOOL_TURNS = 30
READ_FILE_MAX_CHARS = 50_000


def read_api_key():
    """Read [OpenRouter] api_key from CVEFIXES_INI. Returns None if absent."""
    config = ConfigParser()
    if config.read(CVEFIXES_INI):
        key = config.get('OpenRouter', 'api_key', fallback=None)
        if key and key != 'None':
            return key
    return None


def format_code_sections(changes):
    """Turn the [(code_before, code_after, diff), ...] rows of a commit into
    the blind text block appended below the agent instructions.

    Blind means: no repository name, no file paths, no CVE metadata — the
    files are only numbered, so the agent judges the code alone."""
    parts = []
    for i, (before, after, diff) in enumerate(changes, 1):
        parts.append(f'\n\n===== FILE {i} =====\n'
                     f'--- CODE BEFORE ---\n{before}\n'
                     f'--- CODE AFTER ---\n{after}\n'
                     f'--- DIFF ---\n{diff}')
    return ''.join(parts)


def _post(api_key, payload):
    """One HTTP POST to OpenRouter with retries.

    429 (rate limit) and 5xx (server trouble) are retried with a growing
    pause; anything else that fails raises immediately. Returns the assistant
    `message` object from the first choice."""
    headers = {'Authorization': f'Bearer {api_key}'}
    last_error = None
    for attempt in range(MAX_RETRIES):
        try:
            r = requests.post(OPENROUTER_URL, json=payload, headers=headers,
                              timeout=REQUEST_TIMEOUT)
            if r.status_code == 429 or r.status_code >= 500:
                last_error = f'HTTP {r.status_code}'
                time.sleep(15 * (attempt + 1))
                continue
            r.raise_for_status()
            return r.json()['choices'][0]['message']
        except requests.RequestException as e:
            last_error = str(e)
            time.sleep(5)
    raise RuntimeError(f'OpenRouter call failed after retries: {last_error}')


def single_completion(api_key, prompt):
    """Stateless one-shot call: the request contains ONLY this prompt (no
    history, no tools). Used by agent 1. Returns the response text."""
    message = _post(api_key, {
        'model': MODEL,
        'temperature': TEMPERATURE,
        'messages': [{'role': 'user', 'content': prompt}],
    })
    return message.get('content', '')


# ---------------------------------------------------------------------------
# Filesystem tools for repo navigation (agents 2 and 3).
#
# The agent only ever sees paths RELATIVE to the repo root. `_safe_path`
# resolves every path the model asks for and refuses anything that escapes
# the repo or enters .git — .git contains the full history, including the
# fix commit itself, which would leak the answer to the agent.
# ---------------------------------------------------------------------------

# Tool schemas in the OpenAI/OpenRouter function-calling format. This is what
# the model reads to know which tools exist and how to call them.
TOOL_SCHEMAS = [
    {
        'type': 'function',
        'function': {
            'name': 'list_dir',
            'description': 'List the files and subdirectories of a directory '
                           'of the repository. Use "." for the repository root.',
            'parameters': {
                'type': 'object',
                'properties': {
                    'path': {'type': 'string',
                             'description': 'Directory path relative to the repo root'},
                },
                'required': ['path'],
            },
        },
    },
    {
        'type': 'function',
        'function': {
            'name': 'read_file',
            'description': 'Read a file of the repository. Returns its text '
                           f'content (truncated at {READ_FILE_MAX_CHARS} characters).',
            'parameters': {
                'type': 'object',
                'properties': {
                    'path': {'type': 'string',
                             'description': 'File path relative to the repo root'},
                },
                'required': ['path'],
            },
        },
    },
]


def _safe_path(repo_dir, rel_path):
    """Resolve `rel_path` inside `repo_dir`, refusing escapes and .git.
    Raises ValueError on anything outside the sandbox."""
    target = (repo_dir / rel_path).resolve()
    root = repo_dir.resolve()
    if not (target == root or root in target.parents):
        raise ValueError(f'path escapes the repository: {rel_path}')
    if '.git' in target.relative_to(root).parts:
        raise ValueError('access to .git is not allowed')
    return target


def _tool_list_dir(repo_dir, rel_path):
    """Implementation of the list_dir tool: names only, directories marked
    with a trailing '/', .git hidden."""
    target = _safe_path(repo_dir, rel_path)
    if not target.is_dir():
        return f'ERROR: not a directory: {rel_path}'
    entries = []
    for p in sorted(target.iterdir()):
        if p.name == '.git':
            continue
        entries.append(p.name + '/' if p.is_dir() else p.name)
    return '\n'.join(entries) if entries else '(empty directory)'


def _tool_read_file(repo_dir, rel_path):
    """Implementation of the read_file tool: text content, decoded leniently
    (binary bytes replaced) and truncated at READ_FILE_MAX_CHARS."""
    target = _safe_path(repo_dir, rel_path)
    if not target.is_file():
        return f'ERROR: not a file: {rel_path}'
    text = target.read_bytes().decode('utf-8', errors='replace')
    if len(text) > READ_FILE_MAX_CHARS:
        text = text[:READ_FILE_MAX_CHARS] + '\n...[truncated]'
    return text


def _execute_tool(repo_dir, name, arguments):
    """Dispatch one tool call requested by the model. Any error is returned
    as text so the model can recover instead of crashing the loop."""
    try:
        args = json.loads(arguments or '{}')
        path = args.get('path', '.')
        if name == 'list_dir':
            return _tool_list_dir(repo_dir, path)
        if name == 'read_file':
            return _tool_read_file(repo_dir, path)
        return f'ERROR: unknown tool {name}'
    except (ValueError, OSError) as e:
        return f'ERROR: {e}'


def run_tool_loop(api_key, prompt, repo_dir):
    """Agentic loop with repo navigation, stateless across prompts.

    The conversation starts fresh with ONLY `prompt`. Then, while the model
    answers with tool calls, each call is executed on the cloned repo and its
    result appended; the loop ends when the model produces a plain text
    answer. The history that accumulates here lives only inside this single
    loop — it is thrown away when the function returns.

    If the model is still calling tools after MAX_TOOL_TURNS, one last
    request is sent WITHOUT tools to force a final text answer."""
    messages = [{'role': 'user', 'content': prompt}]
    for _ in range(MAX_TOOL_TURNS):
        message = _post(api_key, {
            'model': MODEL,
            'temperature': TEMPERATURE,
            'messages': messages,
            'tools': TOOL_SCHEMAS,
        })
        tool_calls = message.get('tool_calls')
        if not tool_calls:
            # Plain text answer: the agent is done.
            return message.get('content', '')

        # The assistant message that requested the tools must stay in the
        # conversation, followed by one 'tool' message per call, otherwise
        # the API rejects the next request.
        messages.append(message)
        for call in tool_calls:
            result = _execute_tool(repo_dir, call['function']['name'],
                                   call['function'].get('arguments'))
            messages.append({
                'role': 'tool',
                'tool_call_id': call['id'],
                'content': result,
            })

    # Tool budget exhausted: ask for a conclusion, without tools this time.
    messages.append({'role': 'user',
                     'content': 'Tool budget exhausted. '
                                'Give your final answer now.'})
    message = _post(api_key, {
        'model': MODEL,
        'temperature': TEMPERATURE,
        'messages': messages,
    })
    return message.get('content', '')
