"""Gemini backend: a drop-in alternative to common.py that talks to Google's
Gemini API through its NATIVE generateContent endpoint.

Same public interface as common.py (VERDICT_FORMAT, format_code_sections,
single_completion, run_tool_loop, parse_verdict, read_api_key, ...), so main.py
can switch backend with a single flag (see USE_GEMINI in main.py) without any
other change. Every entry point is STATELESS across prompts, exactly like
common.py.

Differences from common.py:
  1. Endpoint/protocol: Google's native `models/<model>:generateContent`, which
     uses contents/parts and functionCall/functionResponse instead of OpenAI's
     messages/tool_calls. Translated here so run_tool_loop behaves the same.
  2. Rate limits (Google AI Studio free tier, per whole project):
       - RPM (requests per minute): if exceeded, the block is brief. Requests
         are pre-throttled to stay under it (see _throttle), and a 429 that is
         a per-minute quota is retried after the delay the server asks for.
       - RPD (requests per day): if exceeded, the key stops answering until the
         quota resets at midnight Pacific time. Retrying is pointless, so such
         a 429 raises immediately with a clear message; the pipeline is
         resumable, so the run simply continues the next day.
"""
import json
import re
import time
from configparser import ConfigParser
from pathlib import Path

import requests

# Shared verdict format every agent's prompt ends with (identical to
# common.py, so the same parse_verdict reads answers from either backend).
VERDICT_FORMAT = """

You may reason above, but you MUST end your entire answer with exactly this
block, using these exact field names, each on its own line, with nothing
after it:

VULNERABILITY_FOUND: yes or no
CWE_ID: the CWE identifier (e.g. CWE-79), or "none" if VULNERABILITY_FOUND is no
CWE_NAME: the short CWE name (e.g. "Cross-Site Scripting"), or "none"

Use the single CWE that best matches. If more than one seems to apply, pick
the most specific one."""

# Candidate paths of the ini file. Same files as common.py; the Gemini API key
# lives in a [Gemini] section (key: api_key) rather than [OpenRouter].
CVEFIXES_INI_CANDIDATES = [
    '/home/medo/.CVEfixes.ini',
    '/home/students/s346086/AlessandroMedvescek/CVEfixes.ini',
]

# The model every agent uses, and the native endpoint template. gemini-3.5-flash
# is the current standard Flash model (July 2026). The API key is passed as a
# query parameter, as the native endpoint expects.
MODEL = 'gemini-3.5-flash'
GEMINI_URL_TEMPLATE = 'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent'

# --- Free-tier rate limits (Google AI Studio) for gemini-3.5-flash -----------
# Per WHOLE project; exceeding returns 429 RESOURCE_EXHAUSTED.
#   RPM (requests/minute):       10
#   TPM (tokens/minute):         250,000
#   RPD (requests/day):          1,500   (resets at midnight Pacific)
#   Context window per request:  1,000,000 tokens  (no big-commit 400s)
# RPM is enforced proactively by _throttle; RPD is handled reactively — a
# per-day 429 stops the run to resume next day (see _post / _is_daily_quota).
FREE_TIER_RPM = 10
FREE_TIER_RPD = 1500     # documentation only; not enforced in-process

# Minimum seconds between the START of consecutive requests, to stay under
# FREE_TIER_RPM. The 0.9 factor keeps a safety margin so clock jitter or a
# burst of retries cannot tip us just over the cap into a 429.
MIN_REQUEST_INTERVAL = 60.0 / (FREE_TIER_RPM * 0.9)

TEMPERATURE = 0          # reproducibility: same input -> same output as far as possible
REQUEST_TIMEOUT = 600    # seconds to wait for a single completion
MAX_RETRIES = 5          # attempts per API call before giving up
RETRY_BACKOFF_BASE = 15  # base seconds for the growing pause between retries
RETRY_WAIT_CAP = 120     # never wait longer than this on a single retry

# Safety limits for the navigation tools (see common.py). Each tool turn is one
# request against the daily RPD budget, so a high MAX_TOOL_TURNS spends the free
# quota faster.
MAX_TOOL_TURNS = 30
READ_FILE_MAX_CHARS = 50_000


def read_api_key():
    """Read [Gemini] api_key from CVEFIXES_INI_CANDIDATES. Returns None if absent.
    Get a free key at https://aistudio.google.com/apikey ."""
    config = ConfigParser()
    if config.read(CVEFIXES_INI_CANDIDATES):
        key = config.get('Gemini', 'api_key', fallback=None)
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


# Module-level timestamp of the last request start, used by _throttle to space
# requests. The pipeline is single-threaded, so a plain global is enough.
_last_request_start = 0.0


def _throttle():
    """Sleep so consecutive requests start at least MIN_REQUEST_INTERVAL apart,
    keeping the request rate under the free-tier RPM. Measured from the START
    of the previous request, so the cap holds even when a request returns fast
    (a quick error, or a retry)."""
    global _last_request_start
    wait = MIN_REQUEST_INTERVAL - (time.monotonic() - _last_request_start)
    if wait > 0:
        time.sleep(wait)
    _last_request_start = time.monotonic()


def _is_daily_quota(body):
    """True if a 429 body is a per-DAY quota (RPD), which only resets at
    midnight Pacific time — retrying is useless, so we stop. A per-minute
    quota (RPM) instead just needs a short wait."""
    return 'perday' in json.dumps(body).lower()


def _retry_delay(body, attempt):
    """Seconds to wait before retrying a 429/5xx. Honors the RetryInfo delay
    Gemini puts in the error body (telling us exactly how long the per-minute
    window lasts), otherwise a linearly growing pause. Capped."""
    for detail in body.get('error', {}).get('details', []):
        if str(detail.get('@type', '')).endswith('RetryInfo'):
            m = re.match(r'(\d+(?:\.\d+)?)s', str(detail.get('retryDelay', '')))
            if m:
                return min(RETRY_WAIT_CAP, max(1.0, float(m.group(1))))
    return min(RETRY_WAIT_CAP, RETRY_BACKOFF_BASE * (attempt + 1))


def _error_message(response):
    """Best-effort human message from an error response body."""
    try:
        return response.json()['error']['message']
    except (ValueError, KeyError, TypeError):
        return response.text[:300]


def _post(api_key, contents, tools=None):
    """One native generateContent call, throttled and retried. Returns the
    response `content` object (with its `parts`) from the first candidate.

    RPM 429 -> wait the server-asked delay and retry. RPD 429 -> raise at once
    (only resets at midnight PT). Other 4xx -> raise. 5xx -> retry."""
    url = GEMINI_URL_TEMPLATE.format(model=MODEL) + f'?key={api_key}'
    payload = {'contents': contents,
               'generationConfig': {'temperature': TEMPERATURE},
               # This is authorized security research (classifying already-fixed
               # CVEs), so relax the category filters that would otherwise block
               # vulnerability/exploit code as "dangerous content". Note: this
               # only lifts category blocks, not the model's own refusals.
               'safetySettings': [
                   {'category': c, 'threshold': 'BLOCK_NONE'} for c in (
                       'HARM_CATEGORY_HARASSMENT', 'HARM_CATEGORY_HATE_SPEECH',
                       'HARM_CATEGORY_SEXUALLY_EXPLICIT',
                       'HARM_CATEGORY_DANGEROUS_CONTENT',
                       'HARM_CATEGORY_CIVIC_INTEGRITY')
               ]}
    if tools:
        payload['tools'] = tools

    last_error = None
    for attempt in range(MAX_RETRIES):
        try:
            _throttle()
            r = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
            if r.status_code == 429:
                body = r.json()
                if _is_daily_quota(body):
                    raise RuntimeError('Gemini daily quota (RPD) exhausted — '
                                       'resets at midnight Pacific time; resume then')
                last_error = 'HTTP 429 (per-minute)'
                time.sleep(_retry_delay(body, attempt))
                continue
            if r.status_code >= 500:
                last_error = f'HTTP {r.status_code}'
                time.sleep(min(RETRY_WAIT_CAP, RETRY_BACKOFF_BASE * (attempt + 1)))
                continue
            if r.status_code >= 400:
                raise RuntimeError(f'Gemini {r.status_code}: {_error_message(r)}')
            candidates = r.json().get('candidates')
            if not candidates:
                # No candidate (e.g. a safety block or an empty response).
                last_error = f'no candidates: {r.json().get("promptFeedback", r.json())}'
                time.sleep(_retry_delay(r.json(), attempt))
                continue
            return candidates[0].get('content', {}) or {}
        except requests.RequestException as e:
            # Redact the key: it is in the URL, which requests echoes in errors.
            last_error = str(e).replace(api_key, 'KEY')
            time.sleep(5)
    raise RuntimeError(f'Gemini call failed after retries: {last_error}')


def _content_text(content):
    """Concatenate the text of all text parts of a response content."""
    return ''.join(p['text'] for p in content.get('parts', []) if 'text' in p)


def _content_calls(content):
    """The functionCall objects ({name, args}) among a content's parts."""
    return [p['functionCall'] for p in content.get('parts', []) if 'functionCall' in p]


def single_completion(api_key, prompt):
    """Stateless one-shot call: the request contains ONLY this prompt (no
    history, no tools). Used by agent 1. Returns the response text."""
    content = _post(api_key, [{'role': 'user', 'parts': [{'text': prompt}]}])
    return _content_text(content)


# ---------------------------------------------------------------------------
# Filesystem tools for repo navigation (agents 2 and 3). Same sandboxing as
# common.py (.git blocked, no path escapes); only the tool-declaration shape
# differs (Gemini's functionDeclarations instead of OpenAI's function schema).
# ---------------------------------------------------------------------------

TOOL_DECLARATIONS = [{
    'functionDeclarations': [
        {
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
        {
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
    ]
}]


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


def _execute_tool(repo_dir, name, args):
    """Run one tool call (args is a dict). Any error is returned as text so the
    model can recover instead of crashing the loop."""
    try:
        path = (args or {}).get('path', '.')
        if name == 'list_dir':
            return _tool_list_dir(repo_dir, path)
        if name == 'read_file':
            return _tool_read_file(repo_dir, path)
        return f'ERROR: unknown tool {name}'
    except (ValueError, OSError) as e:
        return f'ERROR: {e}'


def run_tool_loop(api_key, prompt, repo_dir):
    """Agentic loop with repo navigation, stateless across prompts.

    The conversation starts fresh with ONLY `prompt`. While the model answers
    with functionCall parts, each call is executed on the cloned repo and its
    result fed back as a functionResponse; the loop ends when the model
    produces a text answer with a valid VERDICT_FORMAT block. The history lives
    only inside this single loop.

    A text response with no functionCall AND no valid VERDICT_FORMAT block is
    treated as an invalid turn: the model is asked to retry. If it is still not
    answering after MAX_TOOL_TURNS, one last request is sent WITHOUT tools to
    force a final answer."""
    contents = [{'role': 'user', 'parts': [{'text': prompt}]}]
    for _ in range(MAX_TOOL_TURNS):
        content = _post(api_key, contents, TOOL_DECLARATIONS)
        calls = _content_calls(content)
        if not calls:
            text = _content_text(content)
            if _extract_field(text, 'VULNERABILITY_FOUND') is not None:
                return text   # a real final answer: the agent is done.

            # Neither a tool call nor a valid final answer: ask to retry.
            contents.append(content if content.get('parts') else
                            {'role': 'model', 'parts': [{'text': text}]})
            contents.append({
                'role': 'user',
                'parts': [{'text': 'Your last message was neither a valid tool '
                           'call nor a final answer in the required format. '
                           'Either call a tool properly, or give your final '
                           'answer ending with the exact VERDICT_FORMAT block.'}],
            })
            continue

        # Keep the model's functionCall turn, then answer every call.
        contents.append(content)
        responses = []
        for call in calls:
            name = call.get('name')
            result = _execute_tool(repo_dir, name, call.get('args'))
            responses.append({'functionResponse': {'name': name,
                                                    'response': {'result': result}}})
        contents.append({'role': 'user', 'parts': responses})

    # Tool budget exhausted: ask for a conclusion, without tools this time.
    contents.append({'role': 'user',
                     'parts': [{'text': 'Tool budget exhausted. '
                                'Give your final answer now.'}]})
    content = _post(api_key, contents)
    return _content_text(content)


# ---------------------------------------------------------------------------
# Parsing the shared verdict format out of an agent's free-text response.
# Identical to common.py so results from either backend parse the same way.
# ---------------------------------------------------------------------------

def _extract_field(text, field_name):
    """Find `FIELD_NAME: value` anywhere in `text` (case-insensitive,
    tolerant of markdown **bold** around the field name) and return `value`
    up to the end of that line. None if the field is not present at all."""
    m = re.search(rf'\**{field_name}\**\s*:\s*\**\s*([^\n*]+)', text or '', re.IGNORECASE)
    return m.group(1).strip() if m else None


def parse_verdict(response_text):
    """Extract (found, cwe_id, cwe_name) from an agent's response, per
    VERDICT_FORMAT. Each is None if that field is missing or explicitly
    "none" — which also covers a response that ignored the format entirely."""
    if not response_text:
        return None, None, None

    found_str = _extract_field(response_text, 'VULNERABILITY_FOUND')
    cwe_id = _extract_field(response_text, 'CWE_ID')
    cwe_name = _extract_field(response_text, 'CWE_NAME')

    found = found_str.strip().lower().startswith('yes') if found_str else None
    if cwe_id and cwe_id.strip().lower() == 'none':
        cwe_id = None
    if cwe_name and cwe_name.strip().lower() == 'none':
        cwe_name = None

    return found, cwe_id, cwe_name
