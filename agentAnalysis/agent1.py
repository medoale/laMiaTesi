"""Agent 1 — before/after/diff only.

Receives the code_before, code_after and diff of every file touched by one
fix commit, and nothing else: no repository name, no file paths, no CVE
metadata, no filesystem access. One stateless API call per commit."""
from common import VERDICT_FORMAT, format_code_sections, single_completion

# The numbered code sections (FILE 1, FILE 2, ...) are appended below this
# text automatically; VERDICT_FORMAT fixes the required answer shape.
PROMPT_1 = """You are a security code reviewer. Below is the code before and \
after a single commit, plus its diff, for one or more files from a software \
project. No other context is given — not the project name, not the file paths.

Task: decide whether this commit fixes a security vulnerability.
- If yes, classify it with the single most accurate CWE (Common Weakness \
Enumeration) identifier.
- If no (e.g. a feature, a refactor, or a non-security bug fix), say so.""" \
    + VERDICT_FORMAT


def run(api_key, changes):
    """`changes` is the list of (code_before, code_after, diff) rows of one
    commit. Builds the blind prompt and sends it as a single stateless
    completion. Returns the agent's answer text."""
    prompt = PROMPT_1 + format_code_sections(changes)
    return single_completion(api_key, prompt)
