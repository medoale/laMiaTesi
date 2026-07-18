"""Agent 1 — before/after/diff only.

Receives the code_before, code_after and diff of every file touched by one
fix commit, and nothing else: no repository name, no file paths, no CVE
metadata, no filesystem access. One stateless API call per commit."""
from common import format_code_sections, single_completion

# Fill in the instructions for this agent. The numbered code sections
# (FILE 1, FILE 2, ...) are appended below this text automatically.
PROMPT_1 = """<WRITE PROMPT 1 HERE>"""


def run(api_key, changes):
    """`changes` is the list of (code_before, code_after, diff) rows of one
    commit. Builds the blind prompt and sends it as a single stateless
    completion. Returns the agent's answer text."""
    prompt = PROMPT_1 + format_code_sections(changes)
    return single_completion(api_key, prompt)
