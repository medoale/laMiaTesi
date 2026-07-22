"""Agent 2 — before/after/diff plus repository navigation.

Same blind code sections as agent 1, but the agent can also explore the
repository (cloned and checked out at the PARENT of the fix commit, i.e. the
still-vulnerable version) through the list_dir / read_file tools.

No memory: this agent knows nothing of agent 1 — the tool loop starts from a
brand-new conversation containing only this prompt."""
from common import VERDICT_FORMAT, format_code_sections, run_tool_loop

# The numbered code sections are appended below this text; the navigation
# tools are advertised to the model by the API request itself (see
# TOOL_SCHEMAS in common.py); VERDICT_FORMAT fixes the required answer shape.
PROMPT_2 = """You are a security code reviewer. Below is the code before and \
after a single commit, plus its diff, for one or more files from a software \
project. No other context is given — not the project name, not the file paths.

You also have list_dir and read_file tools to explore the surrounding \
repository, checked out at the version before this commit.

Task: decide whether this commit fixes a security vulnerability.
- If yes, classify it with the single most accurate CWE (Common Weakness \
Enumeration) identifier.
- If no (e.g. a feature, a refactor, or a non-security bug fix), say so.""" \
    + VERDICT_FORMAT


def run(api_key, changes, repo_dir):
    """`changes` are the (code_before, code_after, diff) rows of one commit;
    `repo_dir` is the temporary clone checked out at the parent commit.
    Runs the tool-calling loop and returns the agent's final answer."""
    prompt = PROMPT_2 + format_code_sections(changes)
    return run_tool_loop(api_key, prompt, repo_dir)
