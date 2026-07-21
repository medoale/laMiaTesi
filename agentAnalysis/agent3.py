"""Agent 3 — repository navigation only.

The agent receives NO code sections, no diff, no hint of where the fix is:
just the instructions and the ability to explore the repository (cloned and
checked out at the PARENT of the fix commit, the still-vulnerable version)
through the list_dir / read_file tools.

No memory: this agent knows nothing of agents 1 and 2 — the tool loop starts
from a brand-new conversation containing only this prompt."""
from common import VERDICT_FORMAT, run_tool_loop

# Nothing is appended below this text: the repository reachable through the
# tools is the only material. VERDICT_FORMAT fixes the required answer shape.
PROMPT_3 = """You are a security code reviewer with list_dir and read_file \
tools to explore a software repository. You are given no commit, no diff, \
and no hint of where to look — find it yourself, as if hunting for an \
unreported (zero-day) vulnerability.

Areas that often reward attention: input parsing and validation, \
authentication and authorization, deserialization, file path handling, \
command or query construction, cryptographic code — but the vulnerability \
may be anywhere.

Task: decide whether this codebase contains a security vulnerability.
- If yes, classify it with the single most accurate CWE (Common Weakness \
Enumeration) identifier.
- If you explore and find nothing you are confident about, say so rather \
than guessing.

Use your tool calls efficiently — your budget is limited.""" \
    + VERDICT_FORMAT


def run(api_key, repo_dir):
    """`repo_dir` is the temporary clone checked out at the parent commit.
    Runs the tool-calling loop and returns the agent's final answer."""
    return run_tool_loop(api_key, PROMPT_3, repo_dir)
