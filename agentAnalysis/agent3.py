"""Agent 3 — repository navigation only.

The agent receives NO code sections, no diff, no hint of where the fix is:
just the instructions and the ability to explore the repository (cloned and
checked out at the PARENT of the fix commit, the still-vulnerable version)
through the list_dir / read_file tools.

No memory: this agent knows nothing of agents 1 and 2 — the tool loop starts
from a brand-new conversation containing only this prompt."""
from common import run_tool_loop

# Fill in the instructions for this agent. Nothing is appended below this
# text: the repository reachable through the tools is the only material.
PROMPT_3 = """<WRITE PROMPT 3 HERE>"""


def run(api_key, repo_dir):
    """`repo_dir` is the temporary clone checked out at the parent commit.
    Runs the tool-calling loop and returns the agent's final answer."""
    return run_tool_loop(api_key, PROMPT_3, repo_dir)
