"""Agent 2 — before/after/diff plus repository navigation.

Same blind code sections as agent 1, but the agent can also explore the
repository (cloned and checked out at the PARENT of the fix commit, i.e. the
still-vulnerable version) through the list_dir / read_file tools.

No memory: this agent knows nothing of agent 1 — the tool loop starts from a
brand-new conversation containing only this prompt."""
from common import format_code_sections, run_tool_loop

# Fill in the instructions for this agent. The numbered code sections are
# appended below this text; the navigation tools are advertised to the model
# by the API request itself (see TOOL_SCHEMAS in common.py).
PROMPT_2 = """<WRITE PROMPT 2 HERE>"""


def run(api_key, changes, repo_dir):
    """`changes` are the (code_before, code_after, diff) rows of one commit;
    `repo_dir` is the temporary clone checked out at the parent commit.
    Runs the tool-calling loop and returns the agent's final answer."""
    prompt = PROMPT_2 + format_code_sections(changes)
    return run_tool_loop(api_key, prompt, repo_dir)
