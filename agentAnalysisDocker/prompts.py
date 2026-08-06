"""The three agent prompts, adapted for the OpenCode/workspace setup.

The agents now read their material from files in the container workspace
instead of having it pasted into the prompt, so each prompt tells the agent
WHERE to look. All three end with the shared VERDICT_FORMAT block.

Layout the prompts assume inside the container:
  agent 1:  /work/_CHANGES   the commit's changes (the workspace holds nothing else)
  agent 2:  /work            the repository, plus /changes with the same material
                             (kept outside /work: Docker cannot create a mountpoint
                             inside a read-only bind mount)
  agent 3:  /work            the repository only, no changes anywhere
Each file of the commit gets its own folder with before.txt / after.txt / diff.txt.
"""
from verdict import VERDICT_FORMAT

# Agent 1 — the changes only. The workspace contains ONLY _CHANGES (no repo).
PROMPT_1 = """You are a security code reviewer. The workspace contains the code \
before and after a single commit, plus its diff, for one or more files, under \
the _CHANGES folder (one subfolder per file, each with before.txt, after.txt \
and diff.txt). No other context is given — not the project name, not the real \
file paths.

Read those files and decide whether this commit fixes a security vulnerability.
- If yes, classify it with the most accurate CWE (Common Weakness \
Enumeration) identifier(s) — one, or several if more than one genuinely applies.
- If no (e.g. a feature, a refactor, or a non-security bug fix), say so.""" \
    + VERDICT_FORMAT

# Agent 2 — the changes AND the surrounding repository to explore.
PROMPT_2 = """You are a security code reviewer. The workspace is a software \
repository, checked out at the version BEFORE a single commit. That commit's \
code before and after, plus its diff, are provided separately in the \
/changes folder (one subfolder per file, each with before.txt, after.txt and \
diff.txt).

Explore the repository as much as you find useful, and use the files in \
/changes to decide whether that commit fixes a security vulnerability.
- If yes, classify it with the most accurate CWE (Common Weakness \
Enumeration) identifier(s) — one, or several if more than one genuinely applies.
- If no (e.g. a feature, a refactor, or a non-security bug fix), say so.""" \
    + VERDICT_FORMAT

# Agent 3 — the repository only, no diff, no hint (zero-day style).
PROMPT_3 = """You are a security code reviewer. The workspace is a software \
repository. You are given no commit, no diff, and no hint of where to look — \
find it yourself, as if hunting for an unreported (zero-day) vulnerability.

Explore the repository and decide whether it contains a security vulnerability.
- If yes, classify it with the most accurate CWE (Common Weakness \
Enumeration) identifier(s) — one, or several if more than one genuinely applies.
- If you explore and find nothing you are confident about, say so rather than \
guessing.""" \
    + VERDICT_FORMAT

PROMPTS = {'agent1': PROMPT_1, 'agent2': PROMPT_2, 'agent3': PROMPT_3}
