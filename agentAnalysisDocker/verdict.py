"""The shared answer format the agents must end with, and its parser.

Same contract as the old agentAnalysis tool: every agent, whatever it does in
between, must finish with a fixed VERDICT block, so one parser turns any of
their free-text answers into a structured (found, cwe_id, cwe_name) result.
Copied here (rather than imported) so this tool stands on its own.
"""
import re

VERDICT_FORMAT = """

You are running headless: there is no user, and no question of yours can ever
be answered. Never ask whether to continue or what to focus on — decide by
yourself and carry on until the analysis is done. Take all the time and tool
calls you need, then commit to a conclusion: stopping to ask something is the
one thing that makes this run useless.

You may reason above, but you MUST end your entire answer with exactly this
block, using these exact field names, each on its own line, with nothing
after it:

VULNERABILITY_FOUND: yes or no
CWE_ID: the CWE identifier(s), e.g. CWE-79 — or several comma-separated, like
"CWE-190, CWE-681"; or "none" if VULNERABILITY_FOUND is no
CWE_NAME: the matching short CWE name(s), comma-separated in the same order
(e.g. "Cross-Site Scripting"), or "none"

List every CWE that genuinely applies, most specific first. A single one is
fine when only one applies; do not pad the list."""


def _extract_field(text, field_name):
    """Find `FIELD_NAME: value` anywhere in `text` (case-insensitive, tolerant
    of markdown **bold** around the field name). None if not present."""
    m = re.search(rf'\**{field_name}\**\s*:\s*\**\s*([^\n*]+)', text or '', re.IGNORECASE)
    return m.group(1).strip() if m else None


def parse_verdict(response_text):
    """Extract (found, cwe_id, cwe_name) from an agent's response. Each is None
    if that field is missing or explicitly "none" — which also covers a
    response that ignored the format entirely (all three come back None)."""
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
