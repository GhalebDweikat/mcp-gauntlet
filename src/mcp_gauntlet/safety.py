"""Heuristic read-only classification.

The harness runs an autonomous agent that executes real tool calls, so by default
we keep it away from tools that look like they mutate state. The check is a
conservative name/description heuristic — it over-excludes rather than risk an
unwanted side effect. ``--allow-writes`` disables the filter.
"""

from __future__ import annotations

import re

from mcp_gauntlet.models import ToolInfo

_WRITE_HINTS = re.compile(
    r"\b(create|delete|remove|update|write|set|put|post|send|toggle|drop|insert|"
    r"modify|patch|rename|move|upload|publish|reset|revoke|grant|execute|trigger|"
    r"append|edit|clear|purge|destroy|kill|stop|start|enable|disable|run)\b",
    re.IGNORECASE,
)


def looks_mutating(tool: ToolInfo) -> bool:
    return bool(_WRITE_HINTS.search(f"{tool.name} {tool.description or ''}"))


def filter_read_only(tools: list[ToolInfo]) -> tuple[list[ToolInfo], list[str]]:
    """Return (kept read-only tools, names of excluded possibly-mutating tools)."""
    kept: list[ToolInfo] = []
    excluded: list[str] = []
    for tool in tools:
        if looks_mutating(tool):
            excluded.append(tool.name)
        else:
            kept.append(tool)
    return kept, excluded
