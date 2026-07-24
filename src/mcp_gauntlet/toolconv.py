"""Convert MCP tool definitions into OpenAI-compatible function-calling schema.

MCP tool ``inputSchema`` is already JSON Schema, so it maps directly onto an
OpenAI function's ``parameters``. The one wrinkle is the tool *name*: OpenAI and
some stricter providers only accept ``[a-zA-Z0-9_-]`` and cap the length, while
MCP names can contain other characters (dots, spaces). We sanitize the name for
the model and keep a reverse map so a tool call can be dispatched back to the
real MCP tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from mcp_gauntlet.models import ToolInfo

_INVALID = re.compile(r"[^a-zA-Z0-9_-]")
_MAX_NAME = 64


def _sanitize(name: str) -> str:
    cleaned = _INVALID.sub("_", name)[:_MAX_NAME]
    return cleaned or "tool"


@dataclass
class ToolBridge:
    """OpenAI tool schemas plus a map from sanitized name back to the MCP name."""

    tools: list[dict[str, Any]] = field(default_factory=list)
    name_map: dict[str, str] = field(default_factory=dict)

    def original(self, sanitized: str) -> str:
        """Return the real MCP tool name for a name the model called."""
        return self.name_map.get(sanitized, sanitized)

    def knows(self, sanitized: str) -> bool:
        """Whether the model called a tool this server actually offered."""
        return sanitized in self.name_map


def build_tool_bridge(tools: list[ToolInfo]) -> ToolBridge:
    bridge = ToolBridge()
    used: set[str] = set()
    for tool in tools:
        name = _sanitize(tool.name)
        if name in used:  # keep names unique after sanitizing
            base = name[: _MAX_NAME - 3]
            suffix = 2
            while f"{base}_{suffix}" in used:
                suffix += 1
            name = f"{base}_{suffix}"
        used.add(name)
        bridge.name_map[name] = tool.name
        parameters = tool.input_schema or {"type": "object", "properties": {}}
        bridge.tools.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": tool.description or "",
                    "parameters": parameters,
                },
            }
        )
    return bridge
