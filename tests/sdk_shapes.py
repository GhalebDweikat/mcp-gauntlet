"""Stand-in SDK objects, spelled the way the installed SDK spells them.

Tests that fake an SDK object have to pick a spelling, and picking one hardcodes an era:
`mcp` 2.0 renamed every field to snake_case, so a `SimpleNamespace(inputSchema=...)` is a
1.x object and the modern adapter rightly refuses it. Before this existed, six discovery
tests failed by construction on the modern SDK — not because discovery was broken, but
because the fakes were.

Fields are written here in the **canonical (modern) snake_case** and translated down for
the legacy SDK, matching the direction the adapters and the fixture shim already map in, so
there is one translation table to be wrong in rather than three.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from mcp_gauntlet.adapters import adapter

# Canonical (modern) name -> the legacy SDK's spelling. Only fields that actually differ.
_LEGACY_NAMES = {
    "input_schema": "inputSchema",
    "output_schema": "outputSchema",
    "read_only_hint": "readOnlyHint",
    "destructive_hint": "destructiveHint",
    "idempotent_hint": "idempotentHint",
    "open_world_hint": "openWorldHint",
    "next_cursor": "nextCursor",
    "server_info": "serverInfo",
    "protocol_version": "protocolVersion",
    "mime_type": "mimeType",
    "uri_template": "uriTemplate",
    "is_error": "isError",
    "structured_content": "structuredContent",
    "result_type": "resultType",
    "input_requests": "inputRequests",
    "list_changed": "listChanged",
    "resource_templates": "resourceTemplates",
}

MODERN = adapter().era == "modern"


def shape(**fields: Any) -> Any:
    """One fake SDK object, in the installed era's spelling.

    Pass canonical snake_case names regardless of era; unknown names pass through unchanged,
    which is what makes the shared fields (`name`, `description`, `title`, `annotations`,
    `meta`) need no entry in the table.
    """
    if MODERN:
        return SimpleNamespace(**fields)
    return SimpleNamespace(**{_LEGACY_NAMES.get(key, key): value for key, value in fields.items()})
