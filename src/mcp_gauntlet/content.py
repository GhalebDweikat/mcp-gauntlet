"""Pulling every server-authored string out of an MCP content block.

A content block is not always a ``TextContent``. An *embedded resource* carries its text one
level down (``block.resource.text``), and a *resource link* advertises its target through
title/name/description/uri — all of which reach the model. Reading only a top-level
``.text`` drops those silently, which is both a hole in the transcript and, more
importantly, a hole in every scan fed from it.

It lives in its own module because the same blocks arrive by two routes — tool results and
prompt messages — and the two callers can't import each other.
"""

from __future__ import annotations

from typing import Any

# `text` first for the common case; the rest are what the other block types carry. The SDK's
# own display helper prefers `title` over `name`, so both are read.
_BLOCK_FIELDS = ("text", "title", "name", "description", "uri")
_RESOURCE_FIELDS = ("text", "uri")


def _strings(obj: Any, fields: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for field in fields:
        value = getattr(obj, field, None)
        if value is None:
            continue
        text = value if isinstance(value, str) else str(value)
        if text:
            out.append(text)
    return out


def block_text(block: Any) -> str | None:
    """*All* server-authored text on one content block, or None if it carries none.

    Collects every surface rather than returning the first one found. MCP content models
    permit extra fields, so a server can hang a harmless top-level ``text`` on an embedded
    resource: a first-match reader takes that decoy while a spec-compliant client renders
    the poisoned ``resource.text`` to the model.
    """
    parts = _strings(block, _BLOCK_FIELDS)
    resource = getattr(block, "resource", None)
    if resource is not None:
        parts.extend(_strings(resource, _RESOURCE_FIELDS))
        # A blob is base64, not model-readable prose: identify it rather than decode it.
        if getattr(resource, "blob", None) is not None:
            parts.append("[binary resource]")
    return "\n".join(dict.fromkeys(parts)) if parts else None
