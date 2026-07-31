"""Adapter for `mcp` 2.x — protocol revision 2026-07-28. snake_case field names.

A line-for-line counterpart to `legacy.py`. It reads only the modern spelling of each field,
deliberately: `require()` raises when none of the given names is present, so pointing a
modern adapter at a legacy object fails at discovery — loudly, before any spend — rather
than defaulting its way to a report that scores every server clean.

Field names below were read off the released `mcp` 2.0.0, not inferred from the changelog:

    Tool               inputSchema -> input_schema, outputSchema -> output_schema
    ToolAnnotations    readOnlyHint -> read_only_hint, destructiveHint -> destructive_hint
    InitializeResult   protocolVersion -> protocol_version, serverInfo -> server_info
    ToolsCapability    listChanged -> list_changed
    Resource           mimeType -> mime_type
    ResourceTemplate   uriTemplate -> uri_template
    ListToolsResult    nextCursor -> next_cursor

`ListToolsResult` also gained `cache_scope` and `ttl_ms`. They are deliberately not mapped:
they describe a *listing*, not a tool, so `ToolInfo` has nowhere to put them, and inventing
a home for them here would be modelling the SDK instead of the protocol.
"""

from __future__ import annotations

from typing import Any, Literal

from mcp_gauntlet.adapters.base import meta_of, require
from mcp_gauntlet.content import block_text
from mcp_gauntlet.models import PromptArgumentInfo, PromptInfo, ResourceInfo, ServerInfo, ToolInfo


def _either(obj: Any, *names: str, default: Any) -> Any:
    """A live-result read: first present name wins, and a mapping is accepted too.

    Same rationale as the legacy adapter's: `require()` raises, which is right during
    discovery and wrong here, where `robustness.py` reads last — after a paid evaluation —
    and a raise would throw the whole run away. Both spellings are accepted so a
    mis-detected era yields a suspicious number rather than a lost report.
    """
    for name in names:
        value = getattr(obj, name, None)
        if value is None and isinstance(obj, dict):
            value = obj.get(name)
        if value is not None:
            return value
    return default


class ModernAdapter:
    era: Literal["legacy", "modern"] = "modern"
    # Verified against 2.0.0: the module still exists and still does
    # `logger = logging.getLogger(__name__)`, so the name is unchanged across the eras.
    stdio_logger_name = "mcp.client.stdio"

    def tool_info(self, tool: Any) -> ToolInfo:
        # As in the legacy adapter: `annotations` is legitimately None on most tools, so the
        # hints come off it defensively. require() here would raise on the ordinary case.
        annotations = getattr(tool, "annotations", None)
        return ToolInfo(
            name=require(tool, "name"),
            description=require(tool, "description", default=None),
            input_schema=dict(require(tool, "input_schema") or {}),
            title=require(tool, "title", default=None),
            annotation_title=getattr(annotations, "title", None),
            output_schema=dict(require(tool, "output_schema", default=None) or {}),
            read_only_hint=getattr(annotations, "read_only_hint", None),
            destructive_hint=getattr(annotations, "destructive_hint", None),
            meta=meta_of(tool),
        )

    def server_info(self, init: Any) -> ServerInfo:
        info = require(init, "server_info")
        version = require(init, "protocol_version", default=None)
        return ServerInfo(
            name=require(info, "name", default=None),
            version=require(info, "version", default=None),
            title=require(info, "title", default=None),
            instructions=require(init, "instructions", default=None),
            protocol_version=str(version) if version else None,
        )

    def prompt_info(self, prompt: Any) -> PromptInfo:
        arguments = [
            PromptArgumentInfo(
                name=require(arg, "name", default="") or "",
                description=require(arg, "description", default=None),
                required=bool(require(arg, "required", default=False)),
            )
            for arg in (require(prompt, "arguments", default=None) or [])
        ]
        return PromptInfo(
            name=require(prompt, "name"),
            title=require(prompt, "title", default=None),
            description=require(prompt, "description", default=None),
            arguments=arguments,
            meta=meta_of(prompt),
        )

    def prompt_result(self, result: Any) -> tuple[list[str], str | None, dict[str, Any]]:
        messages = [
            text
            for message in (require(result, "messages", default=None) or [])
            if (text := block_text(getattr(message, "content", None)))
        ]
        return messages, require(result, "description", default=None), meta_of(result)

    def resource_info(self, resource: Any, *, is_template: bool) -> ResourceInfo:
        uri = require(resource, "uri_template" if is_template else "uri", default="")
        return ResourceInfo(
            name=require(resource, "name", default="") or "",
            title=require(resource, "title", default=None),
            uri=str(uri or ""),
            description=require(resource, "description", default=None),
            mime_type=require(resource, "mime_type", default=None),
            is_template=is_template,
            meta=meta_of(resource),
        )

    def next_cursor(self, page: Any) -> str | None:
        cursor = require(page, "next_cursor", default=None)
        return str(cursor) if cursor else None

    def page_params(self, cursor: str | None) -> dict[str, Any]:
        """Keyword arguments requesting one page of a paginated list.

        The bare ``cursor=`` overload the legacy adapter avoids is gone entirely in 2.0, so
        `params` is the only form. Sending nothing at all for the first page keeps that
        request identical in shape to the legacy one.
        """
        from mcp import types

        return {} if cursor is None else {"params": types.PaginatedRequestParams(cursor=cursor)}

    def list_changed(self, init: Any) -> bool:
        capabilities = getattr(init, "capabilities", None)
        tools = getattr(capabilities, "tools", None)
        return bool(getattr(tools, "list_changed", False))

    # ------------------------------------------------------------- live results
    # No require() below this line, for the reason given on `_either`.

    def result_is_error(self, result: Any) -> bool:
        return bool(_either(result, "is_error", "isError", default=False))

    def result_content(self, result: Any) -> list[Any]:
        return list(_either(result, "content", default=None) or [])

    def result_structured(self, result: Any) -> Any:
        return _either(result, "structured_content", "structuredContent", default=None)

    def asks_for_input(self, result: Any) -> bool:
        """Whether the server answered "I need something from a human" (MRTR).

        This is the modern era's whole point for this method: 2026-07-28 forbids a server
        pushing elicitation or sampling at the client, so the request comes back inside an
        ordinary tool result as `result_type: "input_required"`. The harness declines it the
        same way it declined the pushed form, and the decline is attributed to itself rather
        than charged to the server's Tool Reliability.
        """
        if result is None:
            return False
        if _either(result, "result_type", "resultType", default=None) == "input_required":
            return True
        return bool(_either(result, "input_requests", "inputRequests", default=None))

    def protocol_error_type(self) -> type[BaseException]:
        from mcp.shared.exceptions import McpError

        return McpError
