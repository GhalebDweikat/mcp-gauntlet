"""Adapter for `mcp` 1.x — protocol revisions up to 2025-11-25. camelCase field names.

Nothing here is clever; it exists so the *modern* adapter can be written beside it and every
check downstream stays protocol-agnostic. Where a field is genuinely optional in the protocol
a default is passed explicitly and the reason is stated. Everywhere else a rename raises
rather than quietly yielding None.
"""

from __future__ import annotations

from typing import Any, Literal

from mcp_gauntlet.adapters.base import meta_of, require
from mcp_gauntlet.content import block_text
from mcp_gauntlet.models import PromptArgumentInfo, PromptInfo, ResourceInfo, ServerInfo, ToolInfo


class LegacyAdapter:
    era: Literal["legacy", "modern"] = "legacy"
    stdio_logger_name = "mcp.client.stdio"

    def tool_info(self, tool: Any) -> ToolInfo:
        # `annotations` is legitimately None on most tools — a server need not declare any —
        # so the hints come off it defensively rather than through require(), which would
        # raise on the ordinary case.
        annotations = getattr(tool, "annotations", None)
        return ToolInfo(
            name=require(tool, "name"),
            description=require(tool, "description", default=None),
            input_schema=dict(require(tool, "inputSchema") or {}),
            # Display titles and the output schema are server-authored text that reaches the
            # model in some clients, so they are captured to be scanned. Optional in the
            # protocol, hence the defaults.
            title=require(tool, "title", default=None),
            annotation_title=getattr(annotations, "title", None),
            output_schema=dict(require(tool, "outputSchema", default=None) or {}),
            read_only_hint=getattr(annotations, "readOnlyHint", None),
            destructive_hint=getattr(annotations, "destructiveHint", None),
            meta=meta_of(tool),
        )

    def server_info(self, init: Any) -> ServerInfo:
        info = require(init, "serverInfo")
        version = require(init, "protocolVersion", default=None)
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
        # block_text, not `.text`: a prompt message's content can be an embedded resource or
        # a resource link, which is how a prompt puts a document in front of the model — and
        # reading only `.text` dropped both.
        messages = [
            text
            for message in (require(result, "messages", default=None) or [])
            if (text := block_text(getattr(message, "content", None)))
        ]
        return messages, require(result, "description", default=None), meta_of(result)

    def resource_info(self, resource: Any, *, is_template: bool) -> ResourceInfo:
        uri = require(resource, "uriTemplate" if is_template else "uri", default="")
        return ResourceInfo(
            name=require(resource, "name", default="") or "",
            title=require(resource, "title", default=None),
            uri=str(uri or ""),
            description=require(resource, "description", default=None),
            mime_type=require(resource, "mimeType", default=None),
            is_template=is_template,
            meta=meta_of(resource),
        )

    def next_cursor(self, page: Any) -> str | None:
        cursor = require(page, "nextCursor", default=None)
        return str(cursor) if cursor else None

    def page_params(self, cursor: str | None) -> dict[str, Any]:
        """Keyword arguments requesting one page of a paginated list.

        The SDK still accepts a bare ``cursor=`` but marks it deprecated, and the overload
        is gone in 2.0. Sending no ``params`` at all for the first page — rather than an
        empty object — keeps that request byte-identical to what servers answer today.
        """
        from mcp import types

        return {} if cursor is None else {"params": types.PaginatedRequestParams(cursor=cursor)}

    def list_changed(self, init: Any) -> bool:
        capabilities = getattr(init, "capabilities", None)
        tools = getattr(capabilities, "tools", None)
        return bool(getattr(tools, "listChanged", False))
