"""Run a fixture server on whichever SDK era is installed.

A fixture declares its tools as data; this builds a real server from that declaration. The
point is that the *declaration* — the poisoned description, the hidden character, the missing
schema — is written once and fed to both eras, which is what makes "same fixture, both eras,
same ToolInfo" a meaningful assertion. Two hand-maintained implementations could drift, and
the cross-era test would then compare two different servers and pass.

`mcp` 2.0 deleted `mcp.server.fastmcp`. What replaced it, `mcp.server.MCPServer`, turns out to
be the same object under a new name: `add_tool` has a byte-identical signature in 1.29.0 and
2.0.0, both constructors take `log_level`, and both `run()` default to stdio. So this is thin
by luck as much as design — verified by execution against both releases, not by reading the
changelog.

Two things genuinely differ and are mapped here:

* `ToolAnnotations` is camelCase in 1.x and snake_case in 2.0.
* `MCPServer` takes `version`; `FastMCP` has no such parameter.

Tools are declared as ordinary typed Python functions rather than as raw JSON schemas,
deliberately: both eras derive the input schema from the signature the same way, so the
legacy schemas stay byte-identical to what these fixtures produced before this module
existed. `scripts/snapshot_fixtures.py` is what proves that, and it is the acceptance test
for this port — anything but zero drift means a fixture's definition moved.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = ["Tool", "context_type", "prompt_def", "serve", "serve_raw", "tool_def"]


@dataclass(frozen=True)
class Tool:
    """One tool, in terms both eras can build.

    `annotations` uses the modern snake_case spelling as the canonical form and is
    translated for the legacy SDK — one direction of mapping rather than two.
    """

    fn: Callable[..., Any]
    name: str | None = None
    title: str | None = None
    description: str | None = None
    annotations: Mapping[str, Any] | None = None
    meta: Mapping[str, Any] | None = None


# Canonical (modern) name -> the legacy SDK's spelling.
_LEGACY_ANNOTATION_NAMES = {
    "read_only_hint": "readOnlyHint",
    "destructive_hint": "destructiveHint",
    "idempotent_hint": "idempotentHint",
    "open_world_hint": "openWorldHint",
    "title": "title",
}


def _is_modern() -> bool:
    """Whether the installed `mcp` is 2.x.

    Same rule as `adapters.sdk_version()` — by package version, never by probing for an
    attribute, because 2.0 still exports ClientSession and mcp.types so hasattr cannot tell
    the eras apart. Deliberately NOT importing that function: a fixture must be runnable
    under an SDK the harness itself cannot be installed alongside, since the harness pins
    `mcp<2`. Reaching into `mcp_gauntlet.adapters` here would make the modern branch
    permanently untestable — the fixture could only ever run in an environment that, by
    construction, has the wrong SDK for it.
    """
    import importlib.metadata

    try:
        version = importlib.metadata.version("mcp")
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover - mcp is a hard dep
        return False
    head = version.split(".", 1)[0]
    return head.isdigit() and int(head) >= 2


def context_type() -> type:
    """The era's `Context` class, for a tool that wants one injected.

    It has to be the real class, not a stand-in: both SDKs decide whether to inject a
    Context by inspecting the annotation on the tool function, so annotating with anything
    else means the parameter is treated as an ordinary argument and lands in the tool's
    input schema. 2.0 moved the class from `mcp.server.fastmcp` to `mcp.server.mcpserver`;
    `elicit(message, schema)` is unchanged.
    """
    if _is_modern():
        from mcp.server.mcpserver import Context as ModernContext

        return ModernContext
    from mcp.server.fastmcp import Context as LegacyContext

    return LegacyContext


def _annotations(spec: Mapping[str, Any] | None, *, modern: bool) -> Any:
    if not spec:
        return None
    from mcp.types import ToolAnnotations

    if modern:
        return ToolAnnotations(**dict(spec))
    unknown = set(spec) - set(_LEGACY_ANNOTATION_NAMES)
    if unknown:  # a typo here would silently drop a hint the fixture meant to declare
        raise ValueError(f"unknown annotation(s) {sorted(unknown)}")
    return ToolAnnotations(**{_LEGACY_ANNOTATION_NAMES[k]: v for k, v in spec.items()})


def tool_def(
    *,
    name: str,
    description: str,
    input_schema: Mapping[str, Any],
    output_schema: Mapping[str, Any] | None = None,
    title: str | None = None,
    annotations: Mapping[str, Any] | None = None,
) -> Any:
    """A hand-built `types.Tool`, spelled the way the installed SDK spells it.

    The function-based path above cannot express a tool whose schema is deliberately
    malformed, whose payload is nested behind a `$ref`, or whose definition changes between
    two `tools/list` calls. Those are exactly what the malicious demo is made of, so it
    needs to construct the SDK's own type — and that type renamed every field in 2.0.
    """
    from mcp import types

    modern = _is_modern()
    fields: dict[str, Any] = {"name": name, "description": description}
    fields["input_schema" if modern else "inputSchema"] = dict(input_schema)
    if output_schema is not None:
        fields["output_schema" if modern else "outputSchema"] = dict(output_schema)
    if title is not None:
        fields["title"] = title
    if annotations is not None:
        fields["annotations"] = _annotations(annotations, modern=modern)
    return types.Tool(**fields)


def prompt_def(
    *,
    name: str,
    title: str | None = None,
    description: str | None = None,
    arguments: Sequence[Any] = (),
) -> Any:
    """A `types.Prompt`. Every field kept its name across the eras; this is here for symmetry
    with `tool_def` so a fixture never imports `mcp.types` itself."""
    from mcp import types

    return types.Prompt(name=name, title=title, description=description, arguments=list(arguments))


def serve_raw(
    name: str,
    *,
    list_tools: Callable[[], Sequence[Any]],
    call_tool: Callable[[str, dict[str, Any]], tuple[list[Any], dict[str, Any] | None]],
    list_prompts: Callable[[], Sequence[Any]] | None = None,
    get_prompt: Callable[[str, dict[str, str] | None], tuple[str | None, list[Any]]] | None = None,
) -> None:
    """Serve hand-built definitions over stdio, on whichever era is installed.

    The two eras' low-level servers share a name and nothing else. 1.x registers handlers
    through decorators (`@server.list_tools()`) and wraps their return value into the result
    type for you. 2.0 replaced that with `add_request_handler(method, params_type, handler)`,
    where the handler is passed a request context and returns the result model itself. The
    callbacks above are in the fixture's own terms so a fixture states its behaviour once.

    `mcp.server.lowlevel.Server` still *imports* under 2.0 — which is a trap worth naming,
    since the decorators it is imported for are gone. It fails at `@server.list_tools()`
    with an AttributeError rather than at the import, so the era check has to come first.
    """
    import anyio
    from mcp.server.stdio import stdio_server

    modern = _is_modern()

    if modern:
        from mcp import types
        from mcp.server.lowlevel import Server

        server: Any = Server(name)

        async def _tools_handler(_ctx: Any, _params: Any) -> Any:
            return types.ListToolsResult(tools=list(list_tools()))

        async def _call_handler(_ctx: Any, params: Any) -> Any:
            content, structured = call_tool(params.name, dict(params.arguments or {}))
            # snake_case exists only in 2.0; against the pinned SDK this cannot resolve.
            return types.CallToolResult(  # type: ignore[call-arg]
                content=content, structured_content=structured
            )

        server.add_request_handler("tools/list", types.PaginatedRequestParams, _tools_handler)
        server.add_request_handler("tools/call", types.CallToolRequestParams, _call_handler)

        if list_prompts is not None:

            async def _prompts_handler(_ctx: Any, _params: Any) -> Any:
                return types.ListPromptsResult(prompts=list(list_prompts()))

            server.add_request_handler(
                "prompts/list", types.PaginatedRequestParams, _prompts_handler
            )

        if get_prompt is not None:

            async def _get_prompt_handler(_ctx: Any, params: Any) -> Any:
                description, messages = get_prompt(params.name, dict(params.arguments or {}))
                return types.GetPromptResult(description=description, messages=messages)

            server.add_request_handler(
                "prompts/get", types.GetPromptRequestParams, _get_prompt_handler
            )
    else:
        from mcp import types
        from mcp.server.lowlevel import Server

        server = Server(name)

        @server.list_tools()
        async def _list_tools() -> list[Any]:
            return list(list_tools())

        @server.call_tool()
        async def _call_tool(tool: str, arguments: dict[str, Any]) -> Any:
            content, structured = call_tool(tool, arguments)
            # 1.x reads a bare list as unstructured, and a (list, dict) tuple as both.
            return content if structured is None else (content, structured)

        if list_prompts is not None:

            @server.list_prompts()
            async def _list_prompts() -> list[Any]:
                return list(list_prompts())

        if get_prompt is not None:

            @server.get_prompt()
            async def _get_prompt(prompt: str, arguments: dict[str, str] | None) -> Any:
                description, messages = get_prompt(prompt, arguments)
                return types.GetPromptResult(description=description, messages=messages)

    async def _main() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(_main)


def serve(
    name: str,
    tools: Sequence[Tool],
    *,
    version: str | None = None,
    instructions: str | None = None,
) -> None:
    """Build the server and run it on stdio. Does not return."""
    modern = _is_modern()

    server: Any
    if modern:
        # Unresolvable against the pinned SDK by definition: this is the branch for the era
        # that is NOT installed. The dual-era CI leg is what type-checks it — an ignore here
        # is the cost of one codebase spanning two SDKs, not a silenced mistake.
        from mcp.server import MCPServer  # type: ignore[attr-defined]

        server = MCPServer(
            name=name,
            version=version or "",
            instructions=instructions,
            log_level="WARNING",
        )
    else:
        from mcp.server.fastmcp import FastMCP

        # FastMCP has no `version` parameter; it derives one itself. Nothing scores on it —
        # the fixture snapshot drops the server version precisely because it moves whenever
        # a fixture is edited, and the tool definitions are the subject.
        server = FastMCP(name, instructions=instructions, log_level="WARNING")

    for tool in tools:
        server.add_tool(
            tool.fn,
            name=tool.name,
            title=tool.title,
            description=tool.description,
            annotations=_annotations(tool.annotations, modern=modern),
            meta=dict(tool.meta) if tool.meta else None,
        )

    server.run()
