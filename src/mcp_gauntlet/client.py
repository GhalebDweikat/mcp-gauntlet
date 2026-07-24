"""Thin async wrapper over the MCP SDK: connect to a server and discover tools.

Supports both transports:
  * stdio  — launch a local command and speak MCP over its stdin/stdout
  * http   — connect to a remote server over Streamable HTTP
"""

from __future__ import annotations

import logging
import shutil
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import InitializeResult

from mcp_gauntlet.config import ServerSpec, TransportKind
from mcp_gauntlet.models import DiscoveryResult, ServerInfo, ToolInfo

_log = logging.getLogger(__name__)


class MCPConnectionError(RuntimeError):
    """Raised when we cannot establish a usable session with the server."""


def _resolve_command(command: str | None) -> str:
    """Resolve a bare command name to an executable path.

    On Windows this turns ``npx`` into the actual ``npx.cmd`` on PATH, which the
    process launcher needs; on POSIX it just confirms the command exists.
    """
    if not command:
        raise MCPConnectionError("stdio server spec has no command")
    resolved = shutil.which(command)
    if resolved is None:
        raise MCPConnectionError(f"command not found on PATH: {command!r}")
    return resolved


@asynccontextmanager
async def open_session(
    spec: ServerSpec,
) -> AsyncIterator[tuple[ClientSession, InitializeResult]]:
    """Open an initialized MCP session for the given server spec.

    Yields the live session together with the server's ``InitializeResult`` (which
    carries the server name/version and advertised capabilities).
    """
    if spec.kind is TransportKind.STDIO:
        params = StdioServerParameters(command=_resolve_command(spec.command), args=spec.args)
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write) as session,
        ):
            init = await session.initialize()
            yield session, init
    else:
        # Imported lazily so the stdio path doesn't pay for the HTTP stack.
        from mcp.client.streamable_http import streamablehttp_client

        if spec.url is None:  # pragma: no cover - guarded by ServerSpec.parse
            raise MCPConnectionError("http server spec has no url")
        async with (
            streamablehttp_client(spec.url) as (read, write, _),
            ClientSession(read, write) as session,
        ):
            init = await session.initialize()
            yield session, init


async def discover_in_session(session: ClientSession, init: InitializeResult) -> DiscoveryResult:
    """Build a DiscoveryResult from an already-initialized session.

    Follows ``tools/list`` pagination so a server exposing more tools than fit in one
    page isn't silently truncated. Bounded (max pages + repeat-cursor check) so a buggy
    or malicious server can't loop forever.
    """
    raw_tools = []
    seen_names: set[str] = set()
    cursor: str | None = None
    seen_cursors: set[str] = set()
    for _ in range(100):
        listed = await session.list_tools(cursor=cursor)
        for tool in listed.tools:
            # Dedup by name so a server with overlapping pages can't inflate the tool
            # count or manufacture a phantom "name_2" tool downstream.
            if tool.name not in seen_names:
                seen_names.add(tool.name)
                raw_tools.append(tool)
        cursor = listed.nextCursor
        if not cursor or cursor in seen_cursors:
            break
        seen_cursors.add(cursor)
    else:
        _log.warning("tools/list did not terminate within 100 pages; discovery may be truncated")

    tools = [
        ToolInfo(
            name=tool.name,
            description=tool.description,
            input_schema=dict(tool.inputSchema or {}),
            read_only_hint=getattr(tool.annotations, "readOnlyHint", None),
            destructive_hint=getattr(tool.annotations, "destructiveHint", None),
        )
        for tool in raw_tools
    ]
    server = ServerInfo(
        name=getattr(init.serverInfo, "name", None),
        version=getattr(init.serverInfo, "version", None),
    )
    return DiscoveryResult(server=server, tools=tools)


async def discover(spec: ServerSpec) -> DiscoveryResult:
    """Connect to the server and return its advertised tools."""
    async with open_session(spec) as (session, init):
        return await discover_in_session(session, init)
