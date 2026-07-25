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
from dataclasses import dataclass

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.types import InitializeResult

from mcp_gauntlet.config import ServerSpec, TransportKind
from mcp_gauntlet.models import DiscoveryResult, ServerInfo, ToolInfo

_log = logging.getLogger(__name__)


class MCPConnectionError(RuntimeError):
    """Raised when we cannot establish a usable session with the server."""


@dataclass
class InteractionLog:
    """Counts the server-initiated requests the harness declines.

    mcp-gauntlet is a non-interactive harness: it drives no elicitation (asking the
    user to fill a form), sampling (asking the client to run an LLM completion), or
    roots (asking for the client's filesystem roots). A server that needs one of these
    to finish a tool call gets a clean "not supported" decline — but the tool may then
    fail *for that reason*, which is the harness's limitation, not the server's defect.
    Counting the declines lets the evaluation attribute such failures honestly instead
    of charging them to the server's Tool Reliability.
    """

    sampling: int = 0
    elicitation: int = 0
    roots: int = 0

    @property
    def total(self) -> int:
        return self.sampling + self.elicitation + self.roots

    def summary(self) -> str:
        parts = []
        if self.elicitation:
            parts.append(f"{self.elicitation} elicitation")
        if self.sampling:
            parts.append(f"{self.sampling} sampling")
        if self.roots:
            parts.append(f"{self.roots} roots")
        return ", ".join(parts)


class _RecordingSession(ClientSession):
    """A ClientSession that tallies incoming elicitation/sampling/roots requests.

    Counting happens by overriding ``_received_request`` rather than by passing custom
    callbacks *on purpose*: the SDK advertises a client capability whenever its callback
    differs from the default, so a custom callback would tell the server "I support
    sampling" and invite the very requests we then decline. Leaving the callbacks at
    their defaults keeps the honest "not supported" signal in ``initialize`` while still
    letting us observe the requests a non-compliant (or optimistic) server sends anyway.
    """

    def __init__(self, *args: object, interactions: InteractionLog, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._interactions = interactions

    async def _received_request(self, responder: object) -> None:
        root = getattr(getattr(responder, "request", None), "root", None)
        if isinstance(root, types.CreateMessageRequest):
            self._interactions.sampling += 1
        elif isinstance(root, types.ElicitRequest):
            self._interactions.elicitation += 1
        elif isinstance(root, types.ListRootsRequest):
            self._interactions.roots += 1
        await super()._received_request(responder)  # type: ignore[arg-type]


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
) -> AsyncIterator[tuple[ClientSession, InitializeResult, InteractionLog]]:
    """Open an initialized MCP session for the given server spec.

    Yields the live session, the server's ``InitializeResult`` (server name/version
    and advertised capabilities), and an :class:`InteractionLog` that accrues any
    elicitation/sampling/roots requests the server makes so the caller can attribute
    interaction-blocked tool failures correctly.
    """
    interactions = InteractionLog()
    if spec.kind is TransportKind.STDIO:
        params = StdioServerParameters(
            command=_resolve_command(spec.command),
            args=spec.args,
            # None → the SDK's minimal safe default child environment (no secrets leak).
            # A dict → those vars merged over that safe base, so an allow-listed token
            # reaches a server that needs it without exposing the whole parent environment.
            env=spec.env or None,
        )
        async with (
            stdio_client(params) as (read, write),
            _RecordingSession(read, write, interactions=interactions) as session,
        ):
            init = await session.initialize()
            yield session, init, interactions
    else:
        # Imported lazily so the stdio path doesn't pay for the HTTP stack.
        from mcp.client.streamable_http import streamablehttp_client

        if spec.url is None:  # pragma: no cover - guarded by ServerSpec.parse
            raise MCPConnectionError("http server spec has no url")
        async with (
            streamablehttp_client(spec.url, headers=spec.headers or None) as (read, write, _),
            _RecordingSession(read, write, interactions=interactions) as session,
        ):
            init = await session.initialize()
            yield session, init, interactions


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
            # Display titles and the output schema are server-authored text that reaches the
            # model in some clients, so they are captured here to be scanned. Dropping them
            # at discovery made them unreachable by the injection scan — a payload placed in
            # one was invisible to the check that exists to find it.
            title=getattr(tool, "title", None),
            annotation_title=getattr(tool.annotations, "title", None),
            output_schema=dict(getattr(tool, "outputSchema", None) or {}),
            read_only_hint=getattr(tool.annotations, "readOnlyHint", None),
            destructive_hint=getattr(tool.annotations, "destructiveHint", None),
        )
        for tool in raw_tools
    ]
    server = ServerInfo(
        name=getattr(init.serverInfo, "name", None),
        version=getattr(init.serverInfo, "version", None),
        title=getattr(init.serverInfo, "title", None),
        instructions=getattr(init, "instructions", None),
    )
    return DiscoveryResult(server=server, tools=tools)


async def discover(spec: ServerSpec) -> DiscoveryResult:
    """Connect to the server and return its advertised tools."""
    async with open_session(spec) as (session, init, _interactions):
        return await discover_in_session(session, init)
