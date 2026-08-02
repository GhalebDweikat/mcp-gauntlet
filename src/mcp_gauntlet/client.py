"""Thin async wrapper over the MCP SDK: connect to a server and discover tools.

Supports both transports:
  * stdio  — launch a local command and speak MCP over its stdin/stdout
  * http   — connect to a remote server over Streamable HTTP
"""

from __future__ import annotations

import logging
import shutil
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.types import METHOD_NOT_FOUND, InitializeResult
from pydantic import ValidationError

from mcp_gauntlet.adapters import adapter
from mcp_gauntlet.config import ServerSpec, TransportKind
from mcp_gauntlet.errors import describe
from mcp_gauntlet.models import (
    DiscoveryResult,
    PromptInfo,
    ResourceInfo,
)
from mcp_gauntlet.protocol import TransportLog, capture_stderr, watch_transport

_log = logging.getLogger(__name__)


class MCPConnectionError(RuntimeError):
    """Raised when we cannot establish a usable session with the server."""


@dataclass
class InteractionLog:
    """What the harness observed over one session, beyond the answers it asked for.

    Counts the server-initiated requests the harness declines, and carries the
    :class:`TransportLog` of anything the server put on the wire that was not a protocol
    message.

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
    # Protocol-invalid output seen during the session (stdout pollution on stdio).
    transport: TransportLog = field(default_factory=TransportLog)

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


# The one hook each era delivers a server-initiated request through. 1.x calls
# `_received_request` with a responder; 2.0 removed that entirely and calls `_on_request`
# with the method string. Both are private, which is the price of observing a request
# without answering it — see the class docstring.
_ERA_HOOKS = ("_received_request", "_on_request")

# Method strings, read off the SDK's own request models rather than written from memory.
_SAMPLING_METHOD = "sampling/createMessage"
_ELICITATION_METHOD = "elicitation/create"
_ROOTS_METHOD = "roots/list"


class _RecordingSession(ClientSession):
    """A ClientSession that tallies incoming elicitation/sampling/roots requests.

    Counting happens by overriding a private receive hook rather than by passing custom
    callbacks *on purpose*: the SDK advertises a client capability whenever its callback
    differs from the default, so a custom callback would tell the server "I support
    sampling" and invite the very requests we then decline. Leaving the callbacks at
    their defaults keeps the honest "not supported" signal in ``initialize`` while still
    letting us observe the requests a non-compliant (or optimistic) server sends anyway.

    Both eras' hooks are defined below, because they are not the same method and only one
    exists at a time. `mcp` 2.0 deleted `_received_request`; overriding a method the base
    class no longer has raises nothing and warns about nothing — the override is simply
    never called, the counter stays at zero, and every declined elicitation is charged to
    the server's Tool Reliability. That is the misattribution this class exists to prevent,
    so `__init__` refuses to construct a session whose hook is missing rather than let it
    count silently to zero.
    """

    def __init__(self, *args: object, interactions: InteractionLog, **kwargs: object) -> None:
        # Before super().__init__, so the refusal is about the missing hook rather than
        # whatever the base constructor happens to complain about first.
        if not any(hasattr(ClientSession, hook) for hook in _ERA_HOOKS):
            raise RuntimeError(
                f"this mcp SDK exposes none of {_ERA_HOOKS}, so server-initiated requests "
                f"cannot be counted and the harness would charge its own declines to the "
                f"server. Add this SDK's receive hook rather than letting the count read 0."
            )
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._interactions = interactions

    def _note(self, method: str | None) -> None:
        if method == _SAMPLING_METHOD:
            self._interactions.sampling += 1
        elif method == _ELICITATION_METHOD:
            self._interactions.elicitation += 1
        elif method == _ROOTS_METHOD:
            self._interactions.roots += 1

    # --- mcp 1.x. Keyed on type, which is what the responder carries.
    async def _received_request(self, responder: object) -> None:
        root = getattr(getattr(responder, "request", None), "root", None)
        if isinstance(root, types.CreateMessageRequest):
            self._interactions.sampling += 1
        elif isinstance(root, types.ElicitRequest):
            self._interactions.elicitation += 1
        elif isinstance(root, types.ListRootsRequest):
            self._interactions.roots += 1
        await super()._received_request(responder)  # type: ignore[arg-type]

    # --- mcp 2.0. The request arrives as a method string, before it is parsed into a type.
    async def _on_request(self, dctx: object, method: str, params: object) -> object:
        self._note(method)
        return await super()._on_request(dctx, method, params)  # type: ignore[misc]


async def _initialize(session: ClientSession) -> InitializeResult:
    """Initialize, turning a protocol-version mismatch into a message that says so.

    The SDK raises a bare ``RuntimeError`` when the server answers with a revision it does
    not support, which surfaces as an opaque task-group failure and reads exactly like a
    broken server. As the protocol moves, "speaks a newer revision than this harness" will
    become an ordinary thing to encounter, and it is not a defect in the server.
    """
    try:
        return await session.initialize()
    except RuntimeError as exc:
        if "protocol version" not in str(exc).lower():
            raise
        raise MCPConnectionError(
            f"{exc}. mcp-gauntlet speaks MCP {types.LATEST_PROTOCOL_VERSION}; this server "
            "requires a revision it does not support, so it could not be evaluated. This "
            "is a limitation of the harness, not a fault in the server."
        ) from exc


_PYTHON_NAMES = {"python", "python3", "py", "python.exe", "python3.exe", "py.exe"}


def _is_own_fixture(command: str | None, args: list[str]) -> bool:
    """Is this spec launching one of the gauntlet's OWN bundled demo servers?

    `python -m mcp_gauntlet.fixtures.…` is the command every doc uses for the demo, and it
    only works when the `python` first on PATH happens to be the one mcp-gauntlet is
    installed into — true under `uvx`, false under `uv tool install` (isolated env) and
    false in an unactivated venv, which is the normal way to invoke a console script. So
    the README's very first command failed for a tester on the install method the README
    itself recommends, with `No module named 'mcp_gauntlet'`.

    Narrow on purpose: it fires only for a bare python name AND a `-m mcp_gauntlet.` module.
    That module cannot exist anywhere except this interpreter's environment, so resolving it
    to `sys.executable` is not a guess — it is the only interpreter that could ever run it.
    A user's own server never matches, and the "give the interpreter explicitly" advice
    below still stands for it.
    """
    if command is None or Path(command).name.lower() not in _PYTHON_NAMES:
        return False
    return len(args) >= 2 and args[0] == "-m" and args[1].startswith("mcp_gauntlet.")


def _resolve_command(command: str | None, args: list[str] | None = None) -> str:
    """Resolve a bare command name to an executable path.

    On Windows this turns ``npx`` into the actual ``npx.cmd`` on PATH, which the
    process launcher needs; on POSIX it just confirms the command exists.
    """
    if not command:
        raise MCPConnectionError("stdio server spec has no command")
    if _is_own_fixture(command, args or []):
        return sys.executable
    resolved = shutil.which(command)
    if resolved is not None:
        return resolved

    # Say WHICH thing was not found, and where we looked. A user pointing at their own
    # server in a virtualenv — the commonest way this tool is used — got
    # `FileNotFoundError: [WinError 2] The system cannot find the file specified`, which
    # names no file at all: is it the interpreter, the script, something the script imports?
    # One tester burned a cycle guessing. The distinction below is the one that resolves it,
    # because the two cases have completely different fixes.
    looks_like_a_path = any(sep in command for sep in ("/", "\\")) or Path(command).suffix
    if looks_like_a_path:
        raise MCPConnectionError(
            f"no such executable: {command!r} (resolved from {Path.cwd()}). "
            "A relative path is taken from the directory you ran mcp-gauntlet in, not from "
            "the server's own directory — an absolute path is usually what you want here."
        )
    raise MCPConnectionError(
        f"command not found on PATH: {command!r}. If this is your own server, give the "
        "interpreter explicitly — a bare `python` resolves to whichever one is first on "
        "PATH, which under `uvx` is the gauntlet's own and does not have your server's "
        "dependencies installed."
    )


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
            command=_resolve_command(spec.command, spec.args),
            args=spec.args,
            # None → the SDK's minimal safe default child environment (no secrets leak).
            # A dict → those vars merged over that safe base, so an allow-listed token
            # reaches a server that needs it without exposing the whole parent environment.
            env=spec.env or None,
        )
        # Only stdio can suffer this: there stdout IS the protocol channel, so a stray
        # `print` becomes a malformed message. Over HTTP a server's logs go nowhere near
        # the wire, and the check would always read zero.
        started = False
        with watch_transport() as transport, capture_stderr() as child_stderr:
            interactions.transport = transport
            # KNOWN LIMITATION: a server killed by the caller's timeout can outlive us.
            # The SDK terminates the child's process group on exit, but with an `await`, and
            # the cancellation that ends the evaluation cancels that await before the kill
            # lands. Shielding the teardown is the obvious fix and does NOT work here:
            # anyio requires a cancel scope to be exited in the task that entered it, and an
            # @asynccontextmanager finalized under cancellation violates that. Fixing it
            # properly means restructuring this into a class-based context manager, where
            # __aexit__ runs in the caller's task. Until then `tests/test_protocol.py` marks
            # it xfail so it is recorded rather than forgotten, and the survey script reaps
            # leftovers between runs.
            try:
                async with (
                    stdio_client(params, errlog=child_stderr.handle) as (read, write),
                    _RecordingSession(read, write, interactions=interactions) as session,
                ):
                    init = await _initialize(session)
                    started = True
                    yield session, init, interactions
            except Exception as exc:
                # Only enrich failures that happened while STARTING the server. Once the
                # session is live the caller owns what goes wrong, and attaching a server's
                # startup banner to an unrelated error downstream would mislead.
                if started:
                    raise
                reason = child_stderr.tail()
                if not reason:
                    raise
                raise MCPConnectionError(f"{describe(exc)} — the server said: {reason}") from exc
    else:
        # Imported lazily so the stdio path doesn't pay for the HTTP stack.
        #
        # `streamable_http_client`, NOT `streamablehttp_client`. The un-underscored spelling
        # is a 1.x alias that 2.0 removed, so widening the pin to `mcp<3` made EVERY remote
        # server fail before touching the network — `ImportError: cannot import name
        # 'streamablehttp_client'` on a fresh install. Nothing caught it: the cross-era probe
        # exercises stdio fixtures, and no test imported this module's HTTP branch, so a code
        # path outside the adapter seam went unexercised by the very CI leg built to find
        # exactly this.
        #
        # The replacement takes an `http_client` rather than `headers`, so a straight rename
        # would have silently dropped `--header` — which is the only way a credentialed
        # remote server authenticates. `create_mcp_http_client` carries them, and both names
        # exist with identical signatures in 1.29.0 and 2.0.0 (verified by execution).
        from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

        if spec.url is None:  # pragma: no cover - guarded by ServerSpec.parse
            raise MCPConnectionError("http server spec has no url")
        # The two eras yield DIFFERENT ARITIES from the same name:
        #
        #     1.x  yield (read_stream, write_stream, transport.get_session_id)   # 3-tuple
        #     2.0  yield read_stream, write_stream                               # 2-tuple
        #
        # Unpacking three broke every remote server on 2.0 with `ValueError: not enough
        # values to unpack (expected 3, got 2)` — raised before any network I/O, so a
        # refused port, a bad hostname and a healthy live server were indistinguishable.
        # This is the SECOND time this transport shipped broken on 2.0 and the same reason
        # both times: the rename was fixed by reading the SDK's signature, and the arity
        # underneath it was not. Slice instead of unpacking, so a third era adding a
        # fourth element degrades to working rather than to a traceback — the session only
        # ever needed the two streams.
        async with (
            create_mcp_http_client(headers=spec.headers or None) as http_client,
            streamable_http_client(spec.url, http_client=http_client) as streams,
        ):
            read, write = streams[0], streams[1]
            async with _RecordingSession(read, write, interactions=interactions) as session:
                init = await _initialize(session)
                yield session, init, interactions


def _first_validation_error(exc: ValidationError) -> str:
    """One readable line from a pydantic ValidationError.

    The raw string is multi-line and repeats the model name; a report line wants the field
    path and the reason. Falls back to `str(exc)` if the shape is not what we expect, since
    a worse message beats a crash inside the error handler.
    """
    try:
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first.get("loc", ()))
        message = first.get("msg", "")
        return f"{location}: {message}" if location else str(message)
    except Exception:  # noqa: BLE001 - never let error formatting break the run
        return str(exc)[:300]


async def discover_in_session(
    session: ClientSession, init: InitializeResult, *, fetch_prompts: bool = False
) -> DiscoveryResult:
    """Build a DiscoveryResult from an already-initialized session.

    Follows ``tools/list`` pagination so a server exposing more tools than fit in one
    page isn't silently truncated. Bounded (max pages + repeat-cursor check) so a buggy
    or malicious server can't loop forever.
    """
    raw_tools = []
    seen_names: set[str] = set()
    cursor: str | None = None
    seen_cursors: set[str] = set()
    unparseable = ""
    for _ in range(100):
        try:
            listed = await session.list_tools(**_page_params(cursor))
        except ValidationError as exc:
            # The server answered and its answer is not a valid tool list. This used to
            # escape as a connection-level failure: exit 3, NO report.json, and an empty CI
            # artifact — for a defect in the single dimension this tool most exists to
            # check. Break a schema INSIDE the SDK's model and you got HIGH + exit 1; break
            # it AT the model boundary and you got "could not evaluate", which the shipped
            # CI example tells pipelines to RETRY. So a genuine schema regression was
            # retried until it gave up and then reported as a flaky runner.
            #
            # Worse on `mcp` 2.0, which a fresh install resolves: its model is stricter, so
            # `{"type": "objekt"}` and `{"properties": []}` — both of which 1.x reports as
            # findings — also became exit 3 there. The dimension was unreachable on the
            # default SDK for exactly the servers it exists to catch.
            #
            # Recorded, not raised. Pagination stops: the result is unusable, and a later
            # page cannot repair an earlier one.
            unparseable = _first_validation_error(exc)
            _log.warning("tools/list returned an unparseable tool list: %s", unparseable)
            break
        for tool in listed.tools:
            # Dedup by name so a server with overlapping pages can't inflate the tool
            # count or manufacture a phantom "name_2" tool downstream.
            if tool.name not in seen_names:
                seen_names.add(tool.name)
                raw_tools.append(tool)
        cursor = adapter().next_cursor(listed)
        if not cursor or cursor in seen_cursors:
            break
        seen_cursors.add(cursor)
    else:
        _log.warning("tools/list did not terminate within 100 pages; discovery may be truncated")

    sdk = adapter()
    tools = [sdk.tool_info(tool) for tool in raw_tools]
    server = sdk.server_info(init)
    prompts, prompt_gaps = await _discover_prompts(session, fetch_prompts)
    resources, resource_gaps = await _discover_resources(session)
    return DiscoveryResult(
        server=server,
        tools=tools,
        prompts=prompts,
        resources=resources,
        undiscovered=[*prompt_gaps, *resource_gaps],
        unparseable_tools=unparseable,
    )


def _is_absent_primitive(exc: BaseException) -> bool:
    """Whether a listing failed because the server simply does not implement it.

    JSON-RPC -32601 is a server saying "I have no prompts/resources endpoint", which is the
    ordinary case and not worth reporting. Anything else — a transport error, a malformed
    page, a rename the adapter raised on — is the check failing to run, and that has to be
    said rather than returned as an empty list. Keyed on the code, not the message, for the
    same reason the stdout check keys on the exception type: wording is the first thing to
    change upstream.
    """
    for error in (getattr(exc, "error", None), exc):
        code = getattr(error, "code", None)
        if isinstance(code, int) and code == METHOD_NOT_FOUND:
            return True
    return False


def _meta_of(obj: object) -> dict[str, Any]:
    meta = getattr(obj, "meta", None)
    return dict(meta) if isinstance(meta, dict) else {}


def _page_params(cursor: str | None) -> dict[str, Any]:
    """Keyword arguments requesting one page — shape decided by the installed SDK's era."""
    return adapter().page_params(cursor)


async def _paginate(
    fetch_page: Callable[[str | None], Awaitable[Any]], items_of: Callable[[Any], list[Any]]
) -> list[Any]:
    """Follow a paginated list to the end, bounded like ``tools/list`` already is.

    Listing one page and trusting it means a payload on page two is never fetched, let
    alone scanned.
    """
    items: list[Any] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    for _ in range(100):
        page = await fetch_page(cursor)
        items.extend(items_of(page))
        cursor = adapter().next_cursor(page)
        if not cursor or cursor in seen_cursors:
            break
        seen_cursors.add(cursor)
    else:
        _log.warning("a paginated list did not terminate within 100 pages; may be truncated")
    return items


def _dedup_by_name(items: list[Any]) -> list[Any]:
    """Same rule as tools: overlapping pages must not inflate the count or the subject list."""
    seen: set[str] = set()
    out: list[Any] = []
    for item in items:
        name = getattr(item, "name", "")
        if name not in seen:
            seen.add(name)
            out.append(item)
    return out


async def _discover_prompts(
    session: ClientSession, fetch: bool
) -> tuple[list[PromptInfo], list[str]]:
    """List the server's prompts, and render the ones that take no required arguments.

    A ``prompts/get`` response is placed in the model's context verbatim, so the messages
    are the real surface here — the description only advertises them. A prompt that isn't
    rendered records *why*, so the gap is reported rather than passing for clean.

    Listed unconditionally rather than gated on the advertised capability: a server's own
    declaration is trusted only in the direction that makes us more careful, never as
    permission to skip a scan. A server that answers a primitive it never advertised is
    exactly the kind worth looking at.
    """
    try:
        listed = _dedup_by_name(
            await _paginate(
                lambda c: session.list_prompts(**_page_params(c)), lambda p: list(p.prompts)
            )
        )
    except Exception as exc:  # noqa: BLE001 - a listing must not cost the run
        _log.debug("prompts/list unavailable: %s", exc)
        if _is_absent_primitive(exc):
            return [], []
        # The scan did not run. Saying so is the whole point: an empty list otherwise
        # reads as 'this server has no prompts', and a server that errors here skips the
        # prompt-injection scan entirely at no cost to its score.
        return [], [f"prompts could not be listed ({describe(exc, 120)})"]

    sdk = adapter()
    prompts: list[PromptInfo] = []
    for prompt in listed:
        info = sdk.prompt_info(prompt)
        if not fetch:
            info.unrendered_reason = "probing is disabled"
        elif any(arg.required for arg in info.arguments):
            info.unrendered_reason = "it requires arguments"
        else:
            try:
                result = await session.get_prompt(info.name, {})
                info.messages, info.result_description, info.result_meta = sdk.prompt_result(result)
                info.rendered = True
            except Exception as exc:  # noqa: BLE001 - a prompt that won't render isn't fatal
                _log.debug("prompts/get %s failed: %s", info.name, exc)
                info.unrendered_reason = f"rendering it failed ({str(exc)[:120]})"
        prompts.append(info)
    return prompts, []


async def _discover_resources(session: ClientSession) -> tuple[list[ResourceInfo], list[str]]:
    """List resources and resource templates, metadata only.

    The contents are deliberately not read: they are unbounded in size and are passthrough
    content rather than server-authored text. The metadata *is* server-authored, and it is
    what a user or model reads when deciding what to attach.
    """
    found: list[ResourceInfo] = []
    undiscovered: list[str] = []
    try:
        listed_resources = _dedup_by_name(
            await _paginate(
                lambda c: session.list_resources(**_page_params(c)), lambda p: list(p.resources)
            )
        )
        found.extend(
            adapter().resource_info(resource, is_template=False) for resource in listed_resources
        )
    except Exception as exc:  # noqa: BLE001 - a listing must not cost the run
        _log.debug("resources/list unavailable: %s", exc)
        if not _is_absent_primitive(exc):
            undiscovered.append(f"resources could not be listed ({describe(exc, 120)})")
    try:
        templates = _dedup_by_name(
            await _paginate(
                lambda c: session.list_resource_templates(**_page_params(c)),
                adapter().resource_templates,
            )
        )
        found.extend(adapter().resource_info(template, is_template=True) for template in templates)
    except Exception as exc:  # noqa: BLE001 - same
        _log.debug("resources/templates/list unavailable: %s", exc)
        if not _is_absent_primitive(exc):
            undiscovered.append(f"resource templates could not be listed ({describe(exc, 120)})")
    return found, undiscovered


async def discover(spec: ServerSpec) -> DiscoveryResult:
    """Connect to the server and return its advertised tools."""
    async with open_session(spec) as (session, init, _interactions):
        return await discover_in_session(session, init)
