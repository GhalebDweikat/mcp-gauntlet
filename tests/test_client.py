"""Discovery tests: tools/list pagination is followed and bounded."""

from types import SimpleNamespace
from typing import Any, cast

from mcp import ClientSession
from mcp.types import InitializeResult
from sdk_shapes import shape

from mcp_gauntlet.client import discover_in_session


def _tool(name: str) -> Any:
    return shape(name=name, description="d", input_schema={"type": "object"}, annotations=None)


_INIT = cast(InitializeResult, shape(server_info=SimpleNamespace(name="s", version="1")))


class _PaginatedSession:
    # Deliberately accepts ONLY `params`, not the SDK's deprecated `cursor=` overload:
    # that overload disappears in `mcp` 2.0, and a fake that tolerated both would let the
    # old call shape survive here until a user's install broke.
    def __init__(self, pages: list[tuple[list[Any], str | None]]) -> None:
        self._pages = pages
        self.cursors: list[str | None] = []

    async def list_tools(self, *, params: Any = None) -> Any:
        self.cursors.append(params.cursor if params is not None else None)
        tools, next_cursor = self._pages[len(self.cursors) - 1]
        return shape(tools=tools, next_cursor=next_cursor)


async def test_discover_follows_pagination() -> None:
    session = _PaginatedSession([([_tool("a"), _tool("b")], "cur1"), ([_tool("c")], None)])
    result = await discover_in_session(cast(ClientSession, session), _INIT)
    assert [t.name for t in result.tools] == ["a", "b", "c"]
    assert session.cursors == [None, "cur1"]  # first page no cursor, second follows nextCursor


async def test_discover_dedups_tools_across_pages() -> None:
    # A server returning the same tool on two pages (distinct cursors) must not inflate the
    # tool count or manufacture a phantom "name_2" downstream.
    session = _PaginatedSession([([_tool("add"), _tool("echo")], "c1"), ([_tool("add")], None)])
    result = await discover_in_session(cast(ClientSession, session), _INIT)
    assert [t.name for t in result.tools] == ["add", "echo"]


class _LoopingSession:
    def __init__(self) -> None:
        self.calls = 0

    async def list_tools(self, *, params: Any = None) -> Any:
        self.calls += 1
        return shape(tools=[_tool(f"t{self.calls}")], next_cursor="same")


async def test_discover_stops_on_repeated_cursor() -> None:
    # A buggy/malicious server that always returns the same cursor must not loop forever.
    session = _LoopingSession()
    result = await discover_in_session(cast(ClientSession, session), _INIT)
    assert session.calls == 2  # first call + one more that sees the repeated cursor, then stop
    assert [t.name for t in result.tools] == ["t1", "t2"]


async def test_discover_captures_every_model_visible_string() -> None:
    # Display titles and the output schema are server-authored text that reaches the model.
    # Dropping them at discovery put them out of reach of the injection scan entirely.
    rich = shape(
        name="lookup",
        title="Lookup Records",
        description="d",
        input_schema={"type": "object"},
        output_schema={"type": "object", "properties": {"row": {"description": "a row"}}},
        annotations=shape(title="Row Lookup", read_only_hint=True, destructive_hint=None),
    )
    session = _PaginatedSession([([rich], None)])
    tool = (await discover_in_session(cast(ClientSession, session), _INIT)).tools[0]
    assert tool.title == "Lookup Records"
    assert tool.annotation_title == "Row Lookup"
    assert tool.output_schema["properties"]["row"]["description"] == "a row"
    assert tool.read_only_hint is True


async def test_discover_records_the_negotiated_protocol_version() -> None:
    # A score is only interpretable against the spec the server was speaking, and the
    # protocol is changing — this is the field that will say which servers moved.
    init = cast(
        InitializeResult,
        shape(server_info=SimpleNamespace(name="s", version="1"), protocol_version="2025-06-18"),
    )
    session = _PaginatedSession([([_tool("a")], None)])
    found = await discover_in_session(cast(ClientSession, session), init)
    assert found.server.protocol_version == "2025-06-18"


async def test_discover_tolerates_a_server_without_the_newer_fields() -> None:
    # Older servers (and the existing fixtures) send no title/outputSchema at all.
    session = _PaginatedSession([([_tool("a")], None)])
    tool = (await discover_in_session(cast(ClientSession, session), _INIT)).tools[0]
    assert tool.title is None and tool.annotation_title is None
    assert tool.output_schema == {}


# ------------------------------------- "we could not look" must not read as "there is none"


class _FailingListSession:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    async def list_prompts(self, **kwargs: Any) -> Any:
        raise self._exc

    async def list_resources(self, **kwargs: Any) -> Any:
        raise self._exc

    async def list_resource_templates(self, **kwargs: Any) -> Any:
        raise self._exc


def _protocol_error(code: int, message: str) -> BaseException:
    from mcp.types import ErrorData

    from mcp_gauntlet.adapters import adapter

    error_type = adapter().protocol_error_type()
    if adapter().era == "modern":
        return error_type(code=code, message=message)  # type: ignore[call-arg]
    return error_type(ErrorData(code=code, message=message))


async def test_a_server_without_prompts_reports_no_gap() -> None:
    """JSON-RPC -32601 is a server saying it has no prompts endpoint. Ordinary, not a gap."""
    from mcp.types import METHOD_NOT_FOUND

    from mcp_gauntlet.client import _discover_prompts

    session = _FailingListSession(_protocol_error(METHOD_NOT_FOUND, "Method not found"))
    prompts, gaps = await _discover_prompts(cast(ClientSession, session), False)
    assert prompts == [] and gaps == []


async def test_a_failed_prompt_listing_is_reported_not_swallowed() -> None:
    """The distinction that was missing.

    Any non-"method not found" failure — a transport error, a malformed page, a rename the
    adapter raised on — returned an empty list logged at debug. `check_security` then scanned
    nothing and the dimension read clean, so a server that errors on `prompts/list` skipped
    the prompt-injection scan entirely at no cost to its score. The same shape as the
    `resourceTemplates` bug: a scan that never ran reading exactly like one that found nothing.
    """
    from mcp.types import INTERNAL_ERROR

    from mcp_gauntlet.client import _discover_prompts

    session = _FailingListSession(_protocol_error(INTERNAL_ERROR, "database exploded"))
    prompts, gaps = await _discover_prompts(cast(ClientSession, session), False)
    assert prompts == []
    assert gaps and "prompts could not be listed" in gaps[0]


async def test_a_failed_resource_listing_is_reported_too() -> None:
    from mcp.types import INTERNAL_ERROR

    from mcp_gauntlet.client import _discover_resources

    session = _FailingListSession(_protocol_error(INTERNAL_ERROR, "database exploded"))
    resources, gaps = await _discover_resources(cast(ClientSession, session))
    assert resources == []
    # Both the resource list and the template list failed, and both are named.
    assert len(gaps) == 2
    assert any("resources could not be listed" in g for g in gaps)
    assert any("resource templates could not be listed" in g for g in gaps)
