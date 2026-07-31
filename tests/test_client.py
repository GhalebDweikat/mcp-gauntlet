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
