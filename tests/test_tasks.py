"""generate_tasks must degrade to an empty list on any generation failure — a rate
limit, an empty choices list, or a model that returns the wrong JSON shape — so a
transient hiccup while generating tasks can't crash the whole eval (it instead makes
the agentic dimension inconclusive downstream)."""

import json
from types import SimpleNamespace
from typing import Any, cast

from openai import AsyncOpenAI

from mcp_gauntlet.models import DiscoveryResult, ResourceInfo, ServerInfo, ToolInfo
from mcp_gauntlet.tasks import _tools_blurb, generate_tasks

_TOOLS = [ToolInfo(name="add", description="add", input_schema={"type": "object"})]


class _Client:
    """Stands in for AsyncOpenAI: returns (or raises) a single scripted completion."""

    def __init__(self, result: Any) -> None:
        self._result = result
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **kwargs: Any) -> Any:
        if isinstance(self._result, BaseException):
            raise self._result
        return self._result


def _client(result: Any) -> AsyncOpenAI:
    return cast(AsyncOpenAI, _Client(result))


def _completion(content: str) -> Any:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


async def test_generate_tasks_empty_on_llm_error() -> None:
    client = _client(RuntimeError("Error code: 429 rate limit"))
    tasks = await generate_tasks(client, "m", _TOOLS, 3)
    assert tasks == []


async def test_generate_tasks_empty_on_empty_choices() -> None:
    tasks = await generate_tasks(_client(SimpleNamespace(choices=[])), "m", _TOOLS, 3)
    assert tasks == []


async def test_generate_tasks_empty_on_wrong_shape_json() -> None:
    # Model returned a top-level JSON array instead of {"tasks": [...]} — must not crash
    # on data.get("tasks").
    tasks = await generate_tasks(_client(_completion("[1, 2, 3]")), "m", _TOOLS, 3)
    assert tasks == []


async def test_generate_tasks_empty_on_tasks_object_not_list() -> None:
    # Model returned {"tasks": {...}} (an object map) — slicing a dict used to crash.
    tasks = await generate_tasks(_client(_completion('{"tasks": {"a": 1}}')), "m", _TOOLS, 3)
    assert tasks == []


async def test_generate_tasks_empty_on_tasks_scalar() -> None:
    tasks = await generate_tasks(_client(_completion('{"tasks": 5}')), "m", _TOOLS, 3)
    assert tasks == []


async def test_generate_tasks_survives_null_expected_tools() -> None:
    # expected_tools: null (key present, so .get's default is bypassed) used to crash
    # `for n in None`; must yield the task with an empty expected list.
    payload = json.dumps({"tasks": [{"description": "d", "rubric": "r", "expected_tools": None}]})
    tasks = await generate_tasks(_client(_completion(payload)), "m", _TOOLS, 3)
    assert len(tasks) == 1
    assert tasks[0].expected_tools == []


def test_tools_blurb_survives_non_dict_properties() -> None:
    # A server whose schema has `properties` as a list (not an object) must not crash the
    # blurb — it's built before the LLM call, outside generate_tasks's try/except.
    tool = ToolInfo(
        name="t", description="d", input_schema={"type": "object", "properties": ["a", "b"]}
    )
    assert "t(" in _tools_blurb([tool])  # no params extracted, but no crash


async def test_generate_tasks_parses_valid() -> None:
    payload = json.dumps(
        {"tasks": [{"description": "add 1 and 2", "rubric": "r", "expected_tools": ["add"]}]}
    )
    tasks = await generate_tasks(_client(_completion(payload)), "m", _TOOLS, 3)
    assert len(tasks) == 1
    assert tasks[0].description == "add 1 and 2"
    assert tasks[0].expected_tools == ["add"]


def test_grounding_context_reports_what_the_generator_cannot_guess() -> None:
    """The generator sees only tool descriptions, so it invents paths that don't exist.

    That is not a hypothetical: the published leaderboard graded `git` a C and `filesystem`
    a D because every generated task named a directory like `/workspace/assets`, so every
    call failed and the server wore it. Self-contained servers (sqlite, memory) scored A on
    the same run. Whatever this function can state as fact is one less thing invented.
    """
    from mcp_gauntlet.config import ServerSpec
    from mcp_gauntlet.engine import _grounding_context

    spec = ServerSpec.parse("npx -y @modelcontextprotocol/server-filesystem ./sandbox")
    tools = [
        ToolInfo(name="read_file", input_schema={"type": "object", "properties": {"path": {}}}),
        ToolInfo(name="list_allowed_directories", input_schema={"type": "object"}),
    ]
    discovery = DiscoveryResult(
        server=ServerInfo(name="fs", version="1"),
        tools=tools,
        resources=[ResourceInfo(name="r", uri="file:///sandbox/notes.txt")],
    )
    context = _grounding_context(spec, discovery, tools)

    assert "./sandbox" in context  # the real root, straight off the command line
    assert "list_allowed_directories" in context  # callable knowing nothing
    assert "read_file" not in context  # needs an argument — not a discovery entry point
    assert "file:///sandbox/notes.txt" in context


def test_grounding_context_is_empty_when_nothing_is_known() -> None:
    # A bare stdio server with no arguments and no zero-arg tools genuinely offers no
    # ground truth. Saying so is the point: the prompt then requires every task to
    # discover what it needs rather than filling the silence with a plausible guess.
    from mcp_gauntlet.config import ServerSpec
    from mcp_gauntlet.engine import _grounding_context

    spec = ServerSpec.parse("myserver")
    tools = [ToolInfo(name="fetch", input_schema={"type": "object", "properties": {"url": {}}})]
    discovery = DiscoveryResult(server=ServerInfo(name="s", version="1"), tools=tools)
    assert _grounding_context(spec, discovery, tools) == ""


async def test_generate_tasks_puts_grounding_in_the_prompt() -> None:
    # The context has to actually reach the model, not just be computed.
    seen: dict[str, str] = {}

    class _Client:
        class chat:  # noqa: N801
            class completions:  # noqa: N801
                @staticmethod
                async def create(**kwargs: Any) -> Any:
                    seen["prompt"] = kwargs["messages"][0]["content"]
                    return SimpleNamespace(
                        choices=[SimpleNamespace(message=SimpleNamespace(content='{"tasks": []}'))]
                    )

    await generate_tasks(
        cast(AsyncOpenAI, _Client()),
        "m",
        [ToolInfo(name="a", description="does a")],
        1,
        context="- The server was started with these arguments: ./sandbox",
    )
    assert "./sandbox" in seen["prompt"]
    assert "NEVER invent an environment-specific identifier" in seen["prompt"]
