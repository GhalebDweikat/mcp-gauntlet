"""generate_tasks must degrade to an empty list on any generation failure — a rate
limit, an empty choices list, or a model that returns the wrong JSON shape — so a
transient hiccup while generating tasks can't crash the whole eval (it instead makes
the agentic dimension inconclusive downstream)."""

import json
from types import SimpleNamespace
from typing import Any, cast

from openai import AsyncOpenAI

from mcp_gauntlet.models import ToolInfo
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
