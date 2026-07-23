"""Mocked-LLM tests for the agentic path: no network, deterministic.

A ScriptedClient stands in for AsyncOpenAI (agent turns get scripted responses;
judge calls, which set response_format, get a fixed verdict) and a ScriptedSession
stands in for the MCP ClientSession.
"""

import json
from types import SimpleNamespace
from typing import Any, cast

from mcp import ClientSession
from openai import AsyncOpenAI

from mcp_gauntlet.agent import AgentTrace, run_agent_task
from mcp_gauntlet.evaluate import run_agentic_eval
from mcp_gauntlet.judge import judge_task
from mcp_gauntlet.models import ToolInfo
from mcp_gauntlet.tasks import EvalTask
from mcp_gauntlet.toolconv import build_tool_bridge


def _msg(content: str | None = None, tool_calls: list[Any] | None = None) -> Any:
    return SimpleNamespace(content=content, tool_calls=tool_calls)


def _tool_call(call_id: str, name: str, arguments: str) -> Any:
    return SimpleNamespace(id=call_id, function=SimpleNamespace(name=name, arguments=arguments))


def _completion(message: Any, prompt: int = 10, completion: int = 5) -> Any:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=message)],
        usage=SimpleNamespace(prompt_tokens=prompt, completion_tokens=completion),
    )


def _tool_result(text: str, is_error: bool = False) -> Any:
    return SimpleNamespace(
        isError=is_error,
        content=[SimpleNamespace(type="text", text=text)],
        structuredContent=None,
    )


class ScriptedClient:
    def __init__(
        self, agent_responses: list[Any], judge_verdict: dict[str, Any] | None = None
    ) -> None:
        self._agent = iter(agent_responses)
        self._verdict = judge_verdict
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **kwargs: Any) -> Any:
        if kwargs.get("response_format") and self._verdict is not None:
            return _completion(_msg(content=json.dumps(self._verdict)))
        return next(self._agent)


class ScriptedSession:
    def __init__(self, handler: Any) -> None:
        self._handler = handler

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        result = self._handler(name, arguments)
        if isinstance(result, Exception):
            raise result
        return result


def _client(responses: list[Any], judge_verdict: dict[str, Any] | None = None) -> AsyncOpenAI:
    return cast(AsyncOpenAI, ScriptedClient(responses, judge_verdict))


def _session(handler: Any) -> ClientSession:
    return cast(ClientSession, ScriptedSession(handler))


_ADD = ToolInfo(
    name="add",
    description="add",
    input_schema={
        "type": "object",
        "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
        "required": ["a", "b"],
    },
)


async def test_agent_loop_happy_path() -> None:
    bridge = build_tool_bridge([_ADD])
    fn = bridge.tools[0]["function"]["name"]
    responses = [
        _completion(_msg(tool_calls=[_tool_call("c1", fn, '{"a": 1, "b": 2}')])),
        _completion(_msg(content="the sum is 3")),
    ]
    trace = await run_agent_task(
        session=_session(lambda n, a: _tool_result("3")),
        bridge=bridge,
        client=_client(responses),
        model="m",
        task="add 1 and 2",
    )
    assert trace.stop_reason == "end"
    assert trace.turns == 2
    assert trace.called_tools == ["add"]
    assert trace.tool_calls[0].arguments == {"a": 1, "b": 2}
    assert trace.tool_calls[0].ok
    assert trace.tool_calls[0].result_text == "3"
    assert trace.final_text == "the sum is 3"
    assert trace.prompt_tokens == 20
    assert not trace.had_tool_error


async def test_agent_loop_tool_error_result() -> None:
    bridge = build_tool_bridge([_ADD])
    fn = bridge.tools[0]["function"]["name"]
    responses = [
        _completion(_msg(tool_calls=[_tool_call("c1", fn, '{"a": 1, "b": 2}')])),
        _completion(_msg(content="that failed")),
    ]
    trace = await run_agent_task(
        session=_session(lambda n, a: _tool_result("kaboom", is_error=True)),
        bridge=bridge,
        client=_client(responses),
        model="m",
        task="add",
    )
    assert trace.had_tool_error
    assert not trace.tool_calls[0].ok


async def test_agent_loop_raised_tool_error() -> None:
    bridge = build_tool_bridge([_ADD])
    fn = bridge.tools[0]["function"]["name"]
    responses = [
        _completion(_msg(tool_calls=[_tool_call("c1", fn, '{"a": 1, "b": 2}')])),
        _completion(_msg(content="done anyway")),
    ]
    trace = await run_agent_task(
        session=_session(lambda n, a: RuntimeError("transport blip")),
        bridge=bridge,
        client=_client(responses),
        model="m",
        task="add",
    )
    assert trace.had_tool_error
    assert trace.tool_calls[0].error is not None


async def test_agent_loop_max_turns() -> None:
    loop_tool = ToolInfo(name="loop", input_schema={"type": "object", "properties": {}})
    bridge = build_tool_bridge([loop_tool])
    fn = bridge.tools[0]["function"]["name"]
    tool_response = _completion(_msg(tool_calls=[_tool_call("c1", fn, "{}")]))
    trace = await run_agent_task(
        session=_session(lambda n, a: _tool_result("again")),
        bridge=bridge,
        client=_client([tool_response] * 5),
        model="m",
        task="loop forever",
        max_turns=3,
    )
    assert trace.stop_reason == "max_turns"
    assert trace.turns == 3


async def test_judge_parses_verdict() -> None:
    client = _client([], judge_verdict={"success": True, "score": 88, "reasoning": "looks right"})
    verdict = await judge_task(
        client, "m", EvalTask(description="d", rubric="r"), AgentTrace(task="d", final_text="x")
    )
    assert verdict.success
    assert verdict.score == 88


async def test_agentic_eval_aggregates_and_attributes() -> None:
    flaky = ToolInfo(
        name="flaky",
        input_schema={"type": "object", "properties": {"v": {"type": "string"}}, "required": ["v"]},
    )
    fn = build_tool_bridge([flaky]).tools[0]["function"]["name"]
    responses = [
        _completion(_msg(tool_calls=[_tool_call("c1", fn, '{"v": "x"}')])),
        _completion(_msg(content="could not finish")),
    ]
    client = _client(responses, judge_verdict={"success": False, "score": 0, "reasoning": "failed"})
    dims, detail = await run_agentic_eval(
        session=_session(lambda n, a: _tool_result("err", is_error=True)),
        tools=[flaky],
        client=client,
        model="m",
        provider="test",
        tasks=[EvalTask(description="use flaky", rubric="r", expected_tools=["flaky"])],
        repeats=1,
        max_turns=4,
        excluded_write_tools=[],
    )
    assert {d.key for d in dims} == {"task_success", "tool_selection", "tool_reliability"}
    reliability = next(d for d in dims if d.key == "tool_reliability")
    assert reliability.score < 100
    task_success = next(d for d in dims if d.key == "task_success")
    assert any("server signal" in f.message for f in task_success.findings)
    assert detail.results[0].tool_error is True
