"""Run an LLM agent against a live MCP server using only that server's tools.

The loop is a plain OpenAI chat-completions tool-calling loop: the model sees the
server's tools (bridged to function-calling schema), decides which to call, and we
dispatch each call to the real MCP session and feed the result back — capturing a
full trace (calls, arguments, results, turns, tokens) for grading.
"""

from __future__ import annotations

import json
from typing import Any

from mcp import ClientSession
from openai import AsyncOpenAI
from pydantic import BaseModel, Field

from mcp_gauntlet.toolconv import ToolBridge

AGENT_SYSTEM = (
    "You are an agent with access to a set of tools provided by an MCP server. "
    "Use the tools to accomplish the user's task, calling them with correct arguments "
    "based on their schemas. When the task is complete, respond in plain text with a "
    "short final answer describing what you did and the result. Do not ask the user "
    "questions; make reasonable assumptions and proceed."
)


class ToolCallRecord(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    ok: bool = True
    result_text: str = ""
    error: str | None = None
    unknown_tool: bool = False  # model invented a tool the server never offered (agent error)


class AgentTrace(BaseModel):
    task: str
    final_text: str = ""
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    turns: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    stop_reason: str = "end"  # end | max_turns | error
    error: str | None = None

    @property
    def called_tools(self) -> list[str]:
        return [call.tool for call in self.tool_calls]

    @property
    def had_tool_error(self) -> bool:
        # A hallucinated-tool call is an agent error, not a server-reliability signal.
        return any(not call.ok and not call.unknown_tool for call in self.tool_calls)


def _render_tool_result(result: Any) -> tuple[bool, str]:
    """Turn an MCP CallToolResult into (ok, text-for-the-model)."""
    is_error = bool(getattr(result, "isError", False))
    parts: list[str] = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        parts.append(text if text is not None else f"[{getattr(block, 'type', 'content')}]")
    if not parts:
        structured = getattr(result, "structuredContent", None)
        if structured is not None:
            parts.append(json.dumps(structured))
    return (not is_error, "\n".join(parts) if parts else "(no content)")


def _parse_args(raw: str | None) -> dict[str, Any]:
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


async def run_agent_task(
    *,
    session: ClientSession,
    bridge: ToolBridge,
    client: AsyncOpenAI,
    model: str,
    task: str,
    max_turns: int = 8,
    result_char_limit: int = 4000,
) -> AgentTrace:
    trace = AgentTrace(task=task)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": AGENT_SYSTEM},
        {"role": "user", "content": task},
    ]

    for turn in range(1, max_turns + 1):
        trace.turns = turn
        try:
            completion = await client.chat.completions.create(  # type: ignore[call-overload]
                model=model,
                messages=messages,
                tools=bridge.tools,
                tool_choice="auto",
                temperature=0,
            )
        except Exception as exc:  # noqa: BLE001 - any LLM/transport failure ends the run
            trace.stop_reason = "error"
            trace.error = f"llm call failed: {exc}"
            return trace

        if completion.usage:
            trace.prompt_tokens += completion.usage.prompt_tokens or 0
            trace.completion_tokens += completion.usage.completion_tokens or 0

        message = completion.choices[0].message
        # Echo the full assistant message back into history, preserving provider-specific
        # extras (e.g. Gemini's thought_signature on tool calls) that some models require
        # on the follow-up turn. Reconstructing a minimal message would drop them.
        messages.append(message.model_dump(exclude_none=True))

        if not message.tool_calls:
            trace.final_text = message.content or ""
            trace.stop_reason = "end"
            return trace

        for tc in message.tool_calls:
            args = _parse_args(tc.function.arguments)
            if not bridge.knows(tc.function.name):
                # The model invented a tool this server never offered — record it as an
                # agent error (excluded from the server's Tool Reliability) and tell the
                # model, rather than dispatching a bogus name and blaming the server.
                record = ToolCallRecord(
                    tool=tc.function.name,
                    arguments=args,
                    ok=False,
                    unknown_tool=True,
                    error="unknown tool (not offered by this server)",
                    result_text="ERROR: no such tool on this server",
                )
                trace.tool_calls.append(record)
                messages.append(
                    {"role": "tool", "tool_call_id": tc.id, "content": record.result_text}
                )
                continue

            original = bridge.original(tc.function.name)
            record = ToolCallRecord(tool=original, arguments=args)
            try:
                result = await session.call_tool(original, args)
                ok, text = _render_tool_result(result)
                record.ok = ok
                record.result_text = text[:result_char_limit]
                if not ok:
                    record.error = "tool reported an error"
            except Exception as exc:  # noqa: BLE001 - a failed tool call is data, not fatal
                record.ok = False
                record.error = str(exc)
                record.result_text = f"ERROR: {exc}"[:result_char_limit]
            trace.tool_calls.append(record)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": record.result_text or record.error or "(no content)",
                }
            )

    trace.stop_reason = "max_turns"
    return trace
