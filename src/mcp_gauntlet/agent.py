"""Run an LLM agent against a live MCP server using only that server's tools.

The loop is a plain OpenAI chat-completions tool-calling loop: the model sees the
server's tools (bridged to function-calling schema), decides which to call, and we
dispatch each call to the real MCP session and feed the result back — capturing a
full trace (calls, arguments, results, turns, tokens) for grading.
"""

from __future__ import annotations

import json
from typing import Any

import anyio
from mcp import ClientSession
from openai import AsyncOpenAI
from pydantic import BaseModel, Field

from mcp_gauntlet.adapters import adapter
from mcp_gauntlet.client import InteractionLog
from mcp_gauntlet.content import block_text
from mcp_gauntlet.llm import chat_completion
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
    result_text: str = ""  # what the MODEL sees — bounded by the prompt budget
    # What the SCANNER sees, bounded far higher. One string serving both purposes meant the
    # security scan inherited the prompt budget, so a server could push a payload past it by
    # returning a few thousand characters of ordinary text first. Whichever end was clipped
    # went unexamined, and reordering the render only chose which one to sacrifice.
    scan_text: str = ""
    scan_truncated: bool = False  # the output exceeded even the scan budget — say so
    error: str | None = None
    unknown_tool: bool = False  # model invented a tool the server never offered (agent error)
    bad_arguments: bool = False  # model emitted non-JSON-object arguments (agent error)
    needed_interaction: bool = False  # the server asked for elicitation/sampling we declined

    @property
    def agent_fault(self) -> bool:
        """This failed call was the agent's mistake — excluded from server signals."""
        return self.unknown_tool or self.bad_arguments

    @property
    def counts_for_reliability(self) -> bool:
        """Whether this call is a fair Tool Reliability signal for the *server*.

        Excludes the agent's own mistakes (unknown tool, malformed args) and — only
        when the call failed — a call the server could not complete because it needed
        an interactive capability the harness declines. A call that *succeeded* despite
        requesting interaction still counts: the server handled the decline gracefully.

        This is deliberately benefit-of-the-doubt: it excuses a *failed* call whenever an
        interaction was requested during it, without proving the decline *caused* the
        failure (which isn't generally observable). A server could exploit that to hide
        unrelated failures by always requesting an interaction — but it gains little,
        because those failed tasks still sink Agent Task Success (the heaviest dimension),
        and the excused calls are surfaced in the report's interaction note. The clean
        fix — routing a server whose tools are predominantly interaction-blocked to a
        "not evaluable" bucket — is tracked for the leaderboard rework.
        """
        if self.agent_fault:
            return False
        return self.ok or not self.needed_interaction


def _asks_for_input(result: Any) -> bool:
    """Whether a tool result is the MRTR "I need something from a human" shape.

    Delegated to the adapter because the field was renamed: `mcp` 2.0 calls it
    `result_type`, and the first version of this read only `resultType` — so against the
    modern servers that are the only ones speaking MRTR it returned None, and a call the
    harness declined was charged to the server's reliability. The seam exists for exactly
    this.
    """
    return adapter().asks_for_input(result)


class AgentTrace(BaseModel):
    task: str
    final_text: str = ""
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    turns: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    stop_reason: str = "end"  # end | max_turns | error | tool_timeout
    error: str | None = None

    @property
    def called_tools(self) -> list[str]:
        # Only tools that exist on this server: a hallucinated name must not earn
        # selection credit just because it matches an expected tool's original
        # (pre-sanitization) spelling that the bridge never offered under that name.
        return [call.tool for call in self.tool_calls if not call.unknown_tool]

    @property
    def had_tool_error(self) -> bool:
        # A *server* tool error: the call was dispatched, counts as a reliability signal,
        # and failed. Agent mistakes (hallucinated tool, malformed args) and
        # interaction-blocked failures don't count against the server.
        return any(call.counts_for_reliability and not call.ok for call in self.tool_calls)

    @property
    def blocked_on_interaction(self) -> bool:
        # A call the server couldn't complete because it needed an elicitation/sampling
        # capability the harness declines — a harness limitation, not a server or agent
        # fault. Used to attribute the task failure honestly.
        return any(call.needed_interaction and not call.ok for call in self.tool_calls)


_block_text = block_text  # shared with the prompt path; see mcp_gauntlet.content


def _render_tool_result(result: Any) -> tuple[bool, str]:
    """Turn an MCP CallToolResult into (ok, text-for-the-model)."""
    sdk = adapter()
    is_error = sdk.result_is_error(result)
    parts: list[str] = []
    for block in sdk.result_content(result):
        text = _block_text(block)
        parts.append(text if text is not None else f"[{getattr(block, 'type', 'content')}]")
    # ALWAYS include the structured result, not only as a fallback for empty content: a
    # tool declaring an outputSchema must return structuredContent, and nothing stops it
    # also returning a clean text block. Gating on empty content let that pairing carry a
    # payload straight past the scan while the decoy text was all it examined.
    #
    # Order is presentation only — content first, as a client renders it. The scan does NOT
    # depend on it: the caller keeps a separately-budgeted `scan_text`, because while this
    # string was doing both jobs, whichever end the prompt budget clipped went unexamined
    # and the ordering merely chose which one to sacrifice.
    #
    # `ensure_ascii=False` matters as much: escaping to \uXXXX turns a zero-width space or
    # a smuggled combining mark into ordinary ASCII letters, which is exactly what the
    # normalization and hidden-character checks look for — the escape neutralized the scan
    # on the path this was opened to cover. A real client hands the model the parsed object
    # with the characters intact, so the scanner must see them intact too.
    structured = sdk.result_structured(result)
    if structured is not None:
        parts.append(json.dumps(structured, ensure_ascii=False, default=str))
    return (not is_error, "\n".join(parts) if parts else "(no content)")


def _parse_args(raw: str | None) -> dict[str, Any] | None:
    """None means malformed. Dispatching ``{}`` instead would send the server a call
    the model never made and record the server's rejection against ITS reliability."""
    if not raw:  # providers legitimately send "" for a no-argument tool
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


async def run_agent_task(
    *,
    session: ClientSession,
    bridge: ToolBridge,
    client: AsyncOpenAI,
    model: str,
    task: str,
    max_turns: int = 8,
    result_char_limit: int = 4000,
    # Bounded so a server can't exhaust memory, but far above the prompt budget: the scan
    # must not be evadable by padding a result past what the model is shown.
    scan_char_limit: int = 64_000,
    tool_timeout_s: float = 60.0,
    interactions: InteractionLog | None = None,
) -> AgentTrace:
    trace = AgentTrace(task=task)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": AGENT_SYSTEM},
        {"role": "user", "content": task},
    ]

    for turn in range(1, max_turns + 1):
        trace.turns = turn
        try:
            completion = await chat_completion(
                client,
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

        # Providers/proxies do return an empty choices list (content filter, upstream
        # error body) — treat it as an errored (inconclusive) run, not an IndexError crash.
        if not completion.choices:
            trace.stop_reason = "error"
            trace.error = "llm returned no choices"
            return trace
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
                    arguments=args or {},
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
            if args is None:
                # The tool exists but the arguments weren't a JSON object. Don't
                # dispatch {} — the server rejecting a call the model never made would
                # count against the SERVER's reliability for the agent's garbage.
                record = ToolCallRecord(
                    tool=original,
                    ok=False,
                    bad_arguments=True,
                    error="malformed tool arguments (not a JSON object)",
                    result_text="ERROR: tool arguments were not a valid JSON object; "
                    "retry the call with valid JSON",
                )
                trace.tool_calls.append(record)
                messages.append(
                    {"role": "tool", "tool_call_id": tc.id, "content": record.result_text}
                )
                continue

            record = ToolCallRecord(tool=original, arguments=args)
            timed_out = False
            # Snapshot the decline counter: any elicitation/sampling/roots request the
            # server makes lands here, during the call, on the session's receive loop. If
            # the count grows, this tool needed an interactive capability we declined — so
            # a failure is the harness's limit, not the server's, and won't count against
            # Tool Reliability.
            interactions_before = interactions.total if interactions is not None else 0
            result: Any = None
            try:
                # Bound every dispatch: an unbounded call_tool lets one hung tool hang the
                # whole CLI forever (the MCP session has no read timeout of its own).
                with anyio.fail_after(tool_timeout_s):
                    result = await session.call_tool(original, args)
                ok, text = _render_tool_result(result)
                record.ok = ok
                record.result_text = text[:result_char_limit]
                # The scanner gets its own, far larger budget: the prompt budget exists to
                # bound what the model reads, and letting it also bound what the SECURITY
                # scan reads made "return 4000 characters of filler first" an evasion.
                record.scan_text = text[:scan_char_limit]
                # An output too large even for the scan budget is itself a way to push a
                # payload past a bounded scanner, so it is recorded and reported rather
                # than left to read as a clean result — the same rule the schema scan
                # already follows.
                record.scan_truncated = len(text) > scan_char_limit
                if not ok:
                    record.error = "tool reported an error"
            except TimeoutError:
                timed_out = True
                record.ok = False
                # :g not :.0f — a fractional limit must not render as "0s".
                record.error = f"tool did not respond within {tool_timeout_s:g}s"
                record.result_text = f"ERROR: {record.error}"
            except Exception as exc:  # noqa: BLE001 - a failed tool call is data, not fatal
                record.ok = False
                record.error = str(exc)
                # An McpError's message is server-authored, so it gets the scan budget too —
                # symmetry, so no path can drift into scanning less than the model reads.
                record.result_text = f"ERROR: {exc}"[:result_char_limit]
                record.scan_text = f"ERROR: {exc}"[:scan_char_limit]
            if interactions is not None and interactions.total > interactions_before:
                record.needed_interaction = True
            elif _asks_for_input(result):
                # The same fact, arriving the other way round. Under MCP revision
                # 2026-07-28 a server MUST NOT push an elicitation or sampling request at
                # the client; it returns `resultType: "input_required"` inside an ordinary
                # tool result and waits to be re-called with the answers.
                #
                # Detected here because the counter above never moves for such a server:
                # nothing arrives on the receive loop. Without this the attribution silently
                # inverts — a call the harness declined to complete looks like a plain
                # failure and is charged to the server's Tool Reliability, which is the
                # opposite of what this whole path exists to do.
                record.needed_interaction = True
                if interactions is not None:
                    interactions.elicitation += 1
            trace.tool_calls.append(record)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": record.result_text or record.error or "(no content)",
                }
            )
            if timed_out:
                # End the run rather than keep driving a server that just hung. Not because
                # the session is unusable — a cancelled call_tool cleans up after itself and
                # the session stays fine — but because each further turn can cost another
                # full timeout, and the caller's overall budget is finite. The timed-out
                # call is already recorded, so it still counts against Tool Reliability and
                # the partial run is judged normally (a server failure, NOT the "error"
                # stop_reason that means an inconclusive LLM hiccup).
                trace.stop_reason = "tool_timeout"
                return trace

    trace.stop_reason = "max_turns"
    return trace
