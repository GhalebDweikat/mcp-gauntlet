"""Grade an agent run: an LLM-as-judge verdict plus a deterministic tool-selection score."""

from __future__ import annotations

import json

from openai import AsyncOpenAI
from pydantic import BaseModel

from mcp_gauntlet.agent import AgentTrace
from mcp_gauntlet.tasks import EvalTask

_PROMPT = """\
You are grading whether an AI agent accomplished a task using an MCP server's \
tools. Base your judgment only on the transcript (the tool calls, their results, \
and the agent's final answer).

Grade on substance, not style:
- Mark success=true when the agent achieved the task's intended outcome — the \
right tools were used and the correct result was obtained.
- Do NOT penalize differences in wording, formatting, or phrasing when the \
substantive result is correct (e.g. echoing "The sum is 12" instead of the exact \
source string still conveys the correct value 12).
- Mark success=false only when a substantive requirement was not met: a needed \
tool was not used, a tool returned an error that blocked the task, the final \
result is wrong, or the agent gave up.

TASK:
{task}

RUBRIC (guidance — interpret by intent, not literally):
{rubric}

TRANSCRIPT:
{transcript}

Respond with JSON only: {{"success": true|false, "score": 0-100, "reasoning": "one sentence"}}
Score reflects how fully the task's goal was accomplished (100 = fully, 0 = not at all).
"""


class Verdict(BaseModel):
    success: bool = False
    score: float = 0.0
    reasoning: str = ""
    errored: bool = False  # the judge call itself failed (rate limit / bad output) — inconclusive


def selection_score(expected_tools: list[str], called_tools: list[str]) -> float | None:
    """Fraction of the expected tools the agent actually called (None if no expectation)."""
    if not expected_tools:
        return None
    called = set(called_tools)
    hit = sum(1 for name in expected_tools if name in called)
    return 100.0 * hit / len(expected_tools)


def _render_transcript(trace: AgentTrace) -> str:
    lines: list[str] = []
    for i, call in enumerate(trace.tool_calls, start=1):
        status = "ok" if call.ok else f"error: {call.error}"
        result = call.result_text.replace("\n", " ")[:300]
        lines.append(f"{i}. called {call.tool}({call.arguments}) [{status}] -> {result}")
    if not lines:
        lines.append("(the agent made no tool calls)")
    lines.append(f"final answer: {trace.final_text or '(none)'}")
    lines.append(f"stop reason: {trace.stop_reason}")
    return "\n".join(lines)


async def judge_task(client: AsyncOpenAI, model: str, task: EvalTask, trace: AgentTrace) -> Verdict:
    prompt = _PROMPT.format(
        task=task.description,
        rubric=task.rubric or "The task should be completed correctly.",
        transcript=_render_transcript(trace),
    )
    try:
        completion = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            response_format={"type": "json_object"},
        )
        data = json.loads(completion.choices[0].message.content or "{}")
        return Verdict(
            success=bool(data.get("success", False)),
            score=float(data.get("score", 0.0)),
            reasoning=str(data.get("reasoning", "")),
        )
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        return Verdict(errored=True, reasoning=f"judge parse error: {exc}")
    except Exception as exc:  # noqa: BLE001 - a judge/transport failure shouldn't crash the run
        return Verdict(errored=True, reasoning=f"judge call failed: {exc}")
