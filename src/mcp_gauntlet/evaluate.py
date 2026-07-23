"""Orchestrate the agentic evaluation.

Run each (pre-resolved) task against the live server with N repeats, judge every
run, and aggregate into three scored dimensions — Agent Task Success (does the
agent accomplish the task), Tool-Selection Accuracy (does it pick the right
tools), and Tool Reliability (do the server's tools execute without error, a
server-quality signal distinct from whether the agent finished) — plus a per-task
detail record.
"""

from __future__ import annotations

from statistics import mean

from mcp import ClientSession
from openai import AsyncOpenAI

from mcp_gauntlet.agent import run_agent_task
from mcp_gauntlet.judge import judge_task, selection_score
from mcp_gauntlet.models import ToolInfo
from mcp_gauntlet.report import AgenticDetail, DimensionResult, Finding, Severity, TaskResult
from mcp_gauntlet.tasks import EvalTask
from mcp_gauntlet.toolconv import build_tool_bridge


async def run_agentic_eval(
    *,
    session: ClientSession,
    tools: list[ToolInfo],
    client: AsyncOpenAI,
    model: str,
    provider: str,
    tasks: list[EvalTask],
    repeats: int,
    max_turns: int,
    excluded_write_tools: list[str],
) -> tuple[list[DimensionResult], AgenticDetail]:
    bridge = build_tool_bridge(tools)
    detail = AgenticDetail(
        provider=provider,
        model=model,
        tasks_generated=len(tasks),
        repeats=repeats,
        excluded_write_tools=excluded_write_tools,
    )
    if not tasks:
        return [], detail

    success_findings: list[Finding] = []
    selection_findings: list[Finding] = []
    total_calls = 0
    ok_calls = 0

    for task in tasks:
        scores: list[float] = []
        sel_scores: list[float] = []
        successes = 0
        any_tool_error = False
        sample_reasoning = ""
        for _ in range(repeats):
            trace = await run_agent_task(
                session=session,
                bridge=bridge,
                client=client,
                model=model,
                task=task.description,
                max_turns=max_turns,
            )
            total_calls += len(trace.tool_calls)
            ok_calls += sum(1 for call in trace.tool_calls if call.ok)
            any_tool_error = any_tool_error or trace.had_tool_error

            verdict = await judge_task(client, model, task, trace)
            scores.append(verdict.score)
            if verdict.success:
                successes += 1
            elif not sample_reasoning:
                sample_reasoning = verdict.reasoning
            sel = selection_score(task.expected_tools, trace.called_tools)
            if sel is not None:
                sel_scores.append(sel)

        result = TaskResult(
            description=task.description,
            rubric=task.rubric,
            expected_tools=task.expected_tools,
            repeats=repeats,
            successes=successes,
            success_rate=successes / repeats if repeats else 0.0,
            mean_score=round(mean(scores), 1) if scores else 0.0,
            selection_score=round(mean(sel_scores), 1) if sel_scores else None,
            tool_error=any_tool_error,
            sample_reasoning=sample_reasoning,
        )
        detail.results.append(result)

        if successes < repeats:
            severity = Severity.MEDIUM if successes == 0 else Severity.LOW
            attribution = (
                "tool errors blocked it (server signal)"
                if any_tool_error
                else "agent did not complete it (agent signal)"
            )
            success_findings.append(
                Finding(
                    severity=severity,
                    message=f"agent failed a task ({successes}/{repeats} passed) — {attribution}",
                    detail=f"{task.description[:120]} — {sample_reasoning[:140]}",
                )
            )
        if result.selection_score is not None and result.selection_score < 100:
            selection_findings.append(
                Finding(
                    severity=Severity.LOW,
                    message="agent did not call all expected tools",
                    detail=f"{task.description[:120]} (expected {', '.join(task.expected_tools)})",
                )
            )

    task_scores = [r.mean_score for r in detail.results]
    sel_values = [r.selection_score for r in detail.results if r.selection_score is not None]

    dimensions = [
        DimensionResult(
            key="task_success",
            title="Agent Task Success",
            weight=3.0,
            score=round(mean(task_scores), 1) if task_scores else 0.0,
            summary="Whether a live agent, given only this server's tools, completes generated "
            "tasks (LLM-judged, repeated for a success rate).",
            findings=success_findings,
        ),
        DimensionResult(
            key="tool_selection",
            title="Tool-Selection Accuracy",
            weight=1.5,
            score=round(mean(sel_values), 1) if sel_values else 100.0,
            summary="Whether the agent called the tools each task was expected to use.",
            findings=selection_findings,
        ),
        _reliability_dimension(total_calls, ok_calls),
    ]
    return dimensions, detail


def _reliability_dimension(total_calls: int, ok_calls: int) -> DimensionResult:
    findings: list[Finding] = []
    if total_calls == 0:
        score = 100.0
    else:
        score = round(100.0 * ok_calls / total_calls, 1)
        errored = total_calls - ok_calls
        if errored:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM if score < 80 else Severity.LOW,
                    message=f"{errored}/{total_calls} agent tool calls returned an error",
                )
            )
    return DimensionResult(
        key="tool_reliability",
        title="Tool Reliability",
        weight=1.0,
        score=score,
        summary="Fraction of the agent's tool calls the server executed without error — a "
        "server-quality signal distinct from whether the agent finished the task.",
        findings=findings,
    )
