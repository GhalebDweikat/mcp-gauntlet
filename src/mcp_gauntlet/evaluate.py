"""Orchestrate the agentic evaluation.

Run each (pre-resolved) task against the live server with N repeats, judge every
run, and aggregate into scored dimensions. Repeats where the LLM itself failed
(rate limit, transport error, unparseable judge output) are treated as
*inconclusive* and excluded from scoring — an infrastructure hiccup must never be
counted as the server failing its task.
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
        valid_scores: list[float] = []
        valid_sel: list[float] = []
        successes = 0
        valid_repeats = 0
        errored_repeats = 0
        any_tool_error = False
        sample_reasoning = ""
        sample_error = ""

        for _ in range(repeats):
            trace = await run_agent_task(
                session=session,
                bridge=bridge,
                client=client,
                model=model,
                task=task.description,
                max_turns=max_turns,
            )
            if trace.stop_reason == "error":  # agent's own LLM call failed — inconclusive
                errored_repeats += 1
                sample_error = sample_error or (trace.error or "agent LLM error")
                continue

            total_calls += len(trace.tool_calls)
            ok_calls += sum(1 for call in trace.tool_calls if call.ok)
            any_tool_error = any_tool_error or trace.had_tool_error

            verdict = await judge_task(client, model, task, trace)
            if verdict.errored:  # judge call failed — can't grade this run
                errored_repeats += 1
                sample_error = sample_error or verdict.reasoning
                continue

            valid_repeats += 1
            valid_scores.append(verdict.score)
            if verdict.success:
                successes += 1
            elif not sample_reasoning:
                sample_reasoning = verdict.reasoning
            sel = selection_score(task.expected_tools, trace.called_tools)
            if sel is not None:
                valid_sel.append(sel)

        inconclusive = valid_repeats == 0
        result = TaskResult(
            description=task.description,
            rubric=task.rubric,
            expected_tools=task.expected_tools,
            repeats=repeats,
            successes=successes,
            success_rate=(successes / valid_repeats) if valid_repeats else 0.0,
            mean_score=round(mean(valid_scores), 1) if valid_scores else 0.0,
            selection_score=round(mean(valid_sel), 1) if valid_sel else None,
            tool_error=any_tool_error,
            errored_repeats=errored_repeats,
            inconclusive=inconclusive,
            sample_reasoning=(
                f"inconclusive — {sample_error}" if inconclusive else sample_reasoning
            ),
        )
        detail.results.append(result)

        if inconclusive:
            continue

        if successes < valid_repeats:
            severity = Severity.MEDIUM if successes == 0 else Severity.LOW
            attribution = (
                "tool errors blocked it (server signal)"
                if any_tool_error
                else "agent did not complete it (agent signal)"
            )
            message = f"agent failed a task ({successes}/{valid_repeats} passed) — {attribution}"
            success_findings.append(
                Finding(
                    severity=severity,
                    message=message,
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

    conclusive = [r for r in detail.results if not r.inconclusive]
    detail.inconclusive = len(conclusive) == 0

    dimensions: list[DimensionResult] = []
    if conclusive:
        task_scores = [r.mean_score for r in conclusive]
        sel_values = [r.selection_score for r in conclusive if r.selection_score is not None]
        dimensions.append(
            DimensionResult(
                key="task_success",
                title="Agent Task Success",
                weight=3.0,
                score=round(mean(task_scores), 1),
                summary="Whether a live agent, given only this server's tools, completes generated "
                "tasks (LLM-judged, repeated for a success rate).",
                findings=success_findings,
            )
        )
        dimensions.append(
            DimensionResult(
                key="tool_selection",
                title="Tool-Selection Accuracy",
                weight=1.5,
                score=round(mean(sel_values), 1) if sel_values else 100.0,
                summary="Whether the agent called the tools each task was expected to use.",
                findings=selection_findings,
            )
        )
    if total_calls:
        dimensions.append(_reliability_dimension(total_calls, ok_calls))
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
