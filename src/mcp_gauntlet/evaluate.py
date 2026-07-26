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
from mcp_gauntlet.checks import scan_runtime_outputs
from mcp_gauntlet.client import InteractionLog
from mcp_gauntlet.judge import judge_task, selection_score
from mcp_gauntlet.models import ToolInfo
from mcp_gauntlet.report import (
    AgenticDetail,
    Dim,
    DimensionResult,
    Finding,
    Severity,
    TaskResult,
)
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
    tool_timeout_s: float = 60.0,
    interactions: InteractionLog | None = None,
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
        # No tasks means generation failed (rate limit / bad output), not that the server
        # has nothing to test — mark it inconclusive so it reads as "couldn't run", not "0/0".
        detail.inconclusive = True
        return [], detail

    success_findings: list[Finding] = []
    selection_findings: list[Finding] = []
    timeout_findings: list[Finding] = []
    runtime_outputs: list[tuple[str, str]] = []  # (tool, output) for dynamic poisoning scan
    scan_truncated_tools: set[str] = set()  # outputs too large to examine completely
    total_calls = 0
    ok_calls = 0
    hung = False  # a tool blew the per-call timeout — stop after finishing this repeat

    for task in tasks:
        valid_scores: list[float] = []
        valid_sel: list[float] = []
        successes = 0
        valid_repeats = 0
        errored_repeats = 0
        any_tool_error = False
        any_interaction_block = False
        sample_reasoning = ""
        sample_error = ""
        attempts = 0

        for _ in range(repeats):
            attempts += 1
            trace = await run_agent_task(
                session=session,
                bridge=bridge,
                client=client,
                model=model,
                task=task.description,
                max_turns=max_turns,
                tool_timeout_s=tool_timeout_s,
                interactions=interactions,
            )
            # Latch the hang BEFORE any of the paths below that `continue` — a rate-limited
            # judge is exactly when a hang is most likely, and letting that skip the check
            # would grind through every remaining repeat at a full timeout each, blow the
            # caller's budget, and lose the report: the very outcome this prevents.
            if trace.stop_reason == "tool_timeout":
                hung = True

            # Collected BEFORE the inconclusive-repeat `continue` below. What a server
            # returned is evidence whether or not the agent's own LLM survived long enough
            # to be graded on it — and a rate-limited agent (the free tiers this runs on)
            # is exactly when a turn dies mid-task, so gating the security scan on the
            # judge succeeding would quietly drop real payloads. Reliability stays below
            # the `continue` on purpose: it measures how well the SERVER answered a
            # completed attempt, and half an attempt is not a fair denominator.
            #
            # Keyed on a DIFFERENT filter than reliability, also on purpose: a poisoned
            # output must be scanned even when the same call triggered a declined
            # interaction (and is excused from the reliability score). Only the agent's own
            # never-dispatched calls — hallucinated names, malformed args — are skipped;
            # their "output" is a harness-authored error string, not server content.
            # `scan_text` carries the full result, not the clipped copy the model was shown,
            # so a payload can't be pushed past the scan by padding the output. It falls back
            # to result_text for the records that never reached a server (timeouts, transport
            # errors), where the two are the same short string.
            runtime_outputs.extend(
                (call.tool, call.scan_text or call.result_text)
                for call in trace.tool_calls
                if (call.scan_text or call.result_text) and not call.agent_fault
            )
            scan_truncated_tools.update(
                call.tool for call in trace.tool_calls if call.scan_truncated
            )

            if trace.stop_reason == "error":  # agent's own LLM call failed — inconclusive
                # No `if hung: break` needed here: run_agent_task returns the moment a tool
                # times out, so a single trace is never both "error" and "tool_timeout", and
                # a hang in an EARLIER repeat already broke out of this loop.
                errored_repeats += 1
                sample_error = sample_error or (trace.error or "agent LLM error")
                continue

            # Tool Reliability is a SERVER signal, so it counts only calls that are a fair
            # signal for the server: not an agent mistake (hallucinated tool / malformed
            # args the server never saw) and not a failure the server couldn't avoid
            # because it needed an interactive capability the harness declines.
            reliability_calls = [c for c in trace.tool_calls if c.counts_for_reliability]
            total_calls += len(reliability_calls)
            ok_calls += sum(1 for call in reliability_calls if call.ok)
            any_tool_error = any_tool_error or trace.had_tool_error
            any_interaction_block = any_interaction_block or trace.blocked_on_interaction

            verdict = await judge_task(client, model, task, trace)
            if verdict.errored:  # judge call failed — can't grade this run
                errored_repeats += 1
                sample_error = sample_error or verdict.reasoning
                if hung:
                    break
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

            if hung:
                # Stop the whole evaluation, not just this run: a server that hangs once
                # almost always hangs again, and re-learning that costs a full tool timeout
                # per remaining repeat. Same early-stop stance as the robustness probes.
                break

        inconclusive = valid_repeats == 0
        result = TaskResult(
            description=task.description,
            rubric=task.rubric,
            expected_tools=task.expected_tools,
            # Repeats actually ATTEMPTED, not the configured count: a hang can cut a task
            # short, and reporting "0/2" for a task that ran once reads as two failures.
            repeats=attempts,
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

        if hung:
            # Surface the timeout itself: without this the report is byte-identical to a
            # genuinely broken server, and a user whose tool is merely SLOW has no way to
            # tell — nothing else in the report mentions the limit or the flag that raises it.
            timeout_findings.append(
                Finding(
                    severity=Severity.HIGH,
                    message=f"a tool did not respond within the {tool_timeout_s:g}s limit — "
                    "stopped the agent evaluation early",
                    detail="If this server is legitimately slow rather than hung, raise "
                    "--tool-timeout and re-run.",
                )
            )

        # An inconclusive task produced no valid judgment, so it earns no findings.
        if not inconclusive:
            if successes < valid_repeats:
                severity = Severity.MEDIUM if successes == 0 else Severity.LOW
                # Attribution order: a real server tool error dominates; failing that, a
                # declined interactive capability is the harness's limit (not the agent's);
                # otherwise the agent itself didn't get there.
                if any_tool_error:
                    attribution = "tool errors blocked it (server signal)"
                elif any_interaction_block:
                    attribution = (
                        "needed an interactive capability gauntlet declines (harness limit)"
                    )
                else:
                    attribution = "agent did not complete it (agent signal)"
                message = (
                    f"agent failed a task ({successes}/{valid_repeats} passed) — {attribution}"
                )
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
                        detail=f"{task.description[:120]} "
                        f"(expected {', '.join(task.expected_tools)})",
                    )
                )

        if hung:
            break

    conclusive = [r for r in detail.results if not r.inconclusive]
    detail.inconclusive = len(conclusive) == 0
    detail.truncated = hung  # record the fact; downstream must not have to infer it
    if interactions is not None:
        # Record how many interactive requests the server made and we declined, so the
        # report can explain any interaction-blocked failures instead of leaving them to
        # look like server unreliability.
        detail.interactive_requests = interactions.total
        detail.interactive_summary = interactions.summary()

    dimensions: list[DimensionResult] = []
    if conclusive:
        task_scores = [r.mean_score for r in conclusive]
        sel_values = [r.selection_score for r in conclusive if r.selection_score is not None]
        dimensions.append(
            DimensionResult(
                key=Dim.TASK_SUCCESS,
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
                key=Dim.TOOL_SELECTION,
                title="Tool-Selection Accuracy",
                weight=1.5,
                score=round(mean(sel_values), 1) if sel_values else 100.0,
                summary="Whether the agent called the tools each task was expected to use.",
                findings=selection_findings,
            )
        )
    if total_calls:
        reliability = _reliability_dimension(total_calls, ok_calls)
        reliability.findings.extend(timeout_findings)  # a hang is a reliability signal
        dimensions.append(reliability)
    # Dynamic tool-poisoning: scan what the tools actually RETURNED. Independent of judge
    # conclusiveness — the outputs were collected whenever the agent ran.
    response_safety = scan_runtime_outputs(runtime_outputs, scan_truncated_tools)
    if response_safety is not None:
        dimensions.append(response_safety)
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
        key=Dim.TOOL_RELIABILITY,
        title="Tool Reliability",
        weight=1.0,
        score=score,
        summary="Fraction of the agent's tool calls the server executed without error — a "
        "server-quality signal distinct from whether the agent finished the task.",
        findings=findings,
    )
