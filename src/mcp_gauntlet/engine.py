"""Top-level evaluation: discovery + static checks + optional agentic eval → one report.

Everything runs inside a single MCP session so the static analysis and the live
agent share one connection.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path

from mcp import ClientSession
from mcp.types import InitializeResult
from openai import AsyncOpenAI

from mcp_gauntlet.checks import run_static_checks, scan_tool
from mcp_gauntlet.client import discover_in_session, open_session
from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.drift import (
    UnreadableBaseline,
    baseline_file,
    changed_within_session,
    compare_to_baseline,
    compare_within_session,
    load_baseline,
    save_baseline,
    spec_key,
)
from mcp_gauntlet.evaluate import run_agentic_eval
from mcp_gauntlet.llm import LLMConfig, make_async_client
from mcp_gauntlet.models import DiscoveryResult, ToolInfo
from mcp_gauntlet.preflight import probe_credentials
from mcp_gauntlet.protocol import TransportLog
from mcp_gauntlet.report import AgenticDetail, Finding, GauntletReport, Severity, redact
from mcp_gauntlet.robustness import run_robustness_probes
from mcp_gauntlet.safety import filter_read_only
from mcp_gauntlet.taskcache import (
    DEFAULT_CACHE_DIR,
    cache_file,
    load_tasks,
    save_tasks,
    server_key,
)
from mcp_gauntlet.tasks import EvalTask, generate_tasks

_log = logging.getLogger(__name__)


def _grounding_context(spec: ServerSpec, discovery: DiscoveryResult, tools: list[ToolInfo]) -> str:
    """Facts about this server's environment, so task generation needn't guess at it.

    The generator otherwise sees only tool *descriptions*, and for a server whose tools take
    a path, a repository or a table name it has no choice but to invent one. It invents
    plausibly — `/workspace/assets`, `/var/repos/data-pipeline` — and every call then fails,
    scoring the server for the harness's guess. Anything listed here is real; anything not
    listed, the task has to discover before using.
    """
    lines: list[str] = []

    # The spec's own arguments are the cheapest ground truth there is: a filesystem server's
    # root and a git server's repository are sitting right there in the command line.
    if spec.args:
        lines.append(
            "- The server was started with these arguments (paths among them are real): "
            + " ".join(spec.args)
        )
    if spec.url:
        lines.append(f"- The server is reachable at: {spec.url}")

    # Zero-argument tools are the server's own discovery surface — callable with nothing
    # known, which is exactly the position a generated task starts from.
    no_args = [
        t.name
        for t in tools
        if not (t.input_schema.get("properties") or {}) and not t.input_schema.get("required")
    ]
    if no_args:
        lines.append(
            "- These tools take no arguments, so a task may call them first to find out "
            "what exists: " + ", ".join(sorted(no_args))
        )

    # Resource URIs are real identifiers the server published about itself.
    uris = [r.uri for r in discovery.resources if r.uri and not r.is_template][:12]
    if uris:
        lines.append("- Resources the server exposes: " + ", ".join(uris))

    return "\n".join(lines)


def _protocol_findings(transport: TransportLog) -> list[Finding]:
    """A server writing non-protocol output to stdout is breaking the transport it speaks.

    On stdio, stdout carries JSON-RPC framing and nothing else. A framework logger left
    pointed at it — a NestJS banner, a stray `print` — puts lines on that channel that are
    not messages. The SDK skips them, so the server usually still works and its author never
    sees a problem, but it corrupts the stream for every client and a stricter one may not be
    so forgiving.

    Reported as a server-level finding, MEDIUM, so it lowers the score without capping the
    grade: it is a real defect and an objective one, but it is not evidence of an attack,
    and only near-certain attack signals are allowed to cap.
    """
    if not transport.unparseable_lines:
        return []
    return [
        Finding(
            severity=Severity.MEDIUM,
            message=(
                f"server wrote {transport.unparseable_lines} non-protocol line(s) to stdout, "
                "which carries JSON-RPC framing only (logs belong on stderr)"
            ),
            detail=transport.summary() or None,
        )
    ]


async def _resolve_tasks(
    *,
    client: AsyncOpenAI,
    model: str,
    tools: list[ToolInfo],
    discovery: DiscoveryResult,
    spec: ServerSpec,
    n_tasks: int,
    tasks_file: Path | None,
    refresh_tasks: bool,
    cache_dir: Path,
    secrets: frozenset[str] = frozenset(),
) -> list[EvalTask]:
    """Load a pinned/cached task set if present, otherwise generate and save one."""
    path = tasks_file or cache_file(cache_dir, server_key(discovery.server, tools))
    if not refresh_tasks:
        cached = load_tasks(path)
        if cached:  # non-empty hit; an empty/failed set is a miss, not a cached "no tasks"
            return cached
    tasks = await generate_tasks(
        client, model, tools, n_tasks, context=_grounding_context(spec, discovery, tools)
    )
    if secrets and tasks:
        # A task is LLM-generated from server-controlled tool descriptions, and the cache
        # (or a committed --tasks-file) is persisted to disk. If a server echoed a credential
        # into a description and the model copied it into a task, scrub it before it lands.
        tasks = [
            task.model_copy(
                update={
                    "description": redact(task.description, secrets),
                    "rubric": redact(task.rubric, secrets),
                }
            )
            for task in tasks
        ]
    if tasks:  # never cache a failed (empty) generation — that would reproduce the failure
        save_tasks(path, tasks)
    return tasks


async def _check_definition_drift(
    session: ClientSession,
    init: InitializeResult,
    spec: ServerSpec,
    discovery: DiscoveryResult,
    baseline_dir: Path,
    track: bool,
) -> list[Finding]:
    """Compare the tool surface against itself and against the last run.

    Both halves are best-effort: a server that fails the second ``tools/list`` should not
    lose its evaluation over a check that is looking for an anomaly, and a baseline that
    can't be written (read-only checkout, CI sandbox) must not either.
    """
    if not track:
        return []
    findings: list[Finding] = []
    try:
        second = await discover_in_session(session, init)
    except Exception as exc:  # noqa: BLE001 - an unstable re-list can't cost us the run
        # But say the check didn't run. Silently swallowing this let a server defeat the
        # only within-session check by refusing exactly one request, with the report
        # indistinguishable from a server that answered twice identically.
        second = None
        findings.append(
            Finding(
                severity=Severity.LOW,
                message="the server did not answer a second tools/list, so its definitions "
                "were not checked for mid-session changes",
                detail=str(exc)[:200],
            )
        )
    if second is not None:
        tools_capability = getattr(getattr(init, "capabilities", None), "tools", None)
        findings.extend(
            compare_within_session(
                discovery.tools,
                second.tools,
                declared_list_changed=bool(getattr(tools_capability, "listChanged", False)),
            )
        )
        # Scan what the second listing actually said. Reporting only that a definition moved
        # would leave a payload that appears solely in the second listing unexamined — the
        # first listing is what everything else in the run is built from.
        for tool in changed_within_session(discovery.tools, second.tools):
            for finding in scan_tool(tool):
                findings.append(
                    finding.model_copy(update={"message": f"second tools/list: {finding.message}"})
                )

    path = baseline_file(baseline_dir, spec_key(spec.label()))
    try:
        baseline = load_baseline(path)
    except UnreadableBaseline as exc:
        # Say the check didn't run rather than let a corrupt baseline read as "no drift".
        baseline = None
        findings.append(
            Finding(
                severity=Severity.INFO,
                message="could not read the recorded tool definitions, so this run was not "
                "compared against them",
                detail=f"{path}: {exc}",
            )
        )
    if baseline is not None:
        findings.extend(compare_to_baseline(baseline, discovery.server, discovery.tools))
    # Record AFTER comparing, so this run's surface becomes the next run's baseline. A
    # read-only checkout or CI sandbox must not cost the server its evaluation.
    with contextlib.suppress(OSError):
        save_baseline(path, discovery.server, discovery.tools)
    return findings


async def evaluate_server(
    spec: ServerSpec,
    *,
    llm_config: LLMConfig | None,
    n_tasks: int = 3,
    repeats: int = 2,
    max_turns: int = 8,
    allow_writes: bool = False,
    probe: bool = True,
    tasks_file: Path | None = None,
    refresh_tasks: bool = False,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    tool_timeout_s: float = 60.0,
    track_drift: bool = True,
) -> GauntletReport:
    agentic_detail: AgenticDetail | None = None
    async with open_session(spec) as (session, init, interactions):
        # Prompts are fetched only when probing is on: rendering one is a call to the
        # server, and `--no-probe` means "inspect, don't execute". The messages it returns
        # are the point — they reach the model's context verbatim.
        discovery = await discover_in_session(session, init, fetch_prompts=probe)
        drift_findings = await _check_definition_drift(
            session, init, spec, discovery, cache_dir.parent / "baselines", track_drift
        )
        session_findings = drift_findings + _protocol_findings(interactions.transport)
        dimensions = run_static_checks(discovery, session_findings)

        # The set of tools we'll actually execute (probes + agent) — read-only by default.
        exec_tools = discovery.tools
        excluded: list[str] = []
        if not allow_writes:
            exec_tools, excluded = filter_read_only(discovery.tools)

        # Before any LLM spend: is this server usable at all without credentials? A hosted
        # commercial server connects and lists its tools perfectly, then fails every call.
        # Scoring that produces a published D or F for a configuration the harness chose not
        # to supply. Skipped when credentials WERE supplied — then an auth error is a real
        # finding about the server (or about the token), not a reason to stop.
        needs_credentials = ""
        if llm_config is not None and exec_tools and not spec.env and not spec.headers:
            needs_credentials = await probe_credentials(session, exec_tools) or ""

        if needs_credentials:
            _log.info("skipping agent evaluation: %s", needs_credentials)
        elif llm_config is not None and exec_tools:
            client = make_async_client(llm_config)
            tasks = await _resolve_tasks(
                client=client,
                model=llm_config.model,
                tools=exec_tools,
                discovery=discovery,
                spec=spec,
                n_tasks=n_tasks,
                tasks_file=tasks_file,
                refresh_tasks=refresh_tasks,
                cache_dir=cache_dir,
                secrets=spec.secret_values(),
            )
            agentic_dims, agentic_detail = await run_agentic_eval(
                session=session,
                tools=exec_tools,
                client=client,
                model=llm_config.model,
                provider=llm_config.provider,
                tasks=tasks,
                repeats=repeats,
                max_turns=max_turns,
                excluded_write_tools=excluded,
                tool_timeout_s=tool_timeout_s,
                interactions=interactions,
            )
            dimensions.extend(agentic_dims)
        elif llm_config is not None:
            # An LLM was configured but every tool was filtered out as possibly-mutating, so
            # the agent had nothing safe to run. Record that explicitly: otherwise this looks
            # identical to a keyless static-only run, and the leaderboard can't explain why a
            # server it never actually tested is missing the agentic dimensions.
            agentic_detail = AgenticDetail(
                provider=llm_config.provider,
                model=llm_config.model,
                tasks_generated=0,
                repeats=repeats,
                excluded_write_tools=excluded,
            )

        # Robustness probes run last so a probe-induced hiccup can't disturb the agent run.
        # Skipped for a server that needs credentials: every call returns the same auth error
        # regardless of the payload, so the probe would be measuring the auth wall, not the
        # server's input validation.
        if probe and exec_tools and not needs_credentials:
            robustness = await run_robustness_probes(session, exec_tools)
            if robustness is not None:
                dimensions.append(robustness)

    return GauntletReport.build(
        spec=spec.label(),
        server=discovery.server,
        tool_count=len(discovery.tools),
        dimensions=dimensions,
        agentic=agentic_detail,
        unevaluated_reason=needs_credentials,
    )
