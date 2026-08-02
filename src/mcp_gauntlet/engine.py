"""Top-level evaluation: discovery + static checks + optional agentic eval → one report.

Everything runs inside a single MCP session so the static analysis and the live
agent share one connection.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.types import InitializeResult
from openai import AsyncOpenAI

from mcp_gauntlet.adapters import adapter
from mcp_gauntlet.checks import run_static_checks, scan_tool
from mcp_gauntlet.client import discover_in_session, open_session
from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.drift import (
    UnreadableBaseline,
    baseline_file,
    changed_within_session,
    compare_to_baseline,
    compare_within_session,
    era_changed,
    load_baseline,
    save_baseline,
    spec_key,
)
from mcp_gauntlet.evaluate import run_agentic_eval
from mcp_gauntlet.llm import LLMConfig, make_async_client
from mcp_gauntlet.models import DiscoveryResult, ToolInfo
from mcp_gauntlet.preflight import probe_credentials
from mcp_gauntlet.protocol import TransportLog
from mcp_gauntlet.report import (
    AgenticDetail,
    Dim,
    DimensionResult,
    Finding,
    GauntletReport,
    Severity,
    redact,
)
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
    # Computed once and used for BOTH the cache key and the prompt. Deriving them separately
    # is how they would drift apart again — the key has to cover exactly what shaped the
    # tasks, and this string is that.
    context = _grounding_context(spec, discovery, tools)
    path = tasks_file or cache_file(cache_dir, server_key(discovery.server, tools, context))
    if not refresh_tasks:
        cached = load_tasks(path)
        if cached:  # non-empty hit; an empty/failed set is a miss, not a cached "no tasks"
            return cached
    tasks = await generate_tasks(client, model, tools, n_tasks, context=context)
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


_LOGGING_DEPRECATED_FROM = "2026-07-28"


def _deprecated_capability_findings(init: Any, protocol_version: str | None) -> list[Finding]:
    """A capability the revision this server negotiated has deprecated.

    Only `logging` can appear here. `sampling` and `roots` are *client* capabilities and
    have no place in `ServerCapabilities` at all, so looking for them on a server would be
    looking for something that cannot be there.

    Gated on the negotiated revision, which is the whole honesty of it: a server speaking
    2025-11-25 and advertising `logging` is doing nothing wrong, and reporting it would
    manufacture a finding against every correct server built before the deprecation
    existed. INFO either way — a deprecation is a note for the author, not a defect in what
    the server does today.
    """
    if not protocol_version or protocol_version < _LOGGING_DEPRECATED_FROM:
        return []
    if not adapter().advertises_logging(init):
        return []
    return [
        Finding(
            severity=Severity.INFO,
            message="server advertises the `logging` capability, deprecated in the "
            f"revision it negotiated ({protocol_version})",
            detail="Deprecated by SEP-2577 as of 2026-07-28. It still works; newer clients "
            "may stop offering it.",
        )
    ]


async def _check_definition_drift(
    session: ClientSession,
    init: InitializeResult,
    spec: ServerSpec,
    discovery: DiscoveryResult,
    baseline_dir: Path,
    track: bool,
) -> list[Finding]:
    """Compare the tool surface against itself and against the last run.

    Two checks, and only the second one is optional.

    **Within the session** ``tools/list`` is asked twice and anything that changed is
    re-scanned. That is a LIVE attack detector: a server can serve a clean first listing and
    a poisoned second one, and nothing else in the run would look at the second. It needs no
    stored state, so it always runs — ``--no-track-drift`` used to disable it too, which took
    a server serving exactly that attack from a capped C to **A 100.0 with zero findings**
    and nothing in the report saying a check had been turned off. The flag's own help only
    ever described the other half.

    **Across runs** the surface is fingerprinted and compared against a stored baseline.
    That one needs a writable directory and a previous run, so it is what ``track`` governs
    — and a CI runner legitimately has neither.

    Both are best-effort: a server that fails the second ``tools/list`` must not lose its
    evaluation over a check looking for an anomaly, and a baseline that cannot be written
    (read-only checkout, CI sandbox) must not either.
    """
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
        findings.extend(
            compare_within_session(
                discovery.tools,
                second.tools,
                declared_list_changed=adapter().list_changed(init),
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

    if not track:
        # Say it, rather than returning a shorter list that reads as a clean bill. The
        # within-session half above still ran; this is only the cross-run comparison.
        findings.append(
            Finding(
                severity=Severity.INFO,
                message="cross-run definition drift was not checked (--no-track-drift), so a "
                "change since the last run would not have been reported",
            )
        )
        return findings

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
    if baseline is not None and era_changed(baseline):
        # Same principle as the unreadable case: say the comparison did not happen. The
        # alternative is worse than useless — the fingerprints were produced by a different
        # SDK era, so every tool would come back "redefined" and the report would accuse an
        # unchanged server of a rug-pull. Recording below replaces it with a comparable one.
        findings.append(
            Finding(
                severity=Severity.INFO,
                message="the recorded tool definitions were measured with a different MCP "
                "SDK, so this run was not compared against them",
                detail=f"{path}: recorded under {baseline.era or 'legacy'}, "
                f"running {adapter().era}",
            )
        )
        baseline = None
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
    not_measured: list[str] = []
    async with open_session(spec) as (session, init, interactions):
        # Prompts are fetched only when probing is on: rendering one is a call to the
        # server, and `--no-probe` means "inspect, don't execute". The messages it returns
        # are the point — they reach the model's context verbatim.
        discovery = await discover_in_session(session, init, fetch_prompts=probe)
        drift_findings = await _check_definition_drift(
            session, init, spec, discovery, cache_dir.parent / "baselines", track_drift
        )
        discovery_findings = (
            drift_findings
            # A surface that could not be listed is a scan that did not run. Reported at LOW
            # so the reader sees it, rather than left as an empty list indistinguishable from
            # a server that genuinely has no prompts — which is how a server erroring on
            # prompts/list skipped the prompt-injection scan for free.
            + [
                Finding(
                    severity=Severity.LOW,
                    message=f"{gap}, so that surface was not scanned",
                )
                for gap in discovery.undiscovered
            ]
            + _deprecated_capability_findings(init, discovery.server.protocol_version)
        )

        # Dimensions produced by TALKING to the server. Held aside rather than appended to a
        # single list because the static checks now run last (see the assembly below), and
        # the report's dimension order has to stay static-then-live.
        live_dimensions: list[DimensionResult] = []

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
        # Run REGARDLESS of whether an LLM is configured. This used to require one, so the
        # documented CI gate — `--no-agentic` — never reached it, and it was skipped again
        # whenever credentials WERE supplied. The comment above promised that an auth error
        # would then be "a real finding about the server (or about the token)"; no finding
        # was ever produced, and the intention sat unimplemented next to the code that
        # skipped it.
        #
        # What that cost: a server given a WRONG or EXPIRED token, answering 401 to every
        # call, scored **A 100.0 with exit 0** — a report byte-identical to the same server
        # with a working token. Robustness even read 100.0, because a 401 is technically a
        # rejection of malformed input. The only dimension that would have noticed is Tool
        # Reliability, and that needed an LLM key. So the gate asserted a verified pass over
        # a server it had never successfully called.
        #
        # Cheap: at most three tool calls, no LLM. Skipped under --no-probe, which already
        # means "inspect, don't execute", and which says so under Not measured.
        auth_failure = ""
        if probe and exec_tools:
            auth_failure = await probe_credentials(session, exec_tools) or ""
        supplied_credentials = bool(spec.env or spec.headers)
        # Only "this server needs credentials NOBODY supplied" excuses the agent stage. If
        # credentials were supplied and still rejected, the run is not excused — it is wrong.
        needs_credentials = auth_failure if not supplied_credentials else ""

        if auth_failure and supplied_credentials:
            # A named, gating finding rather than a silent skip. Tool Reliability rather than
            # Security Signals, deliberately: a rejected token is not an attack signal and
            # must not cap the grade, but "every call we made failed" is precisely what that
            # dimension measures — and it can be measured here without an LLM.
            live_dimensions.append(
                DimensionResult(
                    key=Dim.TOOL_RELIABILITY,
                    title="Tool Reliability",
                    weight=1.0,
                    score=0.0,
                    summary="Every tool call attempted failed authentication, so nothing "
                    "about this server's behaviour could be measured.",
                    findings=[
                        Finding(
                            severity=Severity.HIGH,
                            message="every tool call failed authentication despite the "
                            "credentials supplied — the token is wrong, expired, or lacks "
                            "the required scope",
                            detail=redact(auth_failure, spec.secret_values()),
                        )
                    ],
                )
            )

        if needs_credentials:
            _log.info("skipping agent evaluation: %s", needs_credentials)
            not_measured.append("agent evaluation (server needs credentials nobody supplied)")
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
            live_dimensions.extend(agentic_dims)
            if not any(d.key == Dim.TOOL_SELECTION for d in agentic_dims) and not (
                agentic_detail.inconclusive
            ):
                # The agent ran and was judged, but no task carried expected tools, so there
                # was nothing to score selection against. Previously emitted as 100.0 at
                # weight 1.5 — a verified perfect result for a check that never happened.
                not_measured.append(
                    "tool-selection accuracy (no generated task named the tools it expected, "
                    "so there was nothing to check the agent's choices against)"
                )
            if agentic_detail.inconclusive:
                # The stage was configured, attempted, and produced nothing usable — the LLM
                # backend errored on every repeat. Without this the console printed a warning
                # while `not_measured` stayed empty, so `report.json` — the file CI actually
                # parses — asserted full coverage of a run whose four heaviest dimensions
                # never happened. An expired key looks exactly like a healthy static run.
                not_measured.append(
                    "agent evaluation, tool-selection accuracy, tool reliability and response "
                    "safety (the LLM backend errored on every attempt — bad or expired API "
                    "key, rate limit, or an unreachable endpoint)"
                )
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
            not_measured.append("agent evaluation (every tool was excluded as possibly-mutating)")
        else:
            # No LLM configured — the ordinary keyless run, and the one that most needed
            # saying. FOUR of the eight advertised dimensions do not run without a key
            # (Agent Task Success, Tool-Selection Accuracy, Tool Reliability, Response
            # Safety), and Task Success is the heaviest at weight 3. Their absence does not
            # lower the score, it removes them from the denominator — so a keyless run
            # published a confident letter grade built from the checks that happen to be
            # free. A first-time user comparing a well-documented server against one whose
            # every description was a single word saw 100.0 A versus 95.8 A, because the
            # dimension that actually separates them is the LLM-judged one that never ran.
            not_measured.append(
                "agent evaluation, tool-selection accuracy, tool reliability and response "
                "safety (no LLM configured — these are the dimensions that judge whether an "
                "agent can actually use this server)"
            )

        # Robustness probes run last so a probe-induced hiccup can't disturb the agent run.
        # Skipped for a server that needs credentials: every call returns the same auth error
        # regardless of the payload, so the probe would be measuring the auth wall, not the
        # server's input validation.
        if probe and exec_tools and not needs_credentials:
            robustness = await run_robustness_probes(session, exec_tools)
            if robustness is not None:
                live_dimensions.append(robustness)
            if excluded:
                # PARTIAL coverage, which is the more misleading case than none at all,
                # because a number IS printed. `Robustness 100.0` on a twelve-tool server
                # where nine looked mutating means "the three we ran were fine" — and the
                # dimension's own summary says "Fraction of PROBED tools", with the
                # denominator recorded nowhere a reader or a script could find it.
                # `not_measured` only ever fired when ALL tools were excluded.
                not_measured.append(
                    f"robustness probes for {len(excluded)} of {len(discovery.tools)} tool(s) "
                    f"excluded as possibly-mutating ({', '.join(sorted(excluded))}) — "
                    "re-run with --allow-writes against a disposable target to include them"
                )
        elif not probe:
            # The one a flag turns off, and the one that moved a score furthest: a server
            # accepting every malformed input goes from C (75.0) to A (93.8) on --no-probe
            # alone, because its Robustness row leaves the mean instead of scoring 0.
            not_measured.append("robustness probes (--no-probe)")
        elif needs_credentials:
            not_measured.append("robustness probes (every call would hit the same auth wall)")
        elif not exec_tools:
            # Name them. The partial case already did, and the TOTAL case — the one where a
            # reader most needs to know which heuristic fired and on what — said only "no
            # read-only tools to probe". That turned a thirty-second fix into a bisect with
            # four throwaway servers for the tester who hit it.
            excluded_note = f" ({', '.join(sorted(excluded))})" if excluded else ""
            not_measured.append(
                "robustness probes — every tool was excluded as possibly-mutating"
                f"{excluded_note}. Annotate a genuinely read-only tool with "
                "`readOnlyHint: true`, or re-run with --allow-writes against a disposable "
                "target."
            )

        if discovery.resources:
            # Only metadata is scanned. A payload in what `resources/read` returns is
            # invisible — and unlike an unrendered prompt, which IS reported as unexamined,
            # this gap was not surfaced anywhere, so the report implied coverage it did not
            # have. Contents are unbounded and are passthrough rather than server-authored,
            # which is why they are not fetched; that is a reason to disclose it, not to
            # leave it implied. See docs/known-gaps.md G8.
            not_measured.append(
                f"the contents of {len(discovery.resources)} resource(s) (only their "
                "metadata is scanned; a payload inside what resources/read returns is not "
                "seen)"
            )

        # LAST, and inside the session: the transport log only stops filling when the
        # session closes. Reading it right after discovery — which is where this used to
        # happen — measured the connect/initialize/list window and nothing else, so a
        # `print` in a tool's own body, or a logger firing once per request, was recorded
        # into a log whose findings had already been taken. That is the MORE common shape
        # of the defect: a stray logger fires per request, not once at boot. A startup
        # banner was caught, the per-request line was not, and METHODOLOGY singles out
        # precisely the one that was missed as the dangerous case.
        session_findings = discovery_findings + _protocol_findings(interactions.transport)

    # Static dimensions first, then the live ones, which is the order the report has always
    # rendered — the static checks are deferred, not reordered.
    dimensions = run_static_checks(discovery, session_findings) + live_dimensions

    return GauntletReport.build(
        spec=spec.label(),
        server=discovery.server,
        tool_count=len(discovery.tools),
        dimensions=dimensions,
        agentic=agentic_detail,
        unevaluated_reason=needs_credentials,
        not_measured=not_measured,
    )
