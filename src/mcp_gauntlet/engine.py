"""Top-level evaluation: discovery + static checks + optional agentic eval → one report.

Everything runs inside a single MCP session so the static analysis and the live
agent share one connection.
"""

from __future__ import annotations

from pathlib import Path

from openai import AsyncOpenAI

from mcp_gauntlet.checks import run_static_checks
from mcp_gauntlet.client import discover_in_session, open_session
from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.evaluate import run_agentic_eval
from mcp_gauntlet.llm import LLMConfig, make_async_client
from mcp_gauntlet.models import DiscoveryResult, ToolInfo
from mcp_gauntlet.report import AgenticDetail, GauntletReport
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


async def _resolve_tasks(
    *,
    client: AsyncOpenAI,
    model: str,
    tools: list[ToolInfo],
    discovery: DiscoveryResult,
    n_tasks: int,
    tasks_file: Path | None,
    refresh_tasks: bool,
    cache_dir: Path,
) -> list[EvalTask]:
    """Load a pinned/cached task set if present, otherwise generate and save one."""
    path = tasks_file or cache_file(cache_dir, server_key(discovery.server, tools))
    if not refresh_tasks:
        cached = load_tasks(path)
        if cached is not None:
            return cached
    tasks = await generate_tasks(client, model, tools, n_tasks)
    save_tasks(path, tasks)
    return tasks


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
) -> GauntletReport:
    agentic_detail: AgenticDetail | None = None
    async with open_session(spec) as (session, init):
        discovery = await discover_in_session(session, init)
        dimensions = run_static_checks(discovery)

        # The set of tools we'll actually execute (probes + agent) — read-only by default.
        exec_tools = discovery.tools
        excluded: list[str] = []
        if not allow_writes:
            exec_tools, excluded = filter_read_only(discovery.tools)

        if llm_config is not None and exec_tools:
            client = make_async_client(llm_config)
            tasks = await _resolve_tasks(
                client=client,
                model=llm_config.model,
                tools=exec_tools,
                discovery=discovery,
                n_tasks=n_tasks,
                tasks_file=tasks_file,
                refresh_tasks=refresh_tasks,
                cache_dir=cache_dir,
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
            )
            dimensions.extend(agentic_dims)

        # Robustness probes run last so a probe-induced hiccup can't disturb the agent run.
        if probe and exec_tools:
            robustness = await run_robustness_probes(session, exec_tools)
            if robustness is not None:
                dimensions.append(robustness)

    return GauntletReport.build(
        spec=spec.label(),
        server=discovery.server,
        tool_count=len(discovery.tools),
        dimensions=dimensions,
        agentic=agentic_detail,
    )
