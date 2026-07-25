"""Command-line entry point for mcp-gauntlet."""

from __future__ import annotations

import functools
import inspect
from pathlib import Path

import anyio
import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.engine import evaluate_server
from mcp_gauntlet.env import load_env
from mcp_gauntlet.htmlreport import to_html
from mcp_gauntlet.leaderboard import ServerListError, load_servers, rerender, run_leaderboard
from mcp_gauntlet.llm import LLMConfig, LLMConfigError, list_models
from mcp_gauntlet.report import (
    GauntletReport,
    Severity,
    interaction_note,
    sort_findings,
    to_markdown,
)
from mcp_gauntlet.robustness import run_robustness_probes

app = typer.Typer(
    add_completion=False,
    help="An agentic evaluation harness for MCP servers.",
    no_args_is_help=True,
)
console = Console()

_GRADE_COLOR = {"A": "green", "B": "green", "C": "yellow", "D": "yellow", "F": "red"}
_SEVERITY_COLOR = {
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


@app.callback()
def main() -> None:
    """An agentic evaluation harness for MCP servers."""
    load_env()


@app.command()
def doctor(
    provider: str | None = typer.Option(
        None, "--provider", help="LLM provider (env MCP_GAUNTLET_PROVIDER; default groq)."
    ),
    model: str | None = typer.Option(None, "--model", help="Override the default model."),
    base_url: str | None = typer.Option(
        None,
        "--base-url",
        help="Custom OpenAI-compatible endpoint (overrides the provider default).",
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        help="API key for the endpoint (overrides the provider's env var; a keyless "
        "--base-url endpoint needs neither).",
    ),
) -> None:
    """Check that the configured LLM backend is reachable (verifies your API key)."""
    try:
        config = LLMConfig.from_env(provider, model=model, base_url=base_url, api_key=api_key)
    except LLMConfigError as exc:
        console.print(f"[red]LLM not configured:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"Backend: [cyan]{config.redacted()}[/cyan]")
    try:
        models = list_models(config)
    except Exception as exc:  # noqa: BLE001 - surface any auth/connectivity failure
        console.print(f"[red]LLM call failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]OK[/green] — backend reachable, {len(models)} models advertised")
    # Some providers (Gemini) list models with a "models/" prefix.
    if config.model in models or f"models/{config.model}" in models:
        console.print(f"[green]Model '{config.model}' is available.[/green]")
    else:
        sample = ", ".join(models[:5])
        console.print(
            f"[yellow]Model '{config.model}' not found.[/yellow] Available include: {sample}"
        )


def write_report(report: GauntletReport, out_dir: Path) -> tuple[Path, Path, Path]:
    """Persist the report as JSON + Markdown + HTML.

    Lives next to the CLI (its only caller) so ``report.py`` needn't import the HTML
    renderer — that report<->htmlreport import cycle is what previously forced a lazy
    in-function import. Here the composition happens at the top level, cycle-free.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"
    html_path = out_dir / "report.html"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    md_path.write_text(to_markdown(report), encoding="utf-8")
    html_path.write_text(to_html(report), encoding="utf-8")
    return json_path, md_path, html_path


def _render_report(report: GauntletReport) -> None:
    color = _GRADE_COLOR.get(report.grade, "white")
    console.print(
        Panel.fit(
            f"[bold {color}]{report.grade}[/]   [bold]{report.overall_score:.1f}[/]/100",
            title=f"{escape(report.server.name or 'server')} — gauntlet score",
        )
    )
    if report.security_critical:
        # An N/A (zero-tool) report keeps its security findings but was never scored, so
        # don't claim a cap that was never applied.
        tail = (
            "this server exposes no tools, so it was never scored"
            if report.grade == "N/A"
            else "overall grade capped"
        )
        console.print(f"[bold red]⚠ Critical security finding(s) — {tail}.[/bold red]")

    table = Table(title="Dimensions")
    table.add_column("Dimension", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Weight", justify="right", style="dim")
    for dimension in report.dimensions:
        table.add_row(dimension.title, f"{dimension.score:.1f}", f"{dimension.weight:g}")
    console.print(table)

    # Any attempted agent evaluation gets reported, results or not — an eval that couldn't
    # run must never render as a clean skip. Mirrors the HTML report's gate exactly.
    if report.agentic is not None:
        detail = report.agentic
        if detail.results:
            tasks_table = Table(
                title=f"Agent task results ({escape(detail.provider)}:{escape(detail.model)})"
            )
            tasks_table.add_column("Task", style="cyan", max_width=58)
            tasks_table.add_column("Pass", justify="right")
            tasks_table.add_column("Score", justify="right")
            tasks_table.add_column("Tools", justify="right")
            for result in detail.results:
                if result.inconclusive:
                    tasks_table.add_row(
                        escape(result.description[:58]), "—", "[dim]incon.[/dim]", "—"
                    )
                    continue
                sel = f"{result.selection_score:.0f}" if result.selection_score is not None else "—"
                tasks_table.add_row(
                    escape(result.description[:58]),
                    f"{result.successes}/{result.repeats}",
                    f"{result.mean_score:.0f}",
                    sel,
                )
            console.print(tasks_table)
        if not detail.results and not detail.inconclusive:
            why = (
                "every tool was excluded as possibly-mutating "
                "(re-run with --allow-writes against a disposable target)"
                if detail.excluded_write_tools
                else "this server exposed no tools for the agent to call"
            )
            console.print(f"[yellow]⚠ Agent evaluation did not run — {why}.[/yellow]")
        note = interaction_note(detail)
        if note:
            console.print(f"[cyan]ℹ {escape(note)}[/cyan]")
        if report.agent_eval_truncated:
            console.print(
                f"[yellow]⚠ Agent evaluation stopped early after a tool hung — "
                f"{len(detail.results)} of {detail.tasks_generated} task(s) ran; "
                "the scores rest on a smaller sample than configured.[/yellow]"
            )
        if detail.inconclusive:
            console.print(
                "[yellow]⚠ Agent evaluation inconclusive — the LLM backend errored "
                "(e.g. rate limit); the grade reflects static checks only.[/yellow]"
            )

    notable = [
        f for f in sort_findings(report.findings) if f.severity in (Severity.HIGH, Severity.MEDIUM)
    ]
    if notable:
        console.print("\n[bold]Notable findings[/bold]")
        for finding in notable[:15]:
            tag = f"[{_SEVERITY_COLOR[finding.severity]}]{finding.severity.upper():<6}[/]"
            scope = finding.tool or "server"
            console.print(f"  {tag} [cyan]{escape(scope)}[/]: {escape(finding.message)}")
        if len(notable) > 15:
            console.print(f"  [dim]… and {len(notable) - 15} more (see report.md)[/dim]")
    else:
        console.print("\n[green]No high/medium-severity findings.[/green]")


@app.command()
def run(
    server: str = typer.Argument(
        ...,
        help="MCP server: an stdio command (e.g. 'npx -y @scope/pkg') or an http(s) URL.",
    ),
    out: Path = typer.Option(
        Path("reports"), "--out", "-o", help="Directory for report.json / report.md."
    ),
    agentic: bool | None = typer.Option(
        None,
        "--agentic/--no-agentic",
        help="Run the agentic evaluation (default: on when an LLM key is configured).",
    ),
    provider: str | None = typer.Option(
        None, "--provider", help="LLM provider (env MCP_GAUNTLET_PROVIDER; default groq)."
    ),
    model: str | None = typer.Option(None, "--model", help="Override the default model."),
    base_url: str | None = typer.Option(
        None,
        "--base-url",
        help="Custom OpenAI-compatible endpoint (overrides the provider default).",
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        help="API key for the endpoint (overrides the provider's env var; a keyless "
        "--base-url endpoint needs neither).",
    ),
    tasks: int = typer.Option(3, "--tasks", help="Tasks to generate for the agentic eval."),
    repeats: int = typer.Option(2, "--repeats", help="Times to run each task (success rate)."),
    max_turns: int = typer.Option(8, "--max-turns", help="Max agent turns per task."),
    allow_writes: bool = typer.Option(
        False,
        "--allow-writes",
        help="Expose possibly-mutating tools to the agent/probes (default: read-only tools only).",
    ),
    probe: bool = typer.Option(
        True, "--probe/--no-probe", help="Run LLM-free robustness probes (malformed inputs)."
    ),
    tasks_file: Path | None = typer.Option(
        None,
        "--tasks-file",
        help="Load/save the task set from this file (pins a reproducible set).",
    ),
    refresh_tasks: bool = typer.Option(
        False, "--refresh-tasks", help="Regenerate tasks even if a cached set exists."
    ),
    fail_under: float | None = typer.Option(
        None,
        "--fail-under",
        help="Exit non-zero if the overall score is below this value (for CI).",
    ),
    timeout: float = typer.Option(
        900.0,
        "--timeout",
        help="Hard wall-clock limit for the whole evaluation, in seconds (0 disables).",
    ),
    tool_timeout: float = typer.Option(
        60.0,
        "--tool-timeout",
        help="Per-tool-call limit for the agent, in seconds; a tool that exceeds it "
        "is recorded as a failed call.",
    ),
) -> None:
    """Connect to an MCP server, run the gauntlet, and write a scored report."""
    spec = ServerSpec.parse(server)

    llm_config: LLMConfig | None = None
    if agentic is None:
        try:
            llm_config = LLMConfig.from_env(
                provider, model=model, base_url=base_url, api_key=api_key
            )
        except LLMConfigError:
            llm_config = None
    elif agentic:
        try:
            llm_config = LLMConfig.from_env(
                provider, model=model, base_url=base_url, api_key=api_key
            )
        except LLMConfigError as exc:
            console.print(f"[red]--agentic requested but no LLM is configured:[/red] {exc}")
            raise typer.Exit(code=1) from exc

    console.print(f"[bold]Evaluating[/bold] {spec.label()} ([cyan]{spec.kind.value}[/cyan]) ...")
    if llm_config is not None:
        mode = "writes allowed" if allow_writes else "read-only tools"
        console.print(
            f"[dim]Agentic eval via {llm_config.redacted()} — "
            f"{tasks} task(s) × {repeats} repeat(s) ({mode})[/dim]"
        )
    else:
        reason = "agentic disabled" if agentic is False else "no LLM configured"
        checks = "Static checks + robustness probes" if probe else "Static checks only"
        console.print(f"[dim]{checks} ({reason}).[/dim]")

    evaluate = functools.partial(
        evaluate_server,
        spec,
        llm_config=llm_config,
        n_tasks=tasks,
        repeats=repeats,
        max_turns=max_turns,
        allow_writes=allow_writes,
        probe=probe,
        tasks_file=tasks_file,
        refresh_tasks=refresh_tasks,
        tool_timeout_s=tool_timeout,
    )

    async def _bounded() -> GauntletReport:
        # A hard outer bound so a server that hangs where no inner timeout reaches — during
        # connect/initialize, or tools/list — can't hang the CLI indefinitely. The agent's
        # per-call --tool-timeout handles the common case (one slow tool) without ever
        # getting here, since that path keeps the run alive and still produces a report.
        if timeout <= 0:
            return await evaluate()
        with anyio.fail_after(timeout):
            return await evaluate()

    try:
        report = anyio.run(_bounded)
    except TimeoutError as exc:
        console.print(
            f"[red]Evaluation timed out[/red] after {timeout:.0f}s "
            "(raise or disable it with --timeout)."
        )
        raise typer.Exit(code=1) from exc
    except Exception as exc:  # noqa: BLE001 - surface any connection/eval failure
        console.print(f"[red]Evaluation failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    # Persist BEFORE rendering: a console-rendering glitch (unencodable glyph on a legacy
    # code page, stray markup from a hostile server name) must never discard the report of
    # a run the user just paid for. Rendering is best-effort on top of a written artifact.
    json_path, md_path, html_path = write_report(report, out)

    console.print()
    try:
        _render_report(report)
    except Exception as exc:  # noqa: BLE001 - the report is already on disk; don't crash on it
        console.print(
            f"[yellow]Could not render the summary to console:[/yellow] {escape(str(exc))}"
        )
    console.print(f"\n[dim]Reports written:[/dim] {json_path} | {md_path} | {html_path}")

    if fail_under is not None and report.overall_score < fail_under:
        console.print(
            f"[red]Overall score {report.overall_score:.1f} is below threshold {fail_under}.[/red]"
        )
        raise typer.Exit(code=1)


@app.command()
def leaderboard(
    servers: Path | None = typer.Option(
        None, "--servers", help='JSON file listing servers ({"servers":[{name,spec}]}).'
    ),
    out: Path = typer.Option(
        Path("docs"), "--out", "-o", help="Output directory for the static site."
    ),
    provider: str | None = typer.Option(
        None, "--provider", help="LLM provider (env MCP_GAUNTLET_PROVIDER; default groq)."
    ),
    model: str | None = typer.Option(None, "--model", help="Override the default model."),
    base_url: str | None = typer.Option(
        None,
        "--base-url",
        help="Custom OpenAI-compatible endpoint (overrides the provider default).",
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        help="API key for the endpoint (overrides the provider's env var; a keyless "
        "--base-url endpoint needs neither).",
    ),
    tasks: int = typer.Option(3, "--tasks", help="Tasks generated per server."),
    repeats: int = typer.Option(2, "--repeats", help="Times each task is run."),
    max_turns: int = typer.Option(8, "--max-turns", help="Max agent turns per task."),
    timeout: float = typer.Option(240.0, "--timeout", help="Per-server time budget (seconds)."),
    tool_timeout: float = typer.Option(
        60.0,
        "--tool-timeout",
        help="Per-tool-call limit for the agent, in seconds; a tool that exceeds it "
        "is recorded as a failed call.",
    ),
    render_only: bool = typer.Option(
        False,
        "--render-only",
        help="Rebuild the site from previously saved results in --out, without "
        "re-evaluating anything (no LLM spend).",
    ),
) -> None:
    """Evaluate many MCP servers and build a static leaderboard site."""
    if render_only:
        results = rerender(out)
        if not results:
            console.print(f"[red]No saved results found in[/red] {out / 'servers'}.")
            raise typer.Exit(code=1)
        console.print(
            f"[green]Re-rendered[/green] {len(results)} saved result(s) — "
            f"no evaluation run. Site: {out / 'index.html'}"
        )
        return

    if servers is None:
        console.print("[red]--servers is required[/red] (or use --render-only).")
        raise typer.Exit(code=1)
    try:
        entries = load_servers(servers)
    except ServerListError as exc:
        console.print(f"[red]Could not load the server list:[/red] {escape(str(exc))}")
        raise typer.Exit(code=1) from exc
    # The defaults are checked by a test, but these are user-supplied. The per-server clock
    # has to cover one permitted agent hang AND a full probe budget; if it can't, the outer
    # bound fires first and the server loses its report entirely instead of being graded.
    probe_budget = inspect.signature(run_robustness_probes).parameters["budget_s"].default
    if tool_timeout + probe_budget >= timeout:
        console.print(
            f"[yellow]⚠ --tool-timeout {tool_timeout:g}s plus the {probe_budget:g}s probe "
            f"budget does not fit inside the {timeout:g}s per-server budget; a slow server "
            "may be dropped as 'could not evaluate' rather than scored. "
            "Raise --timeout.[/yellow]"
        )
    llm_config: LLMConfig | None = None
    try:
        llm_config = LLMConfig.from_env(provider, model=model, base_url=base_url, api_key=api_key)
    except LLMConfigError:
        llm_config = None  # static-only leaderboard (no LLM key configured)

    if llm_config is not None:
        console.print(
            f"[bold]Leaderboard[/bold] — {len(entries)} server(s) via "
            f"{llm_config.redacted()} ({tasks} tasks × {repeats} repeats)"
        )
    else:
        console.print(
            f"[bold]Leaderboard[/bold] — {len(entries)} server(s), "
            "static + robustness checks only (no LLM configured)"
        )
    results = anyio.run(
        functools.partial(
            run_leaderboard,
            entries,
            out_dir=out,
            llm_config=llm_config,
            n_tasks=tasks,
            repeats=repeats,
            max_turns=max_turns,
            timeout_s=timeout,
            tool_timeout_s=tool_timeout,
            log=lambda m: console.print(f"[dim]{m}[/dim]"),
        )
    )
    ok = sum(1 for r in results if r.report is not None)
    console.print(
        f"\n[green]Done[/green] — {ok}/{len(results)} evaluated. Site: {out / 'index.html'}"
    )


if __name__ == "__main__":
    app()
