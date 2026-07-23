"""Command-line entry point for mcp-gauntlet."""

from __future__ import annotations

import functools
from pathlib import Path

import anyio
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.engine import evaluate_server
from mcp_gauntlet.env import load_env
from mcp_gauntlet.leaderboard import load_servers, run_leaderboard
from mcp_gauntlet.llm import LLMConfig, LLMConfigError, list_models
from mcp_gauntlet.report import GauntletReport, Severity, sort_findings, write_report

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
    provider: str = typer.Option("groq", "--provider", help="LLM provider preset."),
    model: str | None = typer.Option(None, "--model", help="Override the default model."),
) -> None:
    """Check that the configured LLM backend is reachable (verifies your API key)."""
    try:
        config = LLMConfig.from_env(provider, model=model)
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
    if config.model in models:
        console.print(f"[green]Model '{config.model}' is available.[/green]")
    else:
        sample = ", ".join(models[:5])
        console.print(
            f"[yellow]Model '{config.model}' not found.[/yellow] Available include: {sample}"
        )


def _render_report(report: GauntletReport) -> None:
    color = _GRADE_COLOR.get(report.grade, "white")
    console.print(
        Panel.fit(
            f"[bold {color}]{report.grade}[/]   [bold]{report.overall_score:.1f}[/]/100",
            title=f"{report.server.name or 'server'} — gauntlet score",
        )
    )
    if report.security_critical:
        console.print("[bold red]⚠ Critical security finding(s) — overall grade capped.[/bold red]")

    table = Table(title="Dimensions")
    table.add_column("Dimension", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Weight", justify="right", style="dim")
    for dimension in report.dimensions:
        table.add_row(dimension.title, f"{dimension.score:.1f}", f"{dimension.weight:g}")
    console.print(table)

    if report.agentic and report.agentic.results:
        detail = report.agentic
        tasks_table = Table(title=f"Agent task results ({detail.provider}:{detail.model})")
        tasks_table.add_column("Task", style="cyan", max_width=58)
        tasks_table.add_column("Pass", justify="right")
        tasks_table.add_column("Score", justify="right")
        tasks_table.add_column("Tools", justify="right")
        for result in detail.results:
            if result.inconclusive:
                tasks_table.add_row(result.description[:58], "—", "[dim]incon.[/dim]", "—")
                continue
            sel = f"{result.selection_score:.0f}" if result.selection_score is not None else "—"
            tasks_table.add_row(
                result.description[:58],
                f"{result.successes}/{result.repeats}",
                f"{result.mean_score:.0f}",
                sel,
            )
        console.print(tasks_table)
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
            console.print(f"  {tag} [cyan]{scope}[/]: {finding.message}")
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
    provider: str = typer.Option("groq", "--provider", help="LLM provider preset."),
    model: str | None = typer.Option(None, "--model", help="Override the default model."),
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
) -> None:
    """Connect to an MCP server, run the gauntlet, and write a scored report."""
    spec = ServerSpec.parse(server)

    llm_config: LLMConfig | None = None
    if agentic is None:
        try:
            llm_config = LLMConfig.from_env(provider, model=model)
        except LLMConfigError:
            llm_config = None
    elif agentic:
        try:
            llm_config = LLMConfig.from_env(provider, model=model)
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
    elif probe:
        console.print("[dim]Static checks + robustness probes — no LLM configured.[/dim]")
    else:
        console.print("[dim]Static checks only — no LLM configured.[/dim]")

    try:
        report = anyio.run(
            functools.partial(
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
            )
        )
    except Exception as exc:  # noqa: BLE001 - surface any connection/eval failure
        console.print(f"[red]Evaluation failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print()
    _render_report(report)

    json_path, md_path, html_path = write_report(report, out)
    console.print(f"\n[dim]Reports written:[/dim] {json_path} | {md_path} | {html_path}")

    if fail_under is not None and report.overall_score < fail_under:
        console.print(
            f"[red]Overall score {report.overall_score:.1f} is below threshold {fail_under}.[/red]"
        )
        raise typer.Exit(code=1)


@app.command()
def leaderboard(
    servers: Path = typer.Option(
        ..., "--servers", help='JSON file listing servers ({"servers":[{name,spec}]}).'
    ),
    out: Path = typer.Option(
        Path("docs"), "--out", "-o", help="Output directory for the static site."
    ),
    provider: str = typer.Option("groq", "--provider", help="LLM provider preset."),
    model: str | None = typer.Option(None, "--model", help="Override the default model."),
    tasks: int = typer.Option(3, "--tasks", help="Tasks generated per server."),
    repeats: int = typer.Option(2, "--repeats", help="Times each task is run."),
    max_turns: int = typer.Option(8, "--max-turns", help="Max agent turns per task."),
    timeout: float = typer.Option(240.0, "--timeout", help="Per-server time budget (seconds)."),
) -> None:
    """Evaluate many MCP servers and build a static leaderboard site."""
    entries = load_servers(servers)
    try:
        llm_config = LLMConfig.from_env(provider, model=model)
    except LLMConfigError as exc:
        console.print(f"[red]The leaderboard needs an LLM:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[bold]Leaderboard[/bold] — {len(entries)} server(s) via "
        f"{llm_config.redacted()} ({tasks} tasks × {repeats} repeats)"
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
            log=lambda m: console.print(f"[dim]{m}[/dim]"),
        )
    )
    ok = sum(1 for r in results if r.report is not None)
    console.print(
        f"\n[green]Done[/green] — {ok}/{len(results)} evaluated. Site: {out / 'index.html'}"
    )


if __name__ == "__main__":
    app()
