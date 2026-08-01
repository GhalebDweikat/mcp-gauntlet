"""Command-line entry point for mcp-gauntlet."""

from __future__ import annotations

import contextlib
import functools
import inspect
import os
import sys
from pathlib import Path

import anyio
import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from mcp_gauntlet.config import ServerSpec, TransportKind, parse_env_args, parse_header_args
from mcp_gauntlet.engine import evaluate_server
from mcp_gauntlet.env import load_env
from mcp_gauntlet.errors import describe
from mcp_gauntlet.exits import EXIT_CODE_HELP, Exit
from mcp_gauntlet.htmlreport import to_html
from mcp_gauntlet.llm import LLMConfig, LLMConfigError, list_models
from mcp_gauntlet.report import (
    GauntletReport,
    Severity,
    cap_note,
    findings_at_or_above,
    interaction_note,
    redact,
    redact_report,
    sort_findings,
    to_markdown,
)
from mcp_gauntlet.robustness import run_robustness_probes
from mcp_gauntlet.scan import ServerListError, load_servers, run_scan


def _use_utf8_stdio() -> None:
    """Put stdout and stderr on UTF-8 before rich takes hold of them.

    Windows gives a process the ANSI codepage — cp1252 across most of the world —
    and cp1252 cannot encode a warning sign, an arrow, or, the part that actually
    matters, the Cyrillic and Greek letters a homoglyph finding is *about*. Printing
    such a finding raised UnicodeEncodeError, so the check that caught an attack was
    the one that killed the run. ``errors="replace"`` keeps a stream we cannot
    re-encode from taking the run down with it: mojibake beats a traceback.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # pythonw, a plain file object, some capture shims
            continue
        # A detached, closed, or non-seekable stream is not worth failing a run over.
        with contextlib.suppress(ValueError, OSError):
            reconfigure(encoding="utf-8", errors="replace")


_use_utf8_stdio()

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


def _show_version(value: bool) -> None:
    if value:
        from mcp_gauntlet import __version__

        console.print(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_show_version,
        is_eager=True,
        help="Show the installed mcp-gauntlet version and exit.",
    ),
) -> None:
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


def write_report(
    report: GauntletReport, out_dir: Path, secrets: frozenset[str] = frozenset()
) -> tuple[Path, Path, Path]:
    """Persist the report as JSON + Markdown + HTML.

    Lives next to the CLI (its only caller) so ``report.py`` needn't import the HTML
    renderer — that report<->htmlreport import cycle is what previously forced a lazy
    in-function import. Here the composition happens at the top level, cycle-free.

    ``secrets`` (credential values from --env/--header) are scrubbed from the report's
    fields BEFORE each format is serialized, so a token a server echoed back never lands in
    a committed report — including in a form (JSON/HTML escaping) that a scrub of the
    rendered string would miss.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    report = redact_report(report, secrets)
    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"
    html_path = out_dir / "report.html"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    md_path.write_text(to_markdown(report), encoding="utf-8")
    html_path.write_text(to_html(report), encoding="utf-8")
    return json_path, md_path, html_path


def _render_report(report: GauntletReport, secrets: frozenset[str] = frozenset()) -> None:
    def r(text: str) -> str:  # scrub any echoed credential from server-controlled console text
        return redact(text, secrets)

    color = _GRADE_COLOR.get(report.grade, "white")
    console.print(
        Panel.fit(
            f"[bold {color}]{report.grade}[/]   [bold]{report.overall_score:.1f}[/]/100",
            title=f"{escape(r(report.server.name or 'server'))} — gauntlet score",
        )
    )
    if report.security_critical:
        # `cap_note` because "capped" was being claimed whenever a critical finding existed,
        # including when the score was already below the ceiling and the cap did nothing.
        console.print(f"[bold red]⚠ Critical security finding(s) — {cap_note(report)}.[/bold red]")
    # The console is where a `run` is usually read, so the omission belongs here too — the
    # overall is a weighted mean over the dimensions that RAN, and a stage which did not run
    # raises it rather than lowering it.
    if report.unevaluated_reason:
        console.print(f"[yellow]Not scored:[/yellow] {escape(r(report.unevaluated_reason))}")
    for omitted in report.not_measured:
        console.print(f"[yellow]Not measured:[/yellow] {escape(omitted)}")

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
                        escape(r(result.description[:58])), "—", "[dim]incon.[/dim]", "—"
                    )
                    continue
                sel = f"{result.selection_score:.0f}" if result.selection_score is not None else "—"
                tasks_table.add_row(
                    escape(r(result.description[:58])),
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
            console.print(f"  {tag} [cyan]{escape(r(scope))}[/]: {escape(r(finding.message))}")
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
    env: list[str] = typer.Option(
        [],
        "--env",
        help="Pass an env var to a stdio server: NAME (from your environment) or NAME=VALUE. "
        "Repeatable. For servers that need a credential (e.g. GITHUB_TOKEN). Redacted from "
        "reports.",
    ),
    header: list[str] = typer.Option(
        [],
        "--header",
        help="Send an HTTP header to a remote server: 'Name: Value' (e.g. "
        "'Authorization: Bearer …'). Repeatable. Redacted from reports.",
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
    track_drift: bool = typer.Option(
        True,
        "--track-drift/--no-track-drift",
        help="Record the server's tool definitions and compare them against the last run, "
        "to catch a server that redefines its tools after you approved them.",
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
        help="Fail if the overall score is below this value. Prefer --fail-on: a score "
        "threshold has to be re-baselined whenever scoring changes, and the security cap "
        "puts a poisoned server ABOVE a low threshold. " + EXIT_CODE_HELP,
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Fail if any finding is at or above this severity: high, medium, low, or info. "
        "This is the gate to use in CI — it keys on what was actually found rather than on "
        "a number, so it does not drift when scoring changes.",
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
    try:
        spec.env = parse_env_args(env, dict(os.environ))
        spec.headers = parse_header_args(header)
    except ValueError as exc:
        console.print(f"[red]Invalid credential option:[/red] {escape(str(exc))}")
        raise typer.Exit(code=Exit.CONFIG) from exc
    if spec.env and spec.kind is not TransportKind.STDIO:
        console.print("[yellow]⚠ --env applies to stdio servers only; ignored for a URL.[/yellow]")
    if spec.headers and spec.kind is TransportKind.STDIO:
        console.print("[yellow]⚠ --header applies to remote (http) servers only; ignored.[/yellow]")
    secrets = spec.secret_values()

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
            raise typer.Exit(code=Exit.CONFIG) from exc

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
        track_drift=track_drift,
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
        # Exit 3, not 1: a wall-clock timeout says nothing about the server's quality,
        # and a gate that reads it as a regression gets switched off after one flake.
        raise typer.Exit(code=Exit.UNEVALUABLE) from exc
    except Exception as exc:  # noqa: BLE001 - surface any connection/eval failure
        # A connection/DSN error can echo a credential (e.g. a Postgres URI with the
        # password); redact before it reaches the terminal or a CI log.
        console.print(
            f"[red]Evaluation failed:[/red] {escape(redact(describe(exc, 400), secrets))}"
        )
        # The server did not start, the transport broke, the URL was wrong. Infra, not
        # quality — and no report.json is written, which used to be the only way to tell.
        raise typer.Exit(code=Exit.UNEVALUABLE) from exc

    # Persist BEFORE rendering: a console-rendering glitch (unencodable glyph on a legacy
    # code page, stray markup from a hostile server name) must never discard the report of
    # a run the user just paid for. Rendering is best-effort on top of a written artifact.
    json_path, md_path, html_path = write_report(report, out, secrets)

    console.print()
    try:
        _render_report(report, secrets)
    except Exception as exc:  # noqa: BLE001 - the report is already on disk; don't crash on it
        console.print(
            "[yellow]Could not render the summary to console:[/yellow] "
            f"{escape(redact(str(exc), secrets))}"
        )
    console.print(f"\n[dim]Reports written:[/dim] {json_path} | {md_path} | {html_path}")

    # Both gates are checked, and either can fail the build. `--fail-on` first, because it is
    # the one that says WHAT was wrong rather than only that a number moved.
    if fail_on is not None:
        try:
            threshold = Severity(fail_on.strip().lower())
        except ValueError:
            console.print(
                f"[red]--fail-on {fail_on!r} is not a severity.[/red] "
                f"Use one of: {', '.join(s.value for s in Severity)}."
            )
            raise typer.Exit(code=Exit.CONFIG) from None
        triggering = findings_at_or_above(report, threshold)
        if triggering:
            worst = sort_findings(triggering)[0]  # already orders severity-first
            console.print(
                f"[red]{len(triggering)} finding(s) at or above {threshold.value}[/red] — "
                f"worst: {escape(redact(worst.message, secrets))}"
            )
            raise typer.Exit(code=Exit.GATE_FAILED)

    if fail_under is not None and report.overall_score < fail_under:
        console.print(
            f"[red]Overall score {report.overall_score:.1f} is below threshold {fail_under}.[/red]"
        )
        raise typer.Exit(code=Exit.GATE_FAILED)


@app.command()
def scan(
    servers: Path = typer.Option(
        ...,
        "--servers",
        help='JSON file listing the servers you own: {"servers":[{"name","spec"}]}.',
    ),
    out: Path = typer.Option(Path("gauntlet-scan"), "--out", help="Directory for the reports."),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Fail if ANY server has a finding at or above this severity: high, medium, "
        "low, info. " + EXIT_CODE_HELP,
    ),
    agentic: bool = typer.Option(
        True,
        "--agentic/--no-agentic",
        help="Run the live-agent evaluation against each server.",
    ),
    probe: bool = typer.Option(
        True, "--probe/--no-probe", help="Send malformed input to each tool (Robustness)."
    ),
    tasks: int = typer.Option(3, "--tasks", help="Generated tasks per server."),
    repeats: int = typer.Option(2, "--repeats", help="Repeats per task."),
    max_turns: int = typer.Option(8, "--max-turns", help="Agent turns per task."),
    timeout: float = typer.Option(240.0, "--timeout", help="Per-server budget, in seconds."),
    tool_timeout: float = typer.Option(60.0, "--tool-timeout", help="Per-tool-call limit."),
    provider: str | None = typer.Option(None, "--provider", help="LLM provider."),
    model: str | None = typer.Option(None, "--model", help="Override the default model."),
    base_url: str | None = typer.Option(None, "--base-url", help="OpenAI-compatible endpoint."),
    api_key: str | None = typer.Option(None, "--api-key", help="API key for the endpoint."),
) -> None:
    """Run the gauntlet across several servers you own and gate on the worst finding.

    Deliberately not a leaderboard. Nothing is ranked and no grades are compared side by
    side: the overall score moves when a stage is skipped, when a server needs credentials,
    and between releases, which is survivable when watching one server over time and is not
    survivable in a sorted public table.
    """
    threshold: Severity | None = None
    if fail_on is not None:
        try:
            threshold = Severity(fail_on.strip().lower())
        except ValueError:
            console.print(
                f"[red]--fail-on {fail_on!r} is not a severity.[/red] "
                f"Use one of: {', '.join(s.value for s in Severity)}."
            )
            raise typer.Exit(code=Exit.CONFIG) from None

    try:
        entries = load_servers(servers)
    except ServerListError as exc:
        console.print(f"[red]Could not load the server list:[/red] {escape(str(exc))}")
        raise typer.Exit(code=Exit.CONFIG) from exc

    # The per-server clock has to cover one permitted agent hang AND a full probe budget; if
    # it cannot, the outer bound fires first and the server is recorded as unevaluable rather
    # than scored.
    probe_budget = inspect.signature(run_robustness_probes).parameters["budget_s"].default
    if tool_timeout + probe_budget >= timeout:
        console.print(
            f"[yellow]⚠ --tool-timeout {tool_timeout:g}s plus the {probe_budget:g}s probe "
            f"budget does not fit inside the {timeout:g}s per-server budget.[/yellow]"
        )

    llm_config: LLMConfig | None = None
    if agentic:
        try:
            llm_config = LLMConfig.from_env(
                provider, model=model, base_url=base_url, api_key=api_key
            )
        except LLMConfigError:
            llm_config = None  # static-only scan

    how = llm_config.redacted() if llm_config is not None else "static + robustness only"
    console.print(f"[bold]Scanning[/bold] {len(entries)} server(s) — {how}")

    results = anyio.run(
        functools.partial(
            run_scan,
            entries,
            out_dir=out,
            llm_config=llm_config,
            fail_on=threshold,
            n_tasks=tasks,
            repeats=repeats,
            probe=probe,
            max_turns=max_turns,
            timeout_s=timeout,
            tool_timeout_s=tool_timeout,
            log=lambda m: console.print(f"[dim]{m}[/dim]"),
        )
    )

    table = Table(title="Scan")
    table.add_column("Server", style="cyan")
    table.add_column("Result", justify="right")
    table.add_column("Gating findings", justify="right")
    for result in results:
        if result.report is None:
            table.add_row(escape(result.name), "[yellow]not evaluated[/yellow]", "—")
        else:
            colour = _GRADE_COLOR.get(result.report.grade, "white")
            table.add_row(
                escape(result.name),
                f"[{colour}]{result.report.grade}[/] {result.report.overall_score:.1f}",
                str(len(result.triggering)) if threshold else "—",
            )
    console.print(table)
    console.print(f"\n[dim]Reports written under:[/dim] {out}")

    # Unevaluated servers are reported but do NOT fail the gate: "could not reach it" is not
    # a verdict about quality, and conflating the two is how a gate earns a reputation for
    # flaking. Exit 3 says it happened.
    unevaluated = [r for r in results if not r.evaluated]
    gated = [r for r in results if r.triggering]
    if gated and threshold is not None:  # `triggering` is only populated when gating
        console.print(
            f"[red]{len(gated)} server(s) have findings at or above {threshold.value}[/red]: "
            + ", ".join(escape(r.name) for r in gated)
        )
        raise typer.Exit(code=Exit.GATE_FAILED)
    if unevaluated:
        console.print(
            f"[yellow]{len(unevaluated)} server(s) could not be evaluated[/yellow] — "
            "infrastructure, not a quality verdict."
        )
        raise typer.Exit(code=Exit.UNEVALUABLE)
