"""The console summary and the persisted report are built from server-controlled text
(server name, tool names, findings). Hostile Rich markup in any of them must not crash
the CLI, and the report is written to disk BEFORE rendering so a render glitch can't
discard a run the user just paid for.
"""

import inspect
import io
import json
from pathlib import Path

import pytest
from rich.console import Console

from mcp_gauntlet import cli
from mcp_gauntlet.htmlreport import to_html
from mcp_gauntlet.models import ServerInfo
from mcp_gauntlet.report import (
    AgenticDetail,
    DimensionResult,
    Finding,
    GauntletReport,
    Severity,
    to_markdown,
)


def _hostile_report() -> GauntletReport:
    # A stray Rich close tag in the tool name (get[/rows]) raises MarkupError if the CLI
    # renders it unescaped; the server name and message carry markup too.
    findings = [
        Finding(tool="get[/rows]", severity=Severity.HIGH, message="poisoned [bold]output[/]")
    ]
    dim = DimensionResult(
        key="security", title="Security", weight=1.0, score=40.0, summary="s", findings=findings
    )
    return GauntletReport.build(
        spec="stdio: evil",
        server=ServerInfo(name="[red]evil-server[/]", version="1"),
        tool_count=1,
        dimensions=[dim],
    )


def test_render_report_survives_hostile_markup(monkeypatch: pytest.MonkeyPatch) -> None:
    # Render to an isolated in-memory Console (UTF-8, fixed width) so the test is immune
    # to the terminal's real encoding; the point is that markup no longer crashes it.
    buf = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=buf, width=100))
    cli._render_report(_hostile_report())  # must NOT raise rich.errors.MarkupError
    out = buf.getvalue()
    assert "evil-server" in out  # the name is shown, just as inert text


def _inconclusive_report() -> GauntletReport:
    # Task generation failed → the agentic detail is inconclusive with an EMPTY results
    # list (the exact shape that used to vanish from the HTML and console renderers).
    dim = DimensionResult(key="static", title="Static", weight=1.0, score=80.0, summary="s")
    detail = AgenticDetail(
        provider="groq", model="m", tasks_generated=0, repeats=2, inconclusive=True, results=[]
    )
    return GauntletReport.build(
        spec="stdio: x",
        server=ServerInfo(name="srv", version="1"),
        tool_count=1,
        dimensions=[dim],
        agentic=detail,
    )


def test_inconclusive_empty_results_surfaces_in_all_renderers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _inconclusive_report()
    assert "Inconclusive" in to_html(report)  # HTML banner, not silently dropped
    assert "Inconclusive" in to_markdown(report)  # markdown banner
    buf = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=buf, width=100))
    cli._render_report(report)
    assert "inconclusive" in buf.getvalue().lower()  # console banner


def _default(command: str, option: str) -> object:
    """The declared default of a typer option, read off the command signature."""
    param = inspect.signature(getattr(cli, command)).parameters[option]
    return param.default.default


def test_timeout_defaults_are_mutually_coherent() -> None:
    # The budgets have to fit each other or the per-tool timeout is inert: if a hung server
    # can burn more than the per-server budget, the outer bound fires first, the report is
    # lost, and the tool timeout never gets to record anything. A hang now ends the agent
    # evaluation after ONE timeout, so that is the figure the budget must cover.
    tool_timeout = _default("leaderboard", "tool_timeout")
    per_server = _default("leaderboard", "timeout")
    assert isinstance(tool_timeout, float) and isinstance(per_server, float)
    # Real headroom, not merely `<`: the budget has to absorb the one permitted hang AND
    # the LLM turns of the tasks that already ran. A bare `tool_timeout < per_server` passes
    # at 239 vs 240, which would leave the timeout inert exactly when it matters.
    assert per_server >= tool_timeout * 3, (
        "per-server budget must cover one hung call plus the rest of the evaluation"
    )
    # The behavioural half of this invariant — that only ONE hang is ever paid for — is
    # pinned by test_agent_mock.py::test_hang_stops_the_whole_eval_and_is_reported.

    # And the single-server path must be at least as generous as the batch path.
    run_timeout = _default("run", "timeout")
    assert isinstance(run_timeout, float)
    assert run_timeout >= per_server
    assert _default("run", "tool_timeout") == tool_timeout  # same limit on both paths


def test_write_report_writes_all_three(tmp_path: Path) -> None:
    json_path, md_path, html_path = cli.write_report(_hostile_report(), tmp_path)
    assert json_path.exists() and md_path.exists() and html_path.exists()
    # JSON round-trips and preserves the hostile text verbatim (contained as data).
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["server"]["name"] == "[red]evil-server[/]"
    assert "get[/rows]" in md_path.read_text(encoding="utf-8")
