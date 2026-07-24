"""The console summary and the persisted report are built from server-controlled text
(server name, tool names, findings). Hostile Rich markup in any of them must not crash
the CLI, and the report is written to disk BEFORE rendering so a render glitch can't
discard a run the user just paid for.
"""

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


def test_write_report_writes_all_three(tmp_path: Path) -> None:
    json_path, md_path, html_path = cli.write_report(_hostile_report(), tmp_path)
    assert json_path.exists() and md_path.exists() and html_path.exists()
    # JSON round-trips and preserves the hostile text verbatim (contained as data).
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["server"]["name"] == "[red]evil-server[/]"
    assert "get[/rows]" in md_path.read_text(encoding="utf-8")
