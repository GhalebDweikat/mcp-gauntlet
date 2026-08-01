"""A stage that was ASKED for and could not run must not exit 0.

Found re-testing the exit-code contract before the 0.9.0 release, by running with a
syntactically-valid but revoked API key — the case a long-lived pipeline actually hits, as
opposed to the no-key case that was already covered.

    mcp-gauntlet run <server> --agentic       # key present, backend rejects it
    → A 98.7/100, "No high/medium-severity findings.", exit 0, green check

The four heaviest dimensions (Agent Task Success at weight 3.0, Tool-Selection Accuracy,
Tool Reliability, Response Safety) never ran, the console said so in a yellow warning, and
`report.json` — the file CI parses — carried an EMPTY `not_measured`, asserting full
coverage. The shipped CI example promised exit 4 for exactly this ("a missing, renamed or
expired secret"), and delivered 0.

A missing key was caught before the run started, so it looked covered. A revoked one is not
discoverable until the first API call, which is why it fell through: it arrives as an
ordinary backend error, indistinguishable at that point from a rate limit, and "inconclusive"
was treated as a clean skip rather than as a stage that failed to produce evidence.

The same bug class as the drift flag and the grade-cap banner before it: a guard that
reports success when it stops working.
"""

import io
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from mcp_gauntlet import cli
from mcp_gauntlet.exits import Exit
from mcp_gauntlet.models import ServerInfo
from mcp_gauntlet.report import AgenticDetail, DimensionResult, GauntletReport

runner = CliRunner()


def _report(*, inconclusive: bool) -> GauntletReport:
    """A report whose static checks are healthy — so nothing but the agentic state can
    decide the exit code. A failing static check would mask the bug rather than expose it."""
    detail = AgenticDetail(
        provider="groq",
        model="m",
        tasks_generated=2,
        repeats=1,
        inconclusive=inconclusive,
        results=[],
    )
    return GauntletReport.build(
        spec="stdio: srv",
        server=ServerInfo(name="srv", version="1"),
        tool_count=2,
        dimensions=[
            DimensionResult(key="schema_health", title="Schema Health", weight=1.0, score=98.0)
        ],
        agentic=detail,
        not_measured=(
            [
                "agent evaluation, tool-selection accuracy, tool reliability and response "
                "safety (the LLM backend errored on every attempt)"
            ]
            if inconclusive
            else []
        ),
    )


@pytest.fixture
def patched(monkeypatch: pytest.MonkeyPatch) -> Callable[[GauntletReport], None]:
    def _apply(report: GauntletReport) -> None:
        async def _fake(*_a: object, **_k: object) -> GauntletReport:
            return report

        monkeypatch.setattr(cli, "evaluate_server", _fake)
        # A key must appear configured, or `--agentic` short-circuits to exit 4 up front and
        # never reaches the case under test.
        monkeypatch.setenv("GROQ_API_KEY", "gsk_test_not_a_real_key")

    return _apply


def test_explicit_agentic_that_could_not_run_is_not_a_pass(
    patched: Callable[[GauntletReport], None], tmp_path: Path
) -> None:
    patched(_report(inconclusive=True))
    result = runner.invoke(
        cli.app, ["run", "python -m srv", "--agentic", "--out", str(tmp_path / "o")]
    )
    # 3, not 0: the run could not be evaluated. And explicitly not 1 — a broken API key is
    # not a verdict about the server, and a gate that conflates them gets switched off.
    assert result.exit_code == Exit.UNEVALUABLE, result.output
    assert "could not run" in result.output


def test_explicit_agentic_that_ran_still_passes(
    patched: Callable[[GauntletReport], None], tmp_path: Path
) -> None:
    # The guard must not fire on a healthy agentic run, or it would fail every green build.
    patched(_report(inconclusive=False))
    result = runner.invoke(
        cli.app, ["run", "python -m srv", "--agentic", "--out", str(tmp_path / "o")]
    )
    assert result.exit_code == Exit.OK, result.output


def test_auto_mode_still_degrades_quietly(
    patched: Callable[[GauntletReport], None], tmp_path: Path
) -> None:
    """Without an explicit `--agentic` the user did not ask for the stage, so degrading to a
    static run is the documented behaviour and stays exit 0. The disclosure carries the
    weight there; only the explicit form is a promise the tool has to keep."""
    patched(_report(inconclusive=True))
    result = runner.invoke(cli.app, ["run", "python -m srv", "--out", str(tmp_path / "o")])
    assert result.exit_code == Exit.OK, result.output


def test_inconclusive_run_discloses_in_the_json(
    patched: Callable[[GauntletReport], None], tmp_path: Path
) -> None:
    """The console warning was never the problem — `report.json` was. CI parses the file."""
    patched(_report(inconclusive=True))
    out = tmp_path / "o"
    runner.invoke(cli.app, ["run", "python -m srv", "--agentic", "--out", str(out)])
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["not_measured"], "an attempted-but-failed stage must not read as full coverage"
    assert "agent evaluation" in " ".join(data["not_measured"])


@pytest.mark.parametrize("command", ["run", "scan"])
def test_bad_fail_on_value_is_a_usage_error_before_any_work(
    command: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`--fail-on hgih` used to connect to the server, generate tasks, pay for a full agentic
    run, and only then report the typo — as exit 4, while an unknown flag gave typer's 2."""
    called = False

    async def _never(*_a: object, **_k: object) -> GauntletReport:
        nonlocal called
        called = True
        raise AssertionError("evaluation must not start with an invalid --fail-on")

    monkeypatch.setattr(cli, "evaluate_server", _never)
    # `--servers` is deliberately pointed at a path that does NOT exist: if the typo is
    # caught first, as it must be, the missing file is never reached.
    argv = (
        ["run", "python -m srv"]
        if command == "run"
        else ["scan", "--servers", str(tmp_path / "nope.json")]
    )
    result = runner.invoke(cli.app, [*argv, "--fail-on", "hgih"])
    assert result.exit_code == Exit.USAGE, result.output
    assert "is not a severity" in result.output
    assert not called


def test_console_still_explains_the_inconclusive_run(
    patched: Callable[[GauntletReport], None],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Exiting non-zero is only half of it — the message has to name the likely cause, or the
    developer who hits it at 2am concludes their server broke."""
    report = _report(inconclusive=True)
    buf = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=buf, width=100))
    cli._render_report(report)
    text = buf.getvalue().lower()
    assert "inconclusive" in text
    assert "not measured" in text
