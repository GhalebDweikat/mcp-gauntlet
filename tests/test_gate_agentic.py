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
import re
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

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Console output with styling removed.

    Any assertion about WORDS in the console has to go through this. Rich emits colour when
    it thinks it is being watched — which on a CI runner it is, and on a developer's captured
    test output it is not — and its highlighter wraps parts of a token in separate escape
    sequences, so `--fail-under` genuinely is not a substring of the coloured render.
    """
    return _ANSI.sub("", text)


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


def test_scan_honours_explicit_agentic_like_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`run --agentic` with no key exited 4; `scan --agentic` degraded and exited 0.

    Same flag, same words in the docs, opposite behaviour — and `scan` is the command the
    repositioned docs push people toward. A fork PR (no secrets) or a rotated secret went
    green with the weight-3.0 dimension never run. `scan` also declared the flag as a plain
    bool defaulting True, so it could not tell "the user asked" from "nobody said", and its
    --help advertised a default that was never the real behaviour.
    """
    for name in ("GROQ_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "load_env", lambda *a, **k: None)  # ignore any .env on disk
    # A REAL list: the file is loaded before the key is checked, so a missing one would
    # short-circuit to the same exit code for an entirely different reason.
    listing = tmp_path / "servers.json"
    listing.write_text('{"servers": [{"name": "s", "spec": "python -m srv"}]}', encoding="utf-8")
    result = runner.invoke(cli.app, ["scan", "--servers", str(listing), "--agentic"])
    assert result.exit_code == Exit.CONFIG, result.output
    assert "no LLM is configured" in result.output


def test_scan_refuses_an_empty_server_list(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Scanning nothing and reporting a pass is the same defect as passing on an expired key.

    Every other malformed-list shape already exited 4; an empty one printed an empty table
    and exited 0. A truncated or mis-templated servers.json is the realistic way to get here.
    """
    listing = tmp_path / "servers.json"
    listing.write_text('{"servers": []}', encoding="utf-8")
    monkeypatch.setattr(cli, "load_env", lambda *a, **k: None)
    result = runner.invoke(cli.app, ["scan", "--servers", str(listing), "--no-agentic"])
    assert result.exit_code == Exit.CONFIG, result.output
    assert "No servers to scan" in result.output


def test_a_server_with_no_tools_is_not_a_pass(
    patched: Callable[[GauntletReport], None], tmp_path: Path
) -> None:
    """`--fail-on high` could not fail a server whose tool registration broke.

    "server exposes no tools" is MEDIUM, and every document pushes `--fail-on high` as THE
    CI gate — so the migration the docs instruct turned a red build green for the most total
    outage there is. Three independent testers found it. Exit 3, not 1: nothing was
    measured, so there is no verdict to give.
    """
    report = GauntletReport.build(
        spec="stdio: srv",
        server=ServerInfo(name="srv", version="1"),
        tool_count=0,
        dimensions=[],
    )
    patched(report)
    # And the SAME verdict at every threshold. It used to exit 3 at `high` and 1 at `medium`,
    # because "exposes no tools" is a MEDIUM finding — so tightening the gate turned "nothing
    # was measured" into a definite fail on a run with no measurements in it. One of those two
    # answers is wrong whichever you believe.
    for gate in ("high", "medium", "low", None):
        argv = ["run", "python -m srv", "--no-agentic", "--out", str(tmp_path / "o")]
        if gate:
            argv += ["--fail-on", gate]
        result = runner.invoke(cli.app, argv)
        assert result.exit_code == Exit.UNEVALUABLE, f"--fail-on {gate}: {result.output}"
        assert "exposes no tools" in result.output


def test_a_real_finding_outranks_an_incomplete_run(
    patched: Callable[[GauntletReport], None], tmp_path: Path
) -> None:
    """When both are true, report the verdict — not the excuse.

    "your server has a HIGH finding" is actionable; "the LLM backend was down" is not, and
    the finding is still real. The reverse must never happen: a PASS reported while a stage
    that would have produced findings never ran. So the order is failing-gate, then
    incomplete-run, then exit 0.
    """
    from mcp_gauntlet.report import Finding, Severity

    detail = AgenticDetail(
        provider="groq", model="m", tasks_generated=2, repeats=1, inconclusive=True, results=[]
    )
    report = GauntletReport.build(
        spec="stdio: srv",
        server=ServerInfo(name="srv", version="1"),
        tool_count=2,
        dimensions=[
            DimensionResult(
                key="security",
                title="Security Signals",
                weight=2.0,
                score=75.0,
                findings=[
                    Finding(
                        tool="t",
                        severity=Severity.HIGH,
                        message="description attempts to override",
                    )
                ],
            )
        ],
        agentic=detail,
    )
    patched(report)
    result = runner.invoke(
        cli.app,
        ["run", "python -m srv", "--agentic", "--fail-on", "high", "--out", str(tmp_path / "o")],
    )
    assert result.exit_code == Exit.GATE_FAILED, result.output
    assert "at or above high" in result.output


@pytest.mark.parametrize(
    ("argv", "flag"),
    [
        (["run", "python -m srv", "--fail-under", "-10"], "--fail-under"),
        (["run", "python -m srv", "--fail-under", "200"], "--fail-under"),
        (["run", "python -m srv", "--tasks", "-5"], "--tasks"),
        (["run", "python -m srv", "--repeats", "0"], "--repeats"),
        (["run", "python -m srv", "--max-turns", "0"], "--max-turns"),
        (["run", "python -m srv", "--tool-timeout", "0"], "--tool-timeout"),
        (["run", "python -m srv", "--timeout", "-1"], "--timeout"),
        (["scan", "--servers", "s.json", "--timeout", "0"], "--timeout"),
        (["scan", "--servers", "s.json", "--tasks", "0"], "--tasks"),
    ],
)
def test_out_of_range_numbers_are_usage_errors(
    argv: list[str], flag: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A gate is only useful if it can both fire and pass.

    `--fail-under -10` was accepted and exits 0 forever — a typo'd gate that looks configured
    and silently does nothing, the same shape as everything else found this round.
    `--fail-under 200` fails forever, which at least announces itself. `--tasks -5` and
    `--repeats 0` were accepted too.

    Enforced with typer's own `min`/`max` rather than hand-rolled checks, so the failure is a
    real usage error at parse time — exit 2, before any work, naming the value and the range.
    """

    async def _never(*_a: object, **_k: object) -> GauntletReport:
        raise AssertionError("evaluation must not start with an out-of-range option")

    monkeypatch.setattr(cli, "evaluate_server", _never)
    result = runner.invoke(cli.app, argv)
    assert result.exit_code == Exit.USAGE, result.output
    # Strip styling before looking for the flag. With colour ON — which is what a CI runner
    # gets, and what nobody gets locally — Rich's highlighter breaks an option name into
    # separately-styled runs, so `--fail-under` is on screen as
    # `\x1b[1;36m-\x1b[0m\x1b[1;36m-fail\x1b[0m\x1b[1;36m-under\x1b[0m` and the literal
    # substring is not in the output at all. This assertion was therefore GREEN on every
    # developer machine and RED on every CI run for twelve consecutive commits, including the
    # one that cut 0.9.2.
    assert flag in _plain(result.output)


def test_zero_timeout_still_means_disabled(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`run --timeout 0` is documented as disabling the bound, so it must stay legal.

    The range is min=0 for exactly this reason: a negative timeout is not a shorter one, but
    zero has a meaning the help text promises.
    """
    patched_report = GauntletReport.build(
        spec="stdio: srv",
        server=ServerInfo(name="srv", version="1"),
        tool_count=1,
        dimensions=[DimensionResult(key="schema_health", title="S", weight=1.0, score=99.0)],
    )

    async def _fake(*_a: object, **_k: object) -> GauntletReport:
        return patched_report

    monkeypatch.setattr(cli, "evaluate_server", _fake)
    result = runner.invoke(
        cli.app, ["run", "python -m srv", "--no-agentic", "--timeout", "0", "--out", str(tmp_path)]
    )
    assert result.exit_code == Exit.OK, result.output
