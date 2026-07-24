"""Core scoring model: the grade cap, the zero-tool N/A branch, and comparability.

`report.py` computes the number everything else displays and ranks, so its edge cases
(a tool-less server, a HIGH security finding, a report the agent never scored) are worth
pinning down directly rather than only through the CLI.
"""

from mcp_gauntlet.htmlreport import to_html
from mcp_gauntlet.models import ServerInfo
from mcp_gauntlet.report import (
    GRADE_CAP_ON_CRITICAL,
    AgenticDetail,
    DimensionResult,
    Finding,
    GauntletReport,
    Severity,
    grade_for,
    score_from_findings,
    to_markdown,
)


def _dim(
    key: str, score: float, weight: float = 1.0, findings: list[Finding] | None = None
) -> DimensionResult:
    return DimensionResult(
        key=key, title=key.title(), weight=weight, score=score, findings=findings or []
    )


def _build(
    dims: list[DimensionResult], tool_count: int = 1, agentic: AgenticDetail | None = None
) -> GauntletReport:
    return GauntletReport.build(
        spec="stdio: x",
        server=ServerInfo(name="srv", version="1"),
        tool_count=tool_count,
        dimensions=dims,
        agentic=agentic,
    )


def test_overall_is_the_weighted_mean() -> None:
    report = _build([_dim("a", 100.0, weight=1.0), _dim("b", 60.0, weight=3.0)])
    assert report.overall_score == 70.0  # (100*1 + 60*3) / 4
    assert report.grade == "C"


def test_high_security_finding_caps_the_grade() -> None:
    security = _dim(
        "security", 40.0, weight=2.0, findings=[Finding(severity=Severity.HIGH, message="poisoned")]
    )
    report = _build([_dim("a", 100.0), security])
    assert report.security_critical is True
    assert report.overall_score <= GRADE_CAP_ON_CRITICAL


def test_response_safety_high_does_not_cap() -> None:
    # Passthrough content a server merely relayed is not evidence the server is malicious,
    # so the runtime dimension lowers the score but must never trip the critical flag.
    runtime = _dim(
        "response_safety",
        40.0,
        findings=[Finding(severity=Severity.HIGH, message="output attempts to override")],
    )
    report = _build([_dim("a", 100.0), runtime])
    assert report.security_critical is False


def test_zero_tool_server_is_na_but_keeps_its_security_findings() -> None:
    # A tool-less server can still ship poisoned `instructions`. The N/A branch used to
    # REPLACE the dimensions with a "no tools" note, silently discarding that finding and
    # resetting security_critical to False.
    security = _dim(
        "security",
        63.0,
        weight=2.0,
        findings=[Finding(severity=Severity.HIGH, message="instructions attempt an override")],
    )
    report = _build([security], tool_count=0)
    assert report.grade == "N/A"  # still unscored...
    assert report.security_critical is True  # ...but not unexamined
    messages = [f.message for f in report.findings]
    assert "instructions attempt an override" in messages
    assert "server exposes no tools" in messages  # the explanatory note is kept too


def test_zero_tool_server_without_security_findings_stays_clean() -> None:
    report = _build([_dim("security", 100.0, weight=2.0)], tool_count=0)
    assert report.grade == "N/A"
    assert report.security_critical is False


def test_agentically_scored_tracks_the_task_success_dimension() -> None:
    # This is what keeps the leaderboard from co-ranking non-comparable overalls: a report
    # without task_success was averaged over a smaller denominator.
    detail = AgenticDetail(provider="p", model="m", tasks_generated=3, repeats=2)
    assert _build([_dim("a", 100.0)]).agentically_scored is False
    assert _build([_dim("a", 100.0)], agentic=detail).agentically_scored is False  # ran, no score
    assert _build([_dim("a", 100.0), _dim("task_success", 70.0, 3.0)]).agentically_scored is True


def test_missing_agentic_dimensions_inflate_the_overall() -> None:
    # The mechanism behind the inversion, pinned so a future weighting change can't hide it.
    static_only = _build([_dim("a", 100.0)])
    tested = _build([_dim("a", 100.0), _dim("task_success", 70.0, 3.0)])
    assert static_only.overall_score > tested.overall_score


def test_na_report_does_not_claim_a_cap_that_never_happened() -> None:
    # The N/A branch keeps its security findings (so security_critical is True) but the
    # grade was never scored, let alone capped — all three renderers must say so.
    security = _dim(
        "security",
        63.0,
        weight=2.0,
        findings=[Finding(severity=Severity.HIGH, message="instructions attempt an override")],
    )
    na = _build([security], tool_count=0)
    capped = _build([security, _dim("a", 100.0)])
    assert na.security_critical and capped.security_critical

    assert "never scored" in to_markdown(na)
    assert "grade is capped" not in to_markdown(na)
    assert "grade is capped" in to_markdown(capped)  # the real cap still says so

    assert "never scored" in to_html(na)
    assert "grade capped" not in to_html(na)
    assert "grade capped" in to_html(capped)


def test_unrunnable_agent_eval_explains_itself_in_html() -> None:
    # When every tool is excluded as possibly-mutating the grade card still advertises an
    # agent model, so the page must explain why no agent results follow.
    detail = AgenticDetail(
        provider="p",
        model="m",
        tasks_generated=0,
        repeats=2,
        excluded_write_tools=["write_file"],
    )
    html = to_html(_build([_dim("a", 100.0)], agentic=detail))
    assert "Agent evaluation" in html
    assert "every tool was excluded as possibly-mutating" in html
    assert "write_file" in html


def test_grade_boundaries() -> None:
    assert [grade_for(s) for s in (90.0, 80.0, 70.0, 60.0, 59.9)] == ["A", "B", "C", "D", "F"]


def test_score_from_findings_floors_at_zero() -> None:
    assert score_from_findings([]) == 100.0
    assert score_from_findings([Finding(severity=Severity.INFO, message="fyi")]) == 100.0
    assert score_from_findings([Finding(severity=Severity.HIGH, message="x")] * 20) == 0.0
