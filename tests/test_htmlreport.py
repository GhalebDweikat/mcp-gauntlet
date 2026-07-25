from mcp_gauntlet.htmlreport import to_html
from mcp_gauntlet.models import ServerInfo
from mcp_gauntlet.report import DimensionResult, Finding, GauntletReport, Severity


def _report(dimensions: list[DimensionResult]) -> GauntletReport:
    return GauntletReport.build(
        spec="python -m demo",
        server=ServerInfo(name="demo", version="1"),
        tool_count=2,
        dimensions=dimensions,
    )


def test_html_has_basic_structure() -> None:
    report = _report([DimensionResult(key="schema_health", title="Schema Health", score=100.0)])
    out = to_html(report)
    assert out.startswith("<!doctype html>")
    assert "demo" in out
    assert "Schema Health" in out
    assert "</body></html>" in out.replace("\n", "")


def test_html_escapes_untrusted_text() -> None:
    # Tool names / descriptions are attacker-controlled — they must be escaped.
    dim = DimensionResult(
        key="security",
        title="Security Signals",
        score=50.0,
        findings=[Finding(tool="<script>", severity=Severity.HIGH, message="x", detail="<b>&bad")],
    )
    out = to_html(_report([dim]))
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "&lt;b&gt;&amp;bad" in out


def test_html_shows_security_cap_banner() -> None:
    dim = DimensionResult(
        key="security",
        title="Security Signals",
        score=50.0,
        findings=[Finding(severity=Severity.HIGH, message="poisoned")],
    )
    report = _report([dim])
    assert report.security_critical is True
    assert "grade capped" in to_html(report)


def test_score_bar_color_matches_grade_bands() -> None:
    # S3: the bar bins had drifted (90/75/60) from the grade bins (90/80/70/60),
    # so a 78 dimension wore a B-green bar while grading C.
    from mcp_gauntlet.htmlreport import _GRADE_COLORS, _score_color
    from mcp_gauntlet.report import grade_for

    for score in (100.0, 95.0, 85.0, 80.0, 78.0, 70.0, 65.0, 60.0, 42.0, 0.0):
        assert _score_color(score) == _GRADE_COLORS[grade_for(score)], score
    assert _score_color(78.0) == _GRADE_COLORS["C"]
