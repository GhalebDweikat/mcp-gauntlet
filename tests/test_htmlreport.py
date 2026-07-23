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
