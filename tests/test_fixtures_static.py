"""Integration tests: launch the bundled fixture servers and run the static checks.

These spawn a real MCP subprocess but make no LLM calls, so they run in CI.
"""

import anyio

from mcp_gauntlet.checks import run_static_checks
from mcp_gauntlet.client import discover
from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.report import GauntletReport, Severity


def _static_report(spec_str: str) -> GauntletReport:
    spec = ServerSpec.parse(spec_str)
    discovery = anyio.run(discover, spec)
    dimensions = run_static_checks(discovery)
    return GauntletReport.build(
        spec=spec.label(),
        server=discovery.server,
        tool_count=len(discovery.tools),
        dimensions=dimensions,
    )


def test_bad_fixture_is_flagged_and_capped() -> None:
    report = _static_report("python -m mcp_gauntlet.fixtures.bad_server")
    assert report.security_critical is True
    assert report.overall_score <= 75.0  # a poisoned server cannot earn an A/B
    high_security = [
        finding
        for dimension in report.dimensions
        if dimension.key == "security"
        for finding in dimension.findings
        if finding.severity is Severity.HIGH
    ]
    assert high_security, "expected HIGH security findings (injection + hidden chars)"


def test_good_fixture_is_clean() -> None:
    report = _static_report("python -m mcp_gauntlet.fixtures.good_server")
    assert report.security_critical is False
    assert report.grade in ("A", "B")
