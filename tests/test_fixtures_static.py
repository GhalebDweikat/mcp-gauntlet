"""Integration tests: launch the bundled fixture servers and run the static checks.

These spawn a real MCP subprocess but make no LLM calls, so they run in CI.
"""

import sys

import anyio

from mcp_gauntlet.checks import run_static_checks
from mcp_gauntlet.client import discover, discover_in_session
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
    report = _static_report(f"{sys.executable} -m mcp_gauntlet.fixtures.bad_server")
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
    report = _static_report(f"{sys.executable} -m mcp_gauntlet.fixtures.good_server")
    assert report.security_critical is False
    assert report.grade in ("A", "B")


def test_a_credential_gated_server_looks_perfect_until_you_call_it() -> None:
    """The premise of the credential pre-flight, pinned against a real subprocess.

    This is the commonest shape in the public registry: good descriptions, valid schemas,
    a clean static read — and every call fails for want of an account. A static scan cannot
    tell it from a healthy server, which is exactly why the pre-flight has to *call* one.
    """
    report = _static_report(f"{sys.executable} -m mcp_gauntlet.fixtures.gated_server")
    assert report.tool_count == 3
    assert report.grade == "A"  # nothing static reveals the problem
    assert not report.security_critical


def test_the_preflight_declines_to_score_the_gated_fixture() -> None:
    # And calling it does reveal the problem — without an LLM, before any spend.
    from mcp_gauntlet.client import open_session
    from mcp_gauntlet.preflight import probe_credentials

    spec = ServerSpec.parse(f"{sys.executable} -m mcp_gauntlet.fixtures.gated_server")

    async def _probe() -> str | None:
        async with open_session(spec) as (session, init, _interactions):
            discovery = await discover_in_session(session, init)
            return await probe_credentials(session, discovery.tools)

    reason = anyio.run(_probe)
    assert reason is not None
    assert "needs credentials" in reason
    assert "GATED_API_KEY" in reason or "401" in reason
