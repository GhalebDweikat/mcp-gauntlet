"""stdout pollution emitted DURING the session, not just at startup.

METHODOLOGY, the README and the CI example all promise this check. It fired for a startup
banner and silently missed a per-request logger — which is the more common shape of the
defect, since a misdirected logger fires once per request rather than once at boot. Found by
a platform engineer wiring up the gate, who verified the line on the wire and then watched
`--fail-on high`, `--fail-on medium`, `--fail-on info` and `--fail-under 99` all return 0.

The cause was ordering, not detection. The transport log was read immediately after
discovery, while every tool call happens afterwards, so the lines were recorded into a log
whose findings had already been taken. The static checks now run after the session's
interactive phase; the dimension order is unchanged.

Why the fixture is hand-rolled rather than built on the shim: both SDK eras rebind
`sys.stdout` inside their stdio transport, exactly so a server's own `print` cannot corrupt
the stream. That protects real SDK servers and makes the defect unreproducible through them
— every attempt through the shim produced a clean wire. The servers that actually exhibit
this are the ones NOT built on the Python SDK, so the fixture speaks JSON-RPC itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

import anyio
import pytest

from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.engine import evaluate_server

FIXTURE = Path(__file__).parent / "data" / "wire_noise_server.py"


def _findings(report: object) -> list[str]:
    messages = []
    for dimension in report.dimensions:  # type: ignore[attr-defined]
        for finding in dimension.findings:
            messages.append(finding.message)
    return messages


@pytest.mark.skipif(not FIXTURE.exists(), reason="fixture missing")
def test_per_request_stdout_pollution_is_reported() -> None:
    spec = ServerSpec.parse(f"{sys.executable} {FIXTURE}")

    async def _go() -> object:
        with anyio.fail_after(120):
            return await evaluate_server(spec, llm_config=None, probe=True, track_drift=False)

    report = anyio.run(_go)
    polluted = [m for m in _findings(report) if "non-protocol line" in m]
    assert polluted, (
        "a log line written to stdout during a tool call must be reported; "
        f"findings were: {_findings(report)}"
    )
    # MEDIUM, not HIGH: a misdirected logger is a bug, not an adversary, and only
    # near-certain attack signals are allowed to cap the grade.
    severities = {
        f.severity
        for d in report.dimensions  # type: ignore[attr-defined]
        for f in d.findings
        if "non-protocol line" in f.message
    }
    assert severities == {"medium"}, severities


@pytest.mark.skipif(not FIXTURE.exists(), reason="fixture missing")
def test_static_checks_run_after_the_interactive_phase() -> None:
    """Guards the ordering directly, so the regression cannot return via a refactor.

    The report's dimension order must stay static-then-live — the static checks were
    deferred to see the whole session, not reordered in the output.
    """
    import inspect

    from mcp_gauntlet import engine

    src = inspect.getsource(engine.evaluate_server)
    read_at = src.index("_protocol_findings(interactions.transport)")
    probes_at = src.index("run_robustness_probes(")
    assert read_at > probes_at, (
        "the transport log must be read AFTER the tool-calling phase, "
        "or everything logged during it is discarded"
    )
