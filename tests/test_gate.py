"""The CI gate: what fails a build, and what must never be mistaken for a failing build.

Two defects motivated all of this, both found by a platform engineer building a real gate
from the documented instructions.

The documented gate could not fail the project's own malicious fixture. `--fail-under 60`,
while a HIGH security finding caps the overall at 75 — and 75 > 60, so the cap acted as a
FLOOR for the gate rather than a ceiling on the grade. Eight HIGH tool-poisoning findings,
exit 0, green check.

And exit 1 meant six different things: your server failed, the server did not start, the run
timed out, the transport broke, `--out` was unwritable, `--agentic` had no key. A gate that
cannot tell "your server regressed" from "the runner had a bad day" gets switched off the
first week it flakes, and everything the tool found goes with it.
"""

from mcp_gauntlet.exits import Exit
from mcp_gauntlet.models import ServerInfo
from mcp_gauntlet.report import (
    DimensionResult,
    Finding,
    GauntletReport,
    Severity,
    findings_at_or_above,
)


def _report(*severities: Severity) -> GauntletReport:
    return GauntletReport.build(
        spec="stdio: srv",
        server=ServerInfo(name="srv"),
        tool_count=2,
        dimensions=[
            DimensionResult(
                key="schema_health",
                title="S",
                weight=1.0,
                score=90.0,
                findings=[
                    Finding(tool="t", severity=s, message=f"a {s.value} thing") for s in severities
                ],
            )
        ],
    )


def test_a_gate_catches_its_own_severity_and_everything_worse() -> None:
    report = _report(Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH)
    assert len(findings_at_or_above(report, Severity.HIGH)) == 1
    assert len(findings_at_or_above(report, Severity.MEDIUM)) == 2
    assert len(findings_at_or_above(report, Severity.LOW)) == 3
    assert len(findings_at_or_above(report, Severity.INFO)) == 4


def test_a_clean_server_trips_no_gate() -> None:
    clean = _report()
    for level in Severity:
        assert findings_at_or_above(clean, level) == []


def test_an_info_finding_does_not_trip_a_high_gate() -> None:
    # INFO carries zero penalty and exists to record things like "this surface was not
    # scanned". Failing a build on it would make the honest disclosures unusable.
    assert findings_at_or_above(_report(Severity.INFO), Severity.HIGH) == []


def test_the_severity_gate_catches_what_the_score_gate_cannot() -> None:
    """The defect in one assertion.

    A poisoned server is pinned AT the cap, 75 — so any `--fail-under` below 75 passes it.
    The documented example used 60. The severity gate keys on the finding instead, which is
    both the thing that was wrong and the thing that does not move when scoring changes.
    """
    poisoned = GauntletReport.build(
        spec="stdio: srv",
        server=ServerInfo(name="srv"),
        tool_count=1,
        dimensions=[
            DimensionResult(
                key="security",
                title="Security Signals",
                weight=2.0,
                score=40.0,
                findings=[Finding(tool="t", severity=Severity.HIGH, message="tool poisoning")],
            ),
            DimensionResult(key="schema_health", title="S", weight=1.0, score=100.0),
        ],
    )
    assert poisoned.security_critical is True
    assert poisoned.overall_score <= 75.0
    # The score gate the docs recommended: passes.
    assert not poisoned.overall_score < 60.0
    # The severity gate: fails, and names what was wrong.
    assert findings_at_or_above(poisoned, Severity.HIGH)


def test_the_exit_codes_are_distinct_and_one_means_quality() -> None:
    """Only exit 1 may fail a build on quality grounds.

    Pinned as a contract because CI keys on nothing else, and because the previous single
    code forced users to reverse-engineer a discriminator (a broken run writes no
    report.json) that was never documented and never meant to be load-bearing.
    """
    codes = [Exit.OK, Exit.GATE_FAILED, Exit.USAGE, Exit.UNEVALUABLE, Exit.CONFIG]
    assert len(set(codes)) == len(codes), "exit codes must be distinguishable"
    assert Exit.OK == 0
    assert Exit.GATE_FAILED == 1  # the only quality verdict
    assert Exit.USAGE == 2  # typer's own, not ours to change
    assert Exit.UNEVALUABLE == 3  # infrastructure — retry, do not report as a regression
    assert Exit.CONFIG == 4
