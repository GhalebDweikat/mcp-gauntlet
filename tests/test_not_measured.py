"""A stage that did not run must be visible, because the score cannot show it.

The overall is a weighted mean over the dimensions PRESENT. A stage that never ran does not
score 0 — it leaves the denominator, so the overall goes UP. The dimension table just has
one fewer row, which reads as a shorter report rather than a narrower measurement.

Two concrete cases motivated this:

* `unevaluated_reason` was set by the engine, stored in the JSON and printed by the
  leaderboard — and rendered by no report renderer at all. A credential-gated server that
  failed every call shipped a `report.md` headed "A (98.8/100)" with nothing saying the
  agent stage never ran. That is the artifact a user commits and links.
* `--no-probe` removes the Robustness dimension. A server that accepts every malformed
  input goes from C to A on that flag alone.
"""

from mcp_gauntlet.htmlreport import to_html
from mcp_gauntlet.models import ServerInfo
from mcp_gauntlet.report import (
    GRADE_CAP_ON_CRITICAL,
    Dim,
    DimensionResult,
    Finding,
    GauntletReport,
    Severity,
    to_markdown,
)


def _report(**kwargs: object) -> GauntletReport:
    return GauntletReport.build(
        spec="stdio: srv",
        server=ServerInfo(name="srv", version="1"),
        tool_count=3,
        dimensions=[
            DimensionResult(key="schema_health", title="Schema Health", weight=1.0, score=98.8)
        ],
        **kwargs,  # type: ignore[arg-type]
    )


def test_a_dropped_dimension_raises_the_overall() -> None:
    """The arithmetic behind the whole finding, asserted so nobody has to take it on trust.

    Robustness carries real weight, so a server that fails it is pulled down. Remove the
    row — do not score it 0, remove it — and the same server scores higher.
    """
    with_probe = GauntletReport.build(
        spec="s",
        server=ServerInfo(name="s"),
        tool_count=2,
        dimensions=[
            DimensionResult(key="schema_health", title="S", weight=1.0, score=100.0),
            DimensionResult(key="robustness", title="R", weight=1.0, score=0.0),
        ],
    )
    without_probe = GauntletReport.build(
        spec="s",
        server=ServerInfo(name="s"),
        tool_count=2,
        dimensions=[DimensionResult(key="schema_health", title="S", weight=1.0, score=100.0)],
    )
    assert with_probe.overall_score == 50.0
    assert without_probe.overall_score == 100.0  # strictly better for having measured less


def test_the_reason_a_server_was_not_scored_reaches_every_renderer() -> None:
    report = _report(unevaluated_reason="needs credentials that were not supplied")
    markdown, html = to_markdown(report), to_html(report)
    for rendered, fmt in ((markdown, "markdown"), (html, "html")):
        assert "needs credentials that were not supplied" in rendered, f"missing from {fmt}"


def test_skipped_stages_reach_every_renderer() -> None:
    report = _report(not_measured=["robustness probes (--no-probe)"])
    markdown, html = to_markdown(report), to_html(report)
    for rendered, fmt in ((markdown, "markdown"), (html, "html")):
        assert "robustness probes (--no-probe)" in rendered, f"missing from {fmt}"


def test_a_fully_measured_report_says_nothing_extra() -> None:
    # The quiet case has to stay quiet, or the banner becomes noise nobody reads.
    markdown = to_markdown(_report())
    assert "Not measured" not in markdown
    assert "Not scored" not in markdown


# ------------------------------------------------- the cap is a fact, not a stored boolean


def _security_dim(severity: Severity) -> DimensionResult:
    return DimensionResult(
        key=Dim.SECURITY,
        title="Security Signals",
        weight=2.0,
        score=60.0,
        findings=[Finding(tool="t", severity=severity, message="tool-poisoning in description")],
    )


def _saved_report(**overrides: object) -> dict[str, object]:
    """A saved report reloaded from disk with `GauntletReport(**raw)`."""
    return {
        "spec": "stdio: srv",
        "server": {"name": "srv", "version": "1"},
        "tool_count": 2,
        "dimensions": [
            _security_dim(Severity.HIGH).model_dump(),
            {"key": "schema_health", "title": "S", "weight": 1.0, "score": 100.0},
        ],
        "overall_score": 78.8,
        "grade": "B",
        "generated_at": "2026-08-01T00:00:00+00:00",
        **overrides,
    }


def test_a_saved_report_cannot_publish_above_the_cap() -> None:
    """The cap was applied once in build() and then carried as a stored boolean.

    `load_results` rebuilds from saved JSON with `GauntletReport(**raw)`, where
    `security_critical` defaults to False and the score and grade are taken verbatim. A
    report carrying a HIGH security finding without the flag published at B / 78.8 against a
    cap of 75 — with the board's own linked page listing the tool-poisoning finding
    underneath. The board is the surface people read.
    """
    report = GauntletReport(**_saved_report())  # type: ignore[arg-type]
    assert report.security_critical is True
    assert report.overall_score == GRADE_CAP_ON_CRITICAL
    assert report.grade == "C"


def test_a_clean_report_is_left_alone() -> None:
    raw = _saved_report(
        dimensions=[{"key": "schema_health", "title": "S", "weight": 1.0, "score": 98.8}]
    )
    report = GauntletReport(**raw)  # type: ignore[arg-type]
    assert report.security_critical is False
    assert report.overall_score == 78.8  # untouched


def test_a_medium_security_finding_does_not_cap() -> None:
    # Only near-certain signals cap; the re-derivation must not widen what counts.
    raw = _saved_report(
        dimensions=[_security_dim(Severity.MEDIUM).model_dump()],
    )
    report = GauntletReport(**raw)  # type: ignore[arg-type]
    assert report.security_critical is False
    assert report.overall_score == 78.8


def test_an_unscored_report_is_not_given_a_grade_by_the_cap() -> None:
    # An N/A report keeps its security findings but was never scored. Clamping a score that
    # does not exist would invent a grade for a server nothing measured.
    raw = _saved_report(grade="N/A", overall_score=0.0)
    report = GauntletReport(**raw)  # type: ignore[arg-type]
    assert report.security_critical is True
    assert report.grade == "N/A"
    assert report.overall_score == 0.0
