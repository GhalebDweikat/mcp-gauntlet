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
from mcp_gauntlet.report import DimensionResult, GauntletReport, to_markdown


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
