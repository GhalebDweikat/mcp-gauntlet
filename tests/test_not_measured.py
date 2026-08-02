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

import json
import subprocess
import sys
from pathlib import Path

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


# ------------------------------------------------ PARTIAL coverage, not just total absence
#
# `not_measured` only ever fired when a stage was skipped ENTIRELY. Partial coverage is the
# more misleading case, because a number is still printed: `Robustness 100.0` on a server
# where most tools were excluded means "the few we ran were fine", and the denominator was
# recorded nowhere. All three cases below were found by testers reading a report that looked
# complete.

_DATA = Path(__file__).parent / "data"


def _report_for(server: str, tmp_path: Path, *extra: str) -> dict:
    out = tmp_path / "out"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "mcp_gauntlet",
            "run",
            server,
            "--no-agentic",
            "--out",
            str(out),
            *extra,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
    )
    return json.loads((out / "report.json").read_text(encoding="utf-8"))


def test_partially_excluded_probes_record_the_denominator(tmp_path: Path) -> None:
    """`Robustness 100.0` when only some tools were probed must say how many.

    The dimension's own summary reads "Fraction of PROBED tools that reject malformed
    input" — and the denominator appeared nowhere a reader or a script could find it. Point
    it at a twelve-tool server where nine look mutating and 100.0 means "the three we ran
    were fine", which is not what anyone takes from it.
    """
    data = _report_for(f"{sys.executable} {_DATA / 'mixed_tools_server.py'}", tmp_path)
    excluded_note = [n for n in data["not_measured"] if "excluded as possibly-mutating" in n]
    assert excluded_note, data["not_measured"]
    # The counts have to be in it; "some tools were skipped" is the sentence that was
    # already implied by the summary and helped nobody.
    assert "of 4 tool(s)" in excluded_note[0], excluded_note[0]
    assert "delete_record" in excluded_note[0], excluded_note[0]


def test_resource_contents_are_declared_unread(tmp_path: Path) -> None:
    """Only resource METADATA is scanned, and that gap was never surfaced.

    An unrendered prompt is correctly reported as unexamined; resource contents were simply
    absent, so the report implied a coverage it did not have (docs/known-gaps.md G8).
    """
    data = _report_for(f"{sys.executable} {_DATA / 'resources_server.py'}", tmp_path)
    note = [n for n in data["not_measured"] if "resource" in n]
    assert note, data["not_measured"]
    assert "2 resource(s)" in note[0], note[0]


def test_resource_metadata_is_still_scanned(tmp_path: Path) -> None:
    """The other half: what IS covered must keep working.

    No bundled fixture exposed a single resource — `serve_raw` has no `list_resources` hook
    — so the resource-scanning path METHODOLOGY advertises had never been exercised by any
    test. A disclosure about what is not read is worth little if what IS read went unchecked.
    """
    data = _report_for(f"{sys.executable} {_DATA / 'resources_server.py'}", tmp_path)
    findings = [f for d in data["dimensions"] for f in d["findings"]]
    poisoned = [f for f in findings if "resource description" in f["message"]]
    assert poisoned, [f["message"] for f in findings]
    assert any(f["severity"] == "high" for f in poisoned), poisoned


def test_selection_accuracy_is_absent_rather_than_a_perfect_100() -> None:
    """It used to be emitted at 100.0 with weight 1.5 when nothing had been checked.

    `score=mean(sel_values) if sel_values else 100.0` asserts a verified perfect result for a
    dimension that had no expectation to verify — and at the second-heaviest weight, it
    pulled the overall up with it. Unit-level because reaching it needs a live agent run.
    """
    import ast
    import inspect
    import textwrap

    from mcp_gauntlet import evaluate

    # Parsed, not grepped: the comment explaining this fix contains the literal `else 100.0`,
    # and the first draft of this test matched its own documentation. The AST does not see
    # inside comments — the same reason `test_no_sdk_shaped_read_survives_outside_the_adapters`
    # parses rather than greps.
    tree = ast.parse(textwrap.dedent(inspect.getsource(evaluate.run_agentic_eval)))
    fallbacks = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.IfExp)
        and isinstance(node.orelse, ast.Constant)
        and node.orelse.value == 100.0
    ]
    assert not fallbacks, "a dimension must not fall back to a perfect score when unmeasured"
