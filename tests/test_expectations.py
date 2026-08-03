"""A suppression mechanism is, structurally, a check that reports success when it stops
working — which is the exact defect this whole project exists to catch.

So the tests here are mostly about what `--expect` must NOT be allowed to do quietly. The
feature itself is twenty lines; the discipline around it is the point.
"""

import json
from pathlib import Path

import pytest

from mcp_gauntlet.expectations import (
    ExpectationsError,
    apply_expectations,
    load_expectations,
    summarize,
)
from mcp_gauntlet.models import ServerInfo
from mcp_gauntlet.report import (
    DimensionResult,
    Finding,
    GauntletReport,
    Severity,
    findings_at_or_above,
)


def _file(tmp_path: Path, *entries: dict) -> Path:
    path = tmp_path / "expect.json"
    path.write_text(json.dumps({"expected": list(entries)}), encoding="utf-8")
    return path


def _report() -> GauntletReport:
    return GauntletReport.build(
        spec="stdio: srv",
        server=ServerInfo(name="srv", version="1"),
        tool_count=2,
        dimensions=[
            DimensionResult(
                key="security",
                title="Security Signals",
                weight=2.0,
                score=40.0,
                findings=[
                    Finding(
                        tool="sanitise",
                        severity=Severity.HIGH,
                        message="description attempts to override prior instructions",
                    ),
                    Finding(
                        tool="wipe_all",
                        severity=Severity.HIGH,
                        message="description hidden-instruction marker (<IMPORTANT>)",
                    ),
                ],
            )
        ],
    )


def test_an_expected_finding_stops_gating_and_nothing_else(tmp_path: Path) -> None:
    """The single most important property. A mechanism that REMOVED the finding would be
    indistinguishable from a check that stopped working."""
    report = _report()
    expectations = load_expectations(
        _file(
            tmp_path,
            {
                "tool": "sanitise",
                "message": "description attempts to override prior instructions",
                "reason": "this tool quotes the attacks it detects — known-gaps G7",
            },
        )
    )
    applied = apply_expectations(report, expectations)
    assert applied.matched == 1

    findings = [f for d in report.dimensions for f in d.findings]
    assert len(findings) == 2  # still there, both of them
    excused = next(f for f in findings if f.tool == "sanitise")
    assert excused.severity is Severity.HIGH  # still HIGH, not downgraded
    assert excused.expected is True
    # The WHY travels with it, into `report.json`. A suppression whose justification lives
    # only in the invocation is one the next reader of the artifact cannot review.
    assert (excused.expected_reason or "").startswith("this tool quotes")

    # …and only the gate changed.
    gating = findings_at_or_above(report, Severity.HIGH)
    assert [f.tool for f in gating] == ["wipe_all"]


def test_every_run_says_what_was_suppressed(tmp_path: Path) -> None:
    """Silence is how a file of forty suppressions becomes invisible."""
    report = _report()
    applied = apply_expectations(
        report,
        load_expectations(
            _file(
                tmp_path,
                {
                    "tool": "sanitise",
                    "message": "description attempts to override prior instructions",
                    "reason": "G7",
                },
            )
        ),
    )
    lines = summarize(applied)
    assert lines and "1 finding(s) matched --expect" in lines[0]


def test_an_expectation_that_matches_nothing_is_reported(tmp_path: Path) -> None:
    """Otherwise the file rots. A finding's wording changes — which has happened in nearly
    every release of this project — the entry silently stops applying, and nobody learns
    until the thing it was hiding matters."""
    report = _report()
    applied = apply_expectations(
        report,
        load_expectations(
            _file(tmp_path, {"tool": "sanitise", "message": "wording that moved", "reason": "x"})
        ),
    )
    assert applied.matched == 0
    assert [e.message for e in applied.unused] == ["wording that moved"]
    assert any("matched nothing" in line for line in summarize(applied))


def test_matching_is_exact_and_never_a_substring(tmp_path: Path) -> None:
    """The two failure directions are not symmetric.

    An entry that stops matching turns the build red — loud, and fixable in a minute. An
    entry that matches too much hides real findings and says nothing at all. So a prefix
    must not match, however tempting the ergonomics.
    """
    report = _report()
    applied = apply_expectations(
        report,
        load_expectations(
            _file(tmp_path, {"tool": "sanitise", "message": "description attempts", "reason": "x"})
        ),
    )
    assert applied.matched == 0
    assert findings_at_or_above(report, Severity.HIGH)  # still gating


def test_the_tool_name_is_part_of_the_match(tmp_path: Path) -> None:
    # Excusing one tool's finding must not excuse the same wording on a different tool.
    report = _report()
    report.dimensions[0].findings.append(
        Finding(
            tool="other",
            severity=Severity.HIGH,
            message="description attempts to override prior instructions",
        )
    )
    applied = apply_expectations(
        report,
        load_expectations(
            _file(
                tmp_path,
                {
                    "tool": "sanitise",
                    "message": "description attempts to override prior instructions",
                    "reason": "G7",
                },
            )
        ),
    )
    assert applied.matched == 1
    assert {f.tool for f in findings_at_or_above(report, Severity.HIGH)} == {"wipe_all", "other"}


def test_a_server_level_finding_is_matched_by_omitting_the_tool(tmp_path: Path) -> None:
    report = _report()
    report.dimensions[0].findings.append(
        Finding(severity=Severity.HIGH, message="server instructions attempt an override")
    )
    applied = apply_expectations(
        report,
        load_expectations(
            _file(tmp_path, {"message": "server instructions attempt an override", "reason": "x"})
        ),
    )
    assert applied.matched == 1


def test_a_reason_is_required(tmp_path: Path) -> None:
    """A suppression nobody can review is how a file becomes institutional amnesia."""
    for entry in (
        {"message": "m"},
        {"message": "m", "reason": ""},
        {"message": "m", "reason": " "},
    ):
        with pytest.raises(ExpectationsError, match='"reason" must be a non-empty string'):
            load_expectations(_file(tmp_path, entry))


def test_the_file_is_validated_by_name_like_every_other_config(tmp_path: Path) -> None:
    with pytest.raises(ExpectationsError, match="unknown key"):
        load_expectations(_file(tmp_path, {"message": "m", "reason": "r", "sevrity": "high"}))

    path = tmp_path / "e.json"
    path.write_text(json.dumps({"expected": [], "failOn": "high"}), encoding="utf-8")
    with pytest.raises(ExpectationsError, match="unknown top-level key"):
        load_expectations(path)

    path.write_text("not json at all", encoding="utf-8")
    with pytest.raises(ExpectationsError, match="not valid JSON"):
        load_expectations(path)

    path.write_text(json.dumps({"expected": "high"}), encoding="utf-8")
    with pytest.raises(ExpectationsError, match='must be an object with an "expected" list'):
        load_expectations(path)

    with pytest.raises(ExpectationsError, match="could not read"):
        load_expectations(tmp_path / "absent.json")


def test_no_expectations_means_no_output_and_no_change() -> None:
    report = _report()
    applied = apply_expectations(report, [])
    assert applied.matched == 0
    assert summarize(applied) == []
    assert len(findings_at_or_above(report, Severity.HIGH)) == 2
