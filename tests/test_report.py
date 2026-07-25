"""Core scoring model: the grade cap, the zero-tool N/A branch, and comparability.

`report.py` computes the number everything else displays and ranks, so its edge cases
(a tool-less server, a HIGH security finding, a report the agent never scored) are worth
pinning down directly rather than only through the CLI.
"""

from mcp_gauntlet.htmlreport import to_html
from mcp_gauntlet.models import ServerInfo
from mcp_gauntlet.report import (
    GRADE_CAP_ON_CRITICAL,
    AgenticDetail,
    DimensionResult,
    Finding,
    GauntletReport,
    Severity,
    TaskResult,
    grade_for,
    score_from_findings,
    to_markdown,
)


def _dim(
    key: str, score: float, weight: float = 1.0, findings: list[Finding] | None = None
) -> DimensionResult:
    return DimensionResult(
        key=key, title=key.title(), weight=weight, score=score, findings=findings or []
    )


def _build(
    dims: list[DimensionResult], tool_count: int = 1, agentic: AgenticDetail | None = None
) -> GauntletReport:
    return GauntletReport.build(
        spec="stdio: x",
        server=ServerInfo(name="srv", version="1"),
        tool_count=tool_count,
        dimensions=dims,
        agentic=agentic,
    )


def test_overall_is_the_weighted_mean() -> None:
    report = _build([_dim("a", 100.0, weight=1.0), _dim("b", 60.0, weight=3.0)])
    assert report.overall_score == 70.0  # (100*1 + 60*3) / 4
    assert report.grade == "C"


def test_high_security_finding_caps_the_grade() -> None:
    security = _dim(
        "security", 40.0, weight=2.0, findings=[Finding(severity=Severity.HIGH, message="poisoned")]
    )
    report = _build([_dim("a", 100.0), security])
    assert report.security_critical is True
    assert report.overall_score <= GRADE_CAP_ON_CRITICAL


def test_response_safety_high_does_not_cap() -> None:
    # Passthrough content a server merely relayed is not evidence the server is malicious,
    # so the runtime dimension lowers the score but must never trip the critical flag.
    runtime = _dim(
        "response_safety",
        40.0,
        findings=[Finding(severity=Severity.HIGH, message="output attempts to override")],
    )
    report = _build([_dim("a", 100.0), runtime])
    assert report.security_critical is False


def test_zero_tool_server_is_na_but_keeps_its_security_findings() -> None:
    # A tool-less server can still ship poisoned `instructions`. The N/A branch used to
    # REPLACE the dimensions with a "no tools" note, silently discarding that finding and
    # resetting security_critical to False.
    security = _dim(
        "security",
        63.0,
        weight=2.0,
        findings=[Finding(severity=Severity.HIGH, message="instructions attempt an override")],
    )
    report = _build([security], tool_count=0)
    assert report.grade == "N/A"  # still unscored...
    assert report.security_critical is True  # ...but not unexamined
    messages = [f.message for f in report.findings]
    assert "instructions attempt an override" in messages
    assert "server exposes no tools" in messages  # the explanatory note is kept too


def test_zero_tool_server_without_security_findings_stays_clean() -> None:
    report = _build([_dim("security", 100.0, weight=2.0)], tool_count=0)
    assert report.grade == "N/A"
    assert report.security_critical is False


def test_agentically_scored_tracks_the_task_success_dimension() -> None:
    # This is what keeps the leaderboard from co-ranking non-comparable overalls: a report
    # without task_success was averaged over a smaller denominator.
    detail = AgenticDetail(provider="p", model="m", tasks_generated=3, repeats=2)
    assert _build([_dim("a", 100.0)]).agentically_scored is False
    assert _build([_dim("a", 100.0)], agentic=detail).agentically_scored is False  # ran, no score
    assert _build([_dim("a", 100.0), _dim("task_success", 70.0, 3.0)]).agentically_scored is True


def test_missing_agentic_dimensions_inflate_the_overall() -> None:
    # The mechanism behind the inversion, pinned so a future weighting change can't hide it.
    static_only = _build([_dim("a", 100.0)])
    tested = _build([_dim("a", 100.0), _dim("task_success", 70.0, 3.0)])
    assert static_only.overall_score > tested.overall_score


def test_na_report_does_not_claim_a_cap_that_never_happened() -> None:
    # The N/A branch keeps its security findings (so security_critical is True) but the
    # grade was never scored, let alone capped — all three renderers must say so.
    security = _dim(
        "security",
        63.0,
        weight=2.0,
        findings=[Finding(severity=Severity.HIGH, message="instructions attempt an override")],
    )
    na = _build([security], tool_count=0)
    capped = _build([security, _dim("a", 100.0)])
    assert na.security_critical and capped.security_critical

    assert "never scored" in to_markdown(na)
    assert "grade is capped" not in to_markdown(na)
    assert "grade is capped" in to_markdown(capped)  # the real cap still says so

    assert "never scored" in to_html(na)
    assert "grade capped" not in to_html(na)
    assert "grade capped" in to_html(capped)


def test_unrunnable_agent_eval_explains_itself_in_html() -> None:
    # When every tool is excluded as possibly-mutating the grade card still advertises an
    # agent model, so the page must explain why no agent results follow.
    detail = AgenticDetail(
        provider="p",
        model="m",
        tasks_generated=0,
        repeats=2,
        excluded_write_tools=["write_file"],
    )
    html = to_html(_build([_dim("a", 100.0)], agentic=detail))
    assert "Agent evaluation" in html
    assert "every tool was excluded as possibly-mutating" in html
    assert "write_file" in html


def test_grade_boundaries() -> None:
    assert [grade_for(s) for s in (90.0, 80.0, 70.0, 60.0, 59.9)] == ["A", "B", "C", "D", "F"]


def test_score_from_findings_floors_at_zero() -> None:
    assert score_from_findings([]) == 100.0
    assert score_from_findings([Finding(severity=Severity.INFO, message="fyi")]) == 100.0
    assert score_from_findings([Finding(severity=Severity.HIGH, message="x")] * 20) == 0.0


# --- Batch B: report-level credential redaction ------------------------------------


def test_redact_report_scrubs_every_string_field_and_keeps_scores() -> None:
    from mcp_gauntlet.report import redact_report

    secret = 'tok"en-with-quote'  # a quote is exactly what the string-scrub approach missed
    security = _dim(
        "security",
        40.0,
        weight=2.0,
        findings=[
            Finding(
                severity=Severity.HIGH,
                tool=f"whoami-{secret}",
                message=f"echoed {secret}",
                detail=f"in output: {secret}",
            )
        ],
    )
    detail = AgenticDetail(provider="p", model="m", tasks_generated=1, repeats=1)
    detail.results.append(
        TaskResult(
            description=f"call whoami expecting {secret}",
            rubric="r",
            expected_tools=[],
            repeats=1,
            successes=0,
            success_rate=0.0,
            mean_score=0.0,
            sample_reasoning=f"got {secret}",
        )
    )
    report = _build([security, _dim("a", 100.0)], agentic=detail)
    before_score, before_grade = report.overall_score, report.grade

    scrubbed = redact_report(report, frozenset({secret}))

    dumped = scrubbed.model_dump_json()
    assert secret not in dumped  # gone from every nested field, before serialization
    f = scrubbed.dimensions[0].findings[0]
    assert secret not in (f.tool or "")
    assert secret not in f.message and secret not in (f.detail or "")
    assert scrubbed.agentic is not None
    assert secret not in scrubbed.agentic.results[0].description
    assert secret not in scrubbed.agentic.results[0].sample_reasoning
    # Redacting text must never move a score or grade.
    assert scrubbed.overall_score == before_score
    assert scrubbed.grade == before_grade
    assert scrubbed.security_critical is True


def test_redact_report_is_a_noop_without_secrets() -> None:
    from mcp_gauntlet.report import redact_report

    report = _build([_dim("a", 100.0)])
    assert redact_report(report, frozenset()) is report


def test_redact_report_does_not_corrupt_a_severity_valued_secret() -> None:
    # A credential that happens to equal a Severity value ("high"/"medium"/"info") must not
    # turn the structural severity field into the placeholder — that would make the rebuilt
    # report fail validation and crash the write, losing a paid run.
    from mcp_gauntlet.report import redact_report

    for word in ("high", "medium", "info"):
        report = _build(
            [_dim("security", 40.0, findings=[Finding(severity=Severity.HIGH, message="x")])]
        )
        scrubbed = redact_report(report, frozenset({word}))  # must not raise ValidationError
        assert scrubbed.dimensions[0].findings[0].severity is Severity.HIGH


# --- R10: report.md must not render untrusted text as Markdown/HTML structure ------


def test_md_sanitizer_units() -> None:
    from mcp_gauntlet.report import _md, _md_code

    assert _md("a|b") == "a\\|b"
    # Escape the backslash FIRST: an attacker-supplied "\|" must not become "\\|"
    # (escaped backslash + LIVE pipe) — that's a table-cell breakout.
    assert _md("a\\|b") == "a\\\\\\|b"
    assert _md("x`y") == "x\\`y"
    assert _md("<img onerror=x>") == "&lt;img onerror=x>"
    assert _md("line1\nline2\r\n#  heading") == "line1 line2 # heading"
    # Inline link/image syntax must not survive: escaping the opening bracket disarms
    # both [text](url) and ![alt](url) (a phishing link / auto-loading tracking pixel).
    assert _md("[trusted](https://evil)") == "\\[trusted](https://evil)"
    assert _md("![x](https://evil/p.png)") == "!\\[x](https://evil/p.png)"
    assert _md_code("spec `with` ticks\nand newline") == "spec 'with' ticks and newline"


def test_markdown_report_neutralizes_hostile_server_text() -> None:
    hostile_tool = "get`</code>|rows\n<script>alert(1)</script>"
    hostile_detail = (
        "pwned | cell\n\n# fake heading\n[phish](https://evil) ![x](https://evil/p.png)"
    )
    dim = _dim(
        "security",
        50.0,
        findings=[
            Finding(severity=Severity.HIGH, message="bad", tool=hostile_tool, detail=hostile_detail)
        ],
    )
    detail = AgenticDetail(provider="p", model="m", tasks_generated=1, repeats=1)
    detail.results.append(
        TaskResult(
            description="do the thing | with pipes\nand `ticks` <b>bold</b>",
            rubric="r",
            expected_tools=[],
            repeats=1,
            successes=1,
            success_rate=1.0,
            mean_score=100.0,
        )
    )
    md = to_markdown(_build([dim], agentic=detail))
    assert "<img" not in md  # plain-text fields get `<` neutralized outright
    assert "\n# fake heading" not in md  # can't open a new block
    # The link/image brackets are escaped, so GitHub renders them as literal text, not
    # a clickable link / auto-loading pixel. No UNescaped opening bracket survives.
    assert "\\[phish](https://evil)" in md
    assert "!\\[x](https://evil/p.png)" in md
    for line in md.splitlines():
        for idx, ch in enumerate(line):
            if ch == "[" and not (idx and line[idx - 1] == "\\"):
                assert line.lstrip().startswith("- **[") and "HIGH" in line, line
    # The hostile tool name ends up in ONE intact inline code span: its own backticks
    # were stripped so it can't terminate the span, and inside a span `<script>` is
    # literal text, never HTML. Outside the span, no raw `<` may survive.
    finding_line = next(line for line in md.splitlines() if "**[HIGH]**" in line)
    assert "alert(1)" in finding_line  # payload text is present but inert, on one line
    assert finding_line.count("`") == 2
    before, _inside, after = finding_line.split("`")
    assert "<" not in before and "<" not in after
    task_row = next(line for line in md.splitlines() if "do the thing" in line)
    assert task_row.count("|") == 6  # 5 structural delimiters + the one escaped \| in the label
    assert "\\|" in task_row
