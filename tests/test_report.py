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
    Dim,
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
    assert "capped" not in to_markdown(na)
    assert "grade capped at 75" in to_markdown(capped)  # a real cap still says so

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


def test_lone_surrogate_from_a_server_cannot_discard_the_report() -> None:
    """A finished evaluation must survive any string the server chose to send.

    A lone surrogate parses fine as JSON and is a legal `str`, but is not encodable as
    UTF-8: one anywhere in the report made `model_dump_json` raise, so a completed — and
    on a paid provider, already-billed — run was thrown away by a single character. Same
    class as the Markdown-injection fix, on the serialization path instead of rendering.
    """
    hostile = "before " + chr(0xD800) + " after"
    report = GauntletReport.build(
        spec="stdio: x",
        server=ServerInfo(name=hostile, version="1"),
        tool_count=1,
        dimensions=[
            _dim(
                "security",
                50.0,
                findings=[Finding(tool=hostile, severity=Severity.HIGH, message=hostile)],
            )
        ],
    )

    # Escaped, not silently dropped: a reviewer still sees what the server sent.
    assert report.server.name == r"before \ud800 after"

    # All three writers, since each has its own encoder.
    report.model_dump_json().encode("utf-8")
    to_markdown(report).encode("utf-8")
    to_html(report).encode("utf-8")

    # Scoring is untouched by the escaping: still a HIGH security finding, still capped.
    assert report.security_critical
    assert report.overall_score <= GRADE_CAP_ON_CRITICAL


def test_clean_reports_are_returned_unchanged_by_the_encodability_pass() -> None:
    # The surrogate scan runs on every build; it must not rewrite ordinary text (including
    # legitimate non-BMP characters like emoji, which are perfectly encodable).
    name = "server \U0001f600 café —"
    report = GauntletReport.build(
        spec="stdio: x",
        server=ServerInfo(name=name, version="1"),
        tool_count=1,
        dimensions=[_dim("security", 100.0)],
    )
    assert report.server.name == name


def test_dimension_keys_used_across_modules_are_the_enum_values() -> None:
    """The cross-module lookups are keyed on `Dim`, so the values must not drift.

    `security` caps the grade, `task_success` decides rankability, `response_safety` earns
    the board's bolt. Each is produced in one module and read in another; pinning the wire
    values here means renaming one is a visible, deliberate change rather than a lookup
    that silently stops matching.
    """
    assert Dim.SECURITY == "security"
    assert Dim.TASK_SUCCESS == "task_success"
    assert Dim.RESPONSE_SAFETY == "response_safety"

    capped = GauntletReport.build(
        spec="s",
        server=ServerInfo(name="n", version="1"),
        tool_count=1,
        dimensions=[
            _dim(Dim.SECURITY, 50.0, findings=[Finding(severity=Severity.HIGH, message="x")])
        ],
    )
    assert capped.security_critical

    # response_safety carries the same HIGH but is passthrough content, so it never caps.
    relayed = GauntletReport.build(
        spec="s",
        server=ServerInfo(name="n", version="1"),
        tool_count=1,
        dimensions=[
            _dim(Dim.RESPONSE_SAFETY, 50.0, findings=[Finding(severity=Severity.HIGH, message="x")])
        ],
    )
    assert not relayed.security_critical


def test_a_report_records_which_sdk_measured_it() -> None:
    """The version stamp alone was not enough to make a score reproducible.

    METHODOLOGY rests comparability on `gauntlet_version`, and tells readers to reproduce a
    score with `uvx mcp-gauntlet@<version>`. But a 2.0-era SDK reads different field names
    off an identical server, so two runs of the same gauntlet version can legitimately
    disagree — and nothing on the report said which era it was. Measured: a 2.0-built server
    negotiates down to 2025-11-25, so both eras really do see the same servers.
    """
    report = GauntletReport.build(
        spec="s",
        server=ServerInfo(name="n", version="1"),
        tool_count=1,
        dimensions=[_dim("security", 100.0, weight=2.0)],
    )
    assert report.mcp_sdk_version, "no SDK recorded — the score cannot be attributed"
    assert report.mcp_sdk_version[0].isdigit()

    # And it reaches the human-readable report, not just the JSON.
    assert "mcp SDK" in to_markdown(report)


def test_a_report_written_before_the_field_existed_still_loads() -> None:
    # Every saved leaderboard row predates this field. Defaulted, so a rebuild of an old
    # board must not need a migration — the whole point of --render-only being free.
    old = {
        "spec": "s",
        "server": {"name": "n", "version": "1"},
        "tool_count": 1,
        "dimensions": [],
        "overall_score": 90.0,
        "grade": "A",
        "generated_at": "2026-07-01T00:00:00+00:00",
        "gauntlet_version": "0.4.0",
    }
    loaded = GauntletReport.model_validate(old)
    assert loaded.mcp_sdk_version == ""
    assert loaded.grade == "A"


def test_a_truncated_credential_is_still_redacted() -> None:
    """Redaction ran on the finished report; excerpts were TRUNCATED before that.

    When the truncation window cut across a credential the full value no longer appeared,
    the exact-match replace found nothing, and a long run of a live token was published into
    report.json / report.md / report.html — 28 of 40 characters in the reproduction, from a
    server that merely echoed its own token back in its `instructions`. The shipped CI
    workflow uploads that directory as a build artifact with `if: always()`, and the README
    promised "credential values are scrubbed from every report".

    It worked in every test written for it, because those tests used short strings where the
    whole value survived. It failed on whichever token happened to straddle the boundary.
    """
    from mcp_gauntlet.report import redact

    token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    secrets = frozenset({token})
    sentence = f"This server is configured with credential {token} for upstream access"

    # Every way an excerpt can be cut, including from the MIDDLE — the first version of this
    # fix walked prefixes and suffixes only, on the reasoning that truncation cuts one end,
    # and still leaked 35 characters of the both-ends case.
    for cut in (
        sentence,
        sentence[:70],
        sentence[20:],
        sentence[30:70],
        sentence[45:80],
        sentence[50:65],
    ):
        scrubbed = redact(cut, secrets)
        longest = max(
            (
                size
                for size in range(len(token), 3, -1)
                if any(token[i : i + size] in scrubbed for i in range(len(token) - size + 1))
            ),
            default=0,
        )
        assert longest == 0, f"{longest} characters of a live token survived: {scrubbed!r}"


def test_redaction_does_not_eat_ordinary_prose() -> None:
    """The threshold is what keeps this honest. At eight characters it turned "the password
    field is required" into "the ***REDACTED*** field is required" for a secret of
    `password123456` — a word that merely opens the token."""
    from mcp_gauntlet.report import redact

    assert (
        redact("the password field is required", frozenset({"password123456"}))
        == "the password field is required"
    )
