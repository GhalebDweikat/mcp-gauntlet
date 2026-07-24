"""Leaderboard rendering: only mutually comparable scores share a ranked table."""

from pathlib import Path

import pytest

from mcp_gauntlet.checks import run_static_checks
from mcp_gauntlet.leaderboard import (
    LeaderboardResult,
    ServerListError,
    _result_payload,
    _unique_slug,
    load_results,
    load_servers,
    render_index,
    rerender,
)
from mcp_gauntlet.models import DiscoveryResult, ServerInfo, ToolInfo
from mcp_gauntlet.report import (
    AgenticDetail,
    DimensionResult,
    Finding,
    GauntletReport,
    Severity,
)


def _report(name: str, tools: list[ToolInfo]) -> GauntletReport:
    discovery = DiscoveryResult(server=ServerInfo(name=name), tools=tools)
    return GauntletReport.build(
        spec=name,
        server=discovery.server,
        tool_count=len(tools),
        dimensions=run_static_checks(discovery),
    )


def _scored(
    name: str, dims: list[DimensionResult], agentic: AgenticDetail | None = None
) -> LeaderboardResult:
    report = GauntletReport.build(
        spec=name, server=ServerInfo(name=name), tool_count=1, dimensions=dims, agentic=agentic
    )
    return LeaderboardResult(name=name, spec=name, report=report, page=f"{name}.html")


def _dim(key: str, score: float, weight: float = 1.0) -> DimensionResult:
    return DimensionResult(key=key, title=key.title(), weight=weight, score=score)


def test_saved_results_round_trip_and_rerender(tmp_path: Path) -> None:
    # Running the board costs real LLM spend, so raw results are persisted next to the
    # rendered pages: changing how results are PRESENTED must never require paying to
    # measure them again.
    servers_dir = tmp_path / "servers"
    servers_dir.mkdir(parents=True)
    scored = _scored("alpha", [_dim("schema", 90.0), _dim("task_success", 80.0, 3.0)])
    failed = LeaderboardResult(name="omega", spec="o", error="connection refused")
    (servers_dir / "alpha.json").write_text(_result_payload(scored), encoding="utf-8")
    (servers_dir / "omega.json").write_text(_result_payload(failed), encoding="utf-8")

    loaded = {r.name: r for r in load_results(tmp_path)}
    assert loaded["alpha"].report is not None
    assert loaded["alpha"].report.overall_score == scored.report.overall_score  # type: ignore[union-attr]
    assert loaded["omega"].report is None and loaded["omega"].error == "connection refused"

    rerender(tmp_path)
    index = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "alpha" in index and "connection refused" in index
    assert (tmp_path / "servers" / "alpha.html").exists()  # per-server page rebuilt too


def test_load_results_surfaces_corrupt_files_instead_of_dropping_them(tmp_path: Path) -> None:
    # A half-written file must not make a server silently vanish from a rebuilt board.
    servers_dir = tmp_path / "servers"
    servers_dir.mkdir(parents=True)
    (servers_dir / "bad.json").write_text("{not json", encoding="utf-8")
    (servers_dir / "array.json").write_text("[1,2,3]", encoding="utf-8")
    (servers_dir / "ok.json").write_text(
        _result_payload(_scored("alpha", [_dim("schema", 90.0)])), encoding="utf-8"
    )
    by_name = {r.name: r for r in load_results(tmp_path)}
    assert by_name["alpha"].report is not None
    for broken in ("bad", "array"):
        assert by_name[broken].report is None
        assert "could not be read" in (by_name[broken].error or "")
    assert "could not be read" in render_index(list(by_name.values()))


def test_load_servers_accepts_utf16(tmp_path: Path) -> None:
    # PowerShell 5.1's plain `>` redirect writes UTF-16LE — more common than the BOM case.
    path = tmp_path / "servers.json"
    path.write_bytes('{"servers":[{"name":"a","spec":"python -m x"}]}'.encode("utf-16"))
    assert [e.name for e in load_servers(path)] == ["a"]


def test_load_servers_accepts_a_utf8_bom(tmp_path: Path) -> None:
    # PowerShell's `Out-File -Encoding utf8` writes a BOM, so the most natural way for a
    # Windows user to author this file used to crash with a raw JSONDecodeError traceback.
    path = tmp_path / "servers.json"
    path.write_text('{"servers":[{"name":"a","spec":"python -m x"}]}', encoding="utf-8-sig")
    assert [e.name for e in load_servers(path)] == ["a"]


def test_load_servers_reports_bad_input_clearly(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ServerListError):
        load_servers(bad)

    wrong_shape = tmp_path / "wrong.json"
    wrong_shape.write_text('["a","b"]', encoding="utf-8")
    with pytest.raises(ServerListError):
        load_servers(wrong_shape)

    missing_key = tmp_path / "missing.json"
    missing_key.write_text('{"servers":[{"name":"a"}]}', encoding="utf-8")
    with pytest.raises(ServerListError):
        load_servers(missing_key)


def test_unique_slug_dedupes_collisions() -> None:
    used: set[str] = set()
    assert _unique_slug("My Server", used) == "my-server"
    assert _unique_slug("my  server", used) == "my-server-2"  # slugs the same -> suffixed
    assert _unique_slug("MY SERVER!", used) == "my-server-3"


def test_na_server_listed_unranked_not_in_score_table() -> None:
    na = _report("empty", [])
    good = _report(
        "good",
        [ToolInfo(name="add", description="Add two integers and return the sum.", input_schema={})],
    )
    results = [
        LeaderboardResult(name="empty", spec="e", report=na, page="servers/empty.html"),
        LeaderboardResult(name="good", spec="g", report=good, page="servers/good.html"),
    ]
    html = render_index(results)
    assert "exposes no tools" in html  # N/A gets the unranked treatment
    assert html.index("good") < html.index("empty")  # graded server ranked above the N/A one


def test_runtime_poisoning_shows_bolt_glyph() -> None:
    # A server flagged only by the runtime Response Safety scan (not the static cap) must
    # surface a distinct glyph, not a silent checkmark.
    rep = _report(
        "leaky",
        [ToolInfo(name="fetch", description="Fetches a record.", input_schema={})],
    )
    rep.dimensions.append(
        DimensionResult(
            key="response_safety",
            title="Response Safety",
            weight=1.0,
            score=40.0,
            findings=[Finding(severity=Severity.HIGH, message="tool output attempts to override")],
        )
    )
    assert rep.security_critical is False  # runtime finding didn't cap
    html = render_index([LeaderboardResult(name="leaky", spec="l", report=rep, page="p.html")])
    # Assert on the table CELL, not a bare "⚡ in html" — the footer legend always mentions
    # both glyphs, so the loose check passed even when no row was ever flagged.
    assert '<td class="ctr">⚡</td>' in html


def test_untested_server_cannot_outrank_a_tested_one() -> None:
    # VERIFIED inversion: the overall is a weighted mean over the dimensions PRESENT, so a
    # server the agent never scored skips Agent Task Success (weight 3), averages higher,
    # and used to outrank a genuinely tested server in the same table.
    static_only = _scored("alpha", [_dim("schema", 100.0)])
    tested = _scored(
        "omega",
        [_dim("schema", 100.0), _dim("task_success", 70.0, 3.0)],
        agentic=AgenticDetail(provider="p", model="m", tasks_generated=3, repeats=2),
    )
    assert static_only.report is not None and tested.report is not None
    assert static_only.report.overall_score > tested.report.overall_score  # inversion is real

    html = render_index([static_only, tested])
    assert "Partially evaluated" in html
    # The tested server heads the ranked table; the unscored one sits below the split.
    assert html.index("omega") < html.index("Partially evaluated") < html.index("alpha")
    assert "static checks only" in html  # and it says WHY it isn't ranked


def test_inconclusive_server_is_segregated_too() -> None:
    # An LLM rate-limit drops the agentic dimensions just the same, so the survivor's
    # inflated score must not be co-ranked either.
    detail = AgenticDetail(provider="p", model="m", tasks_generated=3, repeats=2, inconclusive=True)
    inconclusive = _scored("alpha", [_dim("schema", 100.0)], agentic=detail)
    tested = _scored("omega", [_dim("schema", 100.0), _dim("task_success", 70.0, 3.0)])
    html = render_index([inconclusive, tested])
    assert "Partially evaluated" in html
    assert "inconclusive" in html
    assert html.index("omega") < html.index("Partially evaluated") < html.index("alpha")


def test_all_tools_excluded_says_so_instead_of_static_only() -> None:
    # The real shape behind two servers topping the published board: an LLM WAS configured,
    # but the read-only filter excluded every tool, so the agent never ran. The board must
    # say that rather than imply no LLM was available.
    detail = AgenticDetail(
        provider="p",
        model="m",
        tasks_generated=0,
        repeats=2,
        excluded_write_tools=["write_file", "delete_file"],
    )
    unrunnable = _scored("alpha", [_dim("schema", 100.0)], agentic=detail)
    tested = _scored("omega", [_dim("schema", 100.0), _dim("task_success", 70.0, 3.0)])
    html = render_index([unrunnable, tested])
    assert "no read-only tools to test" in html
    assert html.index("Partially evaluated") < html.index("alpha")


def test_truncated_eval_is_not_co_ranked() -> None:
    # A hang stops the evaluation early, so the score covers only the tasks that ran before
    # it — a sample size the SERVER controls. Left in the ranked table, a server that hangs
    # after one good task outranks one that was measured on all three.
    from mcp_gauntlet.report import TaskResult

    truncated = _scored(
        "alpha",
        [_dim("schema", 100.0), _dim("task_success", 90.0, 3.0)],
        agentic=AgenticDetail(
            provider="p",
            model="m",
            tasks_generated=3,
            repeats=2,
            truncated=True,
            results=[TaskResult(description="one", mean_score=90.0)],  # 1 of 3 ran
        ),
    )
    full = _scored(
        "omega",
        [_dim("schema", 100.0), _dim("task_success", 70.0, 3.0)],
        agentic=AgenticDetail(
            provider="p",
            model="m",
            tasks_generated=2,
            repeats=2,
            results=[TaskResult(description="a"), TaskResult(description="b")],
        ),
    )
    assert truncated.report is not None and full.report is not None
    assert truncated.report.agent_eval_truncated is True
    assert full.report.agent_eval_truncated is False
    assert truncated.report.overall_score > full.report.overall_score  # would have won

    html = render_index([truncated, full])
    assert "stopped early" in html and "1 of 3 tasks ran" in html
    assert html.index("omega") < html.index("Partially evaluated") < html.index("alpha")


def test_repeat_truncation_is_segregated_without_a_bogus_task_count() -> None:
    # A hang on the LAST task truncates repeats, not tasks, so results is full-length. It
    # must still be segregated, and must not claim "3 of 3 tasks ran" as if that explained
    # anything.
    from mcp_gauntlet.report import TaskResult

    results = [TaskResult(description=d) for d in ("a", "b", "c")]
    truncated = _scored(
        "alpha",
        [_dim("schema", 100.0), _dim("task_success", 90.0, 3.0)],
        agentic=AgenticDetail(
            provider="p",
            model="m",
            tasks_generated=3,
            repeats=2,
            truncated=True,
            results=results,
        ),
    )
    full = _scored(
        "omega",
        [_dim("schema", 100.0), _dim("task_success", 95.0, 3.0)],
        agentic=AgenticDetail(
            provider="p", model="m", tasks_generated=3, repeats=2, results=results
        ),
    )
    html = render_index([truncated, full])
    assert "Partially evaluated" in html
    assert "fewer samples than planned" in html
    assert "3 of 3 tasks ran" not in html
    assert html.index("omega") < html.index("Partially evaluated") < html.index("alpha")


def test_all_static_only_servers_are_ranked_together() -> None:
    # A keyless run measures every server the same way, so they ARE mutually comparable —
    # segregating all of them would leave an empty board and no ranking at all.
    high = _scored("alpha", [_dim("schema", 90.0)])
    low = _scored("omega", [_dim("schema", 80.0)])
    html = render_index([low, high])
    assert "Partially evaluated" not in html
    assert html.index("alpha") < html.index("omega")  # ranked by score, together


def test_all_static_board_does_not_claim_an_agent_ran() -> None:
    # Ranking them together must not also republish the standard lead, which promises "a
    # live LLM agent attempts generated tasks" — on this board that is true of no row.
    html = render_index([_scored("alpha", [_dim("schema", 90.0)])])
    assert "STATIC checks only" in html
    assert "a live LLM agent attempts" not in html


def test_partials_are_not_ordered_by_score() -> None:
    # Partials carry different denominators from EACH OTHER too, so ordering them by score
    # would re-imply the comparison this section exists to deny.
    low = _scored("alpha", [_dim("schema", 10.0)])
    high = _scored("omega", [_dim("schema", 99.0)])
    tested = _scored("zeta", [_dim("schema", 100.0), _dim("task_success", 70.0, 3.0)])
    html = render_index([high, low, tested])
    assert html.index("alpha") < html.index("omega")  # alphabetical, not 99 before 10


def test_zero_tool_server_surfaces_its_security_finding() -> None:
    # R5 end-to-end: the finding survives GauntletReport.build's N/A branch AND is visible
    # on the board, rather than the server reading as a harmless empty one.
    security = DimensionResult(
        key="security",
        title="Security",
        weight=2.0,
        score=63.0,
        findings=[Finding(severity=Severity.HIGH, message="instructions attempt an override")],
    )
    report = GauntletReport.build(
        spec="e", server=ServerInfo(name="empty"), tool_count=0, dimensions=[security]
    )
    html = render_index([LeaderboardResult(name="empty", spec="e", report=report, page="p.html")])
    assert "exposes no tools" in html
    assert "critical security finding in its instructions" in html
