"""Leaderboard rendering: only mutually comparable scores share a ranked table."""

import sys
from pathlib import Path

import anyio
import pytest

from mcp_gauntlet.checks import run_static_checks
from mcp_gauntlet.leaderboard import (
    LeaderboardResult,
    ServerEntry,
    ServerListError,
    _partial_reason,
    _result_payload,
    assign_slugs,
    badge_markdown,
    badge_payload,
    load_results,
    load_servers,
    render_index,
    rerender,
    run_leaderboard,
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


def test_slugs_are_clean_when_names_do_not_collide() -> None:
    assert assign_slugs(["My Server", "Other"]) == ["my-server", "other"]


def test_colliding_slugs_do_not_depend_on_list_order() -> None:
    # A badge URL is a public contract pasted into someone else's README, so a slug must
    # depend only on the name it belongs to. Handing the bare slug to whichever name came
    # first would leave THAT url rebinding to a different server on a reorder.
    forward = assign_slugs(["My Server", "my  server"])
    reverse = assign_slugs(["my  server", "My Server"])
    assert forward == list(reversed(reverse))  # each name kept its own slug
    assert "my-server" not in forward  # nobody gets the ambiguous bare slug
    assert all(s.startswith("my-server-") for s in forward)
    assert len(set(forward)) == 2


def test_identical_names_still_get_distinct_slugs() -> None:
    slugs = assign_slugs(["Dup", "Dup"])
    assert len(set(slugs)) == 2  # indistinguishable inputs, but files must not overwrite


def test_a_suffixed_slug_never_collides_with_another_name() -> None:
    # Deduping only WITHIN a colliding group lets a suffixed slug land on some other
    # server's bare slug. Two servers would then share one saved-result file and one badge
    # endpoint: the second overwrites the first, silently discarding a paid evaluation.
    for names in (
        ["My Server", "my  server", "my-server-c2d9a8"],
        ["dup", "dup", "dup 9eb620"],
    ):
        slugs = assign_slugs(names)
        assert len(set(slugs)) == len(names), (names, slugs)


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


# --- Batch C: badges, scan dates, and methodology version --------------------------


def test_badge_payload_is_a_valid_shields_endpoint() -> None:
    import json as _json

    result = _scored("alpha", [_dim("schema", 95.0), _dim("task_success", 92.0, 3.0)])
    assert result.report is not None
    payload = _json.loads(badge_payload(result.report))
    assert payload["schemaVersion"] == 1
    assert payload["label"] == "mcp-gauntlet"
    assert payload["message"].startswith("A (")
    assert payload["color"] == "brightgreen"


def test_badge_says_when_a_grade_was_security_capped() -> None:
    # A bare "C" would read as mediocre-but-fine; the cap is the headline finding.
    import json as _json

    security = DimensionResult(
        key="security",
        title="Security",
        weight=2.0,
        score=40.0,
        findings=[Finding(severity=Severity.HIGH, message="poisoned")],
    )
    report = GauntletReport.build(
        spec="x",
        server=ServerInfo(name="bad"),
        tool_count=1,
        dimensions=[security, _dim("task_success", 100.0, 3.0)],
    )
    payload = _json.loads(badge_payload(report))
    assert "critical security finding" in payload["message"]
    assert payload["color"] == "red"


def test_badge_keeps_the_security_warning_on_an_unscored_server() -> None:
    # A zero-tool server can still ship poisoned `instructions`. The board shows a ⚠ for it;
    # checking N/A before security_critical would replace that with a neutral grey badge on
    # the surface that lands in the author's README.
    import json as _json

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
    assert report.grade == "N/A" and report.security_critical
    payload = _json.loads(badge_payload(report))
    assert "critical security finding" in payload["message"]
    assert payload["color"] == "red"


def test_badge_score_never_contradicts_its_grade_at_a_boundary() -> None:
    # Rounding to whole points made an 89.5 (a B) print "B (90)" — indistinguishable from a
    # genuine A(90), and disagreeing with the board row, which shows one decimal.
    import json as _json

    report = GauntletReport.build(
        spec="x",
        server=ServerInfo(name="edge"),
        tool_count=1,
        dimensions=[_dim("a", 89.5)],
    )
    assert report.grade == "B"
    assert _json.loads(badge_payload(report))["message"] == "B (89.5)"


def test_badge_for_an_unscored_server_does_not_imply_a_grade() -> None:
    import json as _json

    report = GauntletReport.build(
        spec="e", server=ServerInfo(name="empty"), tool_count=0, dimensions=[_dim("s", 100.0)]
    )
    payload = _json.loads(badge_payload(report))
    assert payload["message"] == "not scored"
    assert payload["color"] == "lightgrey"


def test_badge_markdown_points_at_the_endpoint_json() -> None:
    snippet = badge_markdown("my-server", "https://example.github.io/mcp-gauntlet/")
    assert "img.shields.io/endpoint?url=" in snippet
    assert "https://example.github.io/mcp-gauntlet/badges/my-server.json" in snippet
    assert snippet.startswith("[![mcp-gauntlet]")  # a linked image, not a bare image


def test_board_shows_each_row_scan_date_not_the_render_date() -> None:
    # A re-render re-stamps the page timestamp; the rows must keep the date their score was
    # actually measured, or stale scores silently read as fresh.
    result = _scored("alpha", [_dim("schema", 90.0), _dim("task_success", 80.0, 3.0)])
    assert result.report is not None
    result.report.generated_at = "2020-01-02T03:04:05+00:00"
    html = render_index([result])
    assert "2020-01-02" in html
    assert "Scanned" in html


def test_board_reports_the_versions_that_produced_the_scores() -> None:
    a = _scored("alpha", [_dim("schema", 90.0), _dim("task_success", 80.0, 3.0)])
    b = _scored("beta", [_dim("schema", 70.0), _dim("task_success", 60.0, 3.0)])
    assert a.report is not None and b.report is not None
    a.report.gauntlet_version = "0.3.1"
    b.report.gauntlet_version = "0.3.2"
    html = render_index([a, b])
    # A board rebuilt across an upgrade legitimately mixes versions; say so rather than
    # implying every score came from one methodology.
    assert "0.3.1" in html and "0.3.2" in html
    assert "compare scores only within the same version" in html


def test_board_discloses_rows_with_no_recorded_version() -> None:
    # The realistic mixed board: one row re-scanned by the current release, the rest saved
    # before the version was stamped. Dropping the unknowns would let the page claim a
    # single methodology it does not have.
    fresh = _scored("alpha", [_dim("schema", 90.0), _dim("task_success", 80.0, 3.0)])
    old = _scored("beta", [_dim("schema", 70.0), _dim("task_success", 60.0, 3.0)])
    assert fresh.report is not None and old.report is not None
    fresh.report.gauntlet_version = "0.3.2"
    old.report.gauntlet_version = ""
    html = render_index([fresh, old])
    assert "0.3.2" in html
    assert "unrecorded" in html


def test_badge_section_uses_a_placeholder_without_a_board_url() -> None:
    # Defaulting to any real board would hand every other operator a snippet pointing at
    # THAT board — and since slugs are generic server names, it would resolve and quietly
    # advertise a different server's grade instead of 404ing.
    result = _scored("alpha", [_dim("schema", 90.0), _dim("task_success", 80.0, 3.0)])
    html = render_index([result])
    assert "your-board.example" in html
    assert "ghalebdweikat" not in html
    assert "--board-url" in html

    published = render_index([result], "https://example.github.io/board")
    assert "https://example.github.io/board/badges/" in published
    assert "your-board.example" not in published


def test_badge_instructions_describe_the_slug_correctly() -> None:
    # The row link is servers/<slug>.html, so "the last path segment" would send an author
    # to badges/<slug>.html.json — a 404, on the flywheel's primary call to action.
    html = render_index([_scored("alpha", [_dim("schema", 90.0), _dim("task_success", 80.0, 3.0)])])
    assert "without the <code>.html</code>" in html


def test_rerender_retires_badges_for_servers_the_board_no_longer_lists(tmp_path: Path) -> None:
    # A badge claims to reflect "this board's published score"; one for a server that was
    # renamed or dropped is a standing lie living in someone else's README.
    servers_dir = tmp_path / "servers"
    servers_dir.mkdir(parents=True)
    scored = _scored("alpha", [_dim("schema", 90.0), _dim("task_success", 80.0, 3.0)])
    (servers_dir / "alpha.json").write_text(_result_payload(scored), encoding="utf-8")
    rerender(tmp_path)
    assert (tmp_path / "badges" / "alpha.json").exists()

    # The server is dropped from the board entirely.
    (servers_dir / "alpha.json").unlink()
    rerender(tmp_path)
    assert not (tmp_path / "badges" / "alpha.json").exists()


def test_rerender_without_a_results_directory_destroys_nothing(tmp_path: Path) -> None:
    # A moved/misspelled --out, an interrupted sync, a fresh clone: there is nothing to
    # rebuild FROM, so the rebuild must not delete the published badge endpoints (they live
    # in other people's READMEs) or blank the index while the caller reports it found
    # nothing. Note there is no servers/ directory here at all.
    (tmp_path / "badges").mkdir(parents=True)
    (tmp_path / "badges" / "alpha.json").write_text('{"schemaVersion": 1}', encoding="utf-8")
    (tmp_path / "index.html").write_text("<html>previous board</html>", encoding="utf-8")

    assert rerender(tmp_path) == []
    assert (tmp_path / "badges" / "alpha.json").exists()
    assert "previous board" in (tmp_path / "index.html").read_text(encoding="utf-8")


def test_a_partial_run_does_not_retire_other_servers_badges(tmp_path: Path) -> None:
    # Re-scanning one server that changed is the natural workflow; the others' saved results
    # still stand, so their badges must survive rather than break and then be restored by
    # the next --render-only.
    servers_dir = tmp_path / "servers"
    servers_dir.mkdir(parents=True)
    for name in ("alpha", "beta"):
        result = _scored(name, [_dim("schema", 90.0), _dim("task_success", 80.0, 3.0)])
        (servers_dir / f"{name}.json").write_text(_result_payload(result), encoding="utf-8")
    rerender(tmp_path)
    assert (tmp_path / "badges" / "beta.json").exists()

    async def _one_server() -> None:
        await run_leaderboard(
            [
                ServerEntry(
                    name="alpha", spec=f"{sys.executable} -m mcp_gauntlet.fixtures.good_server"
                )
            ],
            out_dir=tmp_path,
            llm_config=None,
            timeout_s=60.0,
            log=lambda _m: None,
        )

    anyio.run(_one_server)
    assert (tmp_path / "badges" / "beta.json").exists()  # bystander untouched


def test_board_url_survives_a_render_only_rebuild(tmp_path: Path) -> None:
    # --render-only is the documented free rebuild; it must not silently downgrade a correct
    # badge snippet to the placeholder just because the flag wasn't repeated.
    servers_dir = tmp_path / "servers"
    servers_dir.mkdir(parents=True)
    result = _scored("alpha", [_dim("schema", 90.0), _dim("task_success", 80.0, 3.0)])
    (servers_dir / "alpha.json").write_text(_result_payload(result), encoding="utf-8")

    rerender(tmp_path, "https://example.github.io/board")
    rerender(tmp_path)  # no --board-url this time
    html = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "https://example.github.io/board/badges/" in html
    assert "your-board.example" not in html


def test_badge_example_uses_a_real_slug_on_a_board_with_no_scored_servers() -> None:
    # rerender writes badges for failed/N-A servers too, so the snippet must name one that
    # exists rather than a placeholder filename that 404s.
    failed = LeaderboardResult(name="zeta", spec="z", error="connection refused", slug="zeta")
    html = render_index([failed], "https://example.github.io/board")
    assert "badges/zeta.json" in html
    assert "your-server.json" not in html


def test_unparseable_scan_date_renders_as_a_dash() -> None:
    # generated_at is an unvalidated string; a hand-edited or foreign saved report must not
    # print a truncated non-date in the column whose whole job is credibility.
    result = _scored("alpha", [_dim("schema", 90.0), _dim("task_success", 80.0, 3.0)])
    assert result.report is not None
    result.report.generated_at = "not-a-date-at-all"
    html = render_index([result])
    assert "not-a-date" not in html


def test_rerender_writes_badges_for_saved_results(tmp_path: Path) -> None:
    servers_dir = tmp_path / "servers"
    servers_dir.mkdir(parents=True)
    scored = _scored("alpha", [_dim("schema", 90.0), _dim("task_success", 80.0, 3.0)])
    (servers_dir / "alpha.json").write_text(_result_payload(scored), encoding="utf-8")

    rerender(tmp_path)
    badge = tmp_path / "badges" / "alpha.json"
    assert badge.exists()  # backfilled from the saved report, with no re-evaluation
    assert "schemaVersion" in badge.read_text(encoding="utf-8")


def test_a_failed_server_does_not_keep_an_older_grade_badge(tmp_path: Path) -> None:
    # An embedded badge must never keep advertising a score the board no longer stands
    # behind: a server that scored A last run and fails this run gets an explicit
    # "not evaluated" badge, not a stale A on its author's README.
    import json as _json

    servers_dir = tmp_path / "servers"
    servers_dir.mkdir(parents=True)
    scored = _scored("alpha", [_dim("schema", 90.0), _dim("task_success", 95.0, 3.0)])
    (servers_dir / "alpha.json").write_text(_result_payload(scored), encoding="utf-8")
    rerender(tmp_path)
    assert "A (" in _json.loads((tmp_path / "badges" / "alpha.json").read_text())["message"]

    # Now the saved result records a failure instead.
    failed = LeaderboardResult(name="alpha", spec="a", error="connection refused")
    (servers_dir / "alpha.json").write_text(_result_payload(failed), encoding="utf-8")
    rerender(tmp_path)
    payload = _json.loads((tmp_path / "badges" / "alpha.json").read_text())
    assert payload["message"] == "not evaluated"
    assert payload["color"] == "lightgrey"


def test_a_server_needing_credentials_says_so_instead_of_looking_untested() -> None:
    """The skip is only useful if a reader can tell it apart from a criticism.

    Without this, a commercial server we declined to authenticate lands under "Partially
    evaluated" reading "no agent evaluation (static checks only)" — indistinguishable from a
    keyless run, and easily read as the server's shortcoming. It is ours.
    """
    reason = "needs credentials that were not supplied — every probed tool reported an error"
    report = GauntletReport.build(
        spec="npx -y some-hosted-server",
        server=ServerInfo(name="hosted", version="1"),
        tool_count=2,
        dimensions=[DimensionResult(key="security", title="Security", weight=2.0, score=100.0)],
        unevaluated_reason=reason,
    )
    assert not report.agentically_scored  # so it cannot be co-ranked with tested servers
    assert _partial_reason(report) == reason

    # On a mixed board (some servers really were agent-scored), it lands in the partial
    # section with its reason spelled out.
    scored = GauntletReport.build(
        spec="npx -y works",
        server=ServerInfo(name="works", version="1"),
        tool_count=1,
        dimensions=[
            DimensionResult(key="task_success", title="Agent Task Success", weight=3.0, score=90.0)
        ],
    )
    html = render_index(
        [
            LeaderboardResult(name="hosted", spec="s", report=report),
            LeaderboardResult(name="works", spec="s2", report=scored),
        ],
        "",
    )
    assert "needs credentials" in html
    assert "Partially evaluated" in html


def test_a_credential_blocked_server_is_not_promoted_onto_a_static_board() -> None:
    """A static-only board pools everything into one table — but not this.

    The pooling exists because on a keyless run every server was measured the same way. A
    server the pre-flight found unusable was not: we know its tools do not work, while its
    STATIC score is untouched by that. Promoting it would rank an unusable server against
    working ones, and with nothing dragging its number down it would plausibly rank first.
    """
    blocked = GauntletReport.build(
        spec="npx -y hosted",
        server=ServerInfo(name="hosted", version="1"),
        tool_count=2,
        dimensions=[DimensionResult(key="security", title="Security", weight=2.0, score=100.0)],
        unevaluated_reason="needs credentials that were not supplied",
    )
    plain = GauntletReport.build(
        spec="npx -y plain",
        server=ServerInfo(name="plain", version="1"),
        tool_count=2,
        dimensions=[DimensionResult(key="security", title="Security", weight=2.0, score=80.0)],
    )
    html = render_index(
        [
            LeaderboardResult(name="hosted", spec="s", report=blocked),
            LeaderboardResult(name="plain", spec="s2", report=plain),
        ],
        "",
    )
    # `plain` (80) is ranked; `hosted` (100) is segregated despite the higher number.
    assert "Partially evaluated" in html
    assert html.index("plain") < html.index("Partially evaluated")
    assert html.index("Partially evaluated") < html.rindex("hosted")
