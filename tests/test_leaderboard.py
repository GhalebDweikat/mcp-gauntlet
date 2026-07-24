"""Leaderboard rendering: N/A (zero-tool) servers are listed unranked, not mis-sorted."""

from mcp_gauntlet.checks import run_static_checks
from mcp_gauntlet.leaderboard import LeaderboardResult, _unique_slug, render_index
from mcp_gauntlet.models import DiscoveryResult, ServerInfo, ToolInfo
from mcp_gauntlet.report import DimensionResult, Finding, GauntletReport, Severity


def _report(name: str, tools: list[ToolInfo]) -> GauntletReport:
    discovery = DiscoveryResult(server=ServerInfo(name=name), tools=tools)
    return GauntletReport.build(
        spec=name,
        server=discovery.server,
        tool_count=len(tools),
        dimensions=run_static_checks(discovery),
    )


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
    assert "⚡" in html
