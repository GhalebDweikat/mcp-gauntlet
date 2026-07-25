"""Server-initiated elicitation/sampling: counting and honest attribution.

The unit-level attribution logic lives in test_agent_mock.py; this file pins the two
ends the mocks can't: that a REAL server's elicitation request is actually counted by
the recording session (the SDK plumbing), and that the count turns into an honest note
in the rendered reports.
"""

import sys

from mcp_gauntlet.client import open_session
from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.htmlreport import to_html
from mcp_gauntlet.models import ServerInfo
from mcp_gauntlet.report import (
    AgenticDetail,
    DimensionResult,
    GauntletReport,
    interaction_note,
    to_markdown,
)


async def test_recording_session_counts_a_real_elicitation() -> None:
    # The interactive fixture's `confirm_and_run` asks the client to elicit a confirmation.
    # The harness declines (it drives no user), so the tool fails — but the request must be
    # counted, which is what lets the evaluation attribute that failure to the harness.
    spec = ServerSpec.parse(f"{sys.executable} -m mcp_gauntlet.fixtures.interactive_server")
    async with open_session(spec) as (session, _init, interactions):
        result = await session.call_tool("confirm_and_run", {"item": "x"})
        assert result.isError is True  # can't proceed without the confirmation we declined
        assert interactions.elicitation == 1
        assert interactions.total == 1
        # A tool that needs no interaction leaves the count untouched.
        ok = await session.call_tool("echo", {"text": "hi"})
        assert ok.isError is False
        assert interactions.elicitation == 1


def test_interaction_note_is_none_without_requests() -> None:
    assert interaction_note(None) is None
    assert (
        interaction_note(AgenticDetail(provider="p", model="m", tasks_generated=1, repeats=1))
        is None
    )


def test_interaction_note_describes_the_requests() -> None:
    detail = AgenticDetail(
        provider="p",
        model="m",
        tasks_generated=1,
        repeats=1,
        interactive_requests=3,
        interactive_summary="2 elicitation, 1 sampling",
    )
    note = interaction_note(detail)
    assert note is not None
    assert "2 elicitation, 1 sampling" in note
    assert "not counted against Tool Reliability" in note


def _report_with_interaction() -> GauntletReport:
    detail = AgenticDetail(
        provider="groq",
        model="llama",
        tasks_generated=1,
        repeats=1,
        interactive_requests=2,
        interactive_summary="2 elicitation",
    )
    return GauntletReport.build(
        spec="stdio: x",
        server=ServerInfo(name="srv", version="1"),
        tool_count=1,
        dimensions=[DimensionResult(key="a", title="A", weight=1.0, score=100.0)],
        agentic=detail,
    )


def test_interaction_note_renders_in_markdown_and_html() -> None:
    report = _report_with_interaction()
    md = to_markdown(report)
    html = to_html(report)
    assert "elicitation/sampling" in md
    assert "elicitation/sampling" in html


async def test_env_allowlist_reaches_a_stdio_child() -> None:
    # The end-to-end credential path: an allow-listed env var must actually arrive in the
    # spawned server process (the SDK merges it over a minimal safe base environment).
    spec = ServerSpec.parse(f"{sys.executable} -m mcp_gauntlet.fixtures.env_echo_server")
    spec.env = {"MCP_GAUNTLET_TEST_TOKEN": "sentinel-value-1234"}
    async with open_session(spec) as (session, _init, _interactions):
        result = await session.call_tool("whoami", {})
        text = "".join(getattr(b, "text", "") for b in (result.content or []))
        assert text == "sentinel-value-1234"


async def test_env_not_passed_stays_unset_in_the_child() -> None:
    # Without --env the child gets only the SDK's minimal safe environment — no leak of the
    # parent's variables into an untrusted server.
    spec = ServerSpec.parse(f"{sys.executable} -m mcp_gauntlet.fixtures.env_echo_server")
    async with open_session(spec) as (session, _init, _interactions):
        result = await session.call_tool("whoami", {})
        text = "".join(getattr(b, "text", "") for b in (result.content or []))
        assert text == "<unset>"
