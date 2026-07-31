"""Server-initiated elicitation/sampling: counting and honest attribution.

The unit-level attribution logic lives in test_agent_mock.py; this file pins the two
ends the mocks can't: that a REAL server's elicitation request is actually counted by
the recording session (the SDK plumbing), and that the count turns into an honest note
in the rendered reports.
"""

import sys

import pytest

from mcp_gauntlet.adapters import adapter
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


@pytest.mark.xfail(
    adapter().era == "modern",
    strict=True,
    reason=(
        "KNOWN BROKEN on mcp 2.0, recorded rather than skipped. `_RecordingSession` counts "
        "by overriding the private `ClientSession._received_request`, and 2.0 removed that "
        "method — MEASURED: `hasattr(ClientSession, '_received_request')` is True on 1.29.0 "
        "and False on 2.0.0. So the override is simply never called: no error, no warning, "
        "the counter stays at zero, and every declined elicitation is charged to the "
        "server's Tool Reliability. That is the exact misattribution this counter exists to "
        "prevent, arriving as a method that silently stopped being called.\n\n"
        "The request does still reach the client — 2.0's default elicitation callback "
        "declines it with INVALID_REQUEST/'Elicitation not supported' and the server then "
        "raises — so this is observable, just not where we are looking. `message_handler` "
        "was tried and counts nothing in EITHER era, so it is not the replacement hook.\n\n"
        "strict=True on purpose: when the hook is fixed this test must fail for passing "
        "unexpectedly, so the xfail cannot outlive the bug. Widening the `mcp` pin should "
        "wait on this — shipping it would ship the misattribution."
    ),
)
async def test_recording_session_counts_a_real_elicitation() -> None:
    # The interactive fixture's `confirm_and_run` asks the client to elicit a confirmation.
    # The harness declines (it drives no user), so the tool fails — but the request must be
    # counted, which is what lets the evaluation attribute that failure to the harness.
    spec = ServerSpec.parse(f"{sys.executable} -m mcp_gauntlet.fixtures.interactive_server")
    async with open_session(spec) as (session, _init, interactions):
        result = await session.call_tool("confirm_and_run", {"item": "x"})
        # can't proceed without the confirmation we declined
        assert adapter().result_is_error(result) is True
        assert interactions.elicitation == 1
        assert interactions.total == 1
        # A tool that needs no interaction leaves the count untouched.
        ok = await session.call_tool("echo", {"text": "hi"})
        assert adapter().result_is_error(ok) is False
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
