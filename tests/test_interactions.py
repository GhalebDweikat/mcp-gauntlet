"""Server-initiated elicitation/sampling: counting and honest attribution.

The unit-level attribution logic lives in test_agent_mock.py; this file pins the two
ends the mocks can't: that a REAL server's elicitation request is actually counted by
the recording session (the SDK plumbing), and that the count turns into an honest note
in the rendered reports.
"""

import sys

import pytest

from mcp_gauntlet.adapters import adapter
from mcp_gauntlet.client import InteractionLog, open_session
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
    """The count is what lets the evaluation blame the harness instead of the server.

    The interactive fixture's `confirm_and_run` asks the client to elicit a confirmation.
    The harness declines — it drives no user — so the tool cannot complete. The failure is
    ours, and only the count says so.

    How that failure SURFACES differs by era and is deliberately not asserted the same way:
    1.x answers the server's request with an error and the tool returns `isError`, while 2.0
    refuses at the client and the *call itself* raises. What must not differ, and is what
    this test is actually for, is that the request was seen and counted.
    """
    spec = ServerSpec.parse(f"{sys.executable} -m mcp_gauntlet.fixtures.interactive_server")
    async with open_session(spec) as (session, _init, interactions):
        try:
            result = await session.call_tool("confirm_and_run", {"item": "x"})
        except Exception as exc:  # noqa: BLE001 - the modern client's own refusal
            assert adapter().era == "modern", f"unexpected raise on the legacy SDK: {exc!r}"
        else:
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


def test_the_counting_hook_refuses_to_run_blind() -> None:
    """The counter must not be allowed to read zero because its hook vanished.

    This is the bug that shipped: `_RecordingSession` counted by overriding the private
    `ClientSession._received_request`, `mcp` 2.0 deleted that method, and overriding a
    method the base class no longer has raises nothing and warns about nothing. The
    override was simply never called — so the count read 0, and every elicitation the
    harness itself declined was charged to the server's Tool Reliability.

    A zero from "nothing happened" and a zero from "we stopped looking" are the same
    number, so the construction refuses rather than producing one of them.
    """
    import mcp_gauntlet.client as client_module

    original = client_module._ERA_HOOKS
    try:
        client_module._ERA_HOOKS = ("_a_hook_no_sdk_has", "_nor_this_one")
        with pytest.raises(RuntimeError, match="cannot be counted"):
            client_module._RecordingSession(None, None, interactions=InteractionLog())
    finally:
        client_module._ERA_HOOKS = original


def test_the_hook_this_era_actually_needs_is_present() -> None:
    # The positive half: whichever era is installed, one of the two hooks must exist, or
    # every session would refuse to construct.
    from mcp import ClientSession

    from mcp_gauntlet.client import _ERA_HOOKS

    present = [hook for hook in _ERA_HOOKS if hasattr(ClientSession, hook)]
    assert present, f"no receive hook on this SDK; tried {_ERA_HOOKS}"
