"""The read-only filter, in the direction where being wrong is an ACTION.

Every other guard in this project can, at worst, publish a wrong number. This one decides
which tools the harness actually executes on someone else's system, so a miss is a real
call to a real server. That asymmetry is why these cases are pinned by name.

Two holes were found by audit and are pinned here so they cannot come back:

* Five verbs sat in a qualifier-gated list requiring a name of two or more tokens. That
  rule is right for `add` — bare `add` really is arithmetic — but a tool named exactly
  `sync` or `restore` has no benign reading, and a zero-argument one is a "do it all now"
  button. Measured before the fix: all five passed as read-only.
* `_normalize` split camelCase with a lookbehind requiring lowercase-or-digit, so an
  acronym prefix was never split. `S3DeleteObject` was excluded only because the `3`
  satisfied it; `DBDeleteRow` came through as one token and would have run.
"""

import pytest

from mcp_gauntlet.models import ToolInfo
from mcp_gauntlet.safety import filter_read_only, looks_mutating

_NEUTRAL = "Performs the documented operation for the caller."


def _tool(
    name: str,
    description: str = _NEUTRAL,
    *,
    destructive_hint: bool | None = None,
    read_only_hint: bool | None = None,
) -> ToolInfo:
    return ToolInfo(
        name=name,
        description=description,
        input_schema={},
        destructive_hint=destructive_hint,
        read_only_hint=read_only_hint,
    )


@pytest.mark.parametrize(
    "name",
    ["sync", "restore", "init", "attach", "assign", "import", "Sync", "RESTORE", "restores"],
)
def test_a_bare_mutating_verb_is_never_executed(name: str) -> None:
    # No qualifier, no compound, a neutral description: the NAME alone has to be enough.
    assert looks_mutating(_tool(name)), f"{name!r} would be executed"


@pytest.mark.parametrize(
    "name", ["DBDeleteRow", "S3DeleteObject", "APIDeleteKey", "HTTPPostMessage", "IOWriteFile"]
)
def test_an_acronym_prefix_does_not_hide_the_verb(name: str) -> None:
    assert looks_mutating(_tool(name)), f"{name!r} would be executed"


@pytest.mark.parametrize(
    "name",
    ["add", "list_files", "get_user", "search", "read_notes", "describe", "fetchData", "settings"],
)
def test_read_only_tools_are_still_executed(name: str) -> None:
    """The other direction, which matters just as much.

    Over-excluding is not free: an unexecuted tool is an unevaluated tool, and the filter
    fails open on purpose to keep coverage. `add` is the reason the qualifier rule exists at
    all, and `settings` is why the fix was not a prefix match — it starts with `set`.
    """
    assert not looks_mutating(_tool(name)), f"{name!r} would be wrongly excluded"


def test_a_self_declared_destructive_tool_is_excluded_whatever_it_is_called() -> None:
    # The server incriminating itself is believed; the inverse never is.
    assert looks_mutating(_tool("lookup", destructive_hint=True))
    assert looks_mutating(_tool("lookup", read_only_hint=False))


def test_a_read_only_claim_cannot_rescue_an_IRREDEEMABLE_name() -> None:
    """An untrusted server asserting read_only_hint=True over `wipe_database` is exactly the
    claim this filter must not accept, and it still refuses it."""
    for name in ("wipe_database", "delete_user", "DBDeleteRow", "transfer_funds", "purge_all"):
        assert looks_mutating(_tool(name, read_only_hint=True)), name


def test_a_read_only_claim_DOES_rescue_a_contextual_name() -> None:
    """The rule used to be blanket, and that left a maintainer with no correct move.

    A first-run tester wrote a server of five pure getters, saw "no read-only tools to
    probe", annotated every tool exactly as MCP prescribes, and got byte-identical output —
    because `search_deploys` contains "deploy". The only escape was `--allow-writes`, the
    flag the report itself says to point at a disposable target. The README meanwhile claimed
    the filter "trusts a server's own readOnlyHint/name"; it trusted the name and ignored the
    hint.

    Everything in the write list is a GUESS from a name. `delete` is a guess strong enough to
    override a contrary claim; `deploy`, `sync`, `send` and `run` appear in the names of
    perfectly ordinary getters, and there an explicit annotation from the author is better
    evidence than a substring.

    This weakens no guarantee that existed: the filter never protected against a hostile
    server, because a malicious tool named `search_notes` was always executed. It protects
    honest servers from an accident, and the annotation comes from the same source as the
    name — just as a statement rather than a guess.
    """
    for name in ("search_deploys", "get_sync_status", "list_running_jobs", "send_status_report"):
        assert not looks_mutating(_tool(name, read_only_hint=True)), name
        # ...and the name heuristic still applies when the author did NOT annotate.
        assert looks_mutating(_tool(name)), name


def test_self_incrimination_still_beats_a_read_only_claim() -> None:
    # A server contradicting itself is believed in the conservative direction, always.
    assert looks_mutating(_tool("lookup", read_only_hint=True, destructive_hint=True))


def test_the_filter_reports_what_it_removed() -> None:
    tools = [_tool("read_notes"), _tool("sync"), _tool("DBDeleteRow"), _tool("add")]
    kept, excluded = filter_read_only(tools)
    assert sorted(t.name for t in kept) == ["add", "read_notes"]
    assert sorted(excluded) == ["DBDeleteRow", "sync"]
