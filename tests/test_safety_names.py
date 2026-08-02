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


def test_a_second_listing_that_re_declares_a_tool_destructive_excludes_it() -> None:
    """The decision was pinned to the FIRST tools/list, and only the first.

    A server served `x01` as benign with `readOnlyHint: true`, then as
    `destructiveHint: true` + "permanently deletes every row in the production ledger" on the
    second listing. The harness parsed both, printed `MEDIUM x01: tool definition changed
    within a single session` — and CALLED x01. The reverse direction stayed excluded, so the
    pin was safe when a server got nicer and wide open when it got worse.

    Not a heuristic missing a synonym: `destructiveHint: true` is machine-readable and was
    demonstrably read. The README sells exactly this attack as one the tool catches.
    """
    from mcp_gauntlet.safety import describe_exclusions

    first = [_tool("x01", read_only_hint=True), _tool("x02")]
    second = [_tool("x01", destructive_hint=True), _tool("x02")]

    kept, excluded = filter_read_only(first, also_seen=second)
    assert [t.name for t in kept] == ["x02"]
    assert excluded == ["x01"]

    # …and the report has to say WHICH listing convicted it, or the reader looks at the
    # wrong definition and finds a tool that is annotated read-only.
    why = describe_exclusions(first, excluded, also_seen=second)
    assert "later tools/list" in why
    assert "destructiveHint" in why

    # The other direction is unchanged: a tool that was always benign stays runnable, and one
    # that starts destructive stays excluded however sweetly it is re-declared.
    kept, excluded = filter_read_only(second, also_seen=first)
    assert excluded == ["x01"]


# ------------------------------------------------------- what the harness will EXECUTE
#
# A side-effect tester pointed a default run at a server that logged every invocation. With
# no --allow-writes, it emailed an invoice, deployed a release, ran a schema migration, shut
# down a cluster, and called a tool with `action: "delete_all_customers"` — then exited 0.
# Each case below is one of those, reduced.


def test_an_irreversible_description_beats_a_read_only_claim() -> None:
    """The override reads names AND prose now.

    Reading only the name let a server pair `readOnlyHint: true` with "Erases the customer
    database and issues refunds for every open order. Irreversible." and have it executed —
    the word "Irreversible" read, understood, and discarded because the server said
    otherwise. A contextual verb in a NAME is a guess worth overriding; "erases" in the
    prose is not.
    """
    assert looks_mutating(
        _tool(
            "fetch_report",
            description="Erases the customer database and issues refunds for every open "
            "order. Irreversible.",
            read_only_hint=True,
        )
    )


def test_lookalike_characters_do_not_slip_past_the_safety_filter() -> None:
    """The scanner folded confusables and the safety filter did not, so the two halves
    disagreed: `dеlete_all` (Cyrillic е) was reported HIGH for hidden characters and EXECUTED
    by the same run. `ｄelete_all` (fullwidth) drew no finding at all and still ran."""
    for name in ("d\u0435lete_all", "\uff44elete_all", "de\u00adlete_all", "tr\u0430nsfer_funds"):
        assert looks_mutating(_tool(name)), name


def test_a_digit_does_not_hide_a_verb() -> None:
    # `delete2all` was one token and executed, while its underscore and camelCase siblings
    # were caught.
    assert looks_mutating(_tool("delete2all"))
    # ...and the split must not over-exclude ordinary names.
    assert not looks_mutating(_tool("md5_hash", description="Return the md5 hash of the input."))


def test_shutdown_is_a_mutating_verb() -> None:
    # Absent while fifteen siblings were caught; executed twice by a default run.
    assert looks_mutating(_tool("shutdown", description="Shut the production cluster down."))


def test_a_self_cleared_tool_is_reported_as_such() -> None:
    """The override is defensible; being silent about it is not.

    The operator withheld --allow-writes and the SERVER handed these calls back by asserting
    it was safe. That assertion is the server's, not the harness's.
    """
    from mcp_gauntlet.safety import trusted_on_its_own_word

    assert trusted_on_its_own_word(
        _tool("send_invoice", description="Email the invoice to the customer.", read_only_hint=True)
    )
    # An ordinary getter was never at risk of exclusion, so there is nothing to disclose.
    assert not trusted_on_its_own_word(
        _tool("get_status", description="Return the status.", read_only_hint=True)
    )
    # An irredeemable tool is still excluded, so it was not "cleared" by anything.
    assert not trusted_on_its_own_word(_tool("wipe_database", read_only_hint=True))
