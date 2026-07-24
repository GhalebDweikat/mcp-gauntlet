from mcp_gauntlet.judge import selection_score
from mcp_gauntlet.models import ToolInfo
from mcp_gauntlet.safety import filter_read_only, looks_mutating


def test_selection_score_none_when_no_expectation() -> None:
    assert selection_score([], ["a", "b"]) is None


def test_selection_score_fraction() -> None:
    assert selection_score(["a", "b"], ["a"]) == 50.0
    assert selection_score(["a", "b"], ["a", "b", "c"]) == 100.0
    assert selection_score(["a"], ["x"]) == 0.0


def test_looks_mutating() -> None:
    assert looks_mutating(ToolInfo(name="delete-file", description="Delete a file"))
    assert looks_mutating(ToolInfo(name="toggle-logging", description="Toggle logging"))
    assert not looks_mutating(ToolInfo(name="get-sum", description="Return the sum of two numbers"))


def test_looks_mutating_matches_inflected_verbs() -> None:
    # Real descriptions are third-person / gerund, not bare imperatives — these all
    # used to slip through as "read-only".
    for desc in (
        "Creates a new file at the given path.",
        "Sends an email to the recipient.",
        "Transfers funds between two accounts.",
        "Commits and pushes changes to the remote.",
        "Saves the note to persistent storage.",
        "Deletes the record and returns nothing.",
        "A tool for deleting stale entries.",
    ):
        assert looks_mutating(ToolInfo(name="tool", description=desc)), desc


def test_looks_mutating_read_only_stays_read_only() -> None:
    for desc in (
        "Returns the current weather for a city.",
        "Fetches account data for the given id.",
        "Lists the files in a directory.",
        "Searches the knowledge base and reports matches.",
    ):
        assert not looks_mutating(ToolInfo(name="tool", description=desc)), desc


def test_looks_mutating_matches_snake_case_and_financial_names() -> None:
    # \b treats "_" as a word char, so name matching needs separator normalization;
    # and the verb list must cover financial/lifecycle verbs, not just CRUD.
    for name in (
        "delete_file",
        "deleteFile",
        "drop_table",
        "issue_refund",
        "withdraw_funds",
        "place_order",
        "mint_token",
        "suspend_user",
    ):
        assert looks_mutating(ToolInfo(name=name, description="")), name


def test_destructive_hint_excludes_but_readonly_hint_never_includes() -> None:
    # A server self-declaring destructive/non-read-only is trusted (conservative).
    assert looks_mutating(
        ToolInfo(name="opaque", description="does a thing", destructive_hint=True)
    )
    assert looks_mutating(
        ToolInfo(name="opaque2", description="does a thing", read_only_hint=False)
    )
    # But an untrusted readOnlyHint=True must NOT wave a clearly-mutating tool through.
    assert looks_mutating(
        ToolInfo(name="wipe-db", description="Deletes all rows.", read_only_hint=True)
    )


def test_filter_read_only_partitions() -> None:
    tools = [
        ToolInfo(name="echo", description="Echo the input"),
        ToolInfo(name="create-item", description="Create a new item"),
        ToolInfo(name="get-sum", description="Add two numbers"),
    ]
    kept, excluded = filter_read_only(tools)
    assert [t.name for t in kept] == ["echo", "get-sum"]
    assert excluded == ["create-item"]
