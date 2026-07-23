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


def test_filter_read_only_partitions() -> None:
    tools = [
        ToolInfo(name="echo", description="Echo the input"),
        ToolInfo(name="create-item", description="Create a new item"),
        ToolInfo(name="get-sum", description="Add two numbers"),
    ]
    kept, excluded = filter_read_only(tools)
    assert [t.name for t in kept] == ["echo", "get-sum"]
    assert excluded == ["create-item"]
