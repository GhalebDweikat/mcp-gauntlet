"""Unwrapping the exception a reader actually needs to see.

anyio runs every session in a task group, so a failure reaching the leaderboard arrives as
"unhandled errors in a TaskGroup (1 sub-exception)". Three of five servers in the first
survey pilot failed with exactly that string: it names no cause, and as a published row it
reads as the harness shrugging rather than as a fact about the server.
"""

import pytest

from mcp_gauntlet.errors import describe


def test_unwraps_a_task_group_to_the_real_cause() -> None:
    inner = FileNotFoundError(2, "No such file or directory: 'ctxl'")
    group = ExceptionGroup("unhandled errors in a TaskGroup (1 sub-exception)", [inner])
    described = describe(group)
    assert "TaskGroup" not in described
    assert "FileNotFoundError" in described
    assert "ctxl" in described


def test_unwraps_nested_groups() -> None:
    deep = ExceptionGroup("outer", [ExceptionGroup("inner", [ValueError("the actual problem")])])
    assert "the actual problem" in describe(deep)
    assert "ValueError" in describe(deep)


def test_reports_several_distinct_causes() -> None:
    group = ExceptionGroup("boom", [ValueError("first"), KeyError("second")])
    described = describe(group)
    assert "first" in described and "second" in described


def test_falls_back_to_the_type_when_the_message_is_empty() -> None:
    # Several SDK exceptions stringify to "", which would render as a blank reason.
    assert describe(ExceptionGroup("x", [RuntimeError()])) == "RuntimeError"


def test_respects_the_length_limit() -> None:
    group = ExceptionGroup("x", [ValueError("y" * 500)])
    assert len(describe(group, limit=80)) <= 80


def test_a_plain_exception_is_described_directly() -> None:
    assert describe(ValueError("plain")) == "ValueError: plain"


def test_duplicate_causes_are_not_repeated() -> None:
    # A server failing the same way on several concurrent tasks should say it once.
    group = ExceptionGroup("x", [ValueError("same"), ValueError("same"), ValueError("same")])
    assert describe(group) == "ValueError: same"


@pytest.mark.parametrize("limit", [10, 50, 200])
def test_never_returns_empty(limit: int) -> None:
    assert describe(ExceptionGroup("x", [RuntimeError("z")]), limit=limit)
