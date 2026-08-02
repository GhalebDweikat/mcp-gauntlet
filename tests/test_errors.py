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


def test_bundled_demo_runs_without_an_activated_venv() -> None:
    """`python -m mcp_gauntlet.fixtures.…` must not depend on what is first on PATH.

    Every doc uses that spelling for the demo, and it only worked when the `python` first on
    PATH happened to be the interpreter mcp-gauntlet is installed into — true under `uvx`,
    false under `uv tool install` (isolated env) and false when a console script is invoked
    from an unactivated venv, which is the normal way. A first-run tester hit
    `No module named 'mcp_gauntlet'` on the very first command in the README, using the
    install method the README recommends.

    Resolving to `sys.executable` is not a guess here: that module cannot exist in any
    environment but this interpreter's.
    """
    import sys

    from mcp_gauntlet.client import _is_own_fixture, _resolve_command

    assert _is_own_fixture("python", ["-m", "mcp_gauntlet.fixtures.good_server"])
    assert _resolve_command("python", ["-m", "mcp_gauntlet.fixtures.good_server"]) == sys.executable

    # Narrow on purpose — a user's own server must keep the "give the interpreter
    # explicitly" behaviour, because for THEM a bare `python` really is ambiguous.
    assert not _is_own_fixture("python", ["-m", "my_server"])
    assert not _is_own_fixture("python", ["server.py"])
    assert not _is_own_fixture("node", ["-m", "mcp_gauntlet.fixtures.good_server"])
    assert not _is_own_fixture("python", [])
