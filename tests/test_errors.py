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


def test_stderr_tail_truncates_the_end_not_the_front() -> None:
    """`[-limit:]` kept the LAST N characters, so it cut the beginning of the first line.

    Real examples handed to a first-time debugger:

        cripts\python.exe: can't open file '...'
        .exe: can't open file '...'

    Neither path exists anywhere. The front is also where the useful part lives — the
    program name and what went wrong — while the tail is usually the rest of a path. A
    visibly truncated string beats a plausible wrong one.
    """
    import tempfile

    from mcp_gauntlet.protocol import ChildStderr

    line = r"C:\proj\.venv\Scripts\python.exe: can't open file " + "'" + "x" * 400 + "'"
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as handle:
        handle.write(line)
        tail = ChildStderr(handle).tail()  # type: ignore[arg-type]
    assert tail.startswith(r"C:\proj\.venv\Scripts\python.exe"), tail[:60]
    assert tail.endswith("…"), tail[-20:]
    assert "cripts" not in tail[:10]  # the specific fabricated fragment


def test_a_short_stderr_tail_is_untouched() -> None:
    import tempfile

    from mcp_gauntlet.protocol import ChildStderr

    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as handle:
        handle.write("Cannot find module 'express'")
        got = ChildStderr(handle).tail()  # type: ignore[arg-type]
        assert got == "Cannot find module 'express'"


@pytest.mark.parametrize(
    ("detail", "expected"),
    [
        ("ConnectError: [Errno 11001] getaddrinfo failed", "does not resolve"),
        ("ConnectError: All connection attempts failed", "nothing is listening"),
        ("ConnectTimeout: timed out", "in time"),
        ("SSLError: certificate verify failed", "TLS handshake"),
        ("RuntimeError: something else entirely", "did not come up"),
    ],
)
def test_remote_failures_name_the_url_and_the_cause(detail: str, expected: str) -> None:
    """A refused port and a nonexistent host produced the SAME message, with no URL in it.

    So a user could not tell whether the server was down, the hostname was wrong, or the
    harness was broken — and for two releases it WAS the harness, since the transport was
    dead on `mcp` 2.0 and this message is what people saw.
    """
    from mcp_gauntlet.errors import explain_remote_failure

    message = explain_remote_failure("https://mcp.example.com/mcp", RuntimeError(detail))
    assert "https://mcp.example.com/mcp" in message
    assert expected in message
    assert detail.split(":")[0] in message  # the raw cause is kept, not swallowed


def test_multiline_stderr_keeps_both_ends() -> None:
    """`lines[-3:]` dropped the FIRST line and said nothing about it.

    A server whose stderr reads "LINE_01: config key 'dsn' missing" followed by four lines of
    framework noise reported only the noise. Character-level truncation was fixed to preserve
    the front in 0.9.2 and LINE truncation was not — the same defect one level up.

    Both ends matter and which one carries the answer depends on the server: a startup error
    announces itself on the first line, a traceback puts its exception on the last. So keep
    both and mark the gap.
    """
    import tempfile

    from mcp_gauntlet.protocol import ChildStderr

    def tail(lines: list[str]) -> str:
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
            return ChildStderr(handle).tail()  # type: ignore[arg-type]

    got = tail(["LINE_01_THE_ACTUAL_ERROR: config missing", *[f"noise_{i}" for i in range(4)]])
    assert got.startswith("LINE_01_THE_ACTUAL_ERROR"), got
    assert "…" in got, got  # the gap is visible, not silent
    assert got.endswith("noise_3"), got

    # A traceback's exception is on the LAST line, and must survive too.
    trace = tail(["Traceback (most recent call last):", "  File a", "  File b", "KeyError: dsn"])
    assert trace.endswith("KeyError: dsn"), trace

    # Short stderr is untouched — no ellipsis, nothing dropped.
    assert tail(["a", "b", "c"]) == "a / b / c"
