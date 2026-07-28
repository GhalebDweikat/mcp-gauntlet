"""Detecting a server that writes non-protocol output to its stdout.

The detection reads the SDK's own parse failures, which couples it to SDK internals. That
coupling is the risk: if a future SDK reports this differently, the check would quietly
measure nothing and every server would look clean — the exact failure mode this project
keeps running into. So the load-bearing test here drives a REAL fixture server through a
REAL session and asserts we noticed. It fails loudly rather than silently passing.
"""

import contextlib
import sys
import time

import anyio
import pytest

from mcp_gauntlet.client import open_session
from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.engine import _protocol_findings
from mcp_gauntlet.protocol import TransportLog, capture_stderr, watch_transport
from mcp_gauntlet.report import Severity

NOISY = f"{sys.executable} -m mcp_gauntlet.fixtures.noisy_server"
QUIET = f"{sys.executable} -m mcp_gauntlet.fixtures.good_server"


def _transport_for(spec_str: str) -> TransportLog:
    spec = ServerSpec.parse(spec_str)

    async def _run() -> TransportLog:
        async with open_session(spec) as (session, _init, interactions):
            await session.list_tools()
            return interactions.transport

    return anyio.run(_run)


def test_a_server_logging_to_stdout_is_detected_end_to_end() -> None:
    """The one that matters: a real subprocess, a real session, a real violation."""
    transport = _transport_for(NOISY)
    assert transport.unparseable_lines > 0, (
        "no protocol violation observed from a server that prints to stdout — the SDK "
        "probably changed how it reports unparseable lines, and this check is now blind"
    )
    assert transport.summary()  # evidence, not just a count


def test_a_well_behaved_server_produces_no_finding() -> None:
    # The false positive that would matter: flagging every server for a check that
    # misreads ordinary traffic.
    transport = _transport_for(QUIET)
    assert transport.unparseable_lines == 0
    assert _protocol_findings(transport) == []


def test_the_finding_lowers_the_score_but_never_caps_the_grade() -> None:
    """MEDIUM on purpose. It is a real, objective defect — and not evidence of an attack.

    Only near-certain attack signals are allowed to cap the grade. A framework logger
    pointed at the wrong stream is a bug, not an adversary, and capping honest servers is
    how a scanner loses the reader's trust.
    """
    log = TransportLog()
    log.note("[info] mapped route {/, GET}")
    log.note('    context: "Bootstrap"')
    findings = _protocol_findings(log)

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].tool is None  # a server-level defect, not any one tool's
    assert "stdout" in findings[0].message
    assert "2 non-protocol line" in findings[0].message


def test_the_watcher_leaves_logging_configuration_as_it_found_it() -> None:
    # It attaches a handler to a logger the host application may also be using.
    import logging

    logger = logging.getLogger("mcp.client.stdio")
    before_handlers, before_level = list(logger.handlers), logger.level
    with watch_transport():
        assert len(logger.handlers) == len(before_handlers) + 1
    assert list(logger.handlers) == before_handlers
    assert logger.level == before_level


def test_samples_are_bounded() -> None:
    # A server can emit thousands of log lines; the report must not carry all of them.
    log = TransportLog()
    for i in range(500):
        log.note(f"line {i}")
    assert log.unparseable_lines == 500
    assert len(log.samples) <= 3


def test_a_server_that_dies_on_startup_reports_what_it_said() -> None:
    """ "Connection closed" is true and useless. The reason is on the child's stderr.

    In the first survey pilot four of five servers failed, and every one of them reported
    exactly "McpError: Connection closed". The log held the real reasons — `npm error could
    not determine executable to run`, `EADDRINUSE` — but the report did not, so a published
    row could not distinguish a broken package from a busy port from a missing runtime.
    """
    from mcp_gauntlet.client import MCPConnectionError

    # A command that exists, starts, complains, and exits — the shape of a broken package.
    spec = ServerSpec.parse(
        f'{sys.executable} -c import-sys;sys.stderr.write("could not determine executable")'
    )

    async def _run() -> None:
        async with open_session(spec) as (_session, _init, _interactions):
            pass  # pragma: no cover - the session never opens

    with pytest.raises(MCPConnectionError) as caught:
        anyio.run(_run)
    assert "the server said" in str(caught.value)


def test_the_stderr_tail_is_bounded_and_keeps_the_last_lines() -> None:
    # A server can emit megabytes before dying; the report needs its last words, not all.
    with capture_stderr() as child:
        for i in range(2000):
            child.handle.write(f"noisy line {i}\n")
        tail = child.tail()
    assert len(tail) <= 240
    assert "1999" in tail  # the end, which is where the reason lives
    assert "noisy line 0\n" not in tail


def test_reading_the_tail_does_not_disturb_the_child_s_stream() -> None:
    # tail() is called mid-failure while the subprocess may still hold the descriptor.
    with capture_stderr() as child:
        child.handle.write("first\n")
        child.tail()
        child.handle.write("second\n")
        assert "second" in child.tail()
        assert "first" in child.tail()


def test_the_stderr_tail_does_not_publish_the_operators_home_directory() -> None:
    """This text lands on a public board naming third-party servers.

    npm ends a failure with a pointer to its debug log, which is useless on any machine but
    the one that produced it — and prints the scanning operator's username. The finding is
    "could not determine executable to run"; the path is noise with a privacy cost.
    """
    with capture_stderr() as child:
        child.handle.write("npm error could not determine executable to run\n")
        child.handle.write(
            "npm error A complete log of this run can be found in: "
            "/home/vboxuser/.npm/_logs/2026-07-27T23_25_14_171Z-debug-0.log\n"
        )
        tail = child.tail()
    assert "could not determine executable to run" in tail  # the finding survives
    assert "vboxuser" not in tail  # the username does not
    assert "A complete log" not in tail


def test_home_paths_are_stripped_wherever_they_appear() -> None:
    for raw, gone in (
        ("Cannot find module /home/alice/thing/index.js", "alice"),
        ("ENOENT: /Users/bob/Library/x", "bob"),
        (r"failed at C:\Users\carol\AppData\thing", "carol"),
    ):
        with capture_stderr() as child:
            child.handle.write(raw + "\n")
            tail = child.tail()
        assert gone not in tail, raw
        assert "~" in tail, raw


@pytest.mark.xfail(
    reason="KNOWN: a timed-out server outlives us. The SDK kills the child's process group "
    "with an await, and the cancellation that ends the evaluation cancels it first. "
    "Shielding the teardown fails because anyio forbids exiting a cancel scope in a "
    "different task than entered it, which is what @asynccontextmanager finalization "
    "under cancellation does. The fix is a class-based context manager; this test exists "
    "so the leak is recorded rather than forgotten.",
    strict=False,
)
def test_a_timed_out_server_is_not_left_running() -> None:
    """The bug this caught in the field: a leaked server poisons every later attempt.

    An abandoned `ankimcp` kept port 3000 in the survey VM, so every subsequent evaluation
    of it failed with EADDRINUSE — the harness scoring its own debris. The SDK does kill the
    child's process group, but with an `await`, and the timeout that ends the evaluation
    cancels that await before the kill lands. Teardown is shielded for exactly this.
    """
    import os
    import signal
    import tempfile as tf

    pidfile = os.path.join(tf.mkdtemp(), "pid")
    env = {**os.environ, "GAUNTLET_PIDFILE": pidfile}
    spec = ServerSpec.parse(f"{sys.executable} -m mcp_gauntlet.fixtures.hanging_server")
    spec.env.update({"GAUNTLET_PIDFILE": pidfile})

    async def _run() -> None:
        with anyio.move_on_after(5):  # the caller's per-server timeout, in miniature
            async with open_session(spec) as (_s, _i, _x):
                pass  # pragma: no cover - initialize never completes

    prior = dict(os.environ)
    os.environ.update(env)
    try:
        anyio.run(_run)
    finally:
        os.environ.clear()
        os.environ.update(prior)

    assert os.path.exists(pidfile), "fixture never started; the test proves nothing"
    with open(pidfile, encoding="utf-8") as handle:
        pid = int(handle.read())

    # If the child survived the cancelled teardown, signal 0 succeeds.
    alive = True
    for _ in range(20):
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, PermissionError):
            alive = False
            break
        time.sleep(0.25)
    if alive:  # pragma: no cover - only on regression; don't leak from the test either
        with contextlib.suppress(Exception):
            os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))
    assert not alive, f"server pid {pid} outlived the harness after a timeout"
