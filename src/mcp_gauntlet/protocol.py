"""Watch the transport for a server breaking the protocol it speaks.

Over stdio, a server's stdout carries JSON-RPC framing and nothing else — the spec is
explicit that anything else there is invalid. Servers violate this constantly by leaving a
framework's default logger pointed at stdout: a NestJS bootstrap, a Python `print`, a
progress bar. The SDK skips the unparseable lines and carries on, so the server often
*appears* to work, and the defect is invisible to its author.

It is worth reporting anyway, for two reasons. It corrupts the stream for every client, not
just this one — another client may be less forgiving. And it is a message-injection surface:
the harness cannot tell a bootstrap banner from a log line echoing user-supplied text, and
if any such line ever parses as JSON-RPC it becomes a protocol message the server never
meant to send.

Detection reads the SDK's own parse failures rather than the child's stdout, because the SDK
owns that pipe. That couples us to a logger name, so `tests/test_protocol.py` drives a real
fixture server that pollutes stdout: if a future SDK stops reporting this the way we expect,
that test fails loudly instead of the check quietly measuring nothing.
"""

from __future__ import annotations

import contextlib
import logging
import re
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TextIO, cast

# The SDK module whose reader parses each stdout line (`logger = logging.getLogger(__name__)`).
_STDIO_LOGGER = "mcp.client.stdio"
_MAX_SAMPLES = 3
_STDERR_TAIL = 240


@dataclass
class TransportLog:
    """What the server put on the wire that was not a protocol message."""

    unparseable_lines: int = 0
    samples: list[str] = field(default_factory=list)

    def note(self, detail: str) -> None:
        self.unparseable_lines += 1
        if len(self.samples) < _MAX_SAMPLES and detail:
            self.samples.append(detail)

    def summary(self) -> str:
        """One line of evidence for the report, with the noise stripped out."""
        if not self.samples:
            return ""
        return " | ".join(s[:120] for s in self.samples)


class _ParseFailureHandler(logging.Handler):
    def __init__(self, log: TransportLog) -> None:
        super().__init__(level=logging.ERROR)
        self._log = log

    def emit(self, record: logging.LogRecord) -> None:
        # Keyed on the exception, not the message text: the wording of a log line is the
        # most likely thing to change between SDK releases, and a check that silently stops
        # matching would report every server as clean.
        exc = record.exc_info[1] if record.exc_info else None
        if exc is None:
            return
        # ...but "has an exception" stopped being specific enough. `mcp` 2.0 added a second
        # logger.exception() on this same logger for a stdout read failing mid-session —
        # which is the server dying, not the server polluting. Counting it would charge a
        # crash to the protocol-compliance check. Discriminating on the exception TYPE keeps
        # us off the log wording: a line that will not parse fails in json/pydantic, both of
        # which are ValueError; a transport read fails with OSError or an anyio stream error,
        # which is not.
        if not isinstance(exc, ValueError):
            return
        detail = ""
        # Pydantic puts the offending line in the error's context; fall back to the message.
        for err in getattr(exc, "errors", lambda: [])():
            value = err.get("input")
            if isinstance(value, str):
                detail = value
                break
        self._log.note(detail or str(exc))


# Lines that carry no information about the failure. `npm` and `pip` both end a failure with
# a pointer to a debug log, which is worthless to anyone reading a report on another machine
# — and on a published board it prints the operator's home directory.
_NOISE = re.compile(
    r"(?i)^(?:npm\s+(?:error|ERR!)\s+)?A complete log of this run can be found in"
    r"|^(?:npm\s+)?(?:error|ERR!)?\s*$"
    r"|^See .* for details\.?$"
)

# Absolute paths through a user's home directory, in the three shapes that show up. The
# report is published; nobody reading it needs the scanning machine's username.
_HOME_PATH = re.compile(r"(?:/home/[^/\s]+|/Users/[^/\s]+|[A-Za-z]:\\Users\\[^\\\s]+)(?=[/\\]|\b)")


class ChildStderr:
    """The child's stderr stream, plus a reader for the last thing it said."""

    def __init__(self, handle: TextIO) -> None:
        self.handle = handle

    def tail(self, limit: int = _STDERR_TAIL) -> str:
        """The last few meaningful lines, with boilerplate and local paths removed.

        Filtered rather than raw because this text is published. `npm error could not
        determine executable to run` is the finding; the debug-log path that follows it is
        noise on any machine but the one that produced it, and it carries the operator's
        username onto a public page.
        """
        try:
            self.handle.flush()
            position = self.handle.tell()
            self.handle.seek(0)
            text = self.handle.read()
            self.handle.seek(position)  # leave the stream where the child left it
        except (OSError, ValueError):  # closed or unreadable — never worth raising over
            return ""
        lines = [
            _HOME_PATH.sub("~", line.strip())
            for line in text.splitlines()
            if line.strip() and not _NOISE.match(line.strip())
        ]
        return " / ".join(lines[-3:])[-limit:]


@contextlib.contextmanager
def capture_stderr() -> Iterator[ChildStderr]:
    """Capture a stdio child's stderr, and yield a reader for its tail.

    When a server dies before it finishes initializing, the SDK reports "Connection closed"
    — true, and useless. The reason is on the child's stderr: `could not determine executable
    to run`, `Cannot find module`, a stack trace, a usage message. Without it, a survey of
    unvetted packages publishes the same four words against every server that failed to
    start, which tells a reader nothing and tells a maintainer less.

    A temp file rather than an in-memory buffer because this is handed to the subprocess and
    has to be a real file descriptor. Only the tail is read back: a server can emit megabytes
    before dying, and a report needs the last thing it said, not all of it.
    """
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as handle:
        # NamedTemporaryFile's wrapper is duck-compatible with TextIO and has a real
        # fileno(), which is what the subprocess actually needs.
        yield ChildStderr(cast(TextIO, handle))


@contextlib.contextmanager
def watch_transport() -> Iterator[TransportLog]:
    """Record protocol-invalid output for the duration of one session.

    The handler is attached to the SDK's stdio logger and removed on exit, so nothing about
    the host application's logging configuration is changed permanently. `propagate` is left
    alone deliberately — suppressing the SDK's own warning would hide the problem from
    anyone running with debug logging on.
    """
    log = TransportLog()
    handler = _ParseFailureHandler(log)
    logger = logging.getLogger(_STDIO_LOGGER)
    previous_level = logger.level
    # The SDK logs this at ERROR; make sure the logger is not filtering it out before our
    # handler ever sees it.
    if logger.level > logging.ERROR or logger.level == logging.NOTSET:
        logger.setLevel(logging.ERROR)
    logger.addHandler(handler)
    try:
        yield log
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
