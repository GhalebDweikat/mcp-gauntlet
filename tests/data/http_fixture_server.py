"""Serve one echo tool over streamable HTTP, on whichever SDK era is installed.

Run as a SUBPROCESS by `tests/test_http_transport.py`, not as a thread. The first version
hosted this in a module-scoped daemon thread, which outlived the module and kept a uvicorn
event loop running for the rest of the pytest session — and `tests/test_llm.py` monkeypatches
`anyio.sleep` globally to assert a retry schedule, so the stray server's sleeps landed in its
list: `assert len(sleeps) == 3` saw 15340. Ordering-dependent, so it passed on re-run, which
is the worst kind of flake.

A separate process is also what a remote server actually is, so the test is more faithful for
the same money.

Usage: python http_fixture_server.py <port>
"""

from __future__ import annotations

import sys

from mcp_gauntlet.fixtures._serve import Tool, serve


def echo(text: str) -> str:
    """Return the text it was given."""
    return text


if __name__ == "__main__":
    serve(
        "http-fixture",
        [Tool(fn=echo, name="echo", description="Return the text it was given.")],
        http=("127.0.0.1", int(sys.argv[1])),
    )
