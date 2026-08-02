"""The HTTP transport, exercised against a real server over a real socket.

This path has now shipped broken on `mcp` 2.0 TWICE, for the same underlying reason both
times, and no test caught either one:

    0.8.0  widened the pin to `mcp<3`; `streamablehttp_client` is a 1.x alias 2.0 removed
           → ImportError before any network I/O
    0.9.0  fixed the name and the `headers=`→`http_client=` change, but 1.x yields
           `(read, write, get_session_id)` and 2.0 yields `(read, write)`
           → ValueError: not enough values to unpack (expected 3, got 2)

Both were found by users, not by CI, because the cross-era probe exercises stdio fixtures
and nothing imported this module's HTTP branch. A comment in `client.py` correctly named
that gap after the first occurrence; a comment does not run.

The failure mode is unusually nasty: it raises before any request is sent, so a refused
port, a nonexistent host and a healthy live server all produce the same message. A user
cannot tell it is the harness rather than their server.

So these tests bind a real port and speak real streamable HTTP. They are slower than the
rest of the suite, which is the price of covering a seam that mocks kept missing.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from collections.abc import Iterator

import anyio
import pytest

from mcp_gauntlet.client import open_session
from mcp_gauntlet.config import ServerSpec, TransportKind
from mcp_gauntlet.fixtures._serve import Tool, serve


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _echo(text: str) -> str:
    """Return the text it was given."""
    return text


@pytest.fixture(scope="module")
def http_server() -> Iterator[str]:
    """A real MCP server over streamable HTTP, in a thread, on a free port.

    Built through the fixtures' era shim rather than by importing a server class directly.
    The first version of this test did `pytest.importorskip("mcp.server.fastmcp")`, which
    2.0 does not have — so it skipped on the only era where the transport was broken and
    reported two passes. The shim runs on both.
    """
    port = _free_port()
    thread = threading.Thread(
        target=lambda: serve(
            "http-fixture",
            [Tool(fn=_echo, name="echo", description="Return the text it was given.")],
            http=("127.0.0.1", port),
        ),
        daemon=True,
    )
    thread.start()

    url = f"http://127.0.0.1:{port}/mcp"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:  # wait for the listener, not a fixed sleep
        with socket.socket() as probe:
            probe.settimeout(0.25)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.1)
    else:  # pragma: no cover - the server never came up
        pytest.skip("the HTTP fixture server did not start")
    yield url


@pytest.mark.skipif(sys.platform == "emscripten", reason="no sockets")
def test_remote_server_can_actually_be_reached(http_server: str) -> None:
    """The regression itself: connect, initialize, list tools, over a real socket.

    Asserting on the tool list rather than on the connection alone — an exception thrown
    while unpacking the transport's yield happens before any request, so a test that only
    checked "did we raise" would have passed against a server that was never contacted.
    """
    spec = ServerSpec.parse(http_server)
    assert spec.kind is TransportKind.HTTP

    async def _go() -> list[str]:
        # The bound has to be INSIDE the event loop; `fail_after` needs a running one.
        with anyio.fail_after(60):
            async with open_session(spec) as (session, _init, _):
                # No read of `init` here: its fields are SDK-shaped and belong behind the
                # adapters (`test_no_sdk_shaped_read_survives_outside_the_adapters` enforces
                # that, and caught the first draft of this test). A returned tool list is a
                # stronger proof anyway — it means initialize completed AND a request made
                # the round trip, which is exactly what the broken transport never did.
                listed = await session.list_tools()
                return [t.name for t in listed.tools]

    names = anyio.run(_go)
    assert "echo" in names


@pytest.mark.skipif(sys.platform == "emscripten", reason="no sockets")
def test_transport_yield_is_sliced_not_unpacked() -> None:
    """Guards the fix directly, without a socket.

    1.x yields three values and 2.0 yields two. Pinning the arity in a test would just
    encode whichever SDK happens to be installed, so this asserts the property that makes
    both work: the code takes the first two elements and ignores the rest.
    """
    import inspect

    from mcp_gauntlet import client

    src = inspect.getsource(client.open_session)
    assert "as streams" in src, "the transport yield must be bound whole, not destructured"
    assert "streams[0], streams[1]" in src
    assert "as (read, write, _)" not in src, "3-tuple unpack is the 2.0 regression"
