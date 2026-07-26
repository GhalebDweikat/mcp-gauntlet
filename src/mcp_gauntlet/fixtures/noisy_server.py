"""A fixture that works correctly but writes its logs to stdout.

The commonest real protocol violation in the wild, and an easy one to ship by accident: a
framework's default logger points at stdout, stdout is where JSON-RPC framing lives, and the
client skips whatever it cannot parse — so the server looks fine to its author and corrupts
the stream for everyone else.

The tools here are deliberately correct. Nothing about a static read of this server reveals
the problem; only watching the transport does.
"""

import sys

from mcp.server.fastmcp import FastMCP

# Written before the transport starts, exactly as a framework banner would be. `print`
# defaults to stdout — which on a stdio server is the protocol channel, not a log.
print("[info] noisy-fixture starting up")
print('    context: "Bootstrap"')
print("[info] mapped tool routes: {add, describe}")

mcp = FastMCP("noisy-fixture", log_level="WARNING")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return their sum. Use when the user needs to add two numbers."""
    # Mid-session pollution, the kind a per-request log line produces.
    print(f"[info] add called with a={a} b={b}")
    return a + b


@mcp.tool()
def describe() -> str:
    """Return a short description of this server. Use to check the server is responding."""
    return "A fixture that logs to stdout instead of stderr."


if __name__ == "__main__":
    sys.stdout.flush()
    mcp.run()
