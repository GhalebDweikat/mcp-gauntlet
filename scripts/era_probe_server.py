"""A minimal MCP server built on `mcp` 2.0, for one question only.

Can mcp-gauntlet's current client — pinned to `mcp<2`, requesting protocol revision
2025-11-25 — complete a handshake with a server built on the 2.0 SDK, whose
LATEST_PROTOCOL_VERSION is 2026-07-28? The answer decides whether the remaining
dual-support work is urgent or can wait a month.

Run under its own SDK:
    uv run --isolated --no-project --with "mcp>=2,<3" python modern_server.py
"""

from mcp.server import MCPServer

mcp = MCPServer("modern-probe")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return their sum. Use when the user needs to add two numbers."""
    return a + b


@mcp.tool()
def describe() -> str:
    """Return a short description of this server, to confirm a call round-trips."""
    return "a server built on the mcp 2.0 SDK"


if __name__ == "__main__":
    mcp.run("stdio")
