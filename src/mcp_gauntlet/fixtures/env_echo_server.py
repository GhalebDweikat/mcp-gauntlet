"""A test-only fixture whose tool echoes an environment variable.

Used to prove that ``--env`` reaches a stdio child process and that the value is then
redacted from the report. Not a demo of good server design — it deliberately returns a
credential-shaped value so the redaction path has something to scrub.
"""

import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("env-echo-fixture", log_level="WARNING")


@mcp.tool()
def whoami() -> str:
    """Return the value of the MCP_GAUNTLET_TEST_TOKEN environment variable, or '<unset>'."""
    return os.environ.get("MCP_GAUNTLET_TEST_TOKEN", "<unset>")


if __name__ == "__main__":
    mcp.run()
