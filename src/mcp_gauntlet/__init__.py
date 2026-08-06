"""mcp-gauntlet: a CI linter for an MCP server, plus a live-agent evaluation of it."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcp-gauntlet")
except PackageNotFoundError:  # running from a source tree that isn't installed
    __version__ = "0.0.0+dev"
