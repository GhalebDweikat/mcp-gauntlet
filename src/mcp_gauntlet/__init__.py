"""mcp-gauntlet: an agentic evaluation harness for MCP servers."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcp-gauntlet")
except PackageNotFoundError:  # running from a source tree that isn't installed
    __version__ = "0.0.0+dev"
