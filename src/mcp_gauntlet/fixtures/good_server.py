"""A well-behaved MCP server fixture: clear descriptions, typed schemas, tools that work."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("good-fixture", log_level="WARNING")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return their sum. Use when the user needs to add two numbers."""
    return a + b


@mcp.tool()
def echo(message: str) -> str:
    """Echo the provided message back verbatim. Use to repeat a piece of text exactly."""
    return message


@mcp.tool()
def reverse(text: str) -> str:
    """Return the input text reversed character by character. Use to reverse a string."""
    return text[::-1]


if __name__ == "__main__":
    mcp.run()
