"""A well-behaved MCP server fixture: clear descriptions, typed schemas, tools that work."""

from mcp_gauntlet.fixtures._serve import Tool, serve


def add(a: int, b: int) -> int:
    """Add two integers and return their sum. Use when the user needs to add two numbers."""
    return a + b


def echo(message: str) -> str:
    """Echo the provided message back verbatim. Use to repeat a piece of text exactly."""
    return message


def reverse(text: str) -> str:
    """Return the input text reversed character by character. Use to reverse a string."""
    return text[::-1]


if __name__ == "__main__":
    serve("good-fixture", [Tool(add), Tool(echo), Tool(reverse)])
