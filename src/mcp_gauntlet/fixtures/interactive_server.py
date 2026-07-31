"""A fixture MCP server that requests interactive capabilities the harness declines.

mcp-gauntlet drives no user or LLM for a server to call back into, so a tool that
requires *elicitation* (a user prompt) can't complete here. This fixture exists to
prove the harness counts such server-initiated requests and attributes the resulting
tool failure to its own limitation rather than to the server's Tool Reliability.
"""

from typing import TYPE_CHECKING

from pydantic import BaseModel

from mcp_gauntlet.fixtures._serve import Tool, context_type, serve

if TYPE_CHECKING:  # the pinned SDK's class, so the annotation type-checks
    from mcp.server.fastmcp import Context
else:
    # At runtime it must be the class the INSTALLED SDK injects on: both eras decide by
    # inspecting this annotation, and the wrong class turns `ctx` into an ordinary argument
    # that shows up in the tool's input schema.
    Context = context_type()


class Confirmation(BaseModel):
    confirm: bool


async def confirm_and_run(item: str, ctx: Context) -> str:
    """Ask the user to confirm, then act on the item. Needs a client that supports
    elicitation (a confirmation prompt); without one, the action cannot proceed."""
    result = await ctx.elicit(message=f"Proceed with {item}?", schema=Confirmation)
    if getattr(result, "action", None) == "accept":
        return f"Ran {item}."
    return f"Declined: no confirmation for {item}."


def echo(text: str) -> str:
    """Return the text unchanged. Needs no interaction — always works."""
    return text


if __name__ == "__main__":
    serve("interactive-fixture", [Tool(confirm_and_run), Tool(echo)])
