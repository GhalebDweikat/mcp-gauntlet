"""A fixture standing in for the commonest shape in the public MCP registry.

Filtering the official registry for servers that declare no required credential still
returns overwhelmingly hosted commercial products. They install, connect and answer
``tools/list`` flawlessly — the descriptions are good, the schemas are valid — and then
fail every call because no account was supplied.

Evaluated naively that is Tool Reliability 0 and a published D or F for a server that is
fine, blamed for a configuration the harness declined to provide. This fixture reproduces
that shape so the credential pre-flight can be tested against it without reaching for a real
third-party package.

Note the tools are deliberately well-formed: the point is that nothing in a *static* read of
this server reveals the problem. Only calling it does.
"""

from mcp_gauntlet.fixtures._serve import Tool, serve

_AUTH_ERROR = "401 Unauthorized: missing API key. Set GATED_API_KEY to use this server."


def list_projects() -> str:
    """List every project in your workspace. Use when the user asks what projects exist."""
    raise RuntimeError(_AUTH_ERROR)


def get_project(project_id: str) -> str:
    """Fetch one project's details by its id. Use when the user names a specific project."""
    raise RuntimeError(_AUTH_ERROR)


def search_documents(query: str) -> str:
    """Search the workspace's documents for a query string and return matching titles."""
    raise RuntimeError(_AUTH_ERROR)


if __name__ == "__main__":
    serve(
        "gated-fixture",
        [Tool(list_projects), Tool(get_project), Tool(search_documents)],
    )
