# mcp-gauntlet

**An agentic evaluation harness for MCP servers.** Point it at any
[Model Context Protocol](https://modelcontextprotocol.io) server and it answers
the question the static analyzers don't: **can an AI agent actually accomplish
real tasks using this server's tools?**

> 🚧 Early development. The plan lives in [PLAN.md](PLAN.md); the competitive
> landscape and rationale are in [docs/prior-art.md](docs/prior-art.md).

## Why

The existing MCP quality tools (`mcp-lighthouse`, `mcp-scorecard`, `mcp-checkup`)
are all **static** — they inspect schemas, count tokens, and lint descriptions.
None of them run an LLM agent against the server to see whether it can actually
complete tasks. That dynamic, agent-in-the-loop evaluation — with a real
**task-success rate**, not just a conformance check — is what mcp-gauntlet does.

> Google Lighthouse tells you your web page is *well-formed*.
> mcp-gauntlet tells you your MCP server is *usable by an agent* — with a
> task-success rate to prove it.

## Quickstart (work in progress)

```bash
# Install (from source, for now)
uv sync --extra dev

# Discover a server's tools (Day-1 slice — more to come)
uv run mcp-gauntlet run "npx -y @modelcontextprotocol/server-everything"
uv run mcp-gauntlet run https://my-server.example.com/mcp
```

## Status

See [PLAN.md](PLAN.md) for the full roadmap. Currently implementing the Day-1
foundation: server connection (stdio + HTTP) and tool discovery.

## License

MIT © Ghaleb Dweikat
