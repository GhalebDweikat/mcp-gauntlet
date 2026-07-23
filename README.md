# mcp-gauntlet

[![CI](https://github.com/GhalebDweikat/mcp-gauntlet/actions/workflows/ci.yml/badge.svg)](https://github.com/GhalebDweikat/mcp-gauntlet/actions/workflows/ci.yml)

**An agentic evaluation harness for MCP servers.** Point it at any
[Model Context Protocol](https://modelcontextprotocol.io) server and it answers
the question the static analyzers don't: **can an AI agent actually accomplish
real tasks using this server's tools?**

## Why

The existing MCP quality tools (`mcp-lighthouse`, `mcp-scorecard`, `mcp-checkup`)
are all **static** — they inspect schemas, count tokens, and lint descriptions.
None of them run an LLM agent against the server to see whether it can actually
complete tasks. That dynamic, agent-in-the-loop evaluation — with a real
**task-success rate**, not just a conformance check — is what mcp-gauntlet does.

> Google Lighthouse tells you your web page is *well-formed*.
> mcp-gauntlet tells you your MCP server is *usable by an agent* — with a
> task-success rate to prove it.

## What it scores

Each run produces a graded report card (JSON + Markdown) across:

- **Schema Health** — valid JSON schemas, typed and described parameters.
- **Description Quality** — can an agent tell when and how to use each tool?
- **Security Signals** — tool-poisoning / prompt-injection markers and hidden
  characters; a critical finding caps the overall grade.
- **Agent Task Success** — a live LLM agent attempts generated tasks using only
  the server's tools; LLM-judged and repeated for a success rate.
- **Tool-Selection Accuracy** — did the agent call the tools it was expected to?
- **Tool Reliability** — did the server's tools execute without error?
- **Robustness** — does the server reject malformed input gracefully?

## Leaderboard

A live leaderboard ranks popular public MCP servers by their gauntlet score:
**[ghalebdweikat.github.io/mcp-gauntlet](https://ghalebdweikat.github.io/mcp-gauntlet/)**

Generate one yourself across any set of servers listed in a JSON file:

```bash
uv run mcp-gauntlet leaderboard --servers leaderboard.servers.json --out docs
```

## Quickstart

```bash
uv sync --extra dev

# Static + robustness checks only — no API key required
uv run mcp-gauntlet run "python -m mcp_gauntlet.fixtures.good_server" --no-agentic

# Full gauntlet, including the live agent (Groq's free tier works)
echo "GROQ_API_KEY=gsk_..." > .env
uv run mcp-gauntlet run "npx -y @modelcontextprotocol/server-everything"
```

The LLM backend is provider-agnostic — any OpenAI-compatible endpoint (Groq by
default; also OpenRouter, Together, or a local Ollama / vLLM). Runs are safe by
default: only read-only tools are exercised unless you pass `--allow-writes`, and
generated task sets are cached so scores are reproducible across runs.

Bundled `good` / `bad` fixture servers make it easy to see the difference:

```bash
uv run mcp-gauntlet run "python -m mcp_gauntlet.fixtures.bad_server"   # capped C — tool poisoning
uv run mcp-gauntlet run "python -m mcp_gauntlet.fixtures.good_server"  # A
```

## Configuration

Configure via a `.env` file (copy [`.env.example`](.env.example) and fill it in)
or real environment variables:

| Variable | Purpose |
|----------|---------|
| `GROQ_API_KEY` / `GEMINI_API_KEY` / `OPENAI_API_KEY` / `OPENROUTER_API_KEY` | API key for the provider the agent should use (only one needed). A free Groq key: [console.groq.com/keys](https://console.groq.com/keys). |
| `MCP_GAUNTLET_PROVIDER` | Which provider: `groq` (default), `gemini`, `openai`, `openrouter`, or `ollama` (local). |
| `MCP_GAUNTLET_MODEL` | Model override for that provider (e.g. `gemini-flash-latest`). Defaults to a sensible per-provider model. |

The `--provider` / `--model` CLI flags override these. The backend is any
OpenAI-compatible endpoint, so the same setup covers cloud providers and a local
Ollama / vLLM.

### No API key? Static mode

Everything except the live agent runs without an LLM. `mcp-gauntlet run <server>`
with no key configured reports a **static grade** from the LLM-free checks —
schema health, description quality, security signals, and robustness probes:

```bash
uv run mcp-gauntlet run "npx -y @modelcontextprotocol/server-everything" --no-agentic
```

Add `--no-probe` for a pure inspection that never executes any of the server's
tools. The leaderboard behaves the same way — with no key it ranks servers on the
static + robustness checks alone.

## License

MIT © Ghaleb Dweikat
