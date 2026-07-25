# mcp-gauntlet

[![CI](https://github.com/GhalebDweikat/mcp-gauntlet/actions/workflows/ci.yml/badge.svg)](https://github.com/GhalebDweikat/mcp-gauntlet/actions/workflows/ci.yml)

**An agentic evaluation harness for MCP servers.** Point it at any
[Model Context Protocol](https://modelcontextprotocol.io) server and it answers
the question the static analyzers don't: **can an AI agent actually accomplish
real tasks using this server's tools?**

## Why

Plenty of tools already inspect MCP servers **statically**: registry quality
scores (Glama, Smithery), security scanners (Snyk Agent Scan, Cisco's
mcp-scanner), and interactive testers (the official MCP Inspector, MCPJam).
Academic benchmarks (MCP-Universe, MCPMark, MCP-Bench) do run live agents — but
over fixed, hand-picked server sets, not as something you can point at *your*
server.

mcp-gauntlet fills the gap between the two: a pip-installable CLI that runs a
live LLM agent against **any** MCP server and measures a real **task-success
rate**, then folds it — together with static checks, robustness probes, and a
runtime scan of what the tools actually **return** — into one graded score you
can gate CI on. To our knowledge, no other *evaluator* scores runtime output
injection: runtime guardrails (MCP gateways, Trail of Bits' context-protector)
protect a session after you've adopted a server, while mcp-gauntlet grades the
server *before* you adopt it — catching a server that looks clean at list-time
but poisons at call-time.

> Google Lighthouse tells you your web page is *well-formed*.
> mcp-gauntlet tells you your MCP server is *usable by an agent* — with a
> task-success rate to prove it.

## What it scores

Each run produces a graded report card (JSON + Markdown) across:

- **Schema Health** — valid JSON schemas, typed and described parameters.
- **Description Quality** — can an agent tell when and how to use each tool?
- **Security Signals** — a *static* scan for tool-poisoning / prompt-injection markers
  and hidden characters, covering the server's init instructions, its tool descriptions,
  and **every string in each tool's input schema** — titles, enums, defaults, examples,
  `$defs` entries and unknown extension keywords included. The whole schema is serialized
  into the model's prompt, so any string in it can carry a payload; scanning only
  `description` fields at the top level is trivially evaded by nesting one behind a
  `$ref`. A critical finding caps the overall grade.
- **Agent Task Success** — a live LLM agent attempts generated tasks using only
  the server's tools; LLM-judged and repeated for a success rate.
- **Tool-Selection Accuracy** — did the agent call the tools it was expected to?
- **Tool Reliability** — did the server's tools execute without error?
- **Response Safety** — a *dynamic* scan of the tools' live **outputs** for the
  same injection / poisoning markers, catching a server that looks clean at
  list-time but poisons at call-time. Reported (and it lowers the score) but
  doesn't cap on its own, since a fetch/filesystem server may faithfully pass
  through untrusted content.
- **Robustness** — does the server reject malformed input gracefully? A tool that
  publishes no argument schema at all scores zero here rather than being skipped:
  a server that declares no contract can't reject anything, and skipping it would
  make omitting schemas a way to score higher.

## Leaderboard

A live leaderboard ranks popular public MCP servers by their gauntlet score:
**[ghalebdweikat.github.io/mcp-gauntlet](https://ghalebdweikat.github.io/mcp-gauntlet/)**

Generate one yourself across any set of servers listed in a JSON file:

```bash
uv run mcp-gauntlet leaderboard --servers leaderboard.servers.json --out docs --board-url https://you.github.io/mcp-gauntlet
```

Each server's raw result is saved to `servers/<name>.json` alongside its page, so the
site can be rebuilt for free after a presentation change — no re-running (or re-paying
for) the evaluation:

```bash
uv run mcp-gauntlet leaderboard --render-only --out docs
```

Only servers the agent actually scored share the ranked table. The overall is a weighted
mean over the dimensions *present*, so a server the agent never ran against — no LLM
configured, the backend rate-limited it, or every tool was excluded as possibly-mutating —
skips Agent Task Success (the heaviest dimension) and would score systematically higher on
a smaller denominator. Those are listed separately under **Partially evaluated**, each with
the reason it wasn't ranked, rather than mixed in where an untested server could outrank a
tested one.

Every row shows the date its score was **measured**, not when the page was last rebuilt,
and the board names the gauntlet versions behind its numbers — scoring changes between
releases, so scores are only comparable within a version.

### Badges

Each listed server gets a [shields.io endpoint](https://shields.io/badges/endpoint-badge)
document at `badges/<slug>.json`, so its author can show a live grade in their README:

```markdown
[![mcp-gauntlet](https://img.shields.io/endpoint?url=https://ghalebdweikat.github.io/mcp-gauntlet/badges/sqlite.json)](https://ghalebdweikat.github.io/mcp-gauntlet/)
```

The badge tracks the published board, so it updates when the board is regenerated. A server
that fails to evaluate reads *not evaluated* rather than keeping its last grade, and
`--render-only` retires the badge of any server no longer in `servers/`.

Renaming a server changes its slug, which leaves the old saved result — and so the old
badge — in place. Delete the stale `servers/<old-slug>.json` and re-render to retire it.
Saved results are never removed automatically: they are the paid-for measurements that make
`--render-only` free.

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
default; also OpenRouter, Together, or a local Ollama / vLLM). Transient 429/5xx
responses are retried with bounded backoff, so a free-tier rate limit costs a
short wait, not the run — only a truly exhausted quota (a long Retry-After) makes
a run inconclusive. Runs are read-only by
default: tools that *look* mutating (by name/description or a self-declared MCP
`destructiveHint`) are excluded unless you pass `--allow-writes`. That exclusion is a
best-effort heuristic, not a guarantee — pair it with read-only credentials or a
throwaway environment for untrusted servers. Generated task sets are cached so scores
are reproducible across runs.

Bundled `good` / `bad` fixture servers make it easy to see the difference:

```bash
uv run mcp-gauntlet run "python -m mcp_gauntlet.fixtures.bad_server"   # capped C — tool poisoning
uv run mcp-gauntlet run "python -m mcp_gauntlet.fixtures.good_server"  # A
```

With an LLM key, the bad fixture also trips **Response Safety**: its `status_report`
tool has a clean description but poisons its *output*, so only the runtime scan
catches it — the static description scan can't.

A server that hangs can't stall the run: every tool call is bounded by
`--tool-timeout` (default 60s) and recorded as a failed call against the server's Tool
Reliability, and `--timeout` (default 900s, `0` disables) caps the evaluation as a whole
so a server that hangs during connect or `tools/list` still can't wedge the CLI. Raise
`--tool-timeout` if a server is legitimately slow rather than stuck — the report says so
when the limit is what stopped it.

## Configuration

Configure via a `.env` file (copy [`.env.example`](.env.example) and fill it in)
or real environment variables:

| Variable | Purpose |
|----------|---------|
| `GROQ_API_KEY` / `GEMINI_API_KEY` / `OPENAI_API_KEY` / `OPENROUTER_API_KEY` | API key for the provider the agent should use (only one needed). A free Groq key: [console.groq.com/keys](https://console.groq.com/keys). |
| `MCP_GAUNTLET_PROVIDER` | Which provider: `groq` (default), `gemini`, `openai`, `openrouter`, or `ollama` (local). |
| `MCP_GAUNTLET_MODEL` | Model override for that provider (e.g. `gemini-flash-latest`). Defaults to a sensible per-provider model. |

The `--provider` / `--model` CLI flags override these, and `--base-url` points at
any OpenAI-compatible endpoint — a local Ollama / vLLM / LM Studio or a gateway.
A keyless local endpoint needs no key configured at all; if your endpoint or
gateway does want one, pass `--api-key` (or the provider's env var):

```bash
uv run mcp-gauntlet run "npx -y @scope/pkg" --base-url http://localhost:11434/v1 --model llama3.1
```

### Servers that need credentials

A server that talks to GitHub, Slack, or a database needs a token to do anything. Pass one
without putting it in the report or your shell history:

```bash
# stdio server: forward an allow-listed env var (value pulled from your environment)
export GITHUB_TOKEN=ghp_...
uv run mcp-gauntlet run "npx -y @modelcontextprotocol/server-github" --env GITHUB_TOKEN

# remote server: send an auth header
uv run mcp-gauntlet run "https://mcp.example.com" --header "Authorization: Bearer $TOKEN"
```

`--env`/`--header` are repeatable. Only the variables you name are forwarded — the child
process otherwise gets a minimal safe environment, not your whole shell. Credential values
are redacted from the report, the console, and the task cache, so a server that echoes its
own token back can't leak it into a committed artifact. **Point credentialed runs at
sandbox or throwaway accounts:** the read-only filter trusts a server's own
`readOnlyHint`/name and is defense-in-depth, not a guarantee, so a mislabeled tool could
still act on a real account.

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

## Use it in CI

Gate your MCP server's pull requests on its gauntlet score. Copy
[`examples/gauntlet-ci.yml`](examples/gauntlet-ci.yml) into your server's repo as
`.github/workflows/gauntlet.yml`, point it at your server, and the build fails
when the score drops below your threshold:

```yaml
- name: Run the gauntlet
  run: uvx mcp-gauntlet@0.3.0 run "python -m your_server" --no-agentic --fail-under 60
```

Pin the version, as above: an unpinned `uvx mcp-gauntlet` would let a new release move
your gate without a commit.

The static + robustness checks need no API key. To include the live agent
evaluation, add an LLM key (e.g. `GROQ_API_KEY`) as a repository secret and drop
`--no-agentic`. The report is uploaded as a build artifact.

## License

MIT © Ghaleb Dweikat
