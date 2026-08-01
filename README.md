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
  and hidden characters across **every server-authored string a client can put in front of
  the model**, in all three MCP primitives: the server's name, title and init instructions;
  each tool's description, display titles, `_meta`, and **both its input and output
  schemas** (nested titles, enums, defaults, examples, `$defs` entries and unknown extension
  keywords included); **prompt** metadata, arguments and the messages `prompts/get` actually
  returns; and **resource** and template metadata. Anything in that set can carry a payload,
  so scanning only top-level `description` fields is trivially evaded by nesting one behind
  a `$ref`, parking it in a display title, or putting it in a prompt — whose messages reach
  the model verbatim. Text is folded to a compatibility skeleton before matching, so
  smuggled invisibles, combining marks, and lookalike alphabets (fullwidth, math-bold) don't
  break a keyword. A critical finding caps the overall grade.
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
- **Definition drift** — did the server change what its tools say *after* you approved
  them? `tools/list` is asked twice per session and the answers compared, and the surface is
  fingerprinted and compared against the previous run. This is the failure registry signing
  can't address: the package is unchanged and correctly signed, only the text served at
  runtime differs. Crucially, a definition that *changed* is then scanned in its own right,
  so a payload that appears only in the second listing raises its own finding rather than a
  bare "something moved". The change itself is reported but never caps on its own — honest
  servers register tools lazily, gate them on auth (MCP has a `tools.listChanged` capability
  for exactly that), and edit descriptions without bumping a static version.

## Leaderboard — withheld for now

There is no live leaderboard. Two boards were published and have been taken down until the
scoring model stops moving; the reasoning is at
**[ghalebdweikat.github.io/mcp-gauntlet](https://ghalebdweikat.github.io/mcp-gauntlet/)** and
the data is kept in `boards-withheld/` rather than deleted, so the corrections stay auditable.

The long version is written up as
**[Eight times my evaluator measured something other than the server](docs/eight-times-i-measured-something-else.md)**
— three families of failure, and they generalise to any eval system.

The short version: inside three days the harness was found to have graded servers on its own
defects three separate times — invented filesystem paths, credential-vocabulary false
positives, and pinning to a registry version that lagged the published package by 23 minor
releases. Each was fixed. But publishing scores about named third parties is the highest-stakes
thing this tool does, and `METHODOLOGY.md` promises those servers advance notice, which they
never got.

Generate your own across any set of servers listed in a JSON file — locally, published nowhere:

```bash
mcp-gauntlet leaderboard --servers leaderboard.servers.json --out board
```

Each server's raw result is saved to `board/servers/<name>.json` alongside its page, so the
site can be rebuilt for free after a presentation change — no re-running, and no re-paying an
LLM provider. `--render-only` does exactly that.

## Quickstart

No install, no API key, no clone — this runs the bundled deliberately-malicious demo
server and shows what a description scanner cannot see:

```bash
uvx mcp-gauntlet run "python -m mcp_gauntlet.fixtures.malicious_server" --no-agentic
```

Or install it properly:

```bash
pip install mcp-gauntlet     # or: uv tool install mcp-gauntlet

# Static + robustness checks only — no API key required
mcp-gauntlet run "python -m mcp_gauntlet.fixtures.good_server" --no-agentic

# Full gauntlet, including the live agent (Groq's free tier works)
export GROQ_API_KEY=gsk_...
mcp-gauntlet run "npx -y @modelcontextprotocol/server-everything"
```

A `.env` file in the working directory is read too, if you prefer that to an export.

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
mcp-gauntlet run "python -m mcp_gauntlet.fixtures.bad_server"   # capped C — tool poisoning
mcp-gauntlet run "python -m mcp_gauntlet.fixtures.good_server"  # A
```

With an LLM key, the bad fixture also trips **Response Safety**: its `status_report`
tool has a clean description but poisons its *output*, so only the runtime scan
catches it — the static description scan can't.

### See what a description scan misses

A third fixture is a working, deliberately malicious server. Every tool has an innocuous
description, so a scanner that reads descriptions finds nothing — the attacks are in a
display title, in an *output* schema behind a `$ref`, in what a tool returns at call time,
in one tool that is completely clean on the first `tools/list` and poisoned on the second,
and in a prompt whose metadata is spotless and whose rendered messages carry the payload:

```bash
mcp-gauntlet run "python -m mcp_gauntlet.fixtures.malicious_server" --no-agentic
```

Four of the five are caught with no API key at all; the call-time one needs the live agent.
The server itself is entirely functional — valid schemas, working tools, 100% task
success — which is the point: it is flagged for what it *says and returns*, not for being
broken.

Because that fixture ships inside the installed package, an MCP security scanner pointed at
your `site-packages` will flag mcp-gauntlet itself. That's expected: the payloads are inert
strings in a test double that touches no filesystem or network, and it prints a warning
banner to stderr on startup.

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
mcp-gauntlet run "npx -y @scope/pkg" --base-url http://localhost:11434/v1 --model llama3.1
```

### Servers that need credentials

A server that talks to GitHub, Slack, or a database needs a token to do anything. Pass one
without putting it in the report or your shell history:

```bash
# stdio server: forward an allow-listed env var (value pulled from your environment)
export GITHUB_TOKEN=ghp_...
mcp-gauntlet run "npx -y @modelcontextprotocol/server-github" --env GITHUB_TOKEN

# remote server: send an auth header
mcp-gauntlet run "https://mcp.example.com" --header "Authorization: Bearer $TOKEN"
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
mcp-gauntlet run "npx -y @modelcontextprotocol/server-everything" --no-agentic
```

Add `--no-probe` for a pure inspection that never executes any of the server's
tools. The leaderboard behaves the same way — with no key it ranks servers on the
static + robustness checks alone.

## Use it in CI

This is where the tool earns its keep: a regression suite for your own MCP server, run on
every pull request. Copy [`examples/gauntlet-ci.yml`](examples/gauntlet-ci.yml) into your
repo as `.github/workflows/gauntlet.yml`, point it at your server, and the build fails on
what it **found**:

```yaml
- name: Run the gauntlet
  run: uvx mcp-gauntlet run "python -m your_server" --no-agentic --fail-on high
```

**Gate on a severity, not a score.** `--fail-on high` fails the build when a HIGH finding
exists — tool poisoning, injection markers, hidden characters. `medium` also catches stdout
pollution, weak descriptions and definition drift; `low` adds undescribed parameters.

`--fail-under` still exists, and is the weaker choice. A HIGH security finding caps the
overall score at 75, so a `--fail-under 60` gate — which this README used to recommend —
**could never fail a poisoned server**: the cap acted as a floor for the gate. A score
threshold also needs re-baselining whenever scoring changes. A severity gate has neither
problem, which is why the example is unpinned: what fails is a finding you can read, not a
number that moved. Pin it if you need a frozen verdict.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Passed |
| `1` | **Gate failed** — a verdict about your server. The only one that should fail a build on quality grounds. |
| `2` | Usage error (bad flag) |
| `3` | **Could not evaluate** — the server didn't start, timed out, or the transport failed. Infrastructure, not quality. |
| `4` | Configuration error — e.g. `--agentic` with no API key |

`3` is separated deliberately. A gate that reports a flaky runner as a quality regression
gets switched off within a week, and everything it would have caught goes with it.

The static + robustness checks need no API key. To include the live agent evaluation, add an
LLM key (e.g. `GROQ_API_KEY`) as a repository secret and pass `--agentic` **explicitly** —
without it, a missing or expired secret silently downgrades to a static run that still exits
0, dropping the heaviest dimension with nothing saying so. The report is uploaded as a build
artifact.

## Development

The commands above are for *using* the tool. To work on it, clone the repo and use the
project environment instead:

```bash
git clone https://github.com/GhalebDweikat/mcp-gauntlet && cd mcp-gauntlet
uv sync --extra dev
uv run mcp-gauntlet run "python -m mcp_gauntlet.fixtures.good_server" --no-agentic

./scripts/gates.sh      # ruff, format, mypy, the fixture-score snapshot, and pytest
```

`scripts/era_fixture_probe.py` builds the same fixture server on `mcp` 1.x and 2.x in
separate environments and fails if the two eras disagree about it.

## License

MIT © Ghaleb Dweikat
