# mcp-gauntlet

[![CI](https://github.com/GhalebDweikat/mcp-gauntlet/actions/workflows/ci.yml/badge.svg)](https://github.com/GhalebDweikat/mcp-gauntlet/actions/workflows/ci.yml)

**A regression suite for your MCP server.** Run it in CI and it catches what you cannot
catch by reading your own code: a payload that only appears when a tool is *called*, a
definition that changes between two `tools/list` calls, a tool that silently accepts
malformed input, a description no agent can act on.

It fails your build on what it **found** — a finding with a name and a location — not on a
score.

What it does **not** catch is written down too: the security checks are pattern-based, and
[docs/known-gaps.md](docs/known-gaps.md) lists, by class, what has been demonstrated to slip
past them — including the most commonly reported real-world poisoning shape. Read it before
you treat a clean report as a clearance.

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

### Pointing it at your own server

This is the case the tool exists for, so it is worth being explicit. Give the **interpreter**
that has your server's dependencies, not a bare `python`:

```bash
# A Python server in a virtualenv — use the venv's interpreter explicitly
mcp-gauntlet run "/path/to/proj/.venv/bin/python -m my_server" --no-agentic
mcp-gauntlet run "C:\path\to\proj\.venv\Scripts\python.exe -m my_server" --no-agentic

# Node
mcp-gauntlet run "node /path/to/proj/dist/index.js" --no-agentic

# A path containing spaces — use SINGLE quotes inside the spec. The spec is parsed
# POSIX-style, so double quotes are consumed by your shell before the tool sees them and
# the path silently splits into extra arguments.
mcp-gauntlet run "C:\Tools\python.exe 'C:\Users\Jane Smith\proj\server.py'" --no-agentic

# A remote server, with auth
mcp-gauntlet run "https://mcp.example.com" --header "Authorization: Bearer $TOKEN"
```

Two things that bite people, both worth knowing before they cost you a debugging cycle:

- **A bare `python` is not your `python`.** Under `uvx`, the gauntlet's own environment comes
  first on `PATH`, so `python -m my_server` runs under *its* interpreter — which does not
  have your server's dependencies and fails with an import error that looks like your bug.
- **Relative paths resolve from wherever you ran the command**, not from your server's
  directory. Absolute paths avoid the whole question.

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

## Why

Plenty of tools already inspect MCP servers **statically**: registry quality
scores (Glama, Smithery), security scanners (Snyk Agent Scan, Cisco's
mcp-scanner), and interactive testers (the official MCP Inspector, MCPJam).
Academic benchmarks (MCP-Universe, MCPMark, MCP-Bench) do run live agents — but
over fixed, hand-picked server sets, not as something you can point at *your*
server.

mcp-gauntlet is for the person who **maintains** the server, and its distinguishing
checks are the *dynamic* ones — the things you cannot learn by reading a file:

- it **calls** your tools and scans what came back, so a server that is clean at list-time
  and poisons at call-time is caught;
- it asks `tools/list` **twice** and re-scans anything that changed, so a definition that
  differs between the two answers raises its own finding;
- it feeds each tool **malformed input** and checks that the tool rejects it;
- with an API key it drives a **live agent** through generated tasks, which is the only way
  to find out whether your descriptions are good enough to act on.

Static scanners read your code. This runs your server.

**What it is not:** a ranking. It does not tell you whether someone else's server is better
than yours, and it deliberately publishes no leaderboard — scores move when a stage is
skipped or between releases, which is fine for watching one server over time and is not fine
for a sorted table. See [What the score is not](METHODOLOGY.md).

## What it scores

Each run writes `report.json`, `report.md` and `report.html` into `--out`, graded across:

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

  Note which half runs where. The *within-session* check — `tools/list` twice, one
  connection — always works. The *across-run* check compares against a fingerprint stored
  under `.gauntlet/baselines/`, and a fresh CI runner (`actions/checkout` + `uvx`) has no
  previous run to compare with, so a tool that was silently **deleted** is invisible there.
  Cache or commit `.gauntlet/baselines/` if you want that check in CI.

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

Add `--no-probe` for a pure inspection that never executes any of the server's tools.

### Several servers at once

If you maintain more than one, `scan` runs them all and gates on the worst finding across
the set. An unreachable server is reported but does **not** fail the gate — that exits 3, not
1, because "could not evaluate this" is a different fact from "this one is bad".

```bash
mcp-gauntlet scan --servers my-servers.json --no-agentic --fail-on high
```

```json
{"servers": [
  {"name": "notes",   "spec": "python -m notes_server"},
  {"name": "billing", "spec": "node dist/billing.js"},
  {"name": "search",  "spec": "https://search.internal/mcp",
   "headers": ["Authorization: Bearer $SEARCH_TOKEN"]},
  {"name": "warehouse", "spec": "python -m warehouse_server",
   "env": ["WAREHOUSE_TOKEN"]}
]}
```

`env` and `headers` take the same forms as `run --env` and `--header`: a bare `"TOKEN"`
reads the value from the environment, so **the secret is never in the committed file**;
`"NAME=value"` inlines one. Credential values are scrubbed from every report.

Two things this file will not do quietly. An unknown key is an **error** naming the key, not
something ignored — a dropped `"env"` you thought was wired up is worse than a failed load.
And a credential that resolves to nothing fails the whole scan before it starts (exit 4)
rather than turning into one unevaluable server (exit 3), because exit 3 is the code you are
told not to fail builds on. That includes a variable that is *set but empty*, which is what
GitHub Actions gives a fork PR for `${{ secrets.TOKEN }}`. Use `"NAME="` if you genuinely
mean empty.

Each server gets its own report directory. Nothing is ranked and no grades are compared side
by side — see [What this does and does not claim](METHODOLOGY.md).

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

**`--fail-on low` is not usable yet on servers built with the official Python SDK.** That SDK
does not carry a docstring's `Args:` section into the JSON schema, so every parameter comes
through undescribed and a perfectly good server emits a LOW finding per argument. The bundled
`good_server` — an A grade — trips it four times. Treat `low` as aspirational until either
the SDK propagates them or this check learns to tell "undocumented" from "the SDK dropped
it"; `medium` is the strict gate that actually works today.

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
| `3` | **Could not evaluate** — the server didn't start, timed out, the transport failed, the tool list was unreadable, or `--agentic` was asked for and the LLM backend errored on every call. Infrastructure, not quality. |
| `4` | Configuration error — e.g. `--agentic` with no API key configured at all, or an unwritable `--out` |
| `130` | Interrupted (Ctrl-C). The child server is reaped; no report is written. |

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
