# mcp-gauntlet — Build Plan

> An agentic evaluation harness for MCP servers. Point it at any Model Context
> Protocol server and it answers the question the static analyzers don't:
> **can an AI agent actually accomplish real tasks using this server's tools?**

Status: planning (pre-scaffold). Target: a 3–4 day build, ~8–10 hrs/day.
Author: Ghaleb Dweikat.

---

## 1. Why this project

The 2026 hiring research is consistent: RAG and agents are table stakes, and the
real differentiator is **evals** — being able to *measure* AI-system quality.
"Eval engineer" is emerging as its own title. Recruiters ask for a GitHub link
and a live demo with quantified metrics before they ask for a resume.

MCP is the other hot surface: 20,000+ servers exist, most AI coding tools speak
it, and there is no standard way to judge whether a given server is any good.

The intersection — **evals for MCP servers** — is where mcp-gauntlet sits.

### What already exists (and why we're not building it)

Three static analyzers already ship on PyPI (see [docs/prior-art.md](docs/prior-art.md)):

- `mcp-lighthouse` — 21 conformance checks, Lighthouse-style compliance score.
- `mcp-scorecard` — token footprint, use-case scoping, security, name safety.
- `mcp-checkup` — token consumption + security hygiene.

**All three are static.** They inspect schemas, count tokens, and lint
descriptions. **None of them run an LLM agent against the server to see whether
it can actually complete tasks.** That dynamic, agent-in-the-loop evaluation is
the open gap — and it's the piece that demonstrates real eval engineering rather
than protocol plumbing.

### The one-line pitch

> Google Lighthouse tells you your web page is *well-formed*. mcp-gauntlet tells
> you your MCP server is *usable by an agent* — with a task-success rate to prove it.

---

## 2. What it does

Point it at a server (a stdio command or an HTTP URL). It runs a **gauntlet** of
graded trials and produces a scorecard.

```
mcp-gauntlet run "npx -y @modelcontextprotocol/server-filesystem /tmp"
mcp-gauntlet run https://my-server.example.com/mcp --model claude-opus-4-8
mcp-gauntlet run ./config.yaml --repeats 3 --report html
```

### Scoring dimensions (the gauntlet)

| # | Dimension | Type | What it measures |
|---|-----------|------|------------------|
| 1 | Schema Health | static | Valid JSON schemas, required fields, well-formed tool defs |
| 2 | Description Quality | LLM-judge | Can an agent tell *when & how* to use each tool from its description alone? |
| 3 | **Agent Task Success** | **dynamic** | **Success rate across auto-generated, rubric-graded tasks — the headline metric** |
| 4 | Tool-Selection Accuracy | dynamic | Did the agent pick the right tool(s) for the task? |
| 5 | Robustness | dynamic | Tool-call error rate; recovery from bad inputs/malformed args |
| 6 | Efficiency | dynamic | Turns + tokens per successful task |
| 7 | Security Signals | static | Tool-poisoning / prompt-injection patterns in descriptions; overly-broad tools |

Dimensions roll up into per-tool grades and an overall grade (0–100 / A–F).

Dimension 7 is where a **Certified Penetration Testing** background becomes a
credible, rare story: "security-aware GenAI engineer." Ground it in the real
tool-poisoning literature (Invariant Labs, OWASP MCP Top 10).

### Proper eval methodology (the resume talking point)

Agents are stochastic, so a single pass is meaningless. Every task runs **N
times** (default 3) and we report a **success rate with variance**, not a
pass/fail. This is the difference between "I ran a demo" and "I built an eval
harness."

---

## 3. Architecture

```
                 ┌─────────────────────────────────────────────┐
   CLI (typer)   │  mcp-gauntlet run <server-spec> [flags]     │
                 └───────────────┬─────────────────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────────┐
         ▼                       ▼                           ▼
   MCP Client              Task Generator                Reporter
   (mcp SDK,               (LLM: schemas →               (JSON + Markdown
    stdio / HTTP)           gradeable tasks+rubrics)      + self-contained HTML)
         │                       │                           ▲
         │ tools/list            │ tasks                     │ scorecard
         ▼                       ▼                           │
   ┌──────────────────────────────────────────────────┐     │
   │ Eval Engine                                       │─────┘
   │  • MCP→OpenAI tool-schema bridge                  │
   │    (provider-agnostic; Groq first)                │
   │  • Agent loop over a tool-calling model, w/ trace │
   │  • Safe mode: read-only gate (--allow-writes)     │
   │  • Repeats (N) → success rate + variance          │
   │  • Grader: LLM-judge (rubric) + deterministic     │
   │    checks (tool selection, call validity, errors) │
   └──────────────────────────────────────────────────┘
```

### Key technical decisions

- **Language: Python 3.11+.** Matches the author's data-science background and
  the richest MCP + Anthropic tooling ecosystem.
- **MCP client: the official `mcp` Python SDK** (stdio + Streamable HTTP transports).
- **LLM backend: provider-agnostic, OpenAI-compatible.** The agent loop and the
  judge talk to any OpenAI-compatible endpoint via the `openai` SDK with a
  configurable `base_url`/`model`. First backend: **Groq free tier** (free, fast,
  tool-calling models) so the tool runs with no paid account. The same code path
  covers OpenRouter, Together, and local Ollama / vLLM / LM Studio; a native
  Claude adapter can be added later. MCP tool schemas are converted to OpenAI
  function-calling format ourselves (a few lines — no vendor helper).
- **Model is configurable and always recorded.** Provider/model set via env +
  flags. Because a weaker agent can fail a task for its *own* reasons rather than
  the server's, we (a) hold the model constant across servers in any comparison,
  (b) stamp the exact model into every report and leaderboard row, and (c) keep
  the model pluggable so a frontier model can produce "official" scores. This is
  eval rigor, not a shortcut.
- **Safe by default.** The harness runs an autonomous agent that executes real
  tool calls. Default to a read-only mode (heuristic + server-declared
  read-only); mutating tools require `--allow-writes`. This is an
  engineering-maturity signal and ties to the security angle.
- **Bundled fixture servers.** Ship a trivially-good and a deliberately-bad local
  MCP server as fixtures. They (a) give the tool something to run against with
  zero external credentials, (b) double as the test suite, and (c) make a great
  README demo ("watch it catch the bad server").

### Outputs

- `report.json` — machine-readable, for CI.
- `report.md` — human-readable scorecard.
- `report.html` — self-contained, styled (great for the README/demo).
- Exit code reflects pass/fail against a configurable threshold (CI-friendly).

**UI decision (settled):** the tool is **command-line only**; the "UI" is the
generated static HTML report plus a static GitHub Pages leaderboard site (Day 4).
No live/interactive dashboard server in scope — it would eat the budget, add
frontend risk, and doesn't match how an eval harness is actually used (CI +
reports). An interactive dashboard is an explicit phase-2, post-core stretch.

---

## 4. Day-by-day plan

Days 1–3 are the must-haves. Day 4 is what makes it *land* as a portfolio piece.
Flex/cut lines are called out per day.

### Day 1 — Foundations + static layer
- Repo scaffold: `uv` project, package layout, `pyproject.toml`, MIT `LICENSE`,
  `ruff` + `mypy`, `pytest`, GitHub Actions CI for the repo itself.
- CLI skeleton (typer) + config model (pydantic): server-spec parsing (stdio
  command | HTTP URL | YAML config).
- MCP client: connect over stdio and Streamable HTTP; `tools/list`; robust
  timeouts + error handling.
- Static checks: schema validity, description linting, token footprint
  (`count_tokens`), security lint (injection/tool-poisoning patterns).
- Report renderer skeleton (JSON + Markdown).
- **Milestone:** `mcp-gauntlet run <server>` connects to a real public server (or
  bundled fixture) and prints a static report.

### Day 2 — Agentic eval engine core
- LLM backend wiring (Groq / OpenAI-compatible via the `openai` SDK); MCP→OpenAI
  tool-schema bridge; agent loop with **only** the server's tools; capture a full
  trace (calls, args, results, tokens, turns).
- Task generator: Claude produces gradeable tasks + rubrics from tool
  schemas/descriptions; support a user-supplied task file.
- Safe mode: read-only classification + `--allow-writes` gate.
- **Milestone:** run one generated task end-to-end against a real server and
  capture a structured trace.
- **Flex:** task-file input can slip to Day 3 if generation takes longer.

### Day 3 — Scoring, repeats, robustness, full report
- Grader: LLM-as-judge against the rubric + deterministic checks (tool-selection
  accuracy, call validity, error recovery).
- Repeats (N=3) → success rate + variance; aggregate to per-tool + overall grades.
- Robustness probes (malformed args, error handling) + efficiency metrics.
- Full report: graded scorecard, per-dimension breakdown → self-contained HTML +
  Markdown + JSON; CI exit code.
- **Milestone:** a full graded report card for a real server.
- **Flex:** robustness probes are the first thing to cut if time is short.

### Day 4 — Launch, polish, packaging
- Run against 8–15 popular public MCP servers → **leaderboard table**.
- **GitHub Pages leaderboard** — publish the leaderboard as a static site
  (generated HTML, no backend; reuses the report renderer). This is the
  clickable "wow" artifact for the resume/demo — a live URL ranking real
  public MCP servers by gauntlet score.
- README that leads with metrics + links the leaderboard; demo GIF/asciinema.
- Packaging: `uvx mcp-gauntlet ...`, versioning, `CONTRIBUTING.md`.
- Example GitHub Action ("run the gauntlet on your MCP server in CI").
- **Flex:** leaderboard breadth (8 vs 15 servers) scales to remaining time.

---

## 5. Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| Public MCP servers need auth/tokens (setup friction) | Bundled good/bad fixture servers — zero-credential demo + tests |
| Cost of tasks × repeats × servers | Configurable model (cheap model for demo runs), `--max-tasks`, cost estimate before running, cache results |
| Agent nondeterminism | Repeats + variance reporting — turn the weakness into a methodology talking point |
| Autonomous agent hits side-effecting tools | Safe mode default; `--allow-writes` gate; run destructive evals only against fixtures |
| Scope creep across 7 dimensions in 3–4 days | Dynamic task-success (dim 3) is the headline; others degrade gracefully. Ship dim 3 well before polishing 5/6/7 |

---

## 6. Resume narrative (what this proves)

- **Evals** — the 2026 differentiator — as the centerpiece, with real methodology
  (repeats, variance, LLM-judge + deterministic grading, rubrics).
- **Agents + MCP + tool use** via a genuine agent loop over a provider-agnostic
  LLM backend (an architecture decision, not just an API call).
- **Production maturity** — CLI, CI, packaging (`uvx`), safe-by-default design,
  cost awareness, quantified README.
- **Security-aware GenAI** — the tool-poisoning dimension, credible via a
  pentesting background. A rare, hireable combination.
- **A launch hook** — the public-server leaderboard is the kind of "who scored
  worst?" artifact that gets a repo noticed.

---

## 7. Open questions (to resolve during the build)

- Agent loop: a small hand-rolled loop over `openai` chat-completions
  tool-calling (provider-agnostic) — no vendor-specific runner needed.
- Default judge model — same as the agent model, or a fixed judge for
  consistency across runs? Leaning fixed judge (recorded in the report).
- Groq model choice for the agent-under-test (e.g. `llama-3.3-70b-versatile`)
  and how much its tool-calling limits affect task-success attribution.
- Leaderboard: which 8–15 public servers, and how to handle the credentialed ones.
