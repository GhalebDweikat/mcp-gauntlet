# Methodology

How mcp-gauntlet produces a score, what that score does and doesn't mean, and the policies
it follows when publishing results about other people's servers.

This document is versioned with the tool. Every report and every leaderboard row records
the gauntlet version that produced it, because **scores are only comparable within a
version** — adding or reweighting a dimension changes the number without anything changing
about the server.

## Which protocol this targets

mcp-gauntlet evaluates servers against MCP revision **2025-11-25**, the current finalized
spec, and records the revision each server negotiated on its report. A server that requires
a revision this harness does not support is reported as unevaluable *by the harness* — that
is a limitation here, not a defect in the server, and it is never scored as a failure.

A further revision (**2026-07-28**) is in release candidate as of this writing. It replaces
the `initialize` handshake with a `server/discover` probe and moves server-initiated
sampling and elicitation to a client-driven pattern. Everything this tool actually scores —
tool fields and annotations, prompts, resources, content blocks, pagination — is unchanged
or only additively changed by it, but support is deliberately not claimed until it lands.

## The scoring model

Each **subject** — one tool, or the server itself — starts at 100 and loses points per
finding by severity:

| Severity | Penalty | Meaning |
|---|---|---|
| HIGH | 25 | Near-certain defect or attack signal |
| MEDIUM | 12 | Real problem, some interpretation |
| LOW | 5 | Minor or stylistic |
| INFO | 0 | Recorded, never scored |

A **dimension** scores the mean of its per-subject scores, so a large server isn't punished
for having more tools. The **overall** is the weighted mean of the dimensions *present*:

| Dimension | Weight | What it measures | Needs an LLM |
|---|---:|---|---|
| Agent Task Success | 3.0 | A live agent attempts generated tasks using only this server's tools; LLM-judged, repeated for a success rate | yes |
| Security Signals | 2.0 | Static scan for tool-poisoning / prompt-injection markers and hidden characters across every server-authored string a client can show the model — all three primitives: server name/title/`instructions`; tool descriptions, display titles, `_meta`, and every string in each tool's input *and output* schema; prompt metadata, arguments and the messages `prompts/get` actually returns; resource and template metadata | no |
| Tool-Selection Accuracy | 1.5 | Whether the agent called the tools each task was expected to use | yes |
| Schema Health | 1.0 | Valid JSON Schema, typed and described parameters, coherent `required` | no |
| Description Quality | 1.0 | Offline heuristics on description presence and length | no |
| Tool Reliability | 1.0 | Fraction of the agent's tool calls the server executed without error | yes |
| Response Safety | 1.0 | Dynamic scan of what the tools actually **returned** for injection markers | yes |
| Robustness | 1.0 | Whether tools reject malformed, schema-violating input | no |

Definition drift is reported inside **Security Signals** rather than as a dimension of its
own: a server that silently redefines its tools is doing tool-poisoning by another route,
and a new weighted dimension would have changed every published number without anything
about those servers changing. Each drift finding is scored against the tool it concerns, so
it can only ever lower a score — scored as a subject of its own it would have been "100
minus its own penalties", and a harmless INFO would have *raised* the dimension, paying a
server for a check that failed to run.

Grades: **A** ≥ 90, **B** ≥ 80, **C** ≥ 70, **D** ≥ 60, **F** below. A server exposing no
tools grades **N/A** — it is unscored, not perfect.

### The security cap

A HIGH finding in **Security Signals** caps the overall at **75** (a C ceiling), no matter
how strong the other dimensions are. Tool poisoning is a "do not trust this server" signal
that averaging must not wash out.

Only near-certain signals are allowed to cap. Definition drift therefore never caps on its
own, in either direction: MCP defines a `tools.listChanged` capability and the reference
servers all advertise it, so a tool list changing mid-session is documented behaviour, and
plenty of honest servers edit descriptions without bumping a static version. What caps is a
*payload* — the changed definition is scanned like any other text, and its own finding does
the work. Note also that a Python MCP server reports the installed SDK's version unless its
author sets one, so "did the server admit the change?" is a weaker signal than it looks.

**Response Safety deliberately does not cap.** It scans content a server *returned*, and a
fetch or filesystem server may faithfully relay untrusted text it did not author. A HIGH
finding there lowers the score and is shown with a ⚡ on the board, but the judgment of
whether the server is at fault is left to the reader.

## What the score is not

- **Not a security audit.** The static scan is pattern-based. It catches known
  tool-poisoning shapes and hidden-character smuggling; it cannot catch plain-prose social
  engineering, and it will never be complete. A clean security score is not a clean bill of
  health. Known gaps, stated rather than implied: **resource contents are not read** (they
  are unbounded and are passthrough rather than server-authored, so only their metadata is
  scanned), and a prompt that requires arguments is listed but not rendered, so its
  messages go unexamined — inventing argument values would mean calling the server with
  data it never asked for. An unrendered prompt is reported as such rather than counted
  as clean, so the gap is visible in the report instead of being implied away.
- **Not deterministic.** Agent and judge runs are stochastic even at temperature 0. Task
  sets are cached per server so they don't drift between runs, and tasks are repeated and
  averaged, but two runs of the same server can differ by a few points. Treat small gaps as
  noise.
- **Partly a measure of the agent.** A weaker model fails tasks a stronger one completes.
  The model is held constant across a leaderboard and stamped into every report, so rows
  are comparable with each other — not with a run on a different model.
- **Not a measure of what the server does when it's used properly.** Runs are read-only by
  default and tasks are generated, not real workloads.

### Breaking the transport

Over stdio, a server's stdout carries JSON-RPC framing and nothing else — the spec is
explicit. Servers violate this routinely by leaving a framework's default logger pointed at
stdout: a NestJS banner, a stray `print`, a progress bar. Clients skip what they cannot
parse, so the server usually still works and its author never sees a problem.

It is reported anyway, as a **MEDIUM** finding in Security Signals that lowers the score
without capping the grade. It corrupts the stream for every client, not only this one, and a
stricter client may not be so forgiving. It is also a message-injection surface: nothing
distinguishes a startup banner from a log line echoing user-supplied text, and any such line
that happens to parse as JSON-RPC becomes a protocol message the server never meant to send.
It does not cap, because a misdirected logger is a bug rather than an adversary, and only
near-certain attack signals are allowed to cap.

This applies to stdio only. Over HTTP a server's logs go nowhere near the wire.

### Servers that score whatever you point them at

Some servers — filesystem, git, database servers — take a target as configuration. Their
Response Safety score is then largely a property of **the target, not the server**: a
filesystem server rooted at a directory containing credentials will faithfully relay them
and be flagged for it, having done nothing wrong.

This is not hypothetical. An early run of this leaderboard rooted the filesystem server at
the working checkout and pointed the git server at this repository, which produced two
findings that were purely artifacts of one machine: the filesystem row was flagged for a
sentence in a README that mentioned a credential filename, and the git row diffed the
board's own generated HTML and read the previous run's findings back to itself. Neither
result was reproducible by anyone else, and both risked publishing fragments of a private
working tree.

The board therefore points those servers at fixed, committed scan targets
(`leaderboard-sandbox/`, and a scratch repository built by
`scripts/make_leaderboard_fixtures.py`). Every operator scans the same bytes, and a score
means the same thing twice. If you run one of these servers against your own data, read its
Response Safety findings as being about that data.

## Comparability rules

The overall is a weighted mean over the dimensions **present**, so a server the agent never
scored skips Agent Task Success — the heaviest dimension — and is averaged over a smaller
denominator, scoring systematically higher. The leaderboard therefore ranks only servers
that were fully agent-scored. Everything else is listed separately under **Partially
evaluated**, each row stating why, so an untested server can never outrank a tested one. A
run cut short by a hung tool is segregated too: its score rests on however many runs
finished, a sample size the server itself controls.

## Safety when evaluating

- **Read-only by default.** Tools that look mutating — by name, description, or a
  self-declared MCP `destructiveHint` — are excluded from execution unless `--allow-writes`
  is passed. This is a **best-effort heuristic and explicitly not a guarantee**: it trusts
  server-declared hints that the harness cannot verify, and a mislabeled tool will slip
  through.
- **Credentialed runs use sandbox accounts only.** When `--env` or `--header` gives a server
  real credentials, a live agent executes real tool calls against whatever those credentials
  reach. Use a throwaway account, a test workspace, a scratch database — never production.
  Credential values are redacted from reports, the console, the task cache, and error
  messages, but redaction is a backstop, not the control.
- **Interactive capabilities are declined.** The harness drives no user (elicitation) and no
  server-side LLM (sampling). It advertises neither, and a server that requests one is
  declined cleanly. A tool call that failed *only* for that reason is not counted against
  the server's Tool Reliability, and the report says so.

## Publishing results about other people's servers

The leaderboard names third-party servers, so it follows these rules:

1. **Coordinated disclosure.** A HIGH-severity *security* finding on a named third-party
   server is reported privately to its maintainers first, with a **14-day** window before
   that server is named in connection with it. Aggregate figures ("N of M servers returned
   injectable content") may be published immediately, without naming.
2. **Notice before publication.** Any server appearing in a published survey with a low
   score gets advance notice and a link to dispute it.
3. **Disputes are free.** Anyone can contest a score by opening an issue. Re-runs cost
   nothing to request. A finding shown to be a false positive is corrected, and the
   correction is noted rather than quietly swapped in.
4. **Every score carries its provenance** — scan date, gauntlet version, model, and repeat
   count — and every row that could not be evaluated says so, with the reason. Servers are
   never silently dropped.
5. **No pay-to-play.** Placement cannot be bought, and no one is charged for a scan, a
   re-scan, or a badge.

## Reproducing a score

```bash
uvx mcp-gauntlet@<version> run "<the exact spec from the report>" --tasks 3 --repeats 2
```

The report's header records the version, model, task count, and repeats. Task sets are
cached per server (name + version + exposed tools) under `.gauntlet/`, and `--tasks-file`
pins a committable set so the same tasks are used across runs.
