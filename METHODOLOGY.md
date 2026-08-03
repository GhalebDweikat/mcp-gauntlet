# Methodology

How mcp-gauntlet produces its findings and its score, and what each does and does not mean.

This document is versioned with the tool. Every report records the gauntlet version that
produced it, because **scores are only comparable within a version** — adding or reweighting a dimension changes the number without anything changing
about the server.

## Which protocol this targets

mcp-gauntlet runs on either MCP SDK era and records both the revision each server negotiated
**and** the SDK that measured it (`mcp_sdk_version` on every report). Those are two different
facts: one is what the *server* agreed to speak, the other is what the *harness* read. A
server requiring a revision this harness cannot speak is reported as unevaluable *by the
harness* — a limitation here, not a defect in the server, and never scored as a failure.

Revision **2026-07-28 finalized on schedule**, and `mcp` SDK 2.0.0 shipped the same day. The
pin is now `mcp>=1.9,<3`, so a resolver may pick either. Every SDK field is read through one
adapter per era, and CI runs the full suite against both, plus a probe that builds the same
fixture server on each SDK and fails if the two eras disagree about it. Still upper-bounded:
2.0 renamed every field to snake_case, and the old reads did not raise — they returned their
defaults, so the checks built on them would have measured nothing and called every server
clean. A major bump is exactly when that recurs.

One thing worth stating plainly, because it bounds what the dual support means: a 2.0-built
server **negotiates down** to 2025-11-25 rather than refusing a legacy client — measured, not
assumed (`scripts/era_probe.py`). So the two eras are mostly a question of which field names
the harness reads, not which servers it can reach.

Three checks come from the newer revision: an argument mapped into an `Mcp-Param-*` request
header via `x-mcp-header` (reported when the argument is secret-named, or when the annotation
is invalid — in which case compliant clients must drop the tool entirely), a `$ref` pointing
off the document, and a `logging` capability advertised on a connection that deprecates it.
The last is gated on the negotiated revision: advertising `logging` under 2025-11-25 is
correct behaviour and is never reported.

Two corrections to what was written here before it landed, since both were repeated widely:
`server/discover` does **not** replace the `initialize` handshake — it is optional for clients,
and the protocol version rides in `_meta` on every request. And output schemas did not become
"unrestricted"; they are still objects. What did change, and does affect a client, is that
server-initiated sampling and elicitation are forbidden in favour of an `input_required`
result, and every SDK field was renamed to snake_case.

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
finding there lowers the score, but the judgment of
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
  The model is stamped into every report, so runs
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

This is not hypothetical. An early run rooted the filesystem server at
the working checkout and pointed the git server at this repository, which produced two
findings that were purely artifacts of one machine: the filesystem row was flagged for a
sentence in a README that mentioned a credential filename, and the git row diffed the
board's own generated HTML and read the previous run's findings back to itself. Neither
result was reproducible by anyone else, and both risked publishing fragments of a private
working tree.

So point such a server at a fixed, committed scan target rather than at your working tree,
and the same bytes are scanned every run. If you point one at live data instead, read its
Response Safety findings as being about *that data* rather than about the server.

## What this does and does not claim

mcp-gauntlet is a CI linter for what a server **you maintain** publishes, plus a live probe
and a change detector. Every claim below is scoped to that.

**It does not exercise your server's behaviour.** In the configuration these docs recommend
for CI (`--no-agentic`), the only things executed are one well-formed call per candidate
read-only tool and one malformed one — enough to establish that the server answers and that
it rejects what it declared invalid, and nothing like a test of what it *does*. A tester put
it plainly: "I'd adopt it as a poisoning and schema linter, not as the regression suite it
says it is." They were right, and the docs say so now. It sits beside your integration tests;
it does not replace them.

**A finding is the product.** Each one names a tool, a field and what is wrong with it, and
is meant to be acted on. That is the part that has held up under adversarial testing: on a
hand-written server it found every real defect and produced no false positives. Gate your
build on findings — `--fail-on high` — not on a number.

**The score is a trend line for one server, not a ranking.** The overall is a weighted mean
over the dimensions that *ran*, so it moves when a stage is skipped, when a server needs
credentials, when `--no-probe` is passed, and between releases as checks are added. Watching
it fall on your own server across two commits is meaningful. Comparing it to somebody else's
server is not, and the tool no longer offers a way to do that.

**It is not a security audit, and a clean report is not a clearance.** The security checks
are pattern-based. They catch payloads placed where a scanner is not usually looking — a
display title, an output schema behind a `$ref`, a prompt's rendered messages, a definition
that changes between two listings — and they will not catch plain-prose social engineering,
a payload written in a language the patterns do not cover, or an instruction encoded rather
than written. Adversarial testing has demonstrated all three. Treat a clean report as "the
known classes were not found", never as "this server is safe".

The specific version of that sentence — what has actually been demonstrated to slip past,
by class — is kept in [Known gaps](docs/known-gaps.md) and updated as they are found.

**Absence is reported, not implied.** When a stage does not run — no API key, `--no-probe`,
a credential-gated server, a listing that failed — the report says so under *Not measured*,
because a skipped dimension does not lower the score, it leaves the denominator and raises
it.

## What v1.0 means here

The bar used to be about publishing: scoring comparable across servers, provenance on every
published row, and a disclosure process exercised before naming anyone. That bar belonged to
a tool that ranked other people's servers, and it was a hard problem — cross-server
comparability was never achieved and, on the evidence, was not going to be.

For a linter you point at your own server the bar is different, weaker, and actually
reachable:

1. **Stable for one server across two consecutive releases.** Upgrading the tool must not
   change the verdict on an unchanged server. Enforced by a recorded snapshot of every
   bundled fixture's full report and per-tool drift fingerprints, which fails on any
   movement rather than on a threshold.
2. **Every check documented** — what it looks at, what a finding means, and what to do about
   it. A finding you cannot act on is a false positive with extra steps.
3. **No new false-positive class** found in that window. Adversarial testing against honest
   servers, including non-English ones, is part of the release rather than a follow-up.
4. **The gate is severity-based and its exit codes are a contract.** A quality failure and an
   infrastructure failure must never share an exit code.

Note what is absent: nothing about ranking, nothing about comparing two servers, nothing
about publishing. Those were dropped rather than deferred.

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

## Reproducing a score

```bash
uvx mcp-gauntlet@<version> run "<the exact spec from the report>" --tasks 3 --repeats 2
```

The report's header records the version, model, task count, and repeats. Task sets are
cached per server (name + version + exposed tools) under `.gauntlet/`, and `--tasks-file`
pins a committable set so the same tasks are used across runs.
