# Withheld boards

Two leaderboards were published here and taken down. The data is kept rather than deleted so
the corrections stay auditable — see
[the withholding notice](https://ghalebdweikat.github.io/mcp-gauntlet/) for why, and
[the write-up](../docs/eight-times-i-measured-something-else.md) for what went wrong.

Read the caveats below before drawing anything from these numbers.

## `registry-survey/` — 50 servers from the official MCP registry

**Every spec on this board was pinned to the version the registry recorded, and that was a
mistake.** The registry's version lags the published package badly — it said `1.7.1` for
`@adeu/mcp-server` where npm shipped `1.30.0`. So every grade here measured code the
maintainer may have shipped long ago and since fixed, including the A grades. Two servers that
score A on latest appear here as outright failures for that reason alone.

`servers-as-scanned.json` is the provenance record: the exact spec, outcome, and self-reported
server version for each of the 50, reconstructed from the board rows. It exists because the
top-level `survey.servers.json` in the repository root is **not** this list — that file was
regenerated after the pinning was reverted, so it shares no specs with what actually ran and
cannot reproduce this board.

Three rows are the harness's own fault, not the servers':

| row | published as | actually |
|---|---|---|
| `adeu-mcp-server` | timed out | a stale pinned version; scores A on latest |
| `oobe-protocol-labs-sap-mcp-server` | module-resolution error | same |
| `ankimcp-anki-mcp-server` | `EADDRINUSE` on port 3000 | a leaked process from an earlier run of ours |

So "23 of 50 could not be started" should read **at least three fewer**, and the remainder has
not been fully re-audited, because the pin touched every row.

## `reference-servers/`, `reference-badges/` — 11 well-known servers

Rows are stamped `gauntlet_version: 0.4.0`, and that stamp is wrong. They were produced from a
working tree that already carried the task-grounding fix released in 0.5.0, so
`uvx mcp-gauntlet@0.4.0` reproduces materially different (worse) numbers — `filesystem` grades
D there rather than the A shown here. The stamp exists to make a score reproducible and in this
case it does the opposite.

## Neither board gave the servers it named advance notice

`METHODOLOGY.md` promises that any server appearing with a low score gets advance notice and a
link to dispute it. That notice was never sent, which is the other half of why these came down.
