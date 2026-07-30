# Picking the servers for the 50-server survey

Written 2026-07-25 while the v0.4.0 board re-scan ran.

## Selection must be mechanical

"I scanned 50 public MCP servers" is only interesting if the 50 weren't chosen to make a
point. So selection runs off the official registry
(`https://registry.modelcontextprotocol.io/v0/servers`, ~4,000 entries) with a scripted
filter, and the script ships with the report.

Schema note that cost a debugging round: entries are **wrapped** — each item is
`{"server": {...}, "_meta": {...}}`, so `packages` lives at `entry["server"]["packages"]`,
not the top level. Also filter `_meta["io.modelcontextprotocol.registry/official"]` on
`status != deleted/deprecated` **and `isLatest is not False`**, or the same server appears
once per published revision.

Filter used: has an `npm` or `pypi` package (⇒ runs over stdio via `npx`/`uvx`, no hosting
and no account) and declares no `isRequired`/`isSecret` environment variable, argument, or
header. That yields **101 candidates** out of ~4,000.

## The trap: "declares no secret" ≠ "works without credentials"

Most of those 101 are commercial pay-per-call SaaS wrappers — `@perplexity-ai/mcp-server`,
`@rapay/mcp-server`, sixteen `@agentutility/*` clusters, and similar. They declare no
required environment variable, install fine, connect fine, and list their tools fine. Then
every actual tool call fails with an auth error.

**mcp-gauntlet would score that as Tool Reliability 0 and publish a D or an F** — blaming a
server for a configuration *we* declined to provide. That is precisely the unfairness
METHODOLOGY.md commits against ("not a measure of what the server does when it's used
properly"), and it would be the first thing a maintainer disputes, correctly.

## Therefore: an auth pre-flight before anything is ranked

Before the paid agentic pass, connect and make **one** trivial call per server, then bucket:

1. **Evaluable** — the call succeeds (or fails for a non-auth reason). Ranked normally.
2. **Needs credentials** — the call fails with an auth/subscription/quota error. Reported in
   a separate section, stating that mcp-gauntlet declined to supply credentials, and
   **never scored**. Same treatment `_initialize` already gives an unsupported protocol
   revision: a limitation of the run, not a fault in the server.
3. **Unreachable** — install or connect fails. Listed with the reason.

The leaderboard already has the machinery for this: R4's "Partially evaluated" segregation
exists so an unscored server can never outrank a scored one. This is a new *reason* for
that bucket, not new plumbing.

Cheap side benefit: bucket 2 is itself a publishable statistic — "N of the M servers the
official registry lists as requiring no credentials cannot actually be used without an
account" is a real finding about registry metadata quality, and it needs no LLM spend.

## Cost

The 10-server board cost ~$0.90 on `gemini-flash-latest` at 3 tasks × 2 repeats, so ~$0.09
per server. Fifty servers ≈ **$4.50**, in hours rather than days.
This supersedes the research critique's assumption that the survey was Groq-free-tier-bound
and would take days — it was, on Groq; on Gemini it simply is not the binding constraint.
Confirm against the actual v0.4.0 re-scan cost before committing, since v0.4.0 scans more
surfaces per server.

## Still to decide

- Whether to include the ~16 `@agentutility/*` near-duplicates at all. They are one vendor's
  cluster; counting them as 16 of 50 would badly skew "the ecosystem". Cap per-publisher
  representation (say 2) and say so in the methodology.
- The registry is not the whole ecosystem (PulseMCP/Glama/awesome-lists list more). Using one
  source is defensible if stated; claiming "the ecosystem" is not.
