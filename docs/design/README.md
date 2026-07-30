# Design notes

Working documents, published because the write-up
([Eight times my evaluator measured something other than the server](../eight-times-i-measured-something-else.md))
claims the reasoning behind each fix is in the repository, and for one of them it was not.

These are notes, not documentation. They record what was believed at the time, including where
that turned out to be wrong — the corrections are the useful part and have been left in place
rather than edited out.

- **[mcp-2.0-compatibility.md](mcp-2.0-compatibility.md)** — what actually shipped in MCP
  revision 2026-07-28 and `mcp` SDK 2.0, and what it means for a client. Contains two claims I
  had repeated from pre-release reporting and later had to strike: `server/discover` does not
  replace the `initialize` handshake, and output schemas did not become unrestricted.
- **[dual-protocol-plan.md](dual-protocol-plan.md)** — the plan for speaking both protocol eras
  from one codebase, after an adversarial review found twelve problems with the first draft. §0a
  is the part worth reading: two rounds of argument about how urgent the port was, settled in
  thirty minutes by building a server on the new SDK and looking.
- **[survey-selection.md](survey-selection.md)** — how the fifty servers were chosen, and why
  selection had to be a script rather than a judgement call.
