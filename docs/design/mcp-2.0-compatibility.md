# MCP 2.0 compatibility — what lands 2026-07-28 and what mcp-gauntlet must do

Written 2026-07-25, three days before the date. Verified against live sources this session
(MCP blog RC post; GitHub releases API for `modelcontextprotocol/python-sdk`), not from the
2026-07-24 research notes alone.

## "MCP 2.0" is two separate things landing the same day

Community shorthand conflates them. They break us in different ways.

| | What it is | How it reaches us |
|---|---|---|
| **Protocol revision `2026-07-28`** | The spec servers speak | Through servers we evaluate |
| **`mcp` Python SDK 2.0.0** | The client library we import | Through our own dependency |

## Status as of 2026-07-25

- Protocol revision is still a **release candidate**; final ships 2026-07-28.
- SDK: latest **stable is 1.28.1** (2026-06-26) — what we pin and test against.
  Pre-releases: `2.0.0a1` (06-11), `a2` (06-16), `a3` (06-26), `b1` (06-30), `b2` (07-14).
  `2.0.0b1` claims **full 2026-07-28 spec support**.
- Every dependency in our lockfile is currently the newest on PyPI, so the 331-test suite
  runs against exactly what a fresh `uvx mcp-gauntlet` resolves today.

## Protocol changes (what servers will do differently)

- **`initialize`/`initialized` handshake removed.** Protocol version, client info and
  capabilities now ride in `_meta` on *every* request. New `server/discover` method
  replaces the upfront capability exchange.
- **Sessions removed.** No `Mcp-Session-Id`, no protocol-level session — stateless across
  server instances.
- **MRTR replaces server-initiated requests.** Instead of the server pushing
  `elicitation/create` / `sampling/createMessage` over SSE, it returns an
  `InputRequiredResult` carrying `inputRequests` + `requestState`; the client re-sends the
  original request with `inputResponses`. Results now carry a `resultType`
  (`"complete"` | `"input_required"`).
- **Roots, Sampling, Logging deprecated** (annotation-only, 12-month removal window).
- **Tool schemas widen.** Input schemas get full JSON Schema 2020-12 composition
  (`oneOf`/`anyOf`/`allOf`); **output schemas become unrestricted and `structuredContent`
  accepts any JSON value, not just an object.**
- **Error code change:** missing resource moves from MCP-custom `-32002` to JSON-RPC
  standard `-32602`.
- **Tasks** graduates out of core into an extension, with a restructured lifecycle.

## SDK 2.0 changes (what breaks in our own code)

- `FastMCP` → `MCPServer`; handlers become constructor parameters.
- `ClientSession` replaced by a dispatcher/runner pipeline (`Client`).
- Protocol types split into a separate **`mcp-types`** package.
- **Field names become snake_case throughout.**
- Version-gated wire validation.
- `httpx` → `httpx2` (b2).
- 1.28.0 already deprecated the WebSocket transport and the experimental tasks API — we use
  neither (verified by grep this session).

## VERIFIED ON THE DAY (2026-07-28) — what actually shipped

Both landed on schedule. `mcp` **2.0.0** is on PyPI (13:45 UTC, and it depends on `httpx2`);
`mcp` **1.29.0** shipped four minutes earlier as the final v1, security fixes only from here.
Tested from a clean install: **our `mcp>=1.9,<2` bound resolves to 1.29.0**, so nothing broke
for anyone running mcp-gauntlet today. The bound did exactly the job it was added for.

Two corrections to what is written below, beyond the struck item 3:

* **"`initialize` removed in favour of `server/discover`" is the wrong framing.**
  `server/discover` is **optional for clients**. Servers must implement it, but the protocol
  version, clientInfo and capabilities ride in `_meta` on *every* request, and a client may
  issue any RPC inline and handle `UnsupportedProtocolVersionError` (`-32022`). Discover is a
  convenience and an stdio backward-compat probe, not a replacement handshake.
* **MCP Apps is not new in this release** — it is a pre-existing extension (2026-01-26). What
  is new is the `extensions` capability field that formalizes negotiating it.

**The exposure is now live rather than theoretical.** The spec's own compatibility matrix
rates *legacy client → modern server* as **Fails**: a modern-only server rejects our
`initialize` outright. Dual-era servers still work, so the practical impact arrives as
modern-only servers appear in the wild — weeks, not months.

## Are we safe on day 1? Yes, and by design rather than by luck

1. **`mcp>=1.9,<2` is already shipped in v0.4.0.** SDK 2.0 simply cannot be installed
   alongside mcp-gauntlet 0.4.0, so nothing a user has pinned changes on 07-28. This bound
   is the whole reason the pre-release spec check existed.
2. **A server speaking only the new revision is already handled honestly.** `_initialize`
   catches the version-negotiation `RuntimeError` and reports the server as unevaluable *by
   the harness* — explicitly a limitation here, never scored as a fault in the server.
   METHODOLOGY.md says which revision we target and that 2026-07-28 support is deliberately
   not claimed until it lands.

So the exposure is not day 1. It is **day 30**, when real servers ship against the new spec
and we still can't grade them.

## The trap in our own code: the migration would fail *silently*

This is the finding that should shape how the port is done. Most of our SDK reads go
through `getattr(obj, "camelCaseName", default)`. Under snake_case renames those do not
raise — they **return the default**, and a security check quietly stops running:

| Read | Silent consequence under SDK 2.0 |
|---|---|
| `getattr(tool, "outputSchema", None)` | Output-schema poisoning scan turns off — the entire point of Batch E |
| `getattr(tool.annotations, "destructiveHint"/"readOnlyHint", None)` | Write-safety filter loses the server's self-incriminating hint and falls back to name/description verbs — **we would execute mutating tools in a read-only run** |
| `getattr(page, "nextCursor", None)` | Pagination stops after page 1; tools on page 2 are never scanned |
| `getattr(init, "protocolVersion", None)` | Protocol revision silently unrecorded on reports |

Direct attribute reads (`init.serverInfo`, `resource.mimeType`, `page.resourceTemplates`,
`tool.inputSchema`) would raise `AttributeError` instead — which is *safer*, because it is
visible. **The defensive `getattr` is the dangerous half.** This is the same failure shape
the project keeps hitting: a check that stops running scores the server as clean.

**Therefore: do not port by adding `getattr(x, "a", getattr(x, "b", None))` fallbacks.**
Read the field once, in one adapter, and make a missing field loud.

## Work list for v0.5.0

Ordered by what actually blocks grading a new-spec server.

1. **One SDK adapter layer.** Funnel every SDK-object read through a single module
   (`sdkcompat.py`) that maps SDK object → our `ToolInfo`/`ServerInfo`/`PromptInfo`/
   `ResourceInfo`. Today those reads are spread across `client.py`, `agent.py`,
   `content.py`. With one seam, supporting both SDKs is a branch in one file.
2. **A test that fails when a field silently disappears.** Assert the adapter actually
   populated `output_schema`, `destructive_hint`, etc. from a known-good fixture — so a
   rename shows up as a red test, not a quiet 100.
3. ~~**Widen `outputSchema` handling to non-object JSON.**~~ **STRUCK — this was wrong.**
   Verified against the finalized `schema.ts` on 2026-07-28: `outputSchema` is still typed
   as an object (`{ $schema?: string; [key: string]: unknown }`). A bare boolean schema is
   *not* legal, so `dict(getattr(tool, "outputSchema", ...))` cannot crash. What actually
   changed is narrower: 2025-11-25 required `type: "object"` *inside* the schema and
   2026-07-28 dropped that, so the schema may now *describe* an array or a string — but it
   is still a dict.

   The real dict-assumption break is one this document missed: **`CallToolResult.
   structuredContent` went from `{[key: string]: unknown}` to plain `unknown`** — any JSON
   value. `agent.py` survives it (it goes through `json.dumps`), but any logic pairing
   `outputSchema` with `structuredContent` must now handle arrays and scalars.
4. **MRTR.** Recognize `resultType: "input_required"` and decline it the way we already
   decline elicitation/sampling — same policy (the harness drives no user), new shape.
   Keep the existing "not counted against Tool Reliability" attribution.
5. **`server/discover` probe**, falling back to `initialize` for older servers. This is
   also the natural place to record the negotiated revision.
6. **Deprecation reporting.** Once the revision is final, a server still relying on
   Sampling/Roots/Logging is worth an INFO — it is on a 12-month clock. INFO, not a
   penalty: deprecated is not broken, and a zero-penalty finding must never be able to
   raise a score (see the drift-subject lesson).
7. **Port the fixtures** (`FastMCP` → `MCPServer`) — needed to test any of the above.
8. **Lift the pin to `<3`** only after 1–7, with CI running both SDK majors.

## Sequencing

The `<2` pin means there is no deadline pressure — which is exactly why it was worth
shipping. Suggested order: do (3) now as a normal bugfix; wait for `mcp` 2.0.0 **final**
(not b2) before starting (1); do not chase the RC.
