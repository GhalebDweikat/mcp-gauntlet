# v0.8.0 — speak both MCP eras from one codebase

Written 2026-07-28, revised 2026-07-29 after an adversarial review found twelve problems with
the first draft. Everything below marked **[verified]** was checked by execution, not asserted.

**Goal.** One codebase evaluating both 1.x-era and 2026-07-28-era servers, where a bugfix or a
new check is written **once**. Not a branch per protocol (every fix written twice, guaranteed
drift), not a cutover (abandons ~all of today's ecosystem).

**Decisions taken:** auto-detect the installed SDK with no user-facing flag; port and
new checks ship together as v0.8.0; the refactor touches only SDK reads, and the `open_session`
teardown restructure (the xfail process leak) stays out of scope.

---

## 0a. MEASURED 2026-07-29: the pin buys real time, so the port is not urgent

The plan and its adversarial review argued at length about how much time the `mcp<2` pin
actually buys. That was cheaply measurable and neither side measured it. Now done —
`scripts/era_probe.py`, re-runnable:

* Built a real server on `mcp` 2.0.0 (`MCPServer`, whose `LATEST_PROTOCOL_VERSION` is
  2026-07-28), ran it in its own environment, and pointed today's client at it.
* **The handshake succeeded.** The 2.0 server **negotiated down to 2025-11-25**. Discovery
  returned both tools with descriptions, input schemas and output schemas intact.

This falsifies the review's sharpest argument for urgency — that "any server whose author
bumps their SDK dependency" would drop off the board one dependabot PR at a time. It will
not: the 2.0 SDK's server side is dual-era by default and answers a legacy client correctly.

The residual exposure is narrower than either side assumed: only a server that *opts into*
modern-only behaviour becomes unevaluable, and the spec's compatibility matrix describes
exactly that case rather than the common one. So steps 4-9 can wait for real modern-only
servers to exist, which also means porting against something other than our own fixtures.

**Revised order:** stop after step 3 (done). Ship the provenance field and publish 0.7.0.
Resume the port when a modern-only server actually appears in the wild, or when a check we
want needs 2026-07-28 data.

## 0. What the review corrected

The first draft claimed "`models.py` already is the seam; dual support is one module that maps
field names." That is **half true**, and the half that is false determines the shape of the work.

**[verified] The module-scope imports survive.** The review called this fatal — that `from mcp
import ClientSession` would fail under 2.0 before `detect()` ever ran. It does not. Against the
released `mcp` 2.0.0: `ClientSession`, `StdioServerParameters`, `mcp.types`,
`mcp.client.stdio` and `mcp.shared.exceptions` all still resolve. What does **not** is
`mcp.server.fastmcp` — which is the **fixtures**, not the client. So the plan's structure holds
and the fixture port is the real cost.

**[verified] The rename is real and total.** `Tool` → `input_schema`, `output_schema`;
`ToolAnnotations` → `read_only_hint`, `destructive_hint`; `CallToolResult` → `is_error`,
`structured_content`, `result_type`; `ListToolsResult` → `next_cursor`; `InitializeResult` →
`protocol_version`, `server_info`. Every one of those is read today through a defaulting
`getattr`, so every one goes silently null.

**This already bit us once.** The MRTR detection shipped on 2026-07-28 read only `resultType`.
Against a modern server — the only kind that speaks MRTR — it returned `None` and the
attribution inverted, charging the harness's own decline to the server. Fixed in `41b8806`. One
incident, the whole argument for the seam.

## 1. Where the seam actually is

Not one boundary. **Two**, and the second is the one the draft missed.

**Behind the seam already** (imports `models`/`report`/`schemas` only, no SDK): Schema Health,
Description Quality, Security Signals, plus `drift.py`, `taskcache.py`, `safety.py`,
`toolconv.py`.

**Not behind it** — five of eight dimensions reach SDK objects through live-call sites:
- `robustness.py:321` reads `isError`; `:300` branches on `McpError`
- `agent.py` `_render_tool_result` reads `isError`/`content`/`structured_content` — and
  Response Safety, Agent Task Success, Tool-Selection and Tool Reliability all derive from the
  `ToolCallRecord` it produces
- `preflight.py:106,108`
- `content.py` — **a second seam**, receiving raw content blocks from three callers

So the boundary is **discovery + four live-call sites**. Restating that honestly is the
correction; the refactor is larger than "map some field names".

```
src/mcp_gauntlet/adapters/
    __init__.py   # detect() -> adapter for the installed SDK, resolved once at import
    base.py       # the Protocol + require()
    legacy.py     # mcp 1.x (camelCase)
    modern.py     # mcp 2.x (snake_case)
```

Interface — larger than the draft's nine methods:

```python
class SdkAdapter(Protocol):
    era: Literal["legacy", "modern"]
    stdio_logger_name: str  # protocol.py couples to this; see §5

    # discovery
    def tool_info(self, tool: Any) -> ToolInfo: ...
    def tool_hints(self, tool: Any) -> tuple[bool | None, bool | None]: ...  # see §2
    def server_info(self, init: Any) -> ServerInfo: ...
    def prompt_info(self, prompt: Any, rendered: Any | None) -> PromptInfo: ...
    def resource_info(self, res: Any, *, is_template: bool) -> ResourceInfo: ...
    def next_cursor(self, page: Any) -> str | None: ...
    def page_params(self, cursor: str | None) -> dict[str, Any]: ...
    def list_changed(self, init: Any) -> bool: ...

    # live calls
    def result_is_error(self, result: Any) -> bool: ...
    def result_content(self, result: Any) -> list[Any]: ...
    def result_structured(self, result: Any) -> Any: ...
    def asks_for_input(self, result: Any) -> bool: ...
    def content_text(self, block: Any) -> str | None: ...  # content.py moves behind this
    def protocol_error_type(self) -> type[BaseException]: ...  # robustness.py's McpError branch
```

## 2. Failing loudly — but only where a crash is survivable

The draft put `require()` everywhere. The review found three places that would turn a
survivable condition into a lost run or a defamed server. Both are worse than the silence.

- **`agent.py` tool dispatch** — inside a bare `except Exception` that sets `record.ok = False`.
  A raise there becomes a *failed tool call charged to the server*. The premise inverts into
  publishing a false result about a named third party.
- **`robustness.py:321`** — **[verified] outside** its try. Robustness runs *last*, after the
  full agentic eval, so a raise loses every dollar already spent and writes no report. This
  project's oldest lesson (R2) is that a completed evaluation must never be discarded.
- **`preflight.py:108`** — pre-spend, so cheap, but turns "needs credentials" into a crash.

**Rule: `require()` is confined to discovery.** Every read on a live result keeps a default and
records an explicit `Finding` instead — loud in the report, never loud in the process.

**And `require()` must not raise on a legitimate `None`.** `Tool.annotations` is `None` for most
tools; `require(tool.annotations, "read_only_hint")` would raise on nearly every server. Hence
`tool_hints()` as a dedicated method with an explicit documented `None` branch, rather than a
generic path walk.

```python
def require(obj: Any, *names: str, default: Any = _MISSING) -> Any:
    """First field that exists, else raise. A default is permitted ONLY where the PROTOCOL
    says the field is optional — never as protection against a rename, which is the bug
    this replaces."""
```

## 3. Packaging

**[verified] The extras idea does not work.** `pip install mcp-gauntlet[mcp2]` resolves
`mcp>=1.9,<2` **and** `mcp>=2,<3`; uv answers "your requirements are unsatisfiable". Extras add
constraints, never replace them — and 2.0 moves to `httpx2`, so coexistence is impossible
anyway.

**Approach: widen to `mcp>=1.9,<3`, adapter picks at import.** Legacy users pin it themselves.
**Widen last**, after both adapters are CI-green — widening first hands every fresh install an
SDK the code cannot use.

**`detect()` mechanism, stated explicitly:** `importlib.metadata.version("mcp")`, parse the
major. Not `hasattr(mcp, "Client")` — **[verified]** 2.0 still exports `ClientSession`, so
attribute probing cannot distinguish the eras. Pre-releases (`2.0.0b2`) parse by major too.

**The pin contract in the README breaks and must be reworded.** `uvx mcp-gauntlet@0.8.0`
resolves `mcp` fresh per invocation, so the same commit can flip eras between days — precisely
what the README promises pinning prevents. Becomes `uvx --with 'mcp<2' mcp-gauntlet@0.8.0`,
with the reason.

**The board must record the era. It currently does not** — `GauntletReport` carries
`gauntlet_version` only, and `ServerInfo.protocol_version` is the *server's* revision, not our
SDK's. METHODOLOGY rests its whole comparability claim on that stamp. Add `mcp_sdk_version`
(defaulted, so old JSON still loads) and surface it on the page and as a board column.

**Two independent axes, do not conflate.** The installed SDK fixes *field names*. The *server's*
negotiated revision is what §4's checks are about. A 2.0 SDK talking to a 2025-11-25 server is
normal — so new checks key on `discovery.server.protocol_version`, never on `adapter.era`.

## 4. New checks — cut from six to three

1. **`x-mcp-header` abuse** — implementable from `ToolInfo.input_schema` alone. Two constraints
   the draft missed: it must **not** use `schemas.arg_surface` (that merges `allOf` and derefs
   `$ref`, which inverts the spec's "statically reachable through `properties` only" rule), and
   the credential-name signal **only fires when the annotation is present** — a name alone must
   never trigger it, or we recreate the 25/25 false-positive class 0.7.0 just removed.
2. **`$ref` to a network URI** — cheap and real. Note **[verified]** the harness already never
   dereferences (`schemas.resolve_ref` returns `None` for anything not `#/`), so that half is a
   regression test, not work. What is new: the raw schema *does* leave the process —
   `toolconv` ships it to the LLM provider verbatim.
3. **Deprecated capabilities** (INFO) — Roots/Sampling/Logging off `init.capabilities`.

**Cut, with reasons:**
- **`cacheScope`/`ttlMs`** — **[verified] not implementable as described.** Those fields are on
  `ListToolsResult`, *not* on `Tool`; `ToolInfo` has nowhere to hold them and
  `discover_in_session` flattens pages before anyone sees them. "Authenticated endpoint" is also
  not a fact the harness has. Needs a model change — defer to its own release.
- **Deterministic ordering** — the draft's rationale was wrong: drift compares *by name*
  (`fingerprint_all` is a dict), so ordering was never a false-positive source. And it cannot
  live in Tool Reliability, which only exists after a live agent run.
- **Composition bounds** — `schema_texts` already bounds the walk and already emits a MEDIUM.
  A second budget finding double-penalizes one oversized schema across two dimensions.
- **HTTP+SSE and OAuth DCR deprecations** — unobservable. The harness only ever dials
  `streamablehttp_client` and does no OAuth.

## 5. Also in scope, missed by the draft

- **`protocol.py:32` hardcodes `_STDIO_LOGGER = "mcp.client.stdio"`.** If 2.0 moves that module
  the handler attaches to a dead logger, `unparseable_lines` stays 0, and the stdout-pollution
  check reports **every server clean** — the signature silent-stop, in a module the draft never
  listed. Goes on the adapter as `stdio_logger_name`.
- **`tests/test_sdk_contract.py` fails by construction on the modern CI leg** — every assertion
  is camelCase. Parameterize on `detect().era`, keeping both name lists so a rename in either
  direction is loud.
- **`_RecordingSession` subclasses `ClientSession` and overrides the private
  `_received_request`**, isinstance-ing three request types the new revision removes. Needs
  checking against 2.0 before step 2.

## 6. Verification — the draft's was self-deceiving

"Scores must not move during the port" cannot be checked the way the draft proposed:

- **There is no baseline to compare against.** `test_fixtures_static.py` asserts `grade in
  ("A","B")` — a 99.4 → 92 move passes. **Capture an exact `GauntletReport` snapshot per
  fixture (timestamps stripped) BEFORE step 1**, or the comparison is vacuous.
- **The fixture path exercises none of the risky code** — no session findings, no agentic
  stage, so none of §2's three sites.
- **The drift baseline is the biggest hidden mover.** `fingerprint()` digests `output_schema`,
  `read_only_hint`, `destructive_hint`, `meta`, `title`. Any change in how those are read —
  including `{}` vs `None` — changes every digest, and `.gauntlet/baselines/` holds live
  baselines for the published board. First post-upgrade run: every tool fires "definition
  changed" at MEDIUM on the weight-2.0 grade-capping dimension. **Add an era/format stamp to
  `Baseline` and treat a mismatch as "no baseline" — re-record, report nothing.**
- **The task cache confounds it.** Run the before/after with `--no-agentic` and separately
  assert the cache key is byte-identical.

## 7. Order of work

1. **Snapshot fixture reports and drift fingerprints.** Nothing else can be trusted without it.
2. `adapters/` + `base.py` + `legacy.py`; move discovery reads behind it. No behaviour change;
   snapshots must match exactly.
3. Move the four live-call sites behind it (`agent`, `robustness`, `preflight`, `content`).
4. `modern.py` + port the fixtures (`FastMCP` → `MCPServer`; seven fixtures and five test
   modules — the largest single chunk).
5. **The identical-`ToolInfo` test**: same fixture, both eras, same model out. The review is
   right that this is the strongest guarantee available and would alone have caught the two
   bugs already found.
6. CI matrix over both SDKs — note `uv run` re-syncs against `uv.lock` (which pins `mcp`), so
   this needs `--frozen`/`UV_NO_SYNC=1` or a second lockfile.
7. Baseline era stamp; `mcp_sdk_version` on the report and board.
8. Widen the pin.
9. The three surviving new checks.
10. METHODOLOGY rewrite — it currently says 2026-07-28 "support is deliberately not claimed
    until it lands", on the document every board page links to. README pin snippet.
11. Release v0.8.0, documenting that scores are not comparable with 0.7.0.

## 8. Sound as drafted, per the review

Extras analysis; "widen the pin last"; saved leaderboard JSON needs no migration
(**[verified]** defaulted fields mean 0.4.0-era JSON still loads, and `DimensionResult.key` is
deliberately `str`); badge URLs unaffected (slugs derive from names only); `models.py` as the
*target* vocabulary.
