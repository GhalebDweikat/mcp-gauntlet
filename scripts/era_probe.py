"""Does today's client work against a server built on the `mcp` 2.0 SDK?

Answer, measured 2026-07-29: YES. A 2.0-built server negotiates DOWN to 2025-11-25, and
discovery returns descriptions, input schemas and output schemas intact.

That is the fact the dual-support roadmap hinged on, and it was cheaper to measure than to
argue about. Kept as a script rather than a test because it installs a second SDK over the
network; re-run it when the ecosystem moves, or before assuming the pin still holds.

The whole dual-support question turns on this. If the handshake completes and discovery
returns sane data, the `mcp<2` pin buys real time and the remaining port steps can wait. If
it fails, every server whose author bumps their SDK dependency drops off the board one
dependabot PR at a time, and the clock is much shorter than assumed.

The child runs under its OWN SDK via `uv run --isolated --with "mcp>=2,<3"`, so this is a
genuine cross-era conversation rather than two copies of the same library talking.
"""

import sys
from pathlib import Path

import anyio
from mcp import types

from mcp_gauntlet.client import discover
from mcp_gauntlet.config import ServerSpec

SERVER = Path(__file__).with_name("era_probe_server.py")
SPEC = f"uv run --isolated --no-project --with mcp>=2,<3 python {SERVER}"

print(f"client requests : MCP {types.LATEST_PROTOCOL_VERSION}  (mcp<2)")
print("server speaks   : MCP 2026-07-28  (mcp 2.0.0)")
print(f"spec            : {SPEC}\n")

try:
    discovery = anyio.run(discover, ServerSpec.parse(SPEC))
except Exception as exc:  # noqa: BLE001 - the failure IS the result here
    print(f"RESULT: handshake FAILED -> {type(exc).__name__}: {str(exc)[:300]}")
    print("\n=> A 2.0-built server is NOT evaluable today. The clock is short.")
    sys.exit(0)

print("RESULT: handshake SUCCEEDED")
print(f"  negotiated revision : {discovery.server.protocol_version}")
print(f"  server name/version : {discovery.server.name} {discovery.server.version}")
print(f"  tools discovered    : {[t.name for t in discovery.tools]}")
for tool in discovery.tools:
    print(f"    {tool.name}: desc={bool(tool.description)} schema_keys={sorted(tool.input_schema)}")
    print(
        f"      title={tool.title!r} output_schema={bool(tool.output_schema)} "
        f"read_only={tool.read_only_hint} destructive={tool.destructive_hint}"
    )

blank = [t.name for t in discovery.tools if not t.description or not t.input_schema]
print(
    "\n=> Evaluable, but check the mapping: "
    + ("fields came through" if not blank else f"EMPTY fields on {blank} — the adapter is blind")
)
