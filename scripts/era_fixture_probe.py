"""Same fixture, both SDK eras, same tool definitions — or a non-zero exit.

The plan called this the strongest guarantee available for the dual-protocol port, and it
is the only check that can catch an adapter or shim that is self-consistently wrong. The
unit tests compare adapters against hand-written stand-ins; those stand-ins are written by
the same person as the adapter, so a wrong assumption about the SDK appears in both and
they agree. This runs the real SDKs.

It cannot be an ordinary test: `mcp` 1.x and 2.x cannot coexist in one environment (2.0
moves to httpx2), so no single interpreter can import both. Each era therefore runs in its
own throwaway environment via `uv`, and only the JSON crosses between them.

`fixtures/_serve.py` deliberately imports nothing from `mcp_gauntlet`, which is what makes
this possible — the harness pins `mcp<2`, so a fixture that reached into the harness could
never be run under the SDK this probe exists to test.

**What this does and does not establish.** MEASURED 2026-07-31: with `mcp` 2.0.0 on *both*
ends, the handshake still settled on **2025-11-25**, even though that SDK's
`LATEST_PROTOCOL_VERSION` is 2026-07-28 and `ClientSession` exposes no way to ask for it.
So the modern leg exercises the 2.0 **SDK** — snake_case attribute names, which is the
entire subject of the adapters — and not the 2026-07-28 **protocol**. The two are
independent: field names are a Python-API fact, the negotiated revision is a wire fact.
Nothing here should be read as evidence about MRTR, `cache_scope`, or anything else that
only exists once 2026-07-28 is actually negotiated.

    python scripts/era_fixture_probe.py            # both eras, compare
    python scripts/era_fixture_probe.py --keep     # leave the workspace for inspection
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVE = ROOT / "src" / "mcp_gauntlet" / "fixtures" / "_serve.py"

LEGACY_SDK = "mcp==1.29.0"  # the last 1.x, protocol 2025-11-25
MODERN_SDK = "mcp==2.0.0"  # the first 2.x, protocol 2026-07-28

# A fixture exercising every field the mapping has to carry across: a description, a typed
# schema, annotation hints (camelCase in 1.x, snake_case in 2.0) and a display title.
FIXTURE = '''
from _serve import Tool, serve


def add(a: int, b: int) -> int:
    """Add two integers and return their sum. Use when the user needs to add two numbers."""
    return a + b


def read_notes(path: str) -> str:
    """Return the contents of a notes file. Use when the user asks to read their notes."""
    return "notes"


if __name__ == "__main__":
    serve(
        "era-fixture",
        [
            Tool(add),
            Tool(
                read_notes,
                title="Read Notes",
                annotations={"read_only_hint": True, "destructive_hint": False,
                             "title": "Notes Reader"},
                meta={"category": "files"},
            ),
        ],
    )
'''

# Reads both spellings and emits one canonical shape, so the two eras' output is directly
# comparable. Mirrors what the adapters produce, without importing them.
DUMPER = """
import json, sys, anyio
import importlib.metadata as md
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def either(obj, *names, default=None):
    for n in names:
        v = getattr(obj, n, None)
        if v is not None:
            return v
    return default


async def main():
    params = StdioServerParameters(command=sys.executable, args=["fixture.py"], cwd=".")
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        init = await s.initialize()
        listed = await s.list_tools()
        tools = {}
        for t in listed.tools:
            ann = getattr(t, "annotations", None)
            tools[t.name] = {
                "description": t.description,
                "input_schema": either(t, "input_schema", "inputSchema", default={}),
                "output_schema": either(t, "output_schema", "outputSchema"),
                "title": getattr(t, "title", None),
                "annotation_title": getattr(ann, "title", None),
                "read_only_hint": either(ann, "read_only_hint", "readOnlyHint"),
                "destructive_hint": either(ann, "destructive_hint", "destructiveHint"),
                "meta": getattr(t, "meta", None),
            }
        print("@@JSON@@" + json.dumps({
            "sdk": md.version("mcp"),
            "protocol": str(either(init, "protocol_version", "protocolVersion")),
            "tools": tools,
        }, sort_keys=True))

anyio.run(main)
"""


def _run_era(workspace: Path, sdk: str) -> dict:
    """Discover the fixture from inside a throwaway environment holding exactly one SDK."""
    done = subprocess.run(
        ["uv", "run", "--isolated", "--no-project", "--with", sdk, "python", "dump.py"],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=600,
    )
    marker = [ln for ln in done.stdout.splitlines() if ln.startswith("@@JSON@@")]
    if done.returncode != 0 or not marker:
        print(f"--- {sdk} failed (exit {done.returncode}) ---")
        print(done.stdout[-1500:])
        print(done.stderr[-2500:], file=sys.stderr)
        raise SystemExit(f"could not discover the fixture under {sdk}")
    return json.loads(marker[0].removeprefix("@@JSON@@"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="leave the workspace in place")
    args = ap.parse_args()

    workspace = Path(tempfile.mkdtemp(prefix="era-fixture-"))
    try:
        shutil.copy(SERVE, workspace / "_serve.py")
        (workspace / "fixture.py").write_text(FIXTURE, encoding="utf-8")
        (workspace / "dump.py").write_text(DUMPER, encoding="utf-8")

        legacy = _run_era(workspace, LEGACY_SDK)
        modern = _run_era(workspace, MODERN_SDK)

        print(f"legacy: mcp {legacy['sdk']:8} protocol {legacy['protocol']}")
        print(f"modern: mcp {modern['sdk']:8} protocol {modern['protocol']}")

        if legacy["tools"] == modern["tools"]:
            print(f"\nIDENTICAL - {len(legacy['tools'])} tool(s) map the same in both eras")
            return 0

        print("\nDIFFERENT - the eras disagree about the same fixture:")
        for name in sorted(set(legacy["tools"]) | set(modern["tools"])):
            was, now = legacy["tools"].get(name), modern["tools"].get(name)
            if was == now:
                continue
            print(f"\n  {name}:")
            for field in sorted(set(was or {}) | set(now or {})):
                a, b = (was or {}).get(field), (now or {}).get(field)
                if a != b:
                    print(f"    {field}:\n      legacy: {a!r}\n      modern: {b!r}")
        return 1
    finally:
        if args.keep:
            print(f"\nworkspace kept at {workspace}")
        else:
            shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
