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
this possible: the module is copied alone into an environment holding one SDK and nothing
else, so a fixture that reached back into the harness could not run here at all.

Two fixtures are checked, because they exercise the two halves of the shim:

* a **declared** fixture, built from typed Python functions, covering the path the six
  ordinary fixtures use;
* the **real malicious demo**, verbatim from the package, covering the raw path — a
  hand-built schema with a payload behind a `$ref`, a poisoned annotation title, prompts,
  and a definition that changes between the first and second `tools/list`. Its import line
  is the only thing rewritten, so what runs here is the server users actually get.

`tools/list` is called twice, because the rug-pull only exists in the difference between
the two answers. A probe that listed once would report the malicious server identical
across eras while being blind to the single attack that needs a second look.

**What this does and does not establish.** MEASURED 2026-07-31: with `mcp` 2.0.0 on *both*
ends, the handshake still settled on **2025-11-25**, even though that SDK's
`LATEST_PROTOCOL_VERSION` is 2026-07-28 and `ClientSession` exposes no way to ask for it.
So the modern leg exercises the 2.0 **SDK** — snake_case attribute names, which is the
entire subject of the adapters — and not the 2026-07-28 **protocol**. The two are
independent: field names are a Python-API fact, the negotiated revision is a wire fact.
Nothing here should be read as evidence about MRTR, `cache_scope`, or anything else that
only exists once 2026-07-28 is actually negotiated.

    python scripts/era_fixture_probe.py            # both fixtures, both eras, compare
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
FIXTURE_DIR = ROOT / "src" / "mcp_gauntlet" / "fixtures"
SERVE = FIXTURE_DIR / "_serve.py"
MALICIOUS = FIXTURE_DIR / "malicious_server.py"

LEGACY_SDK = "mcp==1.29.0"  # the last 1.x, protocol 2025-11-25
MODERN_SDK = "mcp==2.0.0"  # the first 2.x, protocol 2026-07-28

# Exercises every field the mapping carries across: a description, a typed schema,
# annotation hints (camelCase in 1.x, snake_case in 2.0) and a display title.
DECLARED = '''
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


def snapshot(listed):
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
    return tools


async def main():
    target = sys.argv[1]
    params = StdioServerParameters(command=sys.executable, args=[target], cwd=".")
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        init = await s.initialize()
        # Twice: the rug-pull lives entirely in the difference between the two answers.
        first = snapshot(await s.list_tools())
        second = snapshot(await s.list_tools())
        prompts = {}
        try:
            for p in (await s.list_prompts()).prompts:
                got = await s.get_prompt(p.name)
                prompts[p.name] = {
                    "description": got.description,
                    "messages": [getattr(m.content, "text", None) for m in got.messages],
                }
        except Exception:
            prompts = {}

        # BEHAVIOUR, not just definitions. The definitions were byte-identical across eras
        # for weeks while the malicious fixture scored C 75.0 on 1.x and D 60.2 on 2.0,
        # because 1.x validates arguments inside @server.call_tool() and 2.0's raw request
        # handler does not — so the fixtures' own shim was rejecting malformed input on one
        # era and accepting it on the other. Nothing compared that, so nothing saw it.
        #
        # Recorded as "rejected"/"accepted" rather than as the error text, which is worded
        # differently by every era and would make this noisy enough to be switched off.
        behaviour = {}
        for t in (await s.list_tools()).tools:
            schema = either(t, "input_schema", "inputSchema") or {}
            required = schema.get("required") or []
            # Omitting a required argument violates any honest schema. Where nothing is
            # required, send a property the schema does not declare.
            args = {} if required else {"__gauntlet_era_probe__": 1}
            try:
                out = await s.call_tool(t.name, args)
                errored = bool(either(out, "is_error", "isError"))
            except Exception:
                errored = True
            behaviour[t.name] = "rejected" if errored else "accepted"

        print("@@JSON@@" + json.dumps({
            "sdk": md.version("mcp"),
            "protocol": str(either(init, "protocol_version", "protocolVersion")),
            "first": first,
            "second": second,
            "prompts": prompts,
            "behaviour": behaviour,
        }, sort_keys=True))

anyio.run(main)
"""


def _run_era(workspace: Path, sdk: str, target: str) -> dict:
    """Discover a fixture from inside a throwaway environment holding exactly one SDK."""
    done = subprocess.run(
        ["uv", "run", "--isolated", "--no-project", "--with", sdk, "python", "dump.py", target],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=600,
    )
    marker = [ln for ln in done.stdout.splitlines() if ln.startswith("@@JSON@@")]
    if done.returncode != 0 or not marker:
        print(f"--- {target} under {sdk} failed (exit {done.returncode}) ---")
        print(done.stdout[-1500:])
        print(done.stderr[-2500:], file=sys.stderr)
        raise SystemExit(f"could not discover {target} under {sdk}")
    return json.loads(marker[0].removeprefix("@@JSON@@"))


def _report(label: str, legacy: dict, modern: dict) -> int:
    print(f"\n=== {label} ===")
    print(f"  legacy: mcp {legacy['sdk']:8} protocol {legacy['protocol']}")
    print(f"  modern: mcp {modern['sdk']:8} protocol {modern['protocol']}")

    drift_legacy = legacy["first"] != legacy["second"]
    drift_modern = modern["first"] != modern["second"]
    if drift_legacy or drift_modern:
        print(
            f"  definition drift between the two listings: "
            f"legacy={drift_legacy} modern={drift_modern}"
        )

    failures = 0
    # "behaviour" is compared alongside the definitions, and it is the one that was missing.
    # A shim can serve byte-identical definitions on both eras and still ANSWER differently,
    # which is what happened: the malicious fixture rejected schema-violating input on 1.x
    # and accepted it on 2.0, moving its grade 15 points, while this probe reported the two
    # eras identical the whole time. Definitions are what the fixture SAYS; behaviour is
    # what it DOES, and both have to match for "same fixture, both eras" to mean anything.
    for section in ("first", "second", "prompts", "behaviour"):
        if legacy[section] == modern[section]:
            continue
        failures += 1
        print(f"\n  DIFFERENT in '{section}':")
        for key in sorted(set(legacy[section]) | set(modern[section])):
            was, now = legacy[section].get(key), modern[section].get(key)
            if was == now:
                continue
            if not isinstance(was, dict) and not isinstance(now, dict):
                print(f"    {key}:  legacy={was!r}  modern={now!r}")  # behaviour verdicts
                continue
            print(f"    {key}:")
            for field in sorted(set(was or {}) | set(now or {})):
                a, b = (was or {}).get(field), (now or {}).get(field)
                if a != b:
                    print(f"      {field}:\n        legacy: {a!r}\n        modern: {b!r}")
    if failures == 0:
        print(
            f"  IDENTICAL - {len(legacy['first'])} tool(s), both listings, "
            f"{len(legacy['prompts'])} prompt(s), and the same answer to "
            f"{len(legacy['behaviour'])} malformed call(s)"
        )
    # The rug-pull must actually fire, or this fixture has silently stopped demonstrating it.
    if label == "malicious" and not (drift_legacy and drift_modern):
        print("  FAILED: the rug-pull did not fire in both eras")
        failures += 1
    return failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="leave the workspace in place")
    args = ap.parse_args()

    workspace = Path(tempfile.mkdtemp(prefix="era-fixture-"))
    try:
        shutil.copy(SERVE, workspace / "_serve.py")
        (workspace / "declared.py").write_text(DECLARED, encoding="utf-8")
        (workspace / "dump.py").write_text(DUMPER, encoding="utf-8")

        # The real demo, with only its import rewritten — so what runs is what ships.
        source = MALICIOUS.read_text(encoding="utf-8")
        rewritten = source.replace("from mcp_gauntlet.fixtures._serve import", "from _serve import")
        if rewritten == source:
            raise SystemExit("malicious_server.py no longer imports _serve as expected")
        (workspace / "malicious.py").write_text(rewritten, encoding="utf-8")

        failures = 0
        for label, target in (("declared", "declared.py"), ("malicious", "malicious.py")):
            legacy = _run_era(workspace, LEGACY_SDK, target)
            modern = _run_era(workspace, MODERN_SDK, target)
            failures += _report(label, legacy, modern)

        print()
        if failures:
            print(f"{failures} mismatch(es) between the eras")
            return 1
        print("Both fixtures map identically across mcp 1.x and 2.x")
        return 0
    finally:
        if args.keep:
            print(f"\nworkspace kept at {workspace}")
        else:
            shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
