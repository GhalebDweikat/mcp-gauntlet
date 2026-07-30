"""Freeze exactly what the bundled fixtures score, so a refactor cannot move it unnoticed.

Written for the SDK-adapter port. The existing fixture tests assert `grade in ("A","B")` and
`overall_score <= 75`, which a 99.4 -> 92 regression passes cleanly — so "scores must not
change during the port" was unverifiable until this existed.

Captures the full report (minus the fields that legitimately vary per run) plus the drift
fingerprints, which are the likeliest silent mover: `fingerprint()` digests output_schema,
the annotation hints and `_meta`, so any change in how those are READ — including `{}` versus
None — changes every digest and would make every tool look redefined.

    python scripts/snapshot_fixtures.py --write    # record
    python scripts/snapshot_fixtures.py            # compare, non-zero exit on drift
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import anyio

from mcp_gauntlet.checks import run_static_checks
from mcp_gauntlet.client import discover
from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.drift import fingerprint_all
from mcp_gauntlet.report import GauntletReport

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "tests" / "data" / "fixture_scores.json"

FIXTURES = (
    "good_server",
    "bad_server",
    "malicious_server",
    "noisy_server",
    "gated_server",
)

# Fields that legitimately differ between two runs of identical code.
VOLATILE = {"generated_at", "gauntlet_version", "mcp_sdk_version"}


def _capture(name: str) -> dict[str, Any]:
    spec = ServerSpec.parse(f"{sys.executable} -m mcp_gauntlet.fixtures.{name}")
    discovery = anyio.run(discover, spec)
    report = GauntletReport.build(
        spec=f"fixture:{name}",  # not spec.label(): that carries an absolute interpreter path
        server=discovery.server,
        tool_count=len(discovery.tools),
        dimensions=run_static_checks(discovery),
    )
    payload = json.loads(report.model_dump_json())
    for key in VOLATILE:
        payload.pop(key, None)
    # The server's own version moves when a fixture is edited; the scores are the subject.
    payload["server"].pop("version", None)
    return {
        "report": payload,
        "fingerprints": fingerprint_all(discovery.tools),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="record instead of compare")
    args = ap.parse_args()

    current = {name: _capture(name) for name in FIXTURES}

    if args.write:
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(json.dumps(current, indent=2, sort_keys=True), encoding="utf-8")
        print(f"recorded {len(current)} fixture(s) -> {SNAPSHOT.relative_to(ROOT)}")
        for name, cap in current.items():
            r = cap["report"]
            print(f"   {name:20} {r['grade']:>3} {r['overall_score']:>6}  tools={r['tool_count']}")
        return 0

    if not SNAPSHOT.exists():
        print(f"no snapshot at {SNAPSHOT}; run with --write first", file=sys.stderr)
        return 1
    recorded = json.loads(SNAPSHOT.read_text(encoding="utf-8"))

    drifted = 0
    for name in FIXTURES:
        was, now = recorded.get(name), current[name]
        if was == now:
            print(f"   OK   {name}")
            continue
        drifted += 1
        wr, nr = (was or {}).get("report", {}), now["report"]
        print(
            f"   DRIFT {name}: {wr.get('grade')} {wr.get('overall_score')} "
            f"-> {nr['grade']} {nr['overall_score']}"
        )
        if (was or {}).get("fingerprints") != now["fingerprints"]:
            print("         tool fingerprints changed — every tool would report definition drift")
    print(f"\n{drifted} fixture(s) drifted")
    return 1 if drifted else 0


if __name__ == "__main__":
    raise SystemExit(main())
