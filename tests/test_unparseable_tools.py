"""A tool list the SDK cannot parse is a finding about the server, not an infrastructure failure.

Found by a platform engineer wiring up a real CI gate. Break a tool's schema *inside* the
SDK's model and you got HIGH + exit 1. Break it *at* the model boundary and you got
`ValidationError` surfacing as a connection failure: **exit 3, and no `report.json` at all**,
so the uploaded CI artifact was empty too. A developer cannot predict which side of that line
they land on, and it is the tool's own headline dimension.

Worse, `examples/gauntlet-ci.yml` tells pipelines to retry on 3 — so a genuine schema
regression was retried until it gave up and then reported as a flaky runner. In the tester's
words: "a real regression is indistinguishable from a bad runner day."

Measuring it across both SDK eras made it bigger than reported. On `mcp` 1.28.1, three of six
malformed shapes were caught as findings and three died at the boundary. On `mcp` 2.0.0 —
which a fresh `pip install` resolves — **all six died**, including `{"type": "objekt"}` and
`{"properties": []}`, which 1.x reports perfectly well. Schema Health was unreachable on the
default SDK for exactly the servers it exists to catch.

The fixtures are hand-rolled JSON-RPC because the SDK will not *serve* a definition its own
model rejects — the defect only exists on the wire, so the fixture has to write the wire.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_gauntlet.exits import Exit
from mcp_gauntlet.report import UNPARSEABLE_TOOLS_MESSAGE

FIXTURE = Path(__file__).parent / "data" / "unparseable_tools_server.py"

# Which shapes are unparseable depends on the ERA, so the assertions are split accordingly
# rather than pinned to whichever SDK happens to be installed.
#
# These three are rejected by both 1.x and 2.0, so they must always produce the finding.
ALWAYS_UNPARSEABLE = ["missing", "notobject", "nameless"]

# These three are rejected by 2.0 and ACCEPTED by 1.x, where they parse into ordinary tools
# and get ordinary schema findings. Both outcomes are correct; what must never happen on
# either era is the old one — exit 3 with no report.
ERA_DEPENDENT = ["empty", "badtype", "proplist"]

ALL_MALFORMED = [*ALWAYS_UNPARSEABLE, *ERA_DEPENDENT]


def _run(tmp_path: Path, shape: str, *extra: str) -> tuple[int, Path]:
    out = tmp_path / shape
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcp_gauntlet",
            "run",
            f"{sys.executable} {FIXTURE} {shape}",
            "--no-agentic",
            "--out",
            str(out),
            *extra,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
    )
    return proc.returncode, out


@pytest.mark.parametrize("shape", ALL_MALFORMED)
def test_no_malformed_shape_is_ever_unevaluable(shape: str, tmp_path: Path) -> None:
    """The invariant that holds on BOTH eras, and the one that was broken.

    Whether a given shape parses is the SDK's business and differs between 1.x and 2.0. What
    must not differ is that a malformed tool definition is always a *verdict about the
    server*: a report on disk, and never exit 3 — which the shipped CI example tells
    pipelines to retry, turning a real regression into an apparently flaky runner.
    """
    code, out = _run(tmp_path, shape, "--fail-on", "high")
    assert (out / "report.json").exists(), f"{shape}: no report, so the CI artifact is empty"
    assert code != Exit.UNEVALUABLE, f"{shape}: reported as infrastructure, not as a finding"


@pytest.mark.parametrize("shape", ALWAYS_UNPARSEABLE)
def test_an_unparseable_list_fails_the_gate_and_names_itself(shape: str, tmp_path: Path) -> None:
    """For the shapes both eras reject: exit 1, and a finding that says what happened.

    Only these three. On 1.x the era-dependent shapes parse into real tools and earn ordinary
    findings — `{}` becomes a MEDIUM "tool has no input schema", so `--fail-on high` passes it
    and `--fail-on medium` catches it. That is defensible, and pinning a gate outcome for them
    here would encode one SDK's strictness as the contract.
    """
    code, out = _run(tmp_path, shape, "--fail-on", "high")
    assert code == Exit.GATE_FAILED, f"{shape}: expected a failing gate, got exit {code}"
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    messages = [f["message"] for d in data["dimensions"] for f in d["findings"]]
    assert UNPARSEABLE_TOOLS_MESSAGE in messages, messages


def test_it_does_not_cap_the_grade(tmp_path: Path) -> None:
    """HIGH in Schema Health, deliberately NOT in Security Signals.

    A HIGH security finding caps the overall at 75, and METHODOLOGY reserves that for
    near-certain ATTACK signals. A malformed schema is a bug, not an adversary: it should
    lower the score without branding the server untrusted.
    """
    _, out = _run(tmp_path, "notobject")
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["grade_capped"] is False
    assert data["security_critical"] is False
    owner = [
        d["key"]
        for d in data["dimensions"]
        if any(f["message"] == UNPARSEABLE_TOOLS_MESSAGE for f in d["findings"])
    ]
    assert owner == ["schema_health"], owner


def test_it_is_not_reported_as_a_server_with_no_tools(tmp_path: Path) -> None:
    """Zero tools is reached two ways, and they are opposite facts.

    "This server exposes no tools" would send the author into their registration code, when
    the server in fact answered `tools/list` with tools that could not be read.
    """
    _, out = _run(tmp_path, "notobject")
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    messages = [f["message"] for d in data["dimensions"] for f in d["findings"]]
    assert "server exposes no tools" not in messages, messages


def test_a_healthy_server_is_unaffected(tmp_path: Path) -> None:
    """The guard must not fire on a valid tool list, or it fails every green build."""
    code, out = _run(tmp_path, "ok", "--fail-on", "high")
    assert code == Exit.OK
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    messages = [f["message"] for d in data["dimensions"] for f in d["findings"]]
    assert UNPARSEABLE_TOOLS_MESSAGE not in messages
    assert data["tool_count"] == 1
