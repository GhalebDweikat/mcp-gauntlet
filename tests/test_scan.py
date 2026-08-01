"""Scanning several servers you own — deliberately not a leaderboard.

The distinction is the reason this module replaced one. A leaderboard RANKS, which needs
scores to be comparable across servers, and they are not: the overall is a weighted mean over
the dimensions that ran, so it moves when a stage is skipped, when a server is
credential-gated, when `--no-probe` is passed, and between releases. A tester measured the
consequence — a nine-tool server and a copy of it with every description reduced to one word
scored 100.0 and 95.8, both an A.

That variance is survivable when you watch one server over time. It is not survivable in a
sorted public table, which is what the leaderboard was.
"""

import json
from pathlib import Path

import pytest

from mcp_gauntlet.scan import ScanResult, ServerEntry, ServerListError, load_servers


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_a_server_list_loads(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "s.json",
        {"servers": [{"name": "notes", "spec": "python -m notes"}]},
    )
    assert load_servers(path) == [ServerEntry(name="notes", spec="python -m notes")]


@pytest.mark.parametrize(
    ("payload", "because"),
    [
        ({"servers": {}}, "servers must be a list"),
        ({}, "no servers key"),
        ([{"name": "a", "spec": "b"}], "top level must be an object"),
        ({"servers": [{"name": "a"}]}, "an entry missing spec"),
    ],
)
def test_a_malformed_list_says_what_is_wrong(tmp_path: Path, payload: object, because: str) -> None:
    # A CI job pointed at the wrong file should learn that from the message, not from a
    # traceback — this runs before any evaluation and is the first thing a user gets wrong.
    path = _write(tmp_path / "s.json", payload)
    with pytest.raises(ServerListError):
        load_servers(path)


def test_a_missing_file_is_a_list_error_not_an_oserror(tmp_path: Path) -> None:
    with pytest.raises(ServerListError):
        load_servers(tmp_path / "nope.json")


def test_an_unevaluated_server_is_not_a_quality_verdict() -> None:
    """The distinction the exit codes rest on.

    A server that could not be reached has no findings, so it cannot trip the gate. It is
    reported, and the run exits 3 rather than 1 — because a scan that reports an unreachable
    server as a quality regression is a scan that gets switched off after one bad afternoon.
    """
    unreachable = ScanResult(name="down", spec="nope", error="timed out after 240s")
    assert unreachable.evaluated is False
    assert unreachable.triggering == []


def test_an_evaluated_server_carries_its_gating_findings() -> None:
    from mcp_gauntlet.models import ServerInfo
    from mcp_gauntlet.report import DimensionResult, Finding, GauntletReport, Severity

    report = GauntletReport.build(
        spec="stdio: x",
        server=ServerInfo(name="x"),
        tool_count=1,
        dimensions=[
            DimensionResult(
                key="security",
                title="S",
                weight=2.0,
                score=50.0,
                findings=[Finding(tool="t", severity=Severity.HIGH, message="poisoned")],
            )
        ],
    )
    result = ScanResult(name="x", spec="stdio: x", report=report, triggering=["poisoned"])
    assert result.evaluated is True
    assert result.triggering == ["poisoned"]
