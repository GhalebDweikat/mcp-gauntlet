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


# --------------------------------------------------------------- credentials


def _list(tmp_path: Path, **entry: object) -> Path:
    path = tmp_path / "servers.json"
    base = {"name": "s", "spec": "python -m srv"}
    path.write_text(json.dumps({"servers": [{**base, **entry}]}), encoding="utf-8")
    return path


def test_unknown_keys_are_rejected_by_name(tmp_path: Path) -> None:
    """Silently ignoring a key someone wrote is how they end up trusting a gate that is not
    doing what they asked. A tester added `"env": [...]` by analogy with `run --env`, had it
    dropped without a word, and read a scan that could not call anything as healthy."""
    with pytest.raises(ServerListError, match="unknown key"):
        load_servers(_list(tmp_path, totally_bogus_key=123, fail_on="nonsense"))


def test_credentials_reach_the_spec(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`scan` had no --env and no --header at all, so it could not evaluate any server that
    needs a token — and "several servers you own" are exactly the ones with tokens."""
    monkeypatch.setenv("SERVICE_TOKEN", "tok-abc")
    entries = load_servers(
        _list(tmp_path, env=["SERVICE_TOKEN"], headers=["Authorization: Bearer xyz"])
    )
    spec = entries[0].to_spec()
    assert spec.env == {"SERVICE_TOKEN": "tok-abc"}
    assert spec.headers == {"Authorization": "Bearer xyz"}
    assert "tok-abc" in spec.secret_values()


@pytest.mark.parametrize("value", [None, ""])
def test_a_missing_credential_fails_the_load_not_the_scan(
    value: str | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail fast (exit 4) rather than mid-scan (exit 3).

    A credential that resolves to nothing used to surface as "could not evaluate", which is
    the ONE code the docs tell you not to fail a build on — so a scan reported healthy while
    every credentialed server in it went unchecked.

    The empty case is not a corner case: on GitHub Actions a fork PR expands
    `${{ secrets.TOKEN }}` to an empty string, so the variable exists and carries nothing.
    """
    if value is None:
        monkeypatch.delenv("SERVICE_TOKEN", raising=False)
    else:
        monkeypatch.setenv("SERVICE_TOKEN", value)
    with pytest.raises(ServerListError, match="SERVICE_TOKEN"):
        load_servers(_list(tmp_path, env=["SERVICE_TOKEN"]))


def test_an_explicitly_empty_value_is_honoured(tmp_path: Path) -> None:
    """`NAME=` is the escape hatch: the user said empty, so empty it is."""
    entries = load_servers(_list(tmp_path, env=["SERVICE_TOKEN="]))
    assert entries[0].to_spec().env == {"SERVICE_TOKEN": ""}


@pytest.mark.parametrize("key", ["env", "headers"])
def test_credential_fields_must_be_string_lists(key: str, tmp_path: Path) -> None:
    with pytest.raises(ServerListError, match=f'"{key}"'):
        load_servers(_list(tmp_path, **{key: "TOKEN"}))
    with pytest.raises(ServerListError, match=f'"{key}"'):
        load_servers(_list(tmp_path, **{key: [123]}))
