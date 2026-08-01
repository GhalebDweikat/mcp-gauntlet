"""Run the gauntlet across several servers you own, and fail if any of them regressed.

This replaces the leaderboard. The two are not the same thing wearing different names, and
the difference is the whole point of the change.

A leaderboard RANKS servers against each other, which requires their scores to be
comparable — and they are not. A tester built a nine-tool server, then a copy with every
description reduced to a single word, and the two scored 100.0 and 95.8: both an A. The
overall is a weighted mean over the dimensions that ran, so it moves when a stage is skipped,
when a server is credential-gated, when `--no-probe` is passed, and between releases (one
bump moved a fixture 14.8 points). None of that matters when you are watching ONE server over
time. All of it matters the moment you put two servers in a sorted table and publish it.

So this scans a set and reports each on its own terms — no ranking, no grades compared side
by side, no badges, no published site. What it does instead is the thing a monorepo with
three MCP servers actually needs: run them all, write each report, and exit non-zero if any
of them has a finding at or above the severity you gate on.

One server failing does not sink the batch: an unreachable or broken server is recorded and
the rest still run, because "I could not evaluate this one" is a different fact from "this one
is bad" and the exit code keeps them apart.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import anyio

from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.engine import evaluate_server
from mcp_gauntlet.errors import describe
from mcp_gauntlet.jsonio import read_json_text
from mcp_gauntlet.llm import LLMConfig
from mcp_gauntlet.naming import slugify
from mcp_gauntlet.report import GauntletReport, Severity, findings_at_or_above


class ServerListError(ValueError):
    """The `--servers` file could not be read or is not shaped like a server list."""


@dataclass
class ServerEntry:
    name: str
    spec: str


@dataclass
class ScanResult:
    name: str
    spec: str
    report: GauntletReport | None = None
    # Why this server could not be evaluated at all — distinct from scoring badly. Kept as
    # prose because the reader deciding whether to care needs the sentence, not a code.
    error: str | None = None
    triggering: list[str] = field(default_factory=list)

    @property
    def evaluated(self) -> bool:
        return self.report is not None


def load_servers(path: Path) -> list[ServerEntry]:
    """Read a `{"servers": [{"name", "spec"}]}` list, with errors that name the problem."""
    try:
        data = json.loads(read_json_text(path))
    except OSError as exc:
        raise ServerListError(f"could not read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ServerListError(f"{path} is not UTF-8 or UTF-16 text: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ServerListError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("servers"), list):
        raise ServerListError(f'{path} must be an object with a "servers" list')
    try:
        return [ServerEntry(name=str(s["name"]), spec=str(s["spec"])) for s in data["servers"]]
    except (KeyError, TypeError) as exc:
        raise ServerListError(f'{path}: each server needs "name" and "spec"') from exc


async def run_scan(
    entries: list[ServerEntry],
    *,
    out_dir: Path,
    llm_config: LLMConfig | None,
    fail_on: Severity | None = None,
    n_tasks: int = 3,
    repeats: int = 2,
    max_turns: int = 8,
    timeout_s: float = 240.0,
    tool_timeout_s: float = 60.0,
    probe: bool = True,
    log: Callable[[str], None] = print,
) -> list[ScanResult]:
    """Evaluate each server, write its report, and record what would fail the gate."""
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[ScanResult] = []

    for entry in entries:
        log(f"[scan] {entry.name} ...")
        report: GauntletReport | None = None
        error: str | None = None
        try:
            with anyio.fail_after(timeout_s):
                report = await evaluate_server(
                    ServerSpec.parse(entry.spec),
                    llm_config=llm_config,
                    n_tasks=n_tasks,
                    repeats=repeats,
                    max_turns=max_turns,
                    tool_timeout_s=tool_timeout_s,
                    probe=probe,
                )
        except TimeoutError:
            error = f"timed out after {timeout_s:.0f}s"
        except Exception as exc:  # noqa: BLE001 - one bad server must not sink the batch
            # Unwrapped: anyio wraps session failures in a task group, and the bare string is
            # "unhandled errors in a TaskGroup (1 sub-exception)", which names neither the
            # server nor the cause.
            error = describe(exc)

        result = ScanResult(name=entry.name, spec=entry.spec, report=report, error=error)
        if report is not None:
            # Each server's own report, in the same three formats a single `run` produces —
            # the artifact a maintainer reads to find out what to fix.
            from mcp_gauntlet.cli import write_report

            write_report(report, out_dir / slugify(entry.name))
            if fail_on is not None:
                result.triggering = [f.message for f in findings_at_or_above(report, fail_on)]
            log(f"  {report.grade} ({report.overall_score:.1f}) — {len(result.triggering)} gating")
        else:
            log(f"  could not evaluate: {error}")
        results.append(result)

    return results
