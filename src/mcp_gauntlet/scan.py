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
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import anyio

from mcp_gauntlet.config import (
    ServerSpec,
    TransportKind,
    parse_env_args,
    parse_header_args,
)
from mcp_gauntlet.engine import evaluate_server
from mcp_gauntlet.errors import describe, explain_remote_failure
from mcp_gauntlet.jsonio import read_json_text
from mcp_gauntlet.llm import LLMConfig
from mcp_gauntlet.naming import slugify
from mcp_gauntlet.report import GauntletReport, Severity, findings_at_or_above, redact


class ServerListError(ValueError):
    """The `--servers` file could not be read or is not shaped like a server list."""


@dataclass
class ServerEntry:
    name: str
    spec: str
    # Credentials, in the SAME string forms `run --env` / `--header` take, so the semantics
    # cannot drift between the two commands: "NAME" reads the parent environment (a secret
    # never appears in the committed list), "NAME=VALUE" inlines it, "Header: Value" for HTTP.
    env: list[str] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)

    def to_spec(self) -> ServerSpec:
        """The runnable spec, with credentials resolved."""
        spec = ServerSpec.parse(self.spec)
        spec.env = parse_env_args(self.env, dict(os.environ))
        spec.headers = parse_header_args(self.headers, dict(os.environ))
        return spec


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


_ENTRY_KEYS = {"name", "spec", "env", "headers"}


def _string_list(entry: dict, key: str, where: str) -> list[str]:
    value = entry.get(key, [])
    if isinstance(value, str) or not isinstance(value, list):
        raise ServerListError(f'{where}: "{key}" must be a list of strings')
    # Values are never echoed back: an env entry may be NAME=SECRET and a header may be
    # "Authorization: Bearer ...", and this error can reach a CI log.
    if not all(isinstance(item, str) for item in value):
        raise ServerListError(f'{where}: every "{key}" entry must be a string')
    return list(value)


def load_servers(path: Path) -> list[ServerEntry]:
    """Read a `{"servers": [{"name", "spec", "env", "headers"}]}` list.

    Unknown keys are an ERROR, not something to ignore. A user who adds `"env": [...]` by
    analogy with `run --env` and has it silently dropped believes their credentials are
    wired up when they are not — and then reads a scan that could not call anything as a
    healthy gate. Naming the key costs one line and saves that entirely.
    """
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
    entries: list[ServerEntry] = []
    for index, raw in enumerate(data["servers"]):
        where = f"{path}: server #{index + 1}"
        if not isinstance(raw, dict):
            raise ServerListError(f"{where} must be an object")
        if "name" not in raw or "spec" not in raw:
            raise ServerListError(f'{path}: each server needs "name" and "spec"')
        unknown = sorted(set(raw) - _ENTRY_KEYS)
        if unknown:
            raise ServerListError(
                f"{where} ({raw['name']}) has unknown key(s) {', '.join(unknown)}; "
                f"allowed: {', '.join(sorted(_ENTRY_KEYS))}"
            )
        entry = ServerEntry(
            name=str(raw["name"]),
            spec=str(raw["spec"]),
            env=_string_list(raw, "env", where),
            headers=_string_list(raw, "headers", where),
        )
        # Resolve NOW, before anything is scanned. A named variable that is not set in the
        # environment is a configuration error, and letting it surface mid-scan would record
        # the server as "could not evaluate" — exit 3, which the docs correctly tell you NOT
        # to fail a build on. A whole scan then reports healthy while every credentialed
        # server in it went unchecked. Failing fast costs one bad run and no false green.
        try:
            entry.to_spec()
        except ValueError as exc:
            raise ServerListError(f"{where} ({entry.name}): {exc}") from exc
        entries.append(entry)

    # Reports are written to a directory named after the entry, so two entries sharing a
    # name silently overwrite each other — a scan of a healthy server and a poisoned one
    # left ONE directory holding the second, with nothing saying the first had gone. A
    # loader that rejects an unknown KEY by name has no business colliding on names.
    seen: dict[str, int] = {}
    for index, entry in enumerate(entries, 1):
        slug = slugify(entry.name)
        if slug in seen:
            raise ServerListError(
                f"{path}: servers #{seen[slug]} and #{index} both resolve to the report "
                f"directory {slug!r} — give them distinct names"
            )
        seen[slug] = index
    return entries


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
        secrets: frozenset[str] = frozenset()
        try:
            spec = entry.to_spec()
            secrets = spec.secret_values()
            with anyio.fail_after(timeout_s):
                report = await evaluate_server(
                    spec,
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
            # server nor the cause. Redacted for the same reason `run` redacts here: a
            # connection error can echo a credential (a Postgres URI carries its password),
            # and this line goes to the console and into the scan log.
            # Classified for `scan` too. 0.9.2 gave `run` a message naming the URL and the
            # cause and left `scan` with a bare `ConnectError:` — the same asymmetry as the
            # 0.9.1 `scan --agentic` bug, where the fix reached one command and not the
            # other. `scan` is the command that hits remote servers in bulk.
            detail = (
                explain_remote_failure(spec.url, exc)
                if spec.kind is TransportKind.HTTP and spec.url
                else describe(exc)
            )
            error = redact(detail, secrets)

        result = ScanResult(name=entry.name, spec=entry.spec, report=report, error=error)
        if report is not None:
            # Each server's own report, in the same three formats a single `run` produces —
            # the artifact a maintainer reads to find out what to fix.
            from mcp_gauntlet.cli import write_report

            # `secrets` was the missing argument, and without it a scanned credentialed
            # server could write a token a server echoed back into a committed report —
            # exactly what `run` has always scrubbed.
            write_report(report, out_dir / slugify(entry.name), secrets)
            if fail_on is not None:
                result.triggering = [f.message for f in findings_at_or_above(report, fail_on)]
            log(f"  {report.grade} ({report.overall_score:.1f}) — {len(result.triggering)} gating")
        else:
            log(f"  could not evaluate: {error}")
        results.append(result)

    return results
