"""Run the gauntlet across many servers and render a static leaderboard site.

Produces a directory suitable for GitHub Pages: an ``index.html`` ranking table
plus a per-server report page under ``servers/``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import anyio

from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.engine import evaluate_server
from mcp_gauntlet.htmlreport import _GRADE_COLORS, _STYLE, _esc, to_html
from mcp_gauntlet.llm import LLMConfig
from mcp_gauntlet.report import GauntletReport


@dataclass
class ServerEntry:
    name: str
    spec: str


@dataclass
class LeaderboardResult:
    name: str
    spec: str
    report: GauntletReport | None = None
    error: str | None = None
    page: str | None = None


def load_servers(path: Path) -> list[ServerEntry]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [ServerEntry(name=str(s["name"]), spec=str(s["spec"])) for s in data["servers"]]


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "server"


def _dim_score(report: GauntletReport, key: str) -> float | None:
    for dim in report.dimensions:
        if dim.key == key:
            return dim.score
    return None


async def run_leaderboard(
    entries: list[ServerEntry],
    *,
    out_dir: Path,
    llm_config: LLMConfig | None,
    n_tasks: int = 3,
    repeats: int = 2,
    max_turns: int = 8,
    timeout_s: float = 240.0,
    log: Callable[[str], None] = print,
) -> list[LeaderboardResult]:
    servers_dir = out_dir / "servers"
    servers_dir.mkdir(parents=True, exist_ok=True)

    results: list[LeaderboardResult] = []
    for entry in entries:
        log(f"[leaderboard] evaluating {entry.name} ...")
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
                )
        except TimeoutError:
            error = f"timed out after {timeout_s:.0f}s"
        except Exception as exc:  # noqa: BLE001 - one bad server shouldn't sink the batch
            error = str(exc)[:200]

        result = LeaderboardResult(name=entry.name, spec=entry.spec, report=report, error=error)
        if report is not None:
            page = servers_dir / f"{_slug(entry.name)}.html"
            page.write_text(to_html(report), encoding="utf-8")
            result.page = f"servers/{page.name}"
            log(f"  -> {report.grade} ({report.overall_score:.1f})")
        else:
            log(f"  -> FAILED: {error}")
        results.append(result)

    (out_dir / "index.html").write_text(render_index(results), encoding="utf-8")
    return results


_INDEX_STYLE = """
.lead { color:var(--muted); max-width:60ch; }
table.board { margin-top:20px; }
.board th, .board td { padding:10px 12px; }
.gr { display:inline-block; min-width:1.6em; text-align:center; color:#fff; font-weight:700;
  padding:2px 8px; border-radius:8px; }
.ctr { text-align:center; }
tr.failed td { color:var(--muted); }
a { color:#0969da; text-decoration:none; } a:hover { text-decoration:underline; }
@media (prefers-color-scheme: dark) { a { color:#4493f8; } }
.note { color:var(--muted); font-size:.85rem; margin-top:8px; }
"""


def render_index(results: list[LeaderboardResult]) -> str:
    # A zero-tool (N/A) server was not really scored, so keep it out of the ranked table
    # (where its synthetic 0.0 would sort it below a genuinely-graded F) and list it with
    # the unevaluable ones.
    def _is_na(r: LeaderboardResult) -> bool:
        return r.report is not None and r.report.grade == "N/A"

    ranked = sorted(
        (r for r in results if r.report is not None and not _is_na(r)),
        key=lambda r: r.report.overall_score,  # type: ignore[union-attr]
        reverse=True,
    )
    unranked = [r for r in results if r.report is None or _is_na(r)]

    model = "—"
    for r in ranked:
        if r.report and r.report.agentic:
            model = f"{r.report.agentic.provider}:{r.report.agentic.model}"
            break

    rows: list[str] = []
    for i, r in enumerate(ranked, start=1):
        rep = r.report
        assert rep is not None
        grade_color = _GRADE_COLORS.get(rep.grade, "#57606a")
        if rep.agentic and rep.agentic.inconclusive:
            ts = "incon."
        else:
            task_success = _dim_score(rep, "task_success")
            ts = f"{task_success:.0f}" if task_success is not None else "—"
        security = "⚠" if rep.security_critical else "✓"
        name_cell = f'<a href="{_esc(r.page)}">{_esc(r.name)}</a>' if r.page else _esc(r.name)
        rows.append(
            f'<tr><td class="num">{i}</td><td>{name_cell}</td>'
            f'<td><span class="gr" style="background:{grade_color}">{_esc(rep.grade)}</span></td>'
            f'<td class="num">{rep.overall_score:.1f}</td>'
            f'<td class="num">{ts}</td>'
            f'<td class="ctr">{security}</td>'
            f'<td class="num">{rep.tool_count}</td></tr>'
        )
    for r in unranked:
        reason = "exposes no tools" if r.report is not None else f"could not evaluate: {r.error}"
        name_cell = f'<a href="{_esc(r.page)}">{_esc(r.name)}</a>' if r.page else _esc(r.name)
        rows.append(
            f'<tr class="failed"><td class="num">—</td><td>{name_cell}</td>'
            f'<td colspan="5">{_esc(reason)}</td></tr>'
        )

    generated = datetime.now(UTC).isoformat(timespec="minutes")
    body = (
        '<div class="wrap">'
        "<h1>mcp-gauntlet leaderboard</h1>"
        '<p class="lead">Each MCP server is run through the gauntlet: a live LLM agent '
        "attempts generated tasks using only the server's tools, alongside schema, "
        "description, security, reliability, and robustness checks. Grade is the weighted "
        "overall; a critical security finding caps it.</p>"
        '<table class="board"><thead><tr>'
        '<th class="num">#</th><th>Server</th><th>Grade</th><th class="num">Score</th>'
        '<th class="num">Task&nbsp;success</th><th class="ctr">Security</th>'
        '<th class="num">Tools</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table>"
        f'<p class="note">Agent model: {_esc(model)} · generated {_esc(generated)} · '
        "scores from a live agent are stochastic (repeated and averaged); "
        "the ⚠ flag marks tool-poisoning / injection findings.</p>"
        "</div>"
    )
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>mcp-gauntlet leaderboard</title>\n"
        f"<style>{_STYLE}{_INDEX_STYLE}</style>\n</head><body>\n{body}\n</body></html>\n"
    )
