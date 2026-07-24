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
from mcp_gauntlet.report import GauntletReport, Severity


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


def _unique_slug(name: str, used: set[str]) -> str:
    """A slug that won't collide with one already written (two names can slug the same)."""
    base = _slug(name)
    slug = base
    suffix = 2
    while slug in used:
        slug = f"{base}-{suffix}"
        suffix += 1
    used.add(slug)
    return slug


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
    tool_timeout_s: float = 60.0,
    log: Callable[[str], None] = print,
) -> list[LeaderboardResult]:
    servers_dir = out_dir / "servers"
    servers_dir.mkdir(parents=True, exist_ok=True)

    results: list[LeaderboardResult] = []
    used_slugs: set[str] = set()
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
                    tool_timeout_s=tool_timeout_s,
                )
        except TimeoutError:
            error = f"timed out after {timeout_s:.0f}s"
        except Exception as exc:  # noqa: BLE001 - one bad server shouldn't sink the batch
            error = str(exc)[:200]

        result = LeaderboardResult(name=entry.name, spec=entry.spec, report=report, error=error)
        if report is not None:
            page = servers_dir / f"{_unique_slug(entry.name, used_slugs)}.html"
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
h2 { margin-top:36px; font-size:1.1rem; }
.badge { display:inline-block; font-size:.72rem; font-weight:600; padding:2px 8px;
  border-radius:999px; background:var(--track); color:var(--muted); vertical-align:2px; }
"""


def _security_glyph(report: GauntletReport) -> str:
    """⚠ static tool-poisoning (caps the grade); ⚡ runtime output poisoning (does not cap)."""
    rs_dim = next((d for d in report.dimensions if d.key == "response_safety"), None)
    runtime_poison = bool(rs_dim and any(f.severity is Severity.HIGH for f in rs_dim.findings))
    return "⚠" if report.security_critical else ("⚡" if runtime_poison else "✓")


def _partial_reason(report: GauntletReport) -> str:
    """Why this server's overall isn't comparable with the ranked ones."""
    agentic = report.agentic
    if agentic is None:
        return "no agent evaluation (static checks only)"
    # Checked before `inconclusive`: when a hang and a judge error coincide both are true,
    # but blaming the LLM for a server that hung is the wrong attribution.
    if report.agent_eval_truncated:
        ran, planned = len(agentic.results), agentic.tasks_generated
        # A hang on the last task truncates repeats without shortening the task list, so
        # only quote the task count when it actually differs.
        scope = f"{ran} of {planned} tasks ran" if ran < planned else "fewer samples than planned"
        return f"agent evaluation stopped early — a tool hung ({scope})"
    if agentic.inconclusive:
        return "agent evaluation inconclusive (LLM backend errored)"
    if not agentic.tasks_generated and agentic.excluded_write_tools:
        return "no read-only tools to test (all excluded as possibly-mutating)"
    return "agent dimensions missing"


def _score_of(result: LeaderboardResult) -> float:
    return result.report.overall_score if result.report is not None else 0.0


def _board_row(result: LeaderboardResult, rank: str) -> str:
    rep = result.report
    assert rep is not None  # callers filter out result-less entries
    grade_color = _GRADE_COLORS.get(rep.grade, "#57606a")
    if rep.agentic and rep.agentic.inconclusive:
        ts = "incon."
    else:
        task_success = _dim_score(rep, "task_success")
        ts = f"{task_success:.0f}" if task_success is not None else "—"
    name_cell = (
        f'<a href="{_esc(result.page)}">{_esc(result.name)}</a>'
        if result.page
        else _esc(result.name)
    )
    return (
        f'<tr><td class="num">{_esc(rank)}</td><td>{name_cell}</td>'
        f'<td><span class="gr" style="background:{grade_color}">{_esc(rep.grade)}</span></td>'
        f'<td class="num">{rep.overall_score:.1f}</td>'
        f'<td class="num">{ts}</td>'
        f'<td class="ctr">{_security_glyph(rep)}</td>'
        f'<td class="num">{rep.tool_count}</td></tr>'
    )


_BOARD_HEAD = (
    '<table class="board"><thead><tr>'
    '<th class="num">#</th><th>Server</th><th>Grade</th><th class="num">Score</th>'
    '<th class="num">Task&nbsp;success</th><th class="ctr">Security</th>'
    '<th class="num">Tools</th></tr></thead><tbody>'
)


def render_index(results: list[LeaderboardResult]) -> str:
    # A zero-tool (N/A) server was not really scored, so keep it out of the ranked table
    # (where its synthetic 0.0 would sort it below a genuinely-graded F) and list it with
    # the unevaluable ones.
    def _is_na(r: LeaderboardResult) -> bool:
        return r.report is not None and r.report.grade == "N/A"

    scored = [r for r in results if r.report is not None and not _is_na(r)]
    unranked = [r for r in results if r.report is None or _is_na(r)]

    # The overall is a weighted mean over the dimensions PRESENT, so a server whose agent
    # evaluation never ran skips Agent Task Success (weight 3) and is averaged over a much
    # smaller denominator — it scores systematically higher than one that actually faced
    # the agent. Ranking the two together lets an untested server outrank a tested one, so
    # they get separate tables.
    # A truncated eval (stopped early by a hang) is excluded too: its score covers only the
    # tasks that ran before the hang, a sample size the server itself controls.
    def _comparable(r: LeaderboardResult) -> bool:
        return (
            r.report is not None
            and r.report.agentically_scored
            and not r.report.agent_eval_truncated
        )

    full = [r for r in scored if _comparable(r)]
    partial = [r for r in scored if not _comparable(r)]
    # Unless NOTHING was agentically scored (a keyless, static-only run) — then every server
    # was measured the same way, so they are mutually comparable and belong in one table.
    static_board = not full
    if static_board:
        full, partial = partial, []

    ranked = sorted(full, key=_score_of, reverse=True)
    # Partials are NOT sorted by score: they carry different denominators from each other
    # too (static-only vs inconclusive vs nothing-runnable), so ordering them by score would
    # re-imply the very comparison this section exists to deny. Alphabetical instead.
    partial = sorted(partial, key=lambda r: r.name.lower())

    model = "—"
    for r in results:
        if r.report and r.report.agentic:
            model = f"{r.report.agentic.provider}:{r.report.agentic.model}"
            break

    board = (
        _BOARD_HEAD
        + "".join(_board_row(r, str(i)) for i, r in enumerate(ranked, start=1))
        + "</tbody></table>"
    )

    partial_section = ""
    if partial:
        partial_rows = "".join(
            _board_row(r, "—")
            + f'<tr class="failed"><td></td><td colspan="6">{_esc(_partial_reason(r.report))}'
            "</td></tr>"
            for r in partial
            if r.report is not None
        )
        partial_section = (
            '<h2>Partially evaluated <span class="badge">not comparable</span></h2>'
            '<p class="note">These servers were not measured the same way as the ranked '
            "ones — the agent either never scored them, or stopped partway when a tool "
            "hung. Either way their score rests on a different basis: the overall is a "
            "weighted mean over the dimensions present, over however many runs completed, "
            "so a missing Agent Task Success (the heaviest dimension) or a short sample "
            "inflates the number relative to the ranked table. Each row says which "
            "applied.</p>" + _BOARD_HEAD + partial_rows + "</tbody></table>"
        )

    unranked_section = ""
    if unranked:
        unranked_rows = []
        for r in unranked:
            if r.report is not None:
                reason = "exposes no tools"
                # A tool-less server can still ship poisoned instructions — R5 keeps that
                # finding on the report, so surface it here instead of dropping it.
                if r.report.security_critical:
                    reason += " · ⚠ critical security finding in its instructions"
            else:
                reason = f"could not evaluate: {r.error}"
            name_cell = f'<a href="{_esc(r.page)}">{_esc(r.name)}</a>' if r.page else _esc(r.name)
            unranked_rows.append(
                f'<tr class="failed"><td class="num">—</td><td>{name_cell}</td>'
                f'<td colspan="5">{_esc(reason)}</td></tr>'
            )
        unranked_section = (
            "<h2>Not scored</h2>" + _BOARD_HEAD + "".join(unranked_rows) + "</tbody></table>"
        )

    generated = datetime.now(UTC).isoformat(timespec="minutes")
    # On an all-static board nothing was agent-scored, so the standard lead — which promises
    # a live agent — would be a false claim about every row on the page.
    lead = (
        "None of these servers received an agent task-success score — no LLM was "
        "configured, the backend errored, or no read-only tools were available to call. "
        "The grades below therefore reflect the STATIC checks only (schema, description, "
        "security, robustness) and carry none of the agentic signal the gauntlet normally "
        "weighs most heavily. They are comparable with each other, but not with a scored run."
        if static_board
        else "Each MCP server is run through the gauntlet: a live LLM agent attempts "
        "generated tasks using only the server's tools, alongside schema, description, "
        "security, reliability, and robustness checks. Grade is the weighted overall; "
        "a critical security finding caps it."
    )
    body = (
        '<div class="wrap">'
        "<h1>mcp-gauntlet leaderboard</h1>"
        f'<p class="lead">{lead}</p>'
        + board
        + f'<p class="note">Agent model: {_esc(model)} · generated {_esc(generated)}'
        # The stochastic-scores caveat describes agent runs; on an all-static board no row
        # had one, so repeating it there would restate the claim the lead just withdrew.
        + (
            " · "
            if static_board
            else " · scores from a live agent are stochastic (repeated and averaged); "
        )
        + "⚠ = static tool-poisoning in a description (caps the grade), "
        "⚡ = injection in a live tool output (does not cap).</p>"
        + partial_section
        + unranked_section
        + "</div>"
    )
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>mcp-gauntlet leaderboard</title>\n"
        f"<style>{_STYLE}{_INDEX_STYLE}</style>\n</head><body>\n{body}\n</body></html>\n"
    )
