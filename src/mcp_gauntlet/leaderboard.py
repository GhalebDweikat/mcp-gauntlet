"""Run the gauntlet across many servers and render a static leaderboard site.

Produces a directory suitable for GitHub Pages: an ``index.html`` ranking table
plus a per-server report page under ``servers/``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio

from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.engine import evaluate_server
from mcp_gauntlet.htmlreport import _GRADE_COLORS, _STYLE, _esc, to_html
from mcp_gauntlet.jsonio import read_json_text
from mcp_gauntlet.llm import LLMConfig
from mcp_gauntlet.naming import slugify
from mcp_gauntlet.report import Dim, GauntletReport, Severity


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
    # The filename stem this server's artifacts use (page, saved JSON, badge). Kept even
    # when there is no page — a server that failed still needs its badge refreshed, or an
    # embedded one keeps showing the grade from a run this board no longer stands behind.
    slug: str = ""


class ServerListError(ValueError):
    """The --servers file could not be read as a list of servers."""


_read_json_text = read_json_text  # kept as a name here; the implementation is shared


def load_servers(path: Path) -> list[ServerEntry]:
    try:
        data = json.loads(_read_json_text(path))
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
    except (TypeError, KeyError) as exc:
        raise ServerListError(f'every entry in {path} needs "name" and "spec": {exc}') from exc


def _result_payload(result: LeaderboardResult) -> str:
    """Serialize one evaluated server so the site can be rebuilt without re-running it."""
    return json.dumps(
        {
            "name": result.name,
            "spec": result.spec,
            "error": result.error,
            "report": json.loads(result.report.model_dump_json()) if result.report else None,
        },
        indent=2,
    )


def load_results(out_dir: Path) -> list[LeaderboardResult]:
    """Reload previously evaluated servers from ``servers/*.json``.

    Running the board costs real LLM spend, so the raw reports are persisted alongside the
    rendered pages: changing how results are *presented* should never require paying to
    measure them again.
    """
    results: list[LeaderboardResult] = []
    for path in sorted((out_dir / "servers").glob("*.json")):
        data: Any = None
        report: GauntletReport | None = None
        try:
            data = json.loads(_read_json_text(path))
            raw = data.get("report") if isinstance(data, dict) else None
            report = GauntletReport(**raw) if isinstance(raw, dict) else None
        except (OSError, ValueError):  # covers JSONDecodeError and pydantic ValidationError
            data = None
        if not isinstance(data, dict):
            # Surface it as an unevaluable row rather than dropping it: a half-written file
            # would otherwise make a server silently disappear from a rebuilt board.
            results.append(
                LeaderboardResult(
                    name=path.stem,
                    spec="",
                    error=f"saved result could not be read ({path.name})",
                    slug=path.stem,
                )
            )
            continue
        results.append(
            LeaderboardResult(
                name=str(data.get("name") or path.stem),
                spec=str(data.get("spec") or ""),
                report=report,
                error=data.get("error") if report is None else None,
                page=f"servers/{path.stem}.html" if report else None,
                slug=path.stem,
            )
        )
    return results


# shields.io endpoint colors, keyed by grade. Named colors are shields' own vocabulary.
_BADGE_COLORS = {
    "A": "brightgreen",
    "B": "green",
    "C": "yellow",
    "D": "orange",
    "F": "red",
    "N/A": "lightgrey",
}


def badge_payload(report: GauntletReport | None) -> str:
    """A shields.io *endpoint* JSON document for one server's grade.

    Lets a server author embed a live badge that tracks their score with no image hosting
    on our side:
    ``![gauntlet](https://img.shields.io/endpoint?url=<board>/badges/<slug>.json)``.
    The message carries the grade and score together, because a grade alone hides the
    difference between a 90 and a 99 — and a score alone hides the security cap.

    ``None`` (the server could not be evaluated this run) renders an explicit
    "not evaluated" badge rather than leaving the previous run's grade in place — an
    embedded badge must never keep advertising a score the board no longer stands behind.
    """
    if report is None:
        return json.dumps(
            {
                "schemaVersion": 1,
                "label": "mcp-gauntlet",
                "message": "not evaluated",
                "color": "lightgrey",
            },
            indent=2,
        )
    grade = report.grade
    # Security first: a zero-tool server can still ship poisoned `instructions`, and the
    # board shows a ⚠ for exactly that. Checking N/A first would replace the warning with a
    # neutral grey "not scored" on the surface that lands in the author's README.
    if report.security_critical:
        # The cap is the headline finding; a bare "C" would read as mediocre-but-fine.
        detail = "not scored" if grade == "N/A" else f"{grade} ({report.overall_score:.1f})"
        message = f"{detail} — critical security finding"
        color = "red"
    elif grade == "N/A":
        message = "not scored"
        color = "lightgrey"
    else:
        # One decimal, matching the board row exactly. Rounding to whole points made the
        # badge contradict its own grade at every boundary: an 89.5 is a B but printed
        # "B (90)", indistinguishable from a genuine A(90) and disagreeing with the table.
        message = f"{grade} ({report.overall_score:.1f})"
        color = _BADGE_COLORS.get(grade, "lightgrey")
    return json.dumps(
        {"schemaVersion": 1, "label": "mcp-gauntlet", "message": message, "color": color},
        indent=2,
    )


def badge_markdown(slug: str, board_url: str) -> str:
    """The snippet a server author copies into their README to show a live badge."""
    endpoint = f"{board_url.rstrip('/')}/badges/{slug}.json"
    return (
        f"[![mcp-gauntlet](https://img.shields.io/endpoint?url={endpoint})]"
        f"({board_url.rstrip('/')}/)"
    )


_DATE_PREFIX = re.compile(r"\d{4}-\d{2}-\d{2}")


def _scanned_on(report: GauntletReport) -> str:
    """The date this score was measured (not the date the page was rendered).

    A rebuilt board re-stamps the page timestamp but the rows keep their original scan
    date — without this, a re-render would silently present months-old scores as fresh.
    ``generated_at`` is an unvalidated string on the model, so anything that isn't a
    leading ISO date renders as "—" rather than as a truncated non-date in the one column
    whose whole job is credibility.
    """
    match = _DATE_PREFIX.match(report.generated_at or "")
    return match.group(0) if match else "—"


def assign_slugs(names: list[str]) -> list[str]:
    """One distinct filename stem per server name, stable against reordering the list.

    Slugs are assigned over the whole list at once. When several names reduce to the same
    base, **every** one of them takes a name-derived suffix: handing the bare slug to
    whichever happened to be listed first would leave that one URL rebinding to a different
    server on a reorder — the same defect as a positional counter, narrowed to one victim.
    A badge URL is a public contract pasted into someone else's README, and reordering a
    JSON list is a routine edit.

    The result therefore depends on the list as a whole, not on each name alone: adding a
    name that slugs identically to an existing one moves the incumbent off the bare slug.
    That is the rarer disturbance of the two, but it is a real one — pinning slugs durably
    would mean persisting the name→slug map rather than deriving it.

    Uniqueness is enforced globally, not per group: a suffixed slug can otherwise land on
    another group's bare slug, and two servers sharing a stem would overwrite each other's
    saved result — silently discarding a paid evaluation.
    """
    groups: dict[str, list[int]] = {}
    for index, name in enumerate(names):
        groups.setdefault(slugify(name), []).append(index)

    slugs = [""] * len(names)
    used: set[str] = set()
    # Reserve the unambiguous names first, so a suffixed slug can never take one of theirs.
    for base, indexes in groups.items():
        if len(indexes) == 1:
            slugs[indexes[0]] = base
            used.add(base)

    for base, indexes in groups.items():
        if len(indexes) == 1:
            continue
        for index in indexes:
            digest = hashlib.sha256(names[index].encode("utf-8")).hexdigest()[:6]
            slug = f"{base}-{digest}"
            # Two entries with the identical name hash identically; they are
            # indistinguishable anyway, so a counter is as stable as anything can be.
            suffix = 2
            while slug in used:
                slug = f"{base}-{digest}-{suffix}"
                suffix += 1
            used.add(slug)
            slugs[index] = slug
    return slugs


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
    probe: bool = True,
    board_url: str | None = None,
    log: Callable[[str], None] = print,
) -> list[LeaderboardResult]:
    servers_dir = out_dir / "servers"
    servers_dir.mkdir(parents=True, exist_ok=True)

    results: list[LeaderboardResult] = []
    slugs = assign_slugs([entry.name for entry in entries])
    for entry, slug in zip(entries, slugs, strict=True):
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
                    probe=probe,
                )
        except TimeoutError:
            error = f"timed out after {timeout_s:.0f}s"
        except Exception as exc:  # noqa: BLE001 - one bad server shouldn't sink the batch
            error = str(exc)[:200]

        result = LeaderboardResult(
            name=entry.name, spec=entry.spec, report=report, error=error, slug=slug
        )
        if report is not None:
            page = servers_dir / f"{slug}.html"
            page.write_text(to_html(report), encoding="utf-8")
            result.page = f"servers/{page.name}"
            log(f"  -> {report.grade} ({report.overall_score:.1f})")
        else:
            log(f"  -> FAILED: {error}")
        # Always refresh the badge, including on failure: a badge left from an earlier run
        # would keep advertising a stale grade on the author's README for a server this run
        # could not evaluate at all.
        _write_badge(out_dir, slug, report)
        # Persist the raw result too, so the site can be re-rendered later for free.
        (servers_dir / f"{slug}.json").write_text(_result_payload(result), encoding="utf-8")
        results.append(result)

    # No pruning here: this run may cover a SUBSET of the board (re-scanning one server that
    # changed is the natural workflow), and every other server's saved result — and so its
    # place on the next full render — still stands. Retiring badges is `rerender`'s job,
    # where `servers/*.json` gives the complete picture. Pruning to this run's set would
    # break bystander READMEs that the next --render-only would then restore.
    board_url = board_url or _load_board_url(out_dir)
    _save_board_url(out_dir, board_url)
    (out_dir / "index.html").write_text(render_index(results, board_url), encoding="utf-8")
    return results


def _write_badge(out_dir: Path, slug: str, report: GauntletReport | None) -> None:
    badges_dir = out_dir / "badges"
    badges_dir.mkdir(parents=True, exist_ok=True)
    (badges_dir / f"{slug}.json").write_text(badge_payload(report), encoding="utf-8")


def _prune_badges(out_dir: Path, keep: set[str]) -> None:
    """Delete badge files for servers this board no longer publishes.

    A badge claims to reflect "this board's published score", so one for a server that was
    renamed, dropped from the list, or whose saved result was deleted is a standing lie —
    and it lives in someone else's README, where nobody will notice it went stale. The
    rendered index is rewritten wholesale from the current results, so the badges mirror it.
    """
    badges_dir = out_dir / "badges"
    if not badges_dir.is_dir():
        return
    for path in badges_dir.glob("*.json"):
        if path.stem not in keep:
            path.unlink()


def rerender(out_dir: Path, board_url: str | None = None) -> list[LeaderboardResult]:
    """Rebuild the site from saved results, without re-evaluating (and re-paying for) any."""
    results = load_results(out_dir)
    if not (out_dir / "servers").is_dir():
        # There is no saved-results directory to rebuild FROM — a moved or misspelled
        # --out, an interrupted sync, a fresh clone. Return before touching anything:
        # pruning against an empty set would delete every published badge endpoint (they
        # live in other people's READMEs) and blank the index, while the caller reports
        # that it found nothing and exits non-zero. An empty-but-present directory is
        # different: the results were deliberately removed, so retiring their badges is
        # exactly right.
        return results
    for result in results:
        if result.report is not None and result.page:
            (out_dir / result.page).write_text(to_html(result.report), encoding="utf-8")
        # Badges are derived from the saved result, so a re-render refreshes them (and
        # backfills them for boards saved before badges existed). A result with no report
        # gets an explicit "not evaluated" badge rather than keeping an older grade.
        if result.slug:
            _write_badge(out_dir, result.slug, result.report)
    _prune_badges(out_dir, {r.slug for r in results if r.slug})
    board_url = board_url or _load_board_url(out_dir)
    _save_board_url(out_dir, board_url)
    (out_dir / "index.html").write_text(render_index(results, board_url), encoding="utf-8")
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
td.scanned { color:var(--muted); font-size:.85rem; white-space:nowrap; }
pre.snippet { background:var(--card); border:1px solid var(--border); border-radius:8px;
  padding:10px 12px; overflow-x:auto; font-size:.8rem; }
"""


def _security_glyph(report: GauntletReport) -> str:
    """⚠ static tool-poisoning (caps the grade); ⚡ runtime output poisoning (does not cap)."""
    rs_dim = next((d for d in report.dimensions if d.key == Dim.RESPONSE_SAFETY), None)
    runtime_poison = bool(rs_dim and any(f.severity is Severity.HIGH for f in rs_dim.findings))
    return "⚠" if report.security_critical else ("⚡" if runtime_poison else "✓")


def _partial_reason(report: GauntletReport) -> str:
    """Why this server's overall isn't comparable with the ranked ones."""
    # First, ahead of every other case: the harness declined to score this server at all.
    # It is the only reason here that is explicitly NOT a criticism of the server, and
    # collapsing it into "no agent evaluation" would read as one.
    if report.unevaluated_reason:
        return report.unevaluated_reason
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
        task_success = _dim_score(rep, Dim.TASK_SUCCESS)
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
        f'<td class="num">{rep.tool_count}</td>'
        f'<td class="num scanned">{_esc(_scanned_on(rep))}</td></tr>'
    )


# The colspan values below track this column count: bump both when adding a column.
_BOARD_COLUMNS = 8

_BOARD_HEAD = (
    '<table class="board"><thead><tr>'
    '<th class="num">#</th><th>Server</th><th>Grade</th><th class="num">Score</th>'
    '<th class="num">Task&nbsp;success</th><th class="ctr">Security</th>'
    '<th class="num">Tools</th><th class="num">Scanned</th></tr></thead><tbody>'
)


# Deliberately NOT a real board: a snippet is only correct for the board that published it.
# Defaulting to any specific site would make every other operator's page hand out badge URLs
# pointing at that site — and because slugs are generic server names (git, filesystem), the
# badge would resolve and quietly advertise a DIFFERENT server's grade instead of 404ing.
BOARD_URL_PLACEHOLDER = "https://your-board.example"
_BOARD_META = "board.json"
METHODOLOGY_URL = "https://github.com/GhalebDweikat/mcp-gauntlet/blob/main/METHODOLOGY.md"


def _save_board_url(out_dir: Path, board_url: str | None) -> None:
    if board_url:
        (out_dir / _BOARD_META).write_text(
            json.dumps({"board_url": board_url}, indent=2), encoding="utf-8"
        )


def _load_board_url(out_dir: Path) -> str | None:
    """The URL a previous run published this board at.

    ``--render-only`` is the documented free rebuild, so it must not silently downgrade a
    correct badge snippet to the placeholder just because the flag wasn't repeated.
    """
    try:
        data = json.loads(_read_json_text(out_dir / _BOARD_META))
    except (OSError, ValueError):
        return None
    url = data.get("board_url") if isinstance(data, dict) else None
    return str(url) if url else None


def _badge_section(shown: list[LeaderboardResult], board_url: str | None) -> str:
    """Tell a listed server's author how to embed their live badge.

    The badge reads the same ``badges/<slug>.json`` the board writes, so it updates when the
    board does — no action needed from the author after the one-time paste, and no claim
    here that we will keep it fresh beyond the next scan.
    """
    example = next((r for r in shown if r.slug), None)
    slug = example.slug if example else "your-server"
    url = board_url or BOARD_URL_PLACEHOLDER
    snippet = badge_markdown(slug, url)
    unset_note = (
        ""
        if board_url
        else '<p class="note">This board was generated without <code>--board-url</code>, so '
        f"the snippet above uses a placeholder host — replace <code>{_esc(url)}</code> with "
        "the URL this site is published at.</p>"
    )
    return (
        "<h2>Add your badge</h2>"
        '<p class="note">Listed here? Paste this into your README — it reads this board\'s '
        "published score and updates whenever the board is regenerated. Swap "
        f"<code>{_esc(slug)}</code> for your server's slug: the filename of its row link, "
        "without the <code>.html</code>.</p>"
        f'<pre class="snippet">{_esc(snippet)}</pre>'
        + unset_note
        + '<p class="note">Not listed, or think a score is wrong? Open an issue on the '
        "repository — re-runs and corrections are free. How these scores are computed, what "
        "they are not, and the disclosure policy behind publishing them: see "
        f'<a href="{_esc(METHODOLOGY_URL)}">METHODOLOGY.md</a>.</p>'
    )


def render_index(results: list[LeaderboardResult], board_url: str | None = None) -> str:
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
        # But promote only servers that merely went untested. One the pre-flight determined
        # cannot work without credentials was NOT measured the same way: we know its tools
        # do not function, and its static score is untouched by that, so promoting it would
        # rank an unusable server against working ones — plausibly at the top.
        def _blocked(r: LeaderboardResult) -> bool:
            return bool(r.report and r.report.unevaluated_reason)

        full = [r for r in partial if not _blocked(r)]
        partial = [r for r in partial if _blocked(r)]

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

    # Every version that produced a score on this page. A board rebuilt after an upgrade can
    # legitimately mix them, and saying so is the honest alternative to implying one number.
    # Rows with no recorded version are LISTED, never dropped: silently omitting them would
    # let a board with one fresh row and nine unknown ones claim a single methodology —
    # exactly the comparability guarantee this line exists to make good on.
    stamped = {r.report.gauntlet_version for r in results if r.report}
    known = sorted(v for v in stamped if v)
    if known and "" in stamped:
        versions = f"mcp-gauntlet {', '.join(known)} and an unrecorded earlier version"
    elif known:
        versions = f"mcp-gauntlet {', '.join(known)}"
    else:
        versions = "an unrecorded version of mcp-gauntlet"

    board = (
        _BOARD_HEAD
        + "".join(_board_row(r, str(i)) for i, r in enumerate(ranked, start=1))
        + "</tbody></table>"
    )

    partial_section = ""
    if partial:
        partial_rows = "".join(
            _board_row(r, "—") + f'<tr class="failed"><td></td><td colspan="{_BOARD_COLUMNS - 1}">'
            f"{_esc(_partial_reason(r.report))}</td></tr>"
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
                reason = f"could not evaluate: {r.error or 'reason not recorded'}"
            name_cell = f'<a href="{_esc(r.page)}">{_esc(r.name)}</a>' if r.page else _esc(r.name)
            unranked_rows.append(
                f'<tr class="failed"><td class="num">—</td><td>{name_cell}</td>'
                f'<td colspan="{_BOARD_COLUMNS - 2}">{_esc(reason)}</td></tr>'
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
        + f'<p class="note">Scored by {_esc(versions)}. Scoring changes between '
        "releases, so compare scores only within the same version — each row's "
        "<strong>Scanned</strong> date is when that score was measured, not when this page "
        "was rebuilt.</p>"
        + partial_section
        + unranked_section
        # `unranked` included deliberately: rerender writes badges for failed/N-A servers
        # too, so they are legitimate examples — and on a board where nothing scored, they
        # are the ONLY ones, which is exactly when a placeholder filename would be wrong.
        + _badge_section(ranked + partial + unranked, board_url)
        + "</div>"
    )
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>mcp-gauntlet leaderboard</title>\n"
        f"<style>{_STYLE}{_INDEX_STYLE}</style>\n</head><body>\n{body}\n</body></html>\n"
    )
