"""Render a GauntletReport as a self-contained, styled HTML file (no external assets)."""

from __future__ import annotations

import html
from typing import Any

from mcp_gauntlet.report import GauntletReport, Severity, sort_findings

_GRADE_COLORS = {"A": "#1a7f37", "B": "#2da44e", "C": "#9a6700", "D": "#bc4c00", "F": "#cf222e"}
_SEV_COLORS: dict[Severity, str] = {
    Severity.HIGH: "#cf222e",
    Severity.MEDIUM: "#9a6700",
    Severity.LOW: "#0969da",
    Severity.INFO: "#57606a",
}

_STYLE = """
:root { --bg:#fff; --fg:#1f2328; --muted:#656d76; --card:#f6f8fa; --border:#d0d7de; --track:#eaeef2; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --fg:#e6edf3; --muted:#8b949e; --card:#161b22; --border:#30363d; --track:#21262d; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
.wrap { max-width:820px; margin:0 auto; padding:36px 20px 72px; }
.mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
h1 { font-size:1.7rem; margin:0 0 4px; }
.spec { color:var(--muted); font-size:.85rem; word-break:break-all; }
.grade-card { display:flex; align-items:center; gap:22px; background:var(--card);
  border:1px solid var(--border); border-radius:14px; padding:22px 26px; margin:22px 0; }
.grade { font-size:2.8rem; font-weight:800; line-height:1; padding:10px 20px; border-radius:14px; color:#fff; }
.score { font-size:1.6rem; font-weight:700; }
.score small { color:var(--muted); font-weight:400; font-size:.85rem; }
.banner { background:#ffebe9; border:1px solid #ff818266; color:#cf222e; padding:12px 16px;
  border-radius:8px; margin:16px 0; font-weight:600; }
@media (prefers-color-scheme: dark) { .banner { background:#3d1113; color:#ff9492; border-color:#5a1e22; } }
h2 { font-size:1.05rem; margin:32px 0 14px; padding-bottom:7px; border-bottom:1px solid var(--border); }
.dim { display:grid; grid-template-columns:1fr auto; gap:5px 12px; align-items:center; margin:12px 0; }
.dim .name { font-weight:600; }
.dim .val { font-variant-numeric:tabular-nums; font-weight:700; }
.dim .wt { color:var(--muted); font-size:.78rem; font-weight:500; }
.bar { grid-column:1 / -1; height:8px; background:var(--track); border-radius:99px; overflow:hidden; }
.bar > i { display:block; height:100%; border-radius:99px; }
table { width:100%; border-collapse:collapse; font-size:.9rem; }
th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); vertical-align:top; }
th { color:var(--muted); font-weight:600; }
td.num,th.num { text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }
.chip { display:inline-block; background:var(--card); border:1px solid var(--border);
  border-radius:99px; padding:2px 10px; font-size:.8rem; color:var(--muted); }
.finding { display:flex; gap:10px; align-items:flex-start; padding:9px 0; border-bottom:1px solid var(--border); }
.sev { flex:none; font-size:.68rem; font-weight:700; text-transform:uppercase; color:#fff;
  padding:2px 8px; border-radius:99px; margin-top:2px; }
.finding .scope { font-weight:600; }
.finding .detail { color:var(--muted); font-size:.85rem; margin-top:2px; word-break:break-word; }
.muted { color:var(--muted); }
footer { margin-top:44px; color:var(--muted); font-size:.8rem; text-align:center; }
"""


def _esc(value: Any) -> str:
    return html.escape(str(value))


def _score_color(score: float) -> str:
    if score >= 90:
        return "#1a7f37"
    if score >= 75:
        return "#2da44e"
    if score >= 60:
        return "#9a6700"
    return "#cf222e"


def _body(report: GauntletReport) -> str:
    p: list[str] = ['<div class="wrap">']
    p.append(f"<h1>{_esc(report.server.name or 'unknown server')}</h1>")
    p.append(f'<div class="spec mono">{_esc(report.spec)}</div>')

    grade_color = _GRADE_COLORS.get(report.grade, "#57606a")
    meta = f"{report.tool_count} tools"
    if report.agentic:
        meta += f" · agent {_esc(report.agentic.provider)}:{_esc(report.agentic.model)}"
    p.append('<div class="grade-card">')
    p.append(f'<div class="grade" style="background:{grade_color}">{_esc(report.grade)}</div>')
    p.append(
        f'<div><div class="score">{report.overall_score:.1f}<small>/100</small></div>'
        f'<div class="muted">{meta}</div></div>'
    )
    p.append("</div>")

    if report.security_critical:
        p.append('<div class="banner">⚠ Critical security finding(s) — overall grade capped.</div>')

    p.append("<h2>Dimensions</h2>")
    for dim in report.dimensions:
        width = max(0.0, min(100.0, dim.score))
        p.append('<div class="dim">')
        p.append(f'<span class="name">{_esc(dim.title)}</span>')
        p.append(
            f'<span class="val">{dim.score:.1f} <span class="wt">×{dim.weight:g}</span></span>'
        )
        p.append(
            f'<span class="bar"><i style="width:{width}%;background:{_score_color(dim.score)}"></i></span>'
        )
        p.append("</div>")

    agentic = report.agentic
    if agentic and agentic.results:
        p.append("<h2>Agent evaluation</h2>")
        p.append(
            f'<div class="muted" style="margin-bottom:12px">{agentic.tasks_generated} tasks × '
            f'{agentic.repeats} repeat(s) &nbsp;<span class="chip">'
            f"{_esc(agentic.provider)}:{_esc(agentic.model)}</span></div>"
        )
        p.append(
            '<table><thead><tr><th>Task</th><th class="num">Pass</th>'
            '<th class="num">Score</th><th class="num">Tools</th></tr></thead><tbody>'
        )
        for r in agentic.results:
            sel = f"{r.selection_score:.0f}" if r.selection_score is not None else "—"
            p.append(
                f"<tr><td>{_esc(r.description[:120])}</td>"
                f'<td class="num">{r.successes}/{r.repeats}</td>'
                f'<td class="num">{r.mean_score:.0f}</td><td class="num">{sel}</td></tr>'
            )
        p.append("</tbody></table>")
        if agentic.excluded_write_tools:
            excluded = _esc(", ".join(agentic.excluded_write_tools))
            p.append(
                f'<div class="muted" style="margin-top:10px">Excluded '
                f"(possibly-mutating) tools: {excluded}</div>"
            )

    p.append("<h2>Findings</h2>")
    if not report.findings:
        p.append('<div class="muted">No findings.</div>')
    for dim in report.dimensions:
        findings = sort_findings(dim.findings)
        if not findings:
            continue
        p.append(f'<div class="muted" style="margin:16px 0 4px">{_esc(dim.title)}</div>')
        for f in findings:
            scope = _esc(f.tool) if f.tool else "server"
            detail = f'<div class="detail">{_esc(f.detail)}</div>' if f.detail else ""
            p.append(
                f'<div class="finding"><span class="sev" style="background:{_SEV_COLORS[f.severity]}">'
                f"{_esc(f.severity.value)}</span><div>"
                f'<span class="scope">{scope}</span>: {_esc(f.message)}{detail}</div></div>'
            )

    p.append(f"<footer>Generated {_esc(report.generated_at)} · mcp-gauntlet</footer>")
    p.append("</div>")
    return "".join(p)


def to_html(report: GauntletReport) -> str:
    title = _esc(report.server.name or "report")
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>mcp-gauntlet — {title}</title>\n"
        f"<style>{_STYLE}</style>\n</head><body>\n{_body(report)}\n</body></html>\n"
    )
