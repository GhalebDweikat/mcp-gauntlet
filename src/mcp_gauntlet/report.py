"""Report data model, scoring, and renderers (JSON + Markdown).

Scoring model (deliberately simple and explainable): each *subject* — a single
tool, or the server — starts at 100 and loses points per finding by severity.
A dimension's score is the mean of its per-subject scores, so it is normalized
by the number of tools rather than punishing large servers. The overall score is
the weighted mean of the dimension scores.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from mcp_gauntlet.models import ServerInfo


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


SEVERITY_PENALTY: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 5.0,
    Severity.MEDIUM: 12.0,
    Severity.HIGH: 25.0,
}

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
    Severity.INFO: 3,
}

# A HIGH-severity security finding caps the overall score here (a "C" ceiling),
# no matter how strong the other dimensions are.
GRADE_CAP_ON_CRITICAL = 75.0


class Finding(BaseModel):
    tool: str | None = None  # None → a server-level finding
    severity: Severity
    message: str
    detail: str | None = None


class DimensionResult(BaseModel):
    key: str
    title: str
    score: float
    weight: float = 1.0
    summary: str = ""
    findings: list[Finding] = Field(default_factory=list)


class TaskResult(BaseModel):
    description: str
    rubric: str = ""
    expected_tools: list[str] = Field(default_factory=list)
    repeats: int = 0
    successes: int = 0
    success_rate: float = 0.0
    mean_score: float = 0.0
    selection_score: float | None = None
    tool_error: bool = False
    errored_repeats: int = 0  # repeats where the LLM (agent or judge) failed — not counted
    inconclusive: bool = False  # every repeat errored → no valid judgment
    sample_reasoning: str = ""


class AgenticDetail(BaseModel):
    provider: str
    model: str
    tasks_generated: int
    repeats: int
    excluded_write_tools: list[str] = Field(default_factory=list)
    results: list[TaskResult] = Field(default_factory=list)
    inconclusive: bool = False  # the whole agentic eval was inconclusive (e.g. rate-limited)


class GauntletReport(BaseModel):
    spec: str
    server: ServerInfo
    tool_count: int
    dimensions: list[DimensionResult]
    overall_score: float
    grade: str
    generated_at: str
    security_critical: bool = False
    agentic: AgenticDetail | None = None

    @classmethod
    def build(
        cls,
        *,
        spec: str,
        server: ServerInfo,
        tool_count: int,
        dimensions: list[DimensionResult],
        agentic: AgenticDetail | None = None,
    ) -> GauntletReport:
        total_weight = sum(d.weight for d in dimensions) or 1.0
        overall = round(sum(d.score * d.weight for d in dimensions) / total_weight, 1)

        # A tool-poisoning / injection / hidden-character finding is a "do not trust
        # this server" signal that averaging must not wash out — cap the grade.
        security = next((d for d in dimensions if d.key == "security"), None)
        security_critical = bool(
            security and any(f.severity is Severity.HIGH for f in security.findings)
        )
        if security_critical:
            overall = min(overall, GRADE_CAP_ON_CRITICAL)

        return cls(
            spec=spec,
            server=server,
            tool_count=tool_count,
            dimensions=dimensions,
            overall_score=overall,
            grade=grade_for(overall),
            generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
            security_critical=security_critical,
            agentic=agentic,
        )

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for dimension in self.dimensions:
            out.extend(dimension.findings)
        return out


def score_from_findings(findings: list[Finding]) -> float:
    """Score one subject from its findings: 100 minus severity penalties, floored at 0."""
    penalty = sum(SEVERITY_PENALTY[f.severity] for f in findings)
    return max(0.0, 100.0 - penalty)


def grade_for(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER[f.severity], f.tool or "", f.message))


def to_markdown(report: GauntletReport) -> str:
    server_name = report.server.name or "unknown server"
    version = report.server.version or "?"
    lines: list[str] = [
        f"# mcp-gauntlet report — {server_name}",
        "",
        f"- **Server spec:** `{report.spec}`",
        f"- **Server:** {report.server.name or '(unknown)'} v{version}",
        f"- **Tools:** {report.tool_count}",
        f"- **Overall:** **{report.grade}** ({report.overall_score:.1f}/100)",
        f"- **Generated:** {report.generated_at}",
    ]
    if report.security_critical:
        lines.append("- ⚠️ **Critical security finding(s) present — overall grade is capped.**")
    lines += [
        "",
        "## Dimensions",
        "",
        "| Dimension | Score | Weight |",
        "|-----------|------:|-------:|",
    ]
    for dimension in report.dimensions:
        lines.append(f"| {dimension.title} | {dimension.score:.1f} | {dimension.weight:g} |")
    lines.append("")

    for dimension in report.dimensions:
        lines.append(f"### {dimension.title} — {dimension.score:.1f}/100")
        if dimension.summary:
            lines.extend(["", dimension.summary])
        findings = sort_findings(dimension.findings)
        if not findings:
            lines.extend(["", "_No issues found._", ""])
            continue
        lines.append("")
        for finding in findings:
            scope = f"`{finding.tool}`" if finding.tool else "_server_"
            detail = f" — {finding.detail}" if finding.detail else ""
            lines.append(f"- **[{finding.severity.upper()}]** {scope}: {finding.message}{detail}")
        lines.append("")

    if report.agentic:
        agentic = report.agentic
        lines.append("## Agentic evaluation")
        lines.append("")
        if agentic.inconclusive:
            lines.append(
                "> ⚠️ **Inconclusive** — the LLM backend errored (e.g. rate limit) on every "
                "run; the overall grade reflects the static checks only."
            )
            lines.append("")
        lines.append(f"- **Model:** {agentic.provider}:{agentic.model}")
        lines.append(f"- **Tasks:** {agentic.tasks_generated} × {agentic.repeats} repeat(s)")
        if agentic.excluded_write_tools:
            excluded = ", ".join(agentic.excluded_write_tools)
            lines.append(f"- **Excluded (possibly-mutating) tools:** {excluded}")
        lines.extend(
            [
                "",
                "| Task | Pass rate | Mean score | Tool selection |",
                "|------|----------:|-----------:|---------------:|",
            ]
        )
        for result in agentic.results:
            task_label = result.description.replace("\n", " ")[:70]
            if result.inconclusive:
                lines.append(f"| {task_label} | — | inconclusive | — |")
                continue
            sel = f"{result.selection_score:.0f}" if result.selection_score is not None else "—"
            lines.append(
                f"| {task_label} | {result.successes}/{result.repeats} | "
                f"{result.mean_score:.0f} | {sel} |"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_report(report: GauntletReport, out_dir: Path) -> tuple[Path, Path, Path]:
    from mcp_gauntlet.htmlreport import to_html  # lazy: htmlreport imports this module

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"
    html_path = out_dir / "report.html"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    md_path.write_text(to_markdown(report), encoding="utf-8")
    html_path.write_text(to_html(report), encoding="utf-8")
    return json_path, md_path, html_path
