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
    truncated: bool = False  # stopped early because a tool hung — fewer samples than planned


def _has_critical_security(dimensions: list[DimensionResult]) -> bool:
    """Whether the (server-authored) security dimension carries a HIGH finding.

    Keyed on ``security`` specifically: ``response_safety`` scans passthrough *content*
    a server merely relayed, which is not evidence the server itself is malicious, so it
    deliberately never sets this flag.
    """
    security = next((d for d in dimensions if d.key == "security"), None)
    return bool(security and any(f.severity is Severity.HIGH for f in security.findings))


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
        # A server that exposes no tools can't be evaluated — every dimension is
        # vacuously perfect, which would otherwise average to 100/A. Report it as N/A
        # with an explicit finding instead of a misleading top grade.
        if tool_count == 0:
            note = DimensionResult(
                key="discovery",
                title="Discovery",
                weight=1.0,
                score=0.0,
                summary="The gauntlet scores a server's tools; this server exposes none, "
                "so there is nothing to evaluate.",
                findings=[Finding(severity=Severity.MEDIUM, message="server exposes no tools")],
            )
            # KEEP the real dimensions (appending the note) rather than replacing them: a
            # tool-less server can still ship poisoned `instructions`, and dropping the
            # security dimension here would silently discard that finding along with its
            # critical flag. The grade stays N/A — unscored, but not unexamined.
            return cls(
                spec=spec,
                server=server,
                tool_count=0,
                dimensions=[*dimensions, note],
                overall_score=0.0,
                grade="N/A",
                generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
                security_critical=_has_critical_security(dimensions),
                agentic=agentic,
            )

        total_weight = sum(d.weight for d in dimensions) or 1.0
        overall = round(sum(d.score * d.weight for d in dimensions) / total_weight, 1)

        # A tool-poisoning / injection / hidden-character finding is a "do not trust
        # this server" signal that averaging must not wash out — cap the grade.
        security_critical = _has_critical_security(dimensions)
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
    def agentically_scored(self) -> bool:
        """Whether the live-agent dimensions actually contributed to the overall score.

        The overall is a weighted mean over the dimensions that are PRESENT, so a report
        without Agent Task Success (weight 3) is averaged over a much smaller denominator
        and scores systematically higher than one that earned its number the hard way.
        The two are therefore NOT comparable, and the leaderboard must not co-rank them.
        """
        return any(d.key == "task_success" for d in self.dimensions)

    @property
    def agent_eval_truncated(self) -> bool:
        """Whether the agent evaluation stopped early because a tool hung.

        Reads the flag the evaluation *recorded*, rather than inferring it from a short
        results list: a hang on the last task, or on a repeat when only one task was
        generated, truncates the sample without shortening that list at all, so the proxy
        missed exactly the cases where it mattered.

        A truncated score is averaged over however many runs happened before the hang — a
        sample size the server itself controls — so it is no more comparable with a full
        evaluation than one that was never agent-scored.
        """
        return bool(self.agentic and self.agentic.truncated)

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


def _md(value: object) -> str:
    """Sanitize untrusted text for one Markdown line or table cell.

    Server- and LLM-authored strings (tool names, finding text, task descriptions)
    are interpolated into report.md, which users commit and GitHub renders —
    including any raw HTML that slips through. Flatten whitespace so a value can't
    open a new block, escape the backslash first so a crafted trailing escape can't
    neutralize ours, then pipes (table structure), backticks (code-span breakout),
    ``<`` (inline HTML / autolinks), and ``[`` (inline links/images — ``[text](url)``
    and ``![alt](url)`` both need it, so escaping the opening bracket disarms a
    server-supplied phishing link or auto-loading tracking pixel in the report).
    """
    text = " ".join(str(value).split())
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "\\`")
        .replace("<", "&lt;")
        .replace("[", "\\[")
    )


def _md_code(value: object) -> str:
    """Sanitize untrusted text destined for an inline code span.

    Backslash escapes don't apply inside a span, so drop the one character that can
    break out of it: the backtick. Everything else (``<``, pipes) can stay — a code
    span renders its content as literal text, never as HTML or table structure, so
    containment holds as long as the span itself can't be terminated early.
    """
    return " ".join(str(value).split()).replace("`", "'")


def to_markdown(report: GauntletReport) -> str:
    server_name = report.server.name or "unknown server"
    version = report.server.version or "?"
    lines: list[str] = [
        f"# mcp-gauntlet report — {_md(server_name)}",
        "",
        f"- **Server spec:** `{_md_code(report.spec)}`",
        f"- **Server:** {_md(report.server.name or '(unknown)')} v{_md(version)}",
        f"- **Tools:** {report.tool_count}",
        f"- **Overall:** **{report.grade}** ({report.overall_score:.1f}/100)",
        f"- **Generated:** {report.generated_at}",
    ]
    if report.security_critical:
        # Don't claim a cap on an N/A report: it kept its security findings but, exposing
        # no tools, was never scored in the first place.
        tail = (
            "this server exposes no tools, so it was never scored"
            if report.grade == "N/A"
            else "overall grade is capped"
        )
        lines.append(f"- ⚠️ **Critical security finding(s) present — {tail}.**")
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
            scope = f"`{_md_code(finding.tool)}`" if finding.tool else "_server_"
            detail = f" — {_md(finding.detail)}" if finding.detail else ""
            lines.append(
                f"- **[{finding.severity.upper()}]** {scope}: {_md(finding.message)}{detail}"
            )
        lines.append("")

    if report.agentic:
        agentic = report.agentic
        lines.append("## Agentic evaluation")
        lines.append("")
        if agentic.inconclusive:
            lines.append(
                "> ⚠️ **Inconclusive** — the LLM backend errored (e.g. rate limit); "
                "the overall grade reflects the static checks only."
            )
            lines.append("")
        lines.append(f"- **Model:** {_md(agentic.provider)}:{_md(agentic.model)}")
        lines.append(f"- **Tasks:** {agentic.tasks_generated} × {agentic.repeats} repeat(s)")
        if agentic.excluded_write_tools:
            excluded = ", ".join(_md(tool) for tool in agentic.excluded_write_tools)
            lines.append(f"- **Excluded (possibly-mutating) tools:** {excluded}")
        if agentic.results:
            lines.extend(
                [
                    "",
                    "| Task | Pass rate | Mean score | Tool selection |",
                    "|------|----------:|-----------:|---------------:|",
                ]
            )
            for result in agentic.results:
                task_label = _md(result.description[:70])
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
