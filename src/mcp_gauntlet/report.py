"""Report data model, scoring, and renderers (JSON + Markdown).

Scoring model (deliberately simple and explainable): each *subject* — a single
tool, or the server — starts at 100 and loses points per finding by severity.
A dimension's score is the mean of its per-subject scores, so it is normalized
by the number of tools rather than punishing large servers. The overall score is
the weighted mean of the dimension scores.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator

from mcp_gauntlet.models import ServerInfo

REDACTION_PLACEHOLDER = "***REDACTED***"


def encodable(text: str) -> str:
    """Make one server-authored string safe to serialize, losslessly where possible.

    A lone surrogate survives JSON parsing but cannot be encoded as UTF-8, so a single one
    anywhere in a server's output made ``model_dump_json`` raise and discarded the entire
    report — a completed, possibly paid-for evaluation lost to one character. Escaping
    rather than dropping keeps the evidence visible: the reviewer sees ``\\ud800`` where the
    character was, instead of a hole.
    """
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _scrub(obj: object) -> object:
    if isinstance(obj, str):
        return encodable(obj)
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    if isinstance(obj, dict):
        return {str(_scrub(k)): _scrub(v) for k, v in obj.items()}
    return obj


# A fragment shorter than this is not worth blanking: it stops being identifying, and
# redacting it would mangle prose that merely shares a substring with a token. Twelve
# characters of a real token is not a usable credential; eight was, and it also ate the
# word "password" out of ordinary sentences.
_MIN_SECRET_FRAGMENT = 12


def redact(text: str, secrets: Iterable[str]) -> str:
    """Replace each known credential value in one string with a placeholder.

    Defense-in-depth for credentialed evaluations: the tokens passed to a server via
    --env / --header are kept out of the report by construction, but a hostile or careless
    server can echo one back in a tool output, a finding, or its own name. Use this on RAW
    text — a console line, or a field value before serialization. Do NOT run it on already
    serialized JSON/HTML: a secret containing a quote or backslash is escaped there
    (``ab"cd`` → ``ab\\"cd``) and a literal replace would miss the escaped form. For a
    whole report, use :func:`redact_report`, which scrubs the fields before rendering.
    """
    for secret in secrets:
        if not secret:
            continue
        text = text.replace(secret, REDACTION_PLACEHOLDER)
        # PARTIAL matches too, and this is not belt-and-braces — it is the actual bug.
        # Redaction runs on the finished report, and finding excerpts are TRUNCATED before
        # that. When the truncation window cut across a credential, the full value no longer
        # appeared, the exact-match replace found nothing, and a long run of a live token was
        # published into report.json / report.md / report.html — 28 of 40 characters in the
        # reproduction, from a server that merely echoed its own token in its `instructions`.
        # The shipped CI workflow uploads that directory as a build artifact with
        # `if: always()`, and the README promised "credential values are scrubbed from every
        # report". It worked in testing and failed on whichever token straddled the boundary.
        #
        # ANY substring, not just a prefix or a suffix: an excerpt taken from the middle of a
        # long string is cut at both ends, and the first version of this fix — which walked
        # prefixes and suffixes only, on the reasoning that truncation cuts one end — still
        # leaked 35 characters of that case.
        #
        # Longest first, so a placeholder never lands mid-fragment. Bounded by
        # _MIN_SECRET_FRAGMENT: below that a run stops being identifying, and blanking it
        # would mangle honest prose that merely shares a substring with a token — an early
        # threshold of 8 turned "the password field is required" into "the ***REDACTED***
        # field is required" for a secret of `password123456`.
        for size in range(len(secret) - 1, _MIN_SECRET_FRAGMENT - 1, -1):
            for start in range(len(secret) - size + 1):
                fragment = secret[start : start + size]
                if fragment in text:
                    text = text.replace(fragment, REDACTION_PLACEHOLDER)
    return text


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
UNPARSEABLE_TOOLS_MESSAGE = (
    "server returned a tool list this MCP SDK cannot parse, so no tool could be evaluated"
)

GRADE_CAP_ON_CRITICAL = 75.0


class Finding(BaseModel):
    tool: str | None = None  # None → a server-level finding
    severity: Severity
    message: str
    detail: str | None = None
    # Named in an `--expect` file, so it does not fail the gate. It is still REPORTED, and
    # still carries its real severity: an expected finding is one you have read and decided
    # about, not one that stopped existing. See `expectations.py`.
    expected: bool = False
    # Why the operator expects it — copied from the file so the report carries the reasoning
    # rather than only the fact. A suppression whose justification lives somewhere else is a
    # suppression nobody will ever re-examine.
    expected_reason: str | None = None


class Dim(StrEnum):
    """The dimension keys, in one place because several of them are load-bearing.

    Three are read by name from other modules — ``SECURITY`` caps the grade, ``TASK_SUCCESS``
    decides whether a server is rankable, ``RESPONSE_SAFETY`` earns the board's ⚡ — and each
    of those lookups used to be a bare string literal in a different file. Renaming a key
    would have left them silently matching nothing: no error, no test failure, just a grade
    cap that quietly stopped applying. A `StrEnum` keeps the serialized value identical
    (``"security"`` on the wire, so old reports still load) while making the coupling
    greppable and a typo an AttributeError.
    """

    SECURITY = "security"
    RESPONSE_SAFETY = "response_safety"
    TASK_SUCCESS = "task_success"
    TOOL_SELECTION = "tool_selection"
    TOOL_RELIABILITY = "tool_reliability"
    SCHEMA_HEALTH = "schema_health"
    DESCRIPTION_QUALITY = "description_quality"
    ROBUSTNESS = "robustness"
    DISCOVERY = "discovery"


class DimensionResult(BaseModel):
    # Deliberately `str`, not `Dim`: a report written by a newer version can name a
    # dimension this one has never heard of, and it still has to load.
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
    interactive_requests: int = 0  # elicitation/sampling/roots the harness declined
    interactive_summary: str = ""  # e.g. "2 elicitation, 1 sampling" (for the report note)


def interaction_note(detail: AgenticDetail | None) -> str | None:
    """Human-readable note when the server needed interactive capabilities we decline.

    Returned as plain prose (no Markdown/HTML) so every renderer can wrap it as it
    sees fit. ``None`` when the server made no such request.
    """
    if detail is None or detail.interactive_requests <= 0:
        return None
    what = detail.interactive_summary or f"{detail.interactive_requests}"
    return (
        f"This server made {what} request(s) for interactive capabilities "
        "(elicitation/sampling) that mcp-gauntlet declines — it drives no user or LLM "
        "for a server to call back into. Tool calls that failed only for that reason are "
        "not counted against Tool Reliability, but tasks needing them may still not pass."
    )


def _version() -> str:
    """The running gauntlet version, stamped onto every report it produces."""
    from mcp_gauntlet import __version__  # local import: the package __init__ owns the lookup

    return __version__


def _sdk_version() -> str:
    """The MCP SDK this score was measured through.

    Local import to keep `report.py` free of an adapters dependency at module scope — the
    scoring model must not need to know an SDK exists.
    """
    from mcp_gauntlet.adapters import sdk_version

    return sdk_version()


def cap_note(report: GauntletReport) -> str:
    """What the grade cap actually did to this report — in three distinct states.

    Every renderer used to print "overall grade capped" whenever a HIGH security finding
    existed, regardless of whether the cap changed anything. A server scoring 60.2 on its own
    merits is already under the 75 ceiling, so `min(60.2, 75)` does nothing — and a
    first-time reader who hand-computed the weighted mean, matched the published number
    exactly, and asked what it had been capped *from* was asking the right question. The
    answer was "nothing", which is not what the banner said.
    """
    if report.grade == "N/A":
        # Kept its security findings but, exposing no tools, was never scored at all.
        return "this server exposes no tools, so it was never scored"
    if report.grade_capped:
        return f"overall grade capped at {GRADE_CAP_ON_CRITICAL:g}"
    return f"the {GRADE_CAP_ON_CRITICAL:g} cap did not apply — it already scored below it"


def _has_unparseable_tools(dimensions: list[DimensionResult]) -> bool:
    """Did `tools/list` answer with something the SDK could not parse?

    Read off the finding rather than threaded through as a flag, so the finding stays the
    single source of truth — the same reason the grade cap is re-derived rather than stored.
    """
    return any(f.message == UNPARSEABLE_TOOLS_MESSAGE for d in dimensions for f in d.findings)


def unevaluable(report: GauntletReport) -> str | None:
    """Why this run is neither a pass nor a fail, or None if it is a real verdict.

    ONE definition, used by both `run` and `scan`, because they had two and disagreed: a
    zero-tool server exited 3 from `run` and **0** from `scan` — and `scan` is the command
    the docs push you toward for a fleet, so one server's tool registration silently breaking
    left the whole build green. That is the fourth time a fix has reached one command and not
    the other in this project's history, so the answer lives here now rather than in either.

    An UNPARSEABLE tool list is deliberately NOT unevaluable: that is a defect *in* the
    server, it is reported HIGH, and the docs tell you to gate on it.
    """
    if report.unevaluated_reason:
        return report.unevaluated_reason
    if report.tool_count == 0 and not _has_unparseable_tools(report.dimensions):
        return (
            "this server exposes no tools, so nothing was evaluated — neither a pass nor a "
            "quality verdict. If it had tools before, tool registration is broken"
        )
    return None


def _has_critical_security(dimensions: list[DimensionResult]) -> bool:
    """Whether the (server-authored) security dimension carries a HIGH finding.

    Keyed on ``security`` specifically: ``response_safety`` scans passthrough *content*
    a server merely relayed, which is not evidence the server itself is malicious, so it
    deliberately never sets this flag.
    """
    security = next((d for d in dimensions if d.key == Dim.SECURITY), None)
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
    # The version that produced this score. Scoring changes between releases (new
    # dimensions, re-weighting), so a bare number is not comparable across them — every
    # published score has to say which methodology it came from. Defaulted, not required,
    # so a report saved by an older version still loads.
    gauntlet_version: str = ""
    # Which MCP SDK produced this score, and therefore which protocol era it was measured in.
    # A 2.0-era client reads different field names off the same server, so two runs of the
    # same gauntlet version can disagree — the version stamp alone was not enough to make a
    # score reproducible. Defaulted, so reports written before this field existed still load.
    mcp_sdk_version: str = ""
    # Why the live-agent evaluation was deliberately not run — currently only "this server
    # needs credentials nobody gave it". Kept as prose because the board prints it verbatim:
    # a reader deciding whether a missing score is the server's fault or the harness's needs
    # the sentence, not a code.
    unevaluated_reason: str = ""
    # Measurement stages that did NOT run, and why, in prose a reader can act on.
    #
    # The overall is a weighted mean over the dimensions PRESENT, so a stage that did not run
    # does not lower the score — it removes a row from the denominator and RAISES it. Passing
    # `--no-probe` alone moved a server that accepts every malformed input from C (75.0) to
    # A (93.8), and nothing in the report said so: the dimension table simply had one fewer
    # row, which reads as a shorter report rather than a narrower measurement.
    #
    # The agentic dimensions were the only absence the report ever disclosed. Everything else
    # was silent, and silence always moved the score the same direction: up.
    not_measured: list[str] = Field(default_factory=list)
    # Whether the cap actually LOWERED the score, as opposed to merely being eligible to.
    #
    # `security_critical` says a HIGH security finding exists. It does not say the cap did
    # anything: a server scoring 60.2 on its own merits is already below the 75 ceiling, so
    # `min(60.2, 75)` changes nothing — and every renderer still announced "overall grade
    # capped". A first-time user computed the plain weighted mean by hand, got exactly the
    # published number, and asked what it had been capped *from*. Fair question, and the
    # honest answer was "nothing". Announcing an intervention that did not occur is the same
    # failure this codebase keeps finding in itself, pointed at the reader instead of a check.
    grade_capped: bool = False

    @model_validator(mode="after")
    def _enforce_the_cap_from_the_findings(self) -> GauntletReport:
        """Re-derive the critical flag and the cap from the dimensions, on every construction.

        The cap used to be applied once, in `build()`, and then carried as a stored boolean.
        Every other path trusted it — and `leaderboard.load_results` rebuilds a report
        straight from saved JSON with `GauntletReport(**raw)`, where `security_critical`
        simply defaults to False and the score and grade are taken verbatim.

        So a saved report carrying a HIGH security finding without the flag published at
        **B / 78.8** against a cap of 75, with the board's own linked page listing the
        tool-poisoning finding underneath. Board and report disagreeing, and the board is the
        surface people read. Reachable from an older version's saved JSON, a partially
        restored file, or any future writer that does not go through `build()`.

        Deriving it here instead means the finding is the single source of truth and the flag
        cannot drift from it. Idempotent, so `build()` applying the cap first changes nothing.
        """
        critical = _has_critical_security(self.dimensions)
        if self.security_critical != critical:
            self.security_critical = critical
        # Never touch an N/A report: it kept its security findings but, exposing no tools, was
        # never scored — clamping a score that does not exist would invent a grade for it.
        if critical and self.grade != "N/A" and self.overall_score > GRADE_CAP_ON_CRITICAL:
            self.overall_score = GRADE_CAP_ON_CRITICAL
            self.grade = grade_for(GRADE_CAP_ON_CRITICAL)
            self.grade_capped = True
        return self

    @classmethod
    def build(
        cls,
        *,
        spec: str,
        server: ServerInfo,
        tool_count: int,
        dimensions: list[DimensionResult],
        agentic: AgenticDetail | None = None,
        unevaluated_reason: str = "",
        not_measured: list[str] | None = None,
    ) -> GauntletReport:
        # A server that exposes no tools can't be evaluated — every dimension is
        # vacuously perfect, which would otherwise average to 100/A. Report it as N/A
        # with an explicit finding instead of a misleading top grade.
        if tool_count == 0:
            # An UNPARSEABLE tool list also arrives here with zero tools, and the two are
            # opposite facts. "This server exposes no tools" is true of one and false of the
            # other: the second answered `tools/list` WITH tools that could not be read, and
            # reporting the wrong one sends the author looking at their registration code.
            #
            # The grade stays N/A either way, and that is the honest answer: nothing could be
            # scored. Letting it grade normally instead was tried and is worse — with no
            # tools the other dimensions are vacuously perfect, so a Schema Health 0.0
            # averaged UP to C 75.0, which is a better grade than most working servers get.
            # The HIGH finding is what fails the gate; the score is not asked to carry it.
            unparseable = _has_unparseable_tools(dimensions)
            note = DimensionResult(
                key=Dim.DISCOVERY,
                title="Discovery",
                weight=1.0,
                score=0.0,
                summary=(
                    "The server answered tools/list with a list this SDK could not parse, "
                    "so no tool could be evaluated."
                    if unparseable
                    else "The gauntlet scores a server's tools; this server exposes none, "
                    "so there is nothing to evaluate."
                ),
                # No note of its own when the list was unparseable: Schema Health already
                # carries a HIGH saying exactly what happened, and a second finding claiming
                # the server "exposes no tools" would contradict it.
                findings=(
                    []
                    if unparseable
                    else [Finding(severity=Severity.MEDIUM, message="server exposes no tools")]
                ),
            )
            # KEEP the real dimensions (appending the note) rather than replacing them: a
            # tool-less server can still ship poisoned `instructions`, and dropping the
            # security dimension here would silently discard that finding along with its
            # critical flag. The grade stays N/A — unscored, but not unexamined.
            return _encodable(
                cls(
                    spec=spec,
                    server=server,
                    tool_count=0,
                    dimensions=[*dimensions, note],
                    overall_score=0.0,
                    grade="N/A",
                    generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
                    security_critical=_has_critical_security(dimensions),
                    agentic=agentic,
                    gauntlet_version=_version(),
                    mcp_sdk_version=_sdk_version(),
                    unevaluated_reason=unevaluated_reason,
                    not_measured=list(not_measured or []),
                )
            )

        total_weight = sum(d.weight for d in dimensions) or 1.0
        overall = round(sum(d.score * d.weight for d in dimensions) / total_weight, 1)

        # A tool-poisoning / injection / hidden-character finding is a "do not trust
        # this server" signal that averaging must not wash out — cap the grade.
        security_critical = _has_critical_security(dimensions)
        # Record whether it BIT, not just whether it was eligible: a server already scoring
        # below the ceiling on its own merits is not "capped", and saying so invites the
        # reader to ask what it was capped from.
        capped = security_critical and overall > GRADE_CAP_ON_CRITICAL
        if security_critical:
            overall = min(overall, GRADE_CAP_ON_CRITICAL)

        return _encodable(
            cls(
                spec=spec,
                server=server,
                tool_count=tool_count,
                dimensions=dimensions,
                overall_score=overall,
                grade=grade_for(overall),
                generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
                security_critical=security_critical,
                agentic=agentic,
                gauntlet_version=_version(),
                mcp_sdk_version=_sdk_version(),
                unevaluated_reason=unevaluated_reason,
                not_measured=list(not_measured or []),
                grade_capped=capped,
            )
        )

    @property
    def agentically_scored(self) -> bool:
        """Whether the live-agent dimensions actually contributed to the overall score.

        The overall is a weighted mean over the dimensions that are PRESENT, so a report
        without Agent Task Success (weight 3) is averaged over a much smaller denominator
        and scores systematically higher than one that earned its number the hard way.
        The two are therefore NOT comparable, and the leaderboard must not co-rank them.
        """
        return any(d.key == Dim.TASK_SUCCESS for d in self.dimensions)

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


# Closed-vocabulary field values the report model must parse back exactly. If a credential
# happened to equal one of these (e.g. --env X=high with a HIGH finding present), redacting
# it whole would turn "high" into the placeholder and make model_validate reject the rebuilt
# report — crashing the write and losing a paid run. These words are never credentials, so a
# field whose ENTIRE value is one is left intact (a secret merely CONTAINING one as a
# substring is still redacted).
_STRUCTURAL_VALUES = frozenset(s.value for s in Severity)


def _redact_tree(obj: object, secrets: frozenset[str]) -> object:
    if isinstance(obj, str):
        return obj if obj in _STRUCTURAL_VALUES else redact(obj, secrets)
    if isinstance(obj, list):
        return [_redact_tree(v, secrets) for v in obj]
    if isinstance(obj, dict):
        return {k: _redact_tree(v, secrets) for k, v in obj.items()}
    return obj


def redact_report(report: GauntletReport, secrets: frozenset[str]) -> GauntletReport:
    """Return a copy of the report with every string field scrubbed of known secrets.

    Redacts the DATA, before any serializer runs, so a token is caught whatever encoding
    the output format would have applied to it — the escaping gap that makes scrubbing a
    rendered JSON/HTML string unsafe. Walking the model dump covers every field, including
    ones added later, rather than a hand-maintained list of places a secret might land.
    Score fields are preserved verbatim: redacting text never changes a grade.
    """
    if not secrets:
        return report
    scrubbed = _redact_tree(report.model_dump(), secrets)
    return GauntletReport.model_validate(scrubbed)


def _has_surrogate(obj: object) -> bool:
    if isinstance(obj, str):
        return any("\ud800" <= c <= "\udfff" for c in obj)
    if isinstance(obj, list):
        return any(_has_surrogate(v) for v in obj)
    if isinstance(obj, dict):
        return any(_has_surrogate(k) or _has_surrogate(v) for k, v in obj.items())
    return False


def _encodable(report: GauntletReport) -> GauntletReport:
    """Guarantee the report can be serialized, whatever the server put in its strings.

    A lone surrogate is valid JSON input and valid `str`, but not encodable as UTF-8, so one
    reaching any field made `model_dump_json` raise and threw away a finished evaluation —
    the same failure R2 fixed on the rendering path. Doing this once at build time covers
    every writer (report JSON, Markdown, HTML, the leaderboard) instead of each guarding
    itself. The scan is a fast no-op for the overwhelmingly common clean case; the rebuild
    only happens for a server that actually smuggled one.
    """
    dumped = report.model_dump()
    if not _has_surrogate(dumped):
        return report
    return GauntletReport.model_validate(_scrub(dumped))


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
        f"- **MCP protocol:** {_md(report.server.protocol_version or '(not reported)')}",
        # Both, because they answer different questions: the protocol is what the SERVER
        # agreed to speak, the SDK is which field names the HARNESS read off it. A 2.0-era
        # client reads the same server differently, so a score is only reproducible if both
        # are recorded.
        f"- **Measured through:** mcp SDK {_md(report.mcp_sdk_version or '(not recorded)')}",
        f"- **Tools:** {report.tool_count}",
        f"- **Overall:** **{report.grade}** ({report.overall_score:.1f}/100)",
        f"- **Generated:** {report.generated_at}",
    ]
    # Say what was NOT measured, next to the score, because the score cannot show it: the
    # overall is a weighted mean over the dimensions present, so a stage that did not run
    # raises it rather than lowering it. `unevaluated_reason` in particular was set by the
    # engine, stored in the JSON, printed by the leaderboard — and never rendered here, so a
    # credential-gated server that failed every call shipped a report headed "A (98.8)".
    if report.unevaluated_reason:
        lines.append(f"- **Not scored:** {_md(report.unevaluated_reason)}")
    if report.not_measured:
        lines.append(
            "- **Not measured:** "
            + "; ".join(_md(item) for item in report.not_measured)
            + " — the overall is a weighted mean over the dimensions that ran, so these "
            "raise it rather than lower it"
        )
    if report.security_critical:
        # Don't claim a cap on an N/A report: it kept its security findings but, exposing
        # no tools, was never scored in the first place.
        lines.append(f"- ⚠️ **Critical security finding(s) present — {cap_note(report)}.**")
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
        note = interaction_note(agentic)
        if note:
            lines.append(f"> ℹ️ {_md(note)}")
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


def findings_at_or_above(report: GauntletReport, threshold: Severity) -> list[Finding]:
    """Every finding in the report at or above ``threshold``, across all dimensions.

    The basis for `--fail-on`, which exists because gating on a SCORE turned out not to
    work. Two reasons, both measured. The security cap pins a poisoned server at 75, so a
    documented `--fail-under 60` gate could never fail one — the cap acted as a floor for the
    gate rather than a ceiling on the grade. And a threshold has to be re-baselined whenever
    scoring changes: one release moved a fixture 14.8 points, so a pinned number silently
    means something different after an upgrade.

    A severity gate has neither problem. It keys on what was actually found, which is the
    part of this tool that has held up, and it says what was wrong rather than only that a
    number moved.
    """
    return [
        finding
        for dimension in report.dimensions
        for finding in dimension.findings
        # `not expected` is the ONLY thing an `--expect` file changes. The finding keeps its
        # severity, stays in the report and stays on the console; it simply stops deciding
        # the exit code. A mechanism that removed the finding would be indistinguishable from
        # a check that stopped working, which is the defect this whole project is about.
        if not finding.expected and _SEVERITY_ORDER[finding.severity] <= _SEVERITY_ORDER[threshold]
    ]
