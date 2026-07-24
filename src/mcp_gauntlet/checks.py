"""Offline (no-API) static checks over a discovered MCP server.

Three dimensions run here with zero external calls, so the tool is useful without
an API key:

  * Schema Health       — structural validity of each tool's JSON input schema
  * Description Quality  — offline heuristics on the tool description text
  * Security Signals     — tool-poisoning / prompt-injection markers in text

The API-backed dimensions (LLM-judged description quality, exact token footprint,
and the agentic task-success evaluation) are added in a later stage.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from statistics import mean

import jsonschema
from jsonschema.exceptions import SchemaError

from mcp_gauntlet.models import DiscoveryResult, ToolInfo
from mcp_gauntlet.report import DimensionResult, Finding, Severity, score_from_findings


def _f(tool: str | None, severity: Severity, message: str, detail: str | None = None) -> Finding:
    return Finding(tool=tool, severity=severity, message=message, detail=detail)


def _mean_or_full(scores: list[float]) -> float:
    return round(mean(scores), 1) if scores else 100.0


def _dimension(
    key: str,
    title: str,
    summary: str,
    tools: list[ToolInfo],
    check: Callable[[ToolInfo], list[Finding]],
    weight: float = 1.0,
) -> DimensionResult:
    """Run a per-tool ``check`` and aggregate into a DimensionResult."""
    all_findings: list[Finding] = []
    scores: list[float] = []
    for tool in tools:
        tool_findings = check(tool)
        all_findings.extend(tool_findings)
        scores.append(score_from_findings(tool_findings))
    return DimensionResult(
        key=key,
        title=title,
        summary=summary,
        score=_mean_or_full(scores),
        findings=all_findings,
        weight=weight,
    )


# ------------------------------------------------------------- schema health


def _check_tool_schema(tool: ToolInfo) -> list[Finding]:
    schema = tool.input_schema
    if not isinstance(schema, dict) or not schema:
        return [_f(tool.name, Severity.MEDIUM, "tool has no input schema")]

    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        return [
            _f(
                tool.name,
                Severity.HIGH,
                "input schema is not a valid JSON Schema",
                detail=exc.message,
            )
        ]

    findings: list[Finding] = []
    if schema.get("type") != "object":
        findings.append(
            _f(
                tool.name,
                Severity.MEDIUM,
                f"input schema type is {schema.get('type')!r}, expected 'object'",
            )
        )

    props = schema.get("properties")
    required = schema.get("required", [])
    if not isinstance(props, dict):
        if required:
            findings.append(
                _f(tool.name, Severity.HIGH, "schema declares required fields but no properties")
            )
        return findings

    for name, prop in props.items():
        if not isinstance(prop, dict):
            findings.append(
                _f(tool.name, Severity.MEDIUM, f"property {name!r} is not an object schema")
            )
            continue
        if not (prop.keys() & {"type", "enum", "anyOf", "oneOf", "$ref"}):
            findings.append(_f(tool.name, Severity.LOW, f"property {name!r} has no declared type"))
        if not prop.get("description"):
            findings.append(_f(tool.name, Severity.LOW, f"property {name!r} has no description"))

    for req in required if isinstance(required, list) else []:
        if req not in props:
            findings.append(
                _f(tool.name, Severity.MEDIUM, f"required field {req!r} not defined in properties")
            )

    return findings


def check_schema_health(tools: list[ToolInfo]) -> DimensionResult:
    return _dimension(
        "schema_health",
        "Schema Health",
        "Structural validity of each tool's JSON input schema: valid schema, typed and "
        "described properties, and a consistent required list.",
        tools,
        _check_tool_schema,
    )


# -------------------------------------------------------- description quality


def _check_tool_description(tool: ToolInfo) -> list[Finding]:
    desc = (tool.description or "").strip()
    if not desc:
        return [_f(tool.name, Severity.HIGH, "tool has no description")]
    length = len(desc)
    if length < 15:
        return [_f(tool.name, Severity.MEDIUM, "description is very short", f"{length} chars")]
    if length < 40:
        return [_f(tool.name, Severity.LOW, "description is short", f"{length} chars")]
    return []


def check_description_quality(tools: list[ToolInfo]) -> DimensionResult:
    return _dimension(
        "description_quality",
        "Description Quality (heuristic)",
        "Offline heuristics on tool descriptions (presence and length). An LLM-judged "
        "'can an agent tell when to use this?' score is added in the agentic stage.",
        tools,
        _check_tool_description,
    )


# ------------------------------------------------------------ security signals

# Injection signals split by how ambiguous they are. Only *near-certain* ones CAP the
# grade (HIGH): "ignore … instructions" phrasing, an <IMPORTANT> hidden-instruction marker
# (the canonical MCP tool-poisoning payload), and truly hidden characters. Everything
# else is reported but does not cap — "ignore the rule/prompt/guidance" (ordinary domain
# nouns), the ambiguous "hide from the user" phrasings, and secret/exfil references (which
# are damning together but overlap with honest backup/credential-helper tools, so a human
# reviews the flagged MEDIUM/LOW rather than the grade being auto-capped). Verbs match
# inflections, and text is normalized (see _clean_for_match) so a reworded or
# invisible-char-smuggled description can't slip past.
_OVERRIDE_VERB = (
    r"(?:ignor(?:e|es|ed|ing)|disregard(?:s|ed|ing)?|forget(?:s|ting)?|"
    r"overrid(?:e|es|ing|den))"
)
# Up to two qualifiers between verb and noun: "ignore [all] [previous] instructions".
_QUALIFIER = (
    r"(?:(?:all|any|the|your|these|those|prior|previous|earlier|preceding|foregoing|"
    r"above)\s+){0,2}"
)
# "instructions" is essentially never a legit object of ignore/override in a tool
# description, so it caps (HIGH); rule/prompt/guidance/directive/policy are ordinary
# domain nouns (linters, LLM tooling, config), so they only warn (MEDIUM).
# The negative lookahead keeps "ignore the instructions FIELD/parameter" (a tool handling
# an `instructions` data field, e.g. OpenAI Assistants) from capping, while "ignore the
# previous instructions" still does.
_HARD_NOUN = (
    r"(?:instruction)s?\b"
    r"(?!\s+(?:field|parameter|param|argument|property|value|key|column|header)s?)"
)
_SOFT_NOUN = r"(?:rule|prompt|guidance|directive|guideline|polic(?:y|ies))s?"
_HIDE_VERB = r"(?:tell|inform|reveal|disclose|mention)s?"
_PERSON = r"(?:user|caller|human|operator|owner|client|them|anyone)s?"
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], Severity, str]] = [
    (
        re.compile(rf"{_OVERRIDE_VERB}\s+{_QUALIFIER}{_HARD_NOUN}", re.I),
        Severity.HIGH,
        "attempts to override prior instructions",
    ),
    (
        re.compile(rf"{_OVERRIDE_VERB}\s+{_QUALIFIER}{_SOFT_NOUN}", re.I),
        Severity.MEDIUM,
        "possible instruction-override phrasing",
    ),
    (
        re.compile(
            rf"(?:do(?:es)?\s+not|don'?t|never)\s+{_HIDE_VERB}\b[^.]{{0,40}}?"
            rf"(?:to\s+)?(?:the\s+)?{_PERSON}\b",
            re.I,
        ),
        Severity.MEDIUM,
        "instructs the agent to hide behavior from the user",
    ),
    (
        re.compile(
            rf"without\s+(?:telling|informing|notifying|alerting|warning)\s+(?:the\s+)?{_PERSON}\b",
            re.I,
        ),
        Severity.MEDIUM,
        "instructs the agent to act without informing the user",
    ),
    (
        re.compile(r"<\s*important\s*>", re.I),
        Severity.HIGH,
        "hidden-instruction marker (<IMPORTANT>) — canonical tool-poisoning payload",
    ),
    (
        # LLM chat-template control tokens (ChatML / Llama / Gemma). Legitimate prompt-
        # formatter / tokenizer MCP servers document these in their descriptions, so the
        # bare token can't be told from an injected system turn — flag for review (MEDIUM),
        # don't auto-cap.
        re.compile(
            r"<\|[a-z_]+\|>|<<\s*/?\s*sys\s*>>|\[/?INST\]|"
            r"<\s*/?\s*(?:start_of_turn|end_of_turn)\s*>",
            re.I,
        ),
        Severity.MEDIUM,
        "chat-template / system-turn marker",
    ),
    (
        re.compile(r"<!--", re.I),
        Severity.MEDIUM,
        "HTML comment in description (possible hidden instructions)",
    ),
    (re.compile(r"system\s+prompt", re.I), Severity.MEDIUM, "references the system prompt"),
    (
        # Lookarounds, not \b: a leading \b can never match before a dotfile like
        # ".env" (space-then-dot is non-word on both sides), so \b silently missed them.
        re.compile(
            r"(?<!\w)(\.env|id_rsa|\.ssh|\.aws|\.git-?credentials|credentials?|"
            r"secret[_-]?keys?|api[_-]?keys?|access[_-]?tokens?|passwords?)(?!\w)",
            re.I,
        ),
        Severity.MEDIUM,
        "references sensitive files or secrets",
    ),
    (
        re.compile(r"\b(curls?|wgets?|scp|exfiltrat\w*|base64\s+-d)\b", re.I),
        Severity.LOW,
        "references data-transfer / exfiltration tooling",
    ),
]


# ZWJ / variation selector-16 are legitimate only inside an emoji sequence (a family
# emoji joins its members with ZWJ). The same chars smuggled between letters
# ("previ<ZWJ>ous") are an attack, and soft hyphen is never allowlisted — so the
# allowance is context-checked below, not unconditional.
_FORMAT_ALLOWED = {chr(0x200D), chr(0xFE0F)}


def _is_pictographic(ch: str) -> bool:
    return not ch.isascii() and (ord(ch) >= 0x1F000 or unicodedata.category(ch) == "So")


def _is_variation_selector(o: int) -> bool:
    return 0xFE00 <= o <= 0xFE0F or 0xE0100 <= o <= 0xE01EF


def _between_ascii_word(text: str, i: int) -> bool:
    """True when the char at i sits between two ASCII word chars — the signature of a
    combining mark smuggled into an ASCII keyword ("in<combining>structions"). Both-sides
    so a word-final accent ("café" decomposed = e + combining) isn't flagged."""
    return (
        i > 0
        and i + 1 < len(text)
        and text[i - 1].isascii()
        and text[i - 1].isalnum()
        and text[i + 1].isascii()
        and text[i + 1].isalnum()
    )


def _adjacent_ascii_letter(text: str, i: int) -> bool:
    """True when a neighbor is an ASCII letter — the signature of a selector/ZWJ smuggled
    into a Latin word ("Ignore<VS> …"), as opposed to a keycap (digit) or CJK/emoji base."""
    return any(
        0 <= j < len(text) and text[j].isascii() and text[j].isalpha() for j in (i - 1, i + 1)
    )


# Directional MARKS (LRM/RLM/ALM) are legitimate in bidirectional (RTL) text; the
# dangerous Trojan-Source vectors are the bidi override/embedding/isolate controls, which
# are caught as ordinary format chars below.
_BENIGN_BIDI = {0x200E, 0x200F, 0x061C}
# ZWJ / ZWNJ: legitimate in emoji and non-Latin scripts (Persian/Indic need ZWNJ), an
# attack only when wedged into a Latin word.
_CONTEXTUAL = {0x200D, 0x200C}


def _hidden_chars(text: str) -> list[str]:
    """Return invisible / non-printable characters used to smuggle text past the scan.

    Zero-width, format, control chars, and stray bidi overrides are flagged anywhere.
    Context-dependent chars — variation selectors, ZWJ/ZWNJ, and combining marks — are
    flagged only with the smuggle signature (adjacent to ASCII letters), so legitimate
    emoji, CJK variation sequences, keycaps, accented text, and non-Latin scripts aren't.
    (Evasion is handled independently by _clean_for_match, so scoping the flag is safe.)
    """
    out: list[str] = []
    for i, ch in enumerate(text):
        if ch in "\n\r\t ":
            continue
        o = ord(ch)
        category = unicodedata.category(ch)
        is_selector = _is_variation_selector(o)
        is_combining = category in {"Mn", "Me"}
        if not (category in {"Cf", "Cc", "Co"} or is_selector or is_combining):
            continue
        if o in _BENIGN_BIDI:
            continue  # directional marks are legitimate in bidirectional text
        # ZWJ / variation selector inside a real emoji cluster (adjacent to a pictographic
        # char) is legitimate — a family emoji joins members with ZWJ.
        if (ch in _FORMAT_ALLOWED or is_selector) and any(
            _is_pictographic(text[j]) for j in (i - 1, i + 1) if 0 <= j < len(text)
        ):
            continue
        # Selectors / ZWJ / ZWNJ: flag only when smuggled next to an ASCII letter.
        if (is_selector or o in _CONTEXTUAL) and not _adjacent_ascii_letter(text, i):
            continue
        # True combining marks (Mn/Me, excluding selectors): only between ASCII letters.
        if is_combining and not is_selector and not _between_ascii_word(text, i):
            continue
        out.append(ch)
    return out


def _excerpt(text: str, match: re.Match[str], width: int = 60) -> str:
    start = max(0, match.start() - width // 2)
    end = min(len(text), match.end() + width // 2)
    snippet = " ".join(text[start:end].split())
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def _clean_for_match(text: str) -> str:
    """NFC-compose (folding decomposed accents back into é etc.), then drop zero-width /
    format / control / variation-selector / combining chars, so an invisible smuggled into
    a keyword ("in<VS>structions", "ignore<VS> instructions") can't split it before the
    injection patterns run. Detection of the smuggled char itself happens on the raw text.
    """
    composed = unicodedata.normalize("NFC", text)
    kept = [
        ch
        for ch in composed
        if not _is_variation_selector(ord(ch))
        and unicodedata.category(ch) not in {"Cf", "Cc", "Mn", "Me"}
    ]
    return "".join(kept)


def _scan_text(text: str, tool: str | None, where: str) -> list[Finding]:
    findings: list[Finding] = []
    # Match phrase patterns against the normalized text so smuggled invisibles can't break
    # a keyword; detect the smuggled chars themselves against the raw text.
    cleaned = _clean_for_match(text)
    obfuscated = " (obfuscating characters removed)" if cleaned != text else ""
    for pattern, severity, label in _INJECTION_PATTERNS:
        match = pattern.search(cleaned)
        if match:
            detail = _excerpt(cleaned, match) + obfuscated
            findings.append(_f(tool, severity, f"{where} {label}", detail))
    hidden = _hidden_chars(text)
    if hidden:
        codes = ", ".join(sorted({f"U+{ord(c):04X}" for c in hidden}))
        findings.append(
            _f(tool, Severity.HIGH, f"{where} contains hidden/non-printable characters", codes)
        )
    return findings


def _check_tool_security(tool: ToolInfo) -> list[Finding]:
    findings = _scan_text(tool.description or "", tool.name, "description")
    props = tool.input_schema.get("properties") if isinstance(tool.input_schema, dict) else None
    if isinstance(props, dict):
        for name, prop in props.items():
            if isinstance(prop, dict) and prop.get("description"):
                findings.extend(
                    _scan_text(
                        str(prop["description"]), tool.name, f"property {name!r} description"
                    )
                )
    return findings


def check_security(tools: list[ToolInfo], instructions: str | None = None) -> DimensionResult:
    all_findings: list[Finding] = []
    scores: list[float] = []
    for tool in tools:
        tool_findings = _check_tool_security(tool)
        all_findings.extend(tool_findings)
        scores.append(score_from_findings(tool_findings))
    # The server's own init "instructions" are server-authored (not passthrough), so
    # injection there is genuine tool-poisoning and counts like a poisoned description.
    if instructions:
        server_findings = _scan_text(instructions, None, "server instructions")
        all_findings.extend(server_findings)
        scores.append(score_from_findings(server_findings))
    return DimensionResult(
        key="security",
        title="Security Signals",
        weight=2.0,
        score=_mean_or_full(scores),
        summary="Static scan of the server's init instructions plus tool and parameter "
        "descriptions for tool-poisoning / prompt-injection markers and hidden characters "
        "(Invariant Labs / OWASP MCP threat model).",
        findings=all_findings,
    )


def scan_runtime_outputs(outputs: list[tuple[str, str]]) -> DimensionResult | None:
    """Scan the server's live tool OUTPUTS (``(tool_name, text)``) for the same
    injection / poisoning markers as the static description scan — a server can pass a
    description scan yet return poisoned content at call time, and this catches it.

    Returns None if there were no outputs to scan. Reported at the found severities but
    deliberately keyed ``response_safety`` (NOT ``security``), so it lowers the score but
    does NOT trigger the grade cap: markers in an *output* may be the server poisoning its
    responses OR untrusted content it faithfully passed through (a filesystem/fetch server
    reading a poisoned file), so a human — not the auto-cap — should judge intent.
    """
    if not outputs:
        return None
    findings: list[Finding] = []
    seen: set[tuple[str | None, Severity, str]] = set()
    for tool, text in outputs:
        for finding in _scan_text(text, tool, "tool output"):
            key = (finding.tool, finding.severity, finding.message)
            if key not in seen:
                seen.add(key)
                findings.append(finding)
    return DimensionResult(
        key="response_safety",
        title="Response Safety (runtime)",
        weight=1.0,
        score=score_from_findings(findings),
        summary="Dynamic scan of the server's live tool outputs for prompt-injection / "
        "poisoning markers and hidden characters. Markers here may be the server poisoning "
        "its responses, or untrusted content it passed through — either exposes the agent. "
        "Reported (and it lowers the score) but does not cap the grade on its own. Reflects "
        "the outputs the generated tasks happened to elicit, so it can vary run to run.",
        findings=findings,
    )


# ------------------------------------------------------------------ orchestrator


def run_static_checks(discovery: DiscoveryResult) -> list[DimensionResult]:
    tools = discovery.tools
    return [
        check_schema_health(tools),
        check_description_quality(tools),
        check_security(tools, discovery.server.instructions),
    ]
