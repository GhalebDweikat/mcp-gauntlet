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

_INJECTION_PATTERNS: list[tuple[re.Pattern[str], Severity, str]] = [
    (
        re.compile(r"ignore\s+(all\s+)?previous", re.I),
        Severity.HIGH,
        "attempts to override prior instructions",
    ),
    (
        re.compile(r"disregard\s+(the\s+)?(above|previous|prior)", re.I),
        Severity.HIGH,
        "attempts to override prior instructions",
    ),
    (
        re.compile(r"do\s+not\s+(tell|inform|mention|reveal)\b", re.I),
        Severity.HIGH,
        "instructs the agent to hide behavior from the user",
    ),
    (
        re.compile(r"without\s+(telling|informing|notifying)\b", re.I),
        Severity.HIGH,
        "instructs the agent to act without informing the user",
    ),
    (
        re.compile(r"<\s*important\s*>", re.I),
        Severity.MEDIUM,
        "hidden-instruction marker (<IMPORTANT>)",
    ),
    (
        re.compile(r"<!--", re.I),
        Severity.MEDIUM,
        "HTML comment in description (possible hidden instructions)",
    ),
    (re.compile(r"system\s+prompt", re.I), Severity.MEDIUM, "references the system prompt"),
    (
        re.compile(
            r"\b(\.env|id_rsa|\.ssh|credentials?|secret[_-]?keys?|api[_-]?keys?|passwords?)\b", re.I
        ),
        Severity.MEDIUM,
        "references sensitive files or secrets",
    ),
    (
        re.compile(r"\b(curl|wget|exfiltrat\w*|base64\s+-d)\b", re.I),
        Severity.LOW,
        "references data-transfer / exfiltration tooling",
    ),
]


def _hidden_chars(text: str) -> list[str]:
    """Return non-printable / invisible characters (zero-width, format, control)."""
    out: list[str] = []
    for ch in text:
        if ch in "\n\r\t ":
            continue
        if unicodedata.category(ch) in {"Cf", "Cc", "Co"}:
            out.append(ch)
    return out


def _excerpt(text: str, match: re.Match[str], width: int = 60) -> str:
    start = max(0, match.start() - width // 2)
    end = min(len(text), match.end() + width // 2)
    snippet = " ".join(text[start:end].split())
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def _scan_text(text: str, tool: str | None, where: str) -> list[Finding]:
    findings: list[Finding] = []
    for pattern, severity, label in _INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(_f(tool, severity, f"{where} {label}", _excerpt(text, match)))
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


def check_security(tools: list[ToolInfo]) -> DimensionResult:
    return _dimension(
        "security",
        "Security Signals",
        "Static scan of tool and parameter descriptions for tool-poisoning / prompt-injection "
        "markers and hidden characters (Invariant Labs / OWASP MCP threat model).",
        tools,
        _check_tool_security,
        weight=2.0,
    )


# ------------------------------------------------------------------ orchestrator


def run_static_checks(discovery: DiscoveryResult) -> list[DimensionResult]:
    tools = discovery.tools
    return [
        check_schema_health(tools),
        check_description_quality(tools),
        check_security(tools),
    ]
