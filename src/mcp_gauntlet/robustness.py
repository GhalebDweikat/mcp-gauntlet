"""Robustness probes: feed each tool malformed arguments and see how the server copes.

LLM-free. A well-behaved server *rejects* schema-violating input — either with a
JSON-RPC error (surfaced as ``McpError``) or an ``isError`` result — rather than
silently accepting it, hanging, or crashing the connection. The classification is
framework-agnostic on purpose: any error signal counts as a correct rejection, so
we never penalize a server for validating the "wrong" way.
"""

from __future__ import annotations

from typing import Any

import anyio
from mcp import ClientSession
from mcp.shared.exceptions import McpError

from mcp_gauntlet.models import ToolInfo
from mcp_gauntlet.report import DimensionResult, Finding, Severity, score_from_findings

# A value of the wrong JSON type for each schema type, to violate a typed field.
_WRONG: dict[str, Any] = {
    "string": 12345,
    "integer": "not-an-integer",
    "number": "not-a-number",
    "boolean": "not-a-boolean",
    "array": "not-an-array",
    "object": "not-an-object",
}


def malformed_args(schema: dict[str, Any]) -> dict[str, Any] | None:
    """Build one schema-violating argument payload, or None if nothing can be violated."""
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return None
    props = schema.get("properties")
    props = props if isinstance(props, dict) else {}
    required = schema.get("required")
    required = required if isinstance(required, list) else []

    # Strongest violation: a wrong-typed value on a required, typed field.
    for name in required:
        prop = props.get(name)
        prop_type = prop.get("type") if isinstance(prop, dict) else None
        if prop_type in _WRONG:
            return {name: _WRONG[prop_type]}

    # Otherwise: omit all required fields.
    if required:
        return {}

    # No required fields: wrong-type the first typed property.
    for name, prop in props.items():
        if isinstance(prop, dict) and prop.get("type") in _WRONG:
            return {name: _WRONG[prop["type"]]}

    return None


async def run_robustness_probes(
    session: ClientSession,
    tools: list[ToolInfo],
    *,
    timeout_s: float = 15.0,
) -> DimensionResult | None:
    """Probe each tool with malformed input. Returns None if no tool is probeable."""
    findings: list[Finding] = []
    scores: list[float] = []

    for tool in tools:
        payload = malformed_args(tool.input_schema)
        if payload is None:
            continue  # nothing to violate — don't score this tool

        try:
            with anyio.fail_after(timeout_s):
                result = await session.call_tool(tool.name, payload)
        except TimeoutError:
            findings.append(
                Finding(
                    tool=tool.name,
                    severity=Severity.HIGH,
                    message="server hung on malformed input (timed out)",
                )
            )
            scores.append(0.0)
            findings.append(
                Finding(severity=Severity.INFO, message="stopped probing after a timeout")
            )
            break
        except McpError:
            scores.append(100.0)  # protocol-level rejection = correct handling
            continue
        except Exception as exc:  # noqa: BLE001 - transport may be compromised; stop probing
            tool_finding = Finding(
                tool=tool.name,
                severity=Severity.MEDIUM,
                message="unexpected error on malformed input",
                detail=str(exc)[:160],
            )
            findings.append(tool_finding)
            scores.append(score_from_findings([tool_finding]))
            findings.append(
                Finding(severity=Severity.INFO, message="stopped probing after an unexpected error")
            )
            break

        if bool(getattr(result, "isError", False)):
            scores.append(100.0)  # rejected via an isError result = correct handling
        else:
            tool_finding = Finding(
                tool=tool.name,
                severity=Severity.MEDIUM,
                message="server accepted schema-violating input without error",
            )
            findings.append(tool_finding)
            scores.append(score_from_findings([tool_finding]))

    if not scores:
        return None

    return DimensionResult(
        key="robustness",
        title="Robustness",
        weight=1.0,
        score=round(sum(scores) / len(scores), 1),
        summary="How the server handles malformed / schema-violating tool arguments — a "
        "well-behaved server rejects them rather than accepting, hanging, or crashing (LLM-free).",
        findings=findings,
    )
