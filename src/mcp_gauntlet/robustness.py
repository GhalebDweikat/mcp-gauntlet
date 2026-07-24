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
from mcp_gauntlet.report import DimensionResult, Finding, Severity

# A value of the wrong JSON type for each schema type, to violate a typed field.
_WRONG: dict[str, Any] = {
    "string": 12345,
    "integer": "not-an-integer",
    "number": "not-a-number",
    "boolean": "not-a-boolean",
    "array": "not-an-array",
    "object": "not-an-object",
}


# A value of each JSON type, to violate a field by sending a type it doesn't allow.
_OF_TYPE: dict[str, Any] = {
    "object": {"mcp_gauntlet": "invalid"},
    "array": ["mcp-gauntlet-invalid"],
    "string": "mcp-gauntlet-invalid",
    "boolean": True,
    "integer": 987654321,
}
_SENTINEL = "mcp-gauntlet-invalid-value"


def _resolve_ref(ref: str, defs: dict[str, Any]) -> Any:
    """Resolve a local ``#/$defs/Name`` (or ``#/definitions/Name``) reference."""
    if not ref.startswith("#/"):
        return None  # remote refs aren't ours to fetch
    node: Any = defs
    for part in ref[2:].split("/"):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _wrong_for_types(allowed: set[str]) -> tuple[bool, Any]:
    """A value whose JSON type is outside ``allowed`` (so it violates every branch)."""
    for name, value in _OF_TYPE.items():
        if name in allowed:
            continue
        # "integer" also satisfies a "number" schema, so it isn't a violation of one.
        if name == "integer" and "number" in allowed:
            continue
        return True, value
    return False, None  # the field accepts every type — nothing is invalid


def _violating_value(prop: Any, defs: dict[str, Any], depth: int = 0) -> tuple[bool, Any]:
    """A value that violates ``prop``, as ``(found, value)``.

    Beyond a plain ``type``, this understands ``enum``/``const``, ``anyOf``/``oneOf`` and
    local ``$ref``s — the shapes ``pydantic.model_json_schema()`` and zod-to-json-schema
    emit for enums, unions, and nested models. Reading only ``type`` would leave those
    tools silently unprobed, which both under-tests honest servers and hands a free pass
    to any server that declares its arguments that way.
    """
    if not isinstance(prop, dict) or depth > 4:  # depth-bounded: $refs can be cyclic
        return False, None

    ref = prop.get("$ref")
    if isinstance(ref, str):
        target = _resolve_ref(ref, defs)
        return _violating_value(target, defs, depth + 1) if target is not None else (False, None)

    enum = prop.get("enum")
    if isinstance(enum, list) and enum:
        return True, _SENTINEL if _SENTINEL not in enum else _SENTINEL + "-2"
    if "const" in prop:
        return (True, _SENTINEL) if prop["const"] != _SENTINEL else (True, _SENTINEL + "-2")

    for key in ("anyOf", "oneOf"):
        branches = prop.get(key)
        if isinstance(branches, list) and branches:
            allowed: set[str] = set()
            for branch in branches:
                if not isinstance(branch, dict):
                    continue
                resolved = branch
                branch_ref = branch.get("$ref")
                if isinstance(branch_ref, str):
                    target = _resolve_ref(branch_ref, defs)
                    resolved = target if isinstance(target, dict) else branch
                branch_type = resolved.get("type")
                if isinstance(branch_type, str):
                    allowed.add(branch_type)
                elif isinstance(branch_type, list):
                    allowed.update(t for t in branch_type if isinstance(t, str))
                elif "enum" in resolved or "const" in resolved:
                    allowed.add("string")  # conservative: assume the literal may be a string
            return _wrong_for_types(allowed) if allowed else (False, None)

    prop_type = prop.get("type")
    # ``type`` may be a string OR a list (the ``["string", "null"]`` nullable idiom) — a
    # list is unhashable, so guarding the membership test keeps this from crashing.
    if isinstance(prop_type, str):
        return (True, _WRONG[prop_type]) if prop_type in _WRONG else (False, None)
    if isinstance(prop_type, list):
        for item in prop_type:
            if isinstance(item, str) and item != "null" and item in _WRONG:
                return True, _WRONG[item]
    return False, None


def declares_arg_contract(schema: Any) -> bool:
    """Whether the tool publishes an argument contract we could hold it to.

    A tool with an object schema and no violatable field (a zero-argument tool) HAS a
    contract — there is simply nothing invalid to send it. A tool with no schema at all
    has declared nothing, so it cannot reject anything: that is a robustness failure, not
    an exemption. Keeping the distinction matters because omitting schemas would otherwise
    be a way to skip this dimension entirely and score higher for it.
    """
    return isinstance(schema, dict) and schema.get("type") == "object"


def malformed_args(schema: dict[str, Any]) -> dict[str, Any] | None:
    """Build one schema-violating argument payload, or None if nothing can be violated."""
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return None
    props = schema.get("properties")
    props = props if isinstance(props, dict) else {}
    required = schema.get("required")
    required = required if isinstance(required, list) else []
    defs = {k: v for k, v in schema.items() if k in ("$defs", "definitions")}

    # Strongest violation: an invalid value on a required field.
    for name in required:
        if not isinstance(name, str):
            # ``required`` is server data and may hold non-strings; a dict/list entry is
            # unhashable and would crash props.get(name). A non-string can't name a real
            # JSON property anyway, so skip it.
            continue
        found, value = _violating_value(props.get(name), defs)
        if found:
            return {name: value}

    # Otherwise: omit all required fields.
    if required:
        return {}

    # No required fields: send an invalid value for the first constrained property.
    for name, prop in props.items():
        found, value = _violating_value(prop, defs)
        if found:
            return {name: value}

    return None


def declares_arguments(schema: Any) -> bool:
    """Whether the tool takes arguments at all (as opposed to being zero-argument)."""
    if not isinstance(schema, dict):
        return False
    return bool(schema.get("properties")) or bool(schema.get("required"))


async def run_robustness_probes(
    session: ClientSession,
    tools: list[ToolInfo],
    *,
    timeout_s: float = 15.0,
) -> DimensionResult | None:
    """Probe each tool with malformed input.

    Always returns a dimension when there is at least one tool — an omitted dimension
    would shrink the weighted-mean denominator and inflate the overall. Returns None only
    when there are no tools at all.
    """
    if not tools:
        return None
    findings: list[Finding] = []
    scores: list[float] = []

    for tool in tools:
        payload = malformed_args(tool.input_schema)
        if payload is None:
            if not declares_arg_contract(tool.input_schema):
                # No usable contract: the server can't reject anything because it has said
                # nothing is invalid. Score it like an accepted violation, so publishing no
                # schema can't buy a better grade than publishing a real one.
                detail = (
                    "the schema is not an object schema"
                    if isinstance(tool.input_schema, dict) and tool.input_schema
                    else None
                )
                findings.append(
                    Finding(
                        tool=tool.name,
                        severity=Severity.MEDIUM,
                        message="no usable input schema — the server declares no argument "
                        "contract to validate against",
                        detail=detail,
                    )
                )
                scores.append(0.0)
            elif declares_arguments(tool.input_schema):
                # It DOES take arguments, but nothing in the declaration is specific enough
                # to violate. That tool is untested, not exempt — exempting it is what makes
                # "declare arguments loosely" a better dodge than declaring none at all.
                findings.append(
                    Finding(
                        tool=tool.name,
                        severity=Severity.MEDIUM,
                        message="argument types too loose to construct an invalid value — "
                        "the declared contract can't be enforced",
                    )
                )
                scores.append(0.0)
            continue  # a zero-argument tool has nothing to violate — don't score it

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
            # An ungraceful non-protocol failure is not a clean rejection; score it 0 like
            # accept/timeout so that stopping early can only lower the score, never inflate
            # it (otherwise tool order would change the grade).
            findings.append(
                Finding(
                    tool=tool.name,
                    severity=Severity.MEDIUM,
                    message="unexpected error on malformed input",
                    detail=str(exc)[:160],
                )
            )
            scores.append(0.0)
            findings.append(
                Finding(severity=Severity.INFO, message="stopped probing after an unexpected error")
            )
            break

        if bool(getattr(result, "isError", False)):
            scores.append(100.0)  # rejected via an isError result = correct handling
        else:
            # Silently accepting schema-violating input is a validation failure, not a
            # minor ding — score it 0 so the dimension reads as the fraction of tools
            # that correctly reject (a server that validates nothing scores near 0, not 88).
            findings.append(
                Finding(
                    tool=tool.name,
                    severity=Severity.MEDIUM,
                    message="server accepted schema-violating input without error",
                )
            )
            scores.append(0.0)

    if not scores:
        # Every tool was legitimately unprobeable (zero-argument tools with real schemas).
        # Report the dimension anyway rather than omitting it: the overall is a weighted
        # mean over the dimensions PRESENT, so an absent dimension shrinks the denominator
        # and quietly RAISES the score — making "be unprobeable" the winning move.
        findings.append(
            Finding(
                severity=Severity.INFO,
                message="no tool takes arguments that could be violated — nothing to probe",
            )
        )
        return DimensionResult(
            key="robustness",
            title="Robustness",
            weight=1.0,
            score=100.0,
            summary="No tool exposes a violatable argument, so there was nothing to "
            "probe; scored as no-evidence-of-failure rather than omitted.",
            findings=findings,
        )

    return DimensionResult(
        key="robustness",
        title="Robustness",
        weight=1.0,
        score=round(sum(scores) / len(scores), 1),
        summary="Fraction of probed tools that reject malformed / schema-violating "
        "arguments — a well-behaved server rejects them rather than silently accepting, "
        "hanging, or crashing (LLM-free).",
        findings=findings,
    )
