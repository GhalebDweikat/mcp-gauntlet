"""Robustness probes: feed each tool malformed arguments and see how the server copes.

LLM-free. A well-behaved server *rejects* schema-violating input — either with a
JSON-RPC error (surfaced as ``McpError``) or an ``isError`` result — rather than
silently accepting it, hanging, or crashing the connection. The classification is
framework-agnostic on purpose: any error signal counts as a correct rejection, so
we never penalize a server for validating the "wrong" way.
"""

from __future__ import annotations

import re
from typing import Any

import anyio
from mcp import ClientSession

from mcp_gauntlet.adapters import adapter
from mcp_gauntlet.models import ToolInfo
from mcp_gauntlet.preflight import (
    block_text,
    looks_like_missing_credentials,
    machine_auth_code,
    rejected_the_caller,
)
from mcp_gauntlet.report import Dim, DimensionResult, Finding, Severity
from mcp_gauntlet.schemas import (
    arg_surface,
    declares_arg_contract,
    declares_arguments,
    resolve_ref,
)

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
        target = resolve_ref(ref, defs)
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
            unconstrained = False
            for branch in branches:
                if not isinstance(branch, dict):
                    unconstrained = True
                    continue
                resolved = branch
                branch_ref = branch.get("$ref")
                if isinstance(branch_ref, str):
                    target = resolve_ref(branch_ref, defs)
                    resolved = target if isinstance(target, dict) else branch
                branch_type = resolved.get("type")
                if isinstance(branch_type, str):
                    allowed.add(branch_type)
                elif isinstance(branch_type, list):
                    allowed.update(t for t in branch_type if isinstance(t, str))
                elif "enum" in resolved or "const" in resolved:
                    allowed.add("string")  # conservative: assume the literal may be a string
                else:
                    unconstrained = True
            # One unconstrained branch (``{}``) makes the union accept everything, so any
            # value we sent would be VALID — reporting the server for accepting it would be
            # a false accusation about its behaviour. Say we can't violate it instead.
            if unconstrained or not allowed:
                return False, None
            return _wrong_for_types(allowed)

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


def _key_matching(pattern: str) -> str | None:
    """A property name satisfying ``pattern``, so patternProperties can be probed."""
    try:
        compiled = re.compile(pattern)
    except re.error:
        return None
    for candidate in ("mcp_gauntlet_probe", "a", "x_1", "0", "_"):
        if compiled.search(candidate):
            return candidate
    return None


def malformed_args(schema: dict[str, Any]) -> dict[str, Any] | None:
    """Build one schema-violating argument payload, or None if nothing can be violated."""
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return None
    surface = arg_surface(schema)
    props, required = surface.properties, surface.required
    pattern_props, extra, defs = surface.pattern_properties, surface.additional, surface.defs

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

    # Arbitrary-key contracts: a key not named in `properties` is validated against
    # patternProperties / additionalProperties, so violating one of those is a real probe.
    for pattern, sub in pattern_props.items():
        key = _key_matching(pattern) if isinstance(pattern, str) else None
        if key is None:
            continue
        found, value = _violating_value(sub, defs)
        if found:
            return {key: value}
    if isinstance(extra, dict):
        found, value = _violating_value(extra, defs)
        if found:
            return {"mcp_gauntlet_probe": value}

    return None


def _unprobed_after(tools: list[ToolInfo], index: int) -> int:
    """How many tools AFTER ``index`` would have been scored had probing continued.

    Every early exit has to add these as zeros. Scoring only the tool it stopped on is not
    the same thing, and the difference runs the wrong way: the tools never reached are the
    ones that would have scored 0, so dropping them RAISES the mean. Measured on ten tools
    where the second hangs and the rest silently accept malformed input — 50.0 reported
    against an honest 10.0.

    That matters because both inputs are the server's to choose. It picks the order its
    tools are listed in and how slow each one is, so "hang on the second tool" is a
    controllable way to buy a score. Counts only tools that would actually have been scored,
    for the same reason the budget path does: a zero-argument tool contributes nothing on
    the normal path, so counting it here would swing the mean by the same accident of
    ordering these zeros exist to prevent.
    """
    return sum(1 for later in tools[index + 1 :] if is_scored(later.input_schema))


def is_scored(schema: Any) -> bool:
    """Whether this tool contributes a score to the Robustness dimension at all.

    Only a genuinely zero-argument tool does not: it can be probed with nothing, so it is
    neither passed nor failed. Everything else is either probeable or penalised for an
    unenforceable contract.
    """
    if malformed_args(schema) is not None:
        return True
    return not declares_arg_contract(schema) or declares_arguments(schema)


def _protocol_error() -> type[BaseException]:
    """The SDK's protocol-error class, via the adapter.

    A JSON-RPC error is the *correct* way for a server to reject malformed input, so this
    class is control flow rather than a failure — and it moved package in `mcp` 2.0. Resolved
    through the adapter so the era owns the answer, and imported lazily so a top-level import
    cannot fail before the adapter has been chosen.
    """
    return adapter().protocol_error_type()


async def run_robustness_probes(
    session: ClientSession,
    tools: list[ToolInfo],
    *,
    timeout_s: float = 15.0,
    # 60s so the pieces compose: one permitted agent hang (--tool-timeout, 60s) plus a
    # full probe budget still fits inside the leaderboard's 240s per-server allowance.
    budget_s: float = 60.0,
    # Whether the caller has ALREADY emitted a HIGH saying the credentials were rejected.
    # One fact deserves one HIGH: a reader counting "2 findings at or above high" and finding
    # both sentences describing the same wrong token stops trusting the count.
    auth_already_reported: bool = False,
) -> DimensionResult | None:
    """Probe each tool with malformed input.

    Always returns a dimension when there is at least one tool — an omitted dimension
    would shrink the weighted-mean denominator and inflate the overall. Returns None only
    when there are no tools at all.

    ``timeout_s`` bounds a single probe; ``budget_s`` bounds them all together. Without the
    aggregate bound, many merely-slow tools (each finishing inside ``timeout_s``, so no
    timeout ever fires) can still outrun the caller's per-server budget — and when that
    outer bound fires the whole report is lost, which is the outcome these probes are
    meant to survive.
    """
    if not tools:
        return None
    findings: list[Finding] = []
    scores: list[float] = []
    auth_rejected: list[str] = []
    started = anyio.current_time()

    for index, tool in enumerate(tools):
        if scores and anyio.current_time() - started >= budget_s:
            # Count only the tools that would actually have been SCORED. A zero-argument
            # tool contributes nothing on the normal path, so counting it as a failure here
            # would swing the score by the same accident of ordering the 0.0s exist to
            # prevent — just in the other direction. `is_scored` is pure and offline.
            remaining = sum(1 for later in tools[index:] if is_scored(later.input_schema))
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    message=f"stopped probing after {budget_s:g}s — the server is too slow "
                    f"to finish; {remaining} tool(s) went unprobed and count as failures",
                    detail="A server this slow can't be verified within the time budget. "
                    "Investigate the latency, or raise the budget and re-run.",
                )
            )
            # Score the unprobed tools 0 rather than dropping them. Both latency and tool
            # ORDER are server-controlled, so leaving them out would let a server put one
            # slow-but-correct tool first and have the budget cut the probe short before
            # its broken tools were ever reached — turning a 5.0 into a 100.0. Every early
            # exit now adds the same zeros via `_unprobed_after`: stopping early must only
            # ever lower the score, never raise it.
            #
            # This comment used to claim the other exits achieved that by "scoring the tool
            # they stopped on", which is true of the action and false of the effect — the
            # tools never reached are precisely the ones that would have scored 0, so
            # omitting them raised the mean. An audit agent read this comment, called the
            # function sound, and did not read the ten lines below it.
            scores.extend([0.0] * remaining)
            break
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
            unprobed = _unprobed_after(tools, index)
            scores.extend([0.0] * unprobed)
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    message=f"stopped probing after a timeout; {unprobed} later tool(s) went "
                    "unprobed and count as failures",
                )
            )
            break
        except _protocol_error() as exc:
            # …unless the protocol-level rejection was of the CALLER rather than of the
            # payload. A wrongly-credentialed server that answers 401 over the JSON-RPC error
            # channel refuses everything identically, and crediting that 100 is the same
            # inflation the `isError` branch below already guards against — the only
            # difference being which channel the refusal arrived on. It scored 100 here for
            # two releases because nothing on this path read the error's code or data.
            if rejected_the_caller(exc):
                auth_rejected.append(tool.name)
                continue
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
            unprobed = _unprobed_after(tools, index)
            scores.extend([0.0] * unprobed)
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    message=f"stopped probing after an unexpected error; {unprobed} later "
                    "tool(s) went unprobed and count as failures",
                )
            )
            break

        if adapter().result_is_error(result):
            sdk = adapter()
            text = " ".join(x for block in sdk.result_content(result) if (x := block_text(block)))
            if machine_auth_code(sdk.result_structured(result)) or looks_like_missing_credentials(
                text
            ):
                # An auth rejection is NOT evidence that the server validates its input — it
                # never got as far as looking. Crediting it 100 is how a server given a wrong
                # or expired token scored **A 100.0 with exit 0**, producing a report
                # byte-identical to the same server with a working one: every call 401'd, and
                # a 401 is technically "rejected the malformed input".
                #
                # Not scored either way. Whether this server validates is simply unknown, and
                # a 0 would blame it for a credential problem that is probably the caller's.
                # The finding below carries the verdict; the number stays out of it.
                auth_rejected.append(tool.name)
                continue
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

    if auth_rejected and not scores:
        # EVERY probed tool refused on authentication, so nothing about this server's
        # behaviour was observed. Reported rather than scored, and HIGH so the documented
        # gate (`--fail-on high`) catches it: a run where every call was rejected must not
        # read as a pass. This needs no LLM — a 100% auth-failure rate is an offline fact,
        # and Tool Reliability, the dimension that would otherwise notice, requires one.
        # "every tool call" was printed over a probe of three tools on a ten-tool server.
        # Say what was probed, not what exists — the whole complaint here is that a number
        # was reported over a measurement that never happened.
        probed = len(auth_rejected)
        return DimensionResult(
            key=Dim.ROBUSTNESS,
            title="Robustness",
            weight=1.0,
            score=0.0,
            summary=f"All {probed} probed tool(s) were rejected for authentication, so "
            "whether this server validates its input could not be observed.",
            findings=[
                Finding(
                    severity=Severity.INFO if auth_already_reported else Severity.HIGH,
                    message=(
                        f"all {probed} probed tool(s) were rejected for authentication"
                        + (
                            " — see the Tool Reliability finding; nothing about this "
                            "server's input validation was measured either"
                            if auth_already_reported
                            else " — the credentials supplied are wrong, expired, or lack "
                            "the required scope, so nothing about this server was "
                            "actually measured"
                        )
                    ),
                    detail=", ".join(sorted(auth_rejected)[:8]),
                )
            ],
        )

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
            key=Dim.ROBUSTNESS,
            title="Robustness",
            weight=1.0,
            score=100.0,
            summary="No tool exposes a violatable argument, so there was nothing to "
            "probe; scored as no-evidence-of-failure rather than omitted.",
            findings=findings,
        )

    return DimensionResult(
        key=Dim.ROBUSTNESS,
        title="Robustness",
        weight=1.0,
        score=round(sum(scores) / len(scores), 1),
        summary="Fraction of probed tools that reject malformed / schema-violating "
        "arguments — a well-behaved server rejects them rather than silently accepting, "
        "hanging, or crashing (LLM-free).",
        findings=findings,
    )
