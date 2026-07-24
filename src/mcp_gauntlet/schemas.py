"""Shared JSON Schema traversal for a tool's argument surface.

MCP tool schemas are server-authored and routinely *composed* — ``allOf``, ``$ref`` into
``$defs``, ``anyOf`` — because that is what ``pydantic.model_json_schema()`` and
zod-to-json-schema emit for nested models, unions and enums. Any check that reads a
tool's arguments from the top level alone therefore misses a declaration one level down.

That blind spot has bitten this codebase in three separate places, which is why the
traversal lives here rather than in whichever module noticed it first:

* **Robustness** skipped composed tools entirely — and, because an unprobed tool used to
  count as argument-less, handed them a free perfect score.
* **Schema Health** never inspected their properties, so a composed schema drew none of
  the per-property penalties an equivalent flat one did.
* **Security** never read their property *descriptions* — letting a poisoned description
  hide behind a ``$ref`` and evade the injection scanner altogether.

Every traversal here is depth-bounded: ``$ref`` and ``allOf`` can be cyclic, and the
schemas are untrusted input.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any, NamedTuple

MAX_DEPTH = 4


def collect_defs(schema: Any) -> dict[str, Any]:
    """The local definition blocks a ``$ref`` in this schema can point into."""
    if not isinstance(schema, dict):
        return {}
    return {k: v for k, v in schema.items() if k in ("$defs", "definitions")}


def resolve_ref(ref: str, defs: dict[str, Any]) -> Any:
    """Resolve a local ``#/$defs/Name`` (or ``#/definitions/Name``) reference."""
    if not ref.startswith("#/"):
        return None  # remote refs aren't ours to fetch
    node: Any = defs
    for part in ref[2:].split("/"):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def subschemas(schema: Any, defs: dict[str, Any], depth: int = 0) -> list[dict[str, Any]]:
    """The schema itself plus any ``allOf`` branches it composes, with local $refs resolved."""
    if not isinstance(schema, dict) or depth > MAX_DEPTH:
        return []
    ref = schema.get("$ref")
    if isinstance(ref, str):
        return subschemas(resolve_ref(ref, defs), defs, depth + 1)
    out = [schema]
    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for branch in all_of:
            out.extend(subschemas(branch, defs, depth + 1))
    return out


def deref(node: Any, defs: dict[str, Any], depth: int = 0) -> Any:
    """A property declaration with its local ``$ref`` resolved.

    Sibling keywords stay and win over the target's, so an explicit description or type at
    the use site isn't lost. Without this a property declared as a bare ``$ref`` looks like
    it has no type and no description at all.
    """
    if not isinstance(node, dict) or depth > MAX_DEPTH:
        return node
    ref = node.get("$ref")
    if not isinstance(ref, str):
        return node
    target = resolve_ref(ref, defs)
    if not isinstance(target, dict):
        return node
    merged = {**deref(target, defs, depth + 1), **{k: v for k, v in node.items() if k != "$ref"}}
    return merged


# Slots holding sample DATA, identifiers, or machine tokens rather than prose the model
# reads as guidance. Everything else — `description`, `title`, `$comment`, and any unknown
# or extension keyword — counts as prose. The split matters because the checks calibrated
# for prose (credential-name references, invisible characters) are normal in these:
# `required: ["password"]` names a credential field correctly, and a soft hyphen or
# zero-width space survives a copy-paste into a sample value constantly.
_LITERAL_SLOTS = frozenset(
    {
        "enum",
        "const",
        "default",
        "examples",
        "format",
        "contentEncoding",
        "contentMediaType",
        "pattern",
        "required",
        "dependentRequired",
        "$ref",
        "$schema",
        "$id",
        "$anchor",
        "$dynamicRef",
        "$dynamicAnchor",
        "type",
    }
)
# Keys whose value is a MAP of named subschemas, so their keys are names (and become path
# segments) rather than schema keywords.
_NAMED_SUBSCHEMAS = frozenset(
    {"properties", "patternProperties", "dependentSchemas", "$defs", "definitions"}
)
# Keys whose value is (or contains) a nested SCHEMA rather than a value. Descending through
# one starts a fresh classification context; descending into anything else means we are
# inside a value, and everything below it inherits that value's classification. This is a
# structural fact about JSON Schema, not a guess about where prose lives — which matters,
# because the classification must be decided by the OUTERMOST slot a string sits under.
_SCHEMA_KEYWORDS = frozenset(
    {
        "items",
        "prefixItems",
        "additionalProperties",
        "unevaluatedItems",
        "unevaluatedProperties",
        "contains",
        "not",
        "if",
        "then",
        "else",
        "propertyNames",
        "allOf",
        "anyOf",
        "oneOf",
    }
)


# `title` is prose — a title reading "ignore all instructions" is genuinely suspicious — but
# it is AUTO-GENERATED by pydantic from the field name, so a field correctly named
# `password` produces `title: "Password"`. Running the credential-reference patterns over
# it would penalise every auth-bearing server for naming its own credential field.
_LABEL_SLOTS = frozenset({"title"})


class _Mode(IntEnum):
    """How much of the scan applies. Lower = more scrutiny; the walk only ever tightens."""

    PROSE = 0  # guidance the model reads: everything applies
    LABEL = 1  # prose, but not the credential-reference patterns
    LITERAL = 2  # sample data / identifiers: injection phrasing only, never capping


def _mode_for(key: str) -> _Mode:
    if key in _LITERAL_SLOTS:
        return _Mode.LITERAL
    if key in _LABEL_SLOTS:
        return _Mode.LABEL
    return _Mode.PROSE


class SchemaText(NamedTuple):
    label: str  # where it was found, e.g. "property 'cfg.mode' description"
    text: str
    prose: bool  # full-severity injection patterns + the hidden-character check
    references: bool  # also run the sensitive-file / exfiltration reference patterns


class TextScan(NamedTuple):
    texts: list[SchemaText]  # deduplicated by text
    truncated: bool  # the walk hit its node/depth bound, so coverage is incomplete


def schema_texts(schema: Any, *, max_nodes: int = 5000, max_depth: int = 64) -> TextScan:
    """Every prose string the schema ships to the model, labelled with where it was found.

    The *whole* input schema is serialized into the tool's ``parameters`` (see
    ``toolconv``), so every string in it reaches the model's prompt — and any of them can
    carry a poisoned instruction. An allowlist of "keywords that hold prose" cannot close
    that: ``title`` (which ``pydantic.model_json_schema()`` emits for every field and model
    by default), ``enum`` members, ``const``, ``default``, ``examples``, ``$comment`` and
    arbitrary extension keywords like ``x-note`` are all shipped verbatim, and JSON Schema
    permits unknown keywords, so the list can never be complete. This walks the document
    generically instead and scans every string in it — values and object keys alike.

    Each string is classified by the OUTERMOST slot it sits under, never by its immediate
    parent key, so that neither direction is exploitable: an object-valued ``default``
    (ordinary pydantic output) keeps data treatment all the way down, and a payload buried
    under ``description: {"type": …}`` cannot borrow the laxer treatment of an inner key.

    Walking the document also removes the need to resolve ``$ref``: the targets live in
    ``$defs``/``definitions``, which are walked wholesale — including entries nothing
    references, since those are serialized to the model too.

    Results are deduplicated **by text**: one shared node reached from nine properties is
    one problem, and reporting it nine times would multiply the penalty on a grade-capping
    dimension for what is a single string.

    Bounded by node count and depth (untrusted, possibly cyclic input); ``truncated`` says
    whether a bound was hit, so partial coverage is never read as "nothing found".
    """
    seen: dict[str, tuple[str, _Mode]] = {}  # text -> (label, strictest mode seen)
    visited: set[int] = set()
    budget = [max_nodes]
    truncated = [False]

    def record(text: str, path: str, slot: str, mode: _Mode) -> None:
        if not text.strip():
            return
        where = f"property {path!r}" if path else "schema"
        label = f"{where} {slot}" if slot else where
        previous = seen.get(text)
        # Keep the STRICTEST treatment the string was seen under anywhere, and the label
        # that goes with it, so a promoted string isn't reported against the laxer slot.
        if previous is None or mode < previous[1]:
            seen[text] = (label, mode)

    def walk(node: Any, path: str, slot: str, depth: int, mode: _Mode) -> None:
        if budget[0] <= 0 or depth > max_depth:
            truncated[0] = True
            return
        if isinstance(node, str):
            record(node, path, slot, mode)
            return
        if isinstance(node, dict):
            if id(node) in visited:  # cyclic $ref / allOf
                return
            visited.add(id(node))
            budget[0] -= 1
            for key, value in node.items():
                if slot:
                    # Inside a VALUE. Its own keys are data, so record them (a JSON key can
                    # hold a payload) but do NOT let them re-enter schema interpretation —
                    # this branch has to come first, or a tool that legitimately takes a
                    # JSON Schema as a parameter has the schema inside its `default` read
                    # as a real schema, and a payload under `description: {"properties":
                    # {…}}` borrows the never-capping literal treatment.
                    record(str(key), path, slot, mode)
                    walk(value, path, slot, depth + 1, mode)
                elif key in _NAMED_SUBSCHEMAS and isinstance(value, dict):
                    for name, sub in value.items():
                        child = f"{path}.{name}" if path else str(name)
                        # The NAME itself ships to the model too, and JSON keys may contain
                        # spaces — so a payload can be written as a property name. Scanned
                        # as a literal: it's an identifier, not guidance.
                        record(str(name), child, "name", _Mode.LITERAL)
                        walk(sub, child, "", depth + 1, _Mode.PROSE)
                elif key in _SCHEMA_KEYWORDS:
                    walk(value, path, "", depth + 1, _Mode.PROSE)  # a nested schema
                else:
                    walk(value, path, str(key), depth + 1, _mode_for(str(key)))
        elif isinstance(node, list):
            budget[0] -= 1
            for item in node:
                walk(item, path, slot, depth + 1, mode)

    walk(schema, "", "", 0, _Mode.PROSE)
    return TextScan(
        [
            SchemaText(label, text, prose=mode <= _Mode.LABEL, references=mode is _Mode.PROSE)
            for text, (label, mode) in seen.items()
        ],
        truncated[0],
    )


class ArgSurface(NamedTuple):
    """The effective arguments a tool accepts, gathered across composition."""

    properties: dict[str, Any]
    required: list[Any]
    pattern_properties: dict[str, Any]
    additional: Any  # additionalProperties: a schema, True, False, or None if unstated
    defs: dict[str, Any]
    has_properties: bool  # some subschema declared a `properties` mapping (even an empty one)


def arg_surface(schema: Any) -> ArgSurface:
    properties: dict[str, Any] = {}
    required: list[Any] = []
    pattern_properties: dict[str, Any] = {}
    additional: Any = None
    has_properties = False
    defs = collect_defs(schema)
    for sub in subschemas(schema, defs):
        if isinstance(sub.get("properties"), dict):
            # Deref each declaration: a property written as a bare `$ref` would otherwise
            # look untyped and undescribed to every caller.
            properties.update({k: deref(v, defs) for k, v in sub["properties"].items()})
            has_properties = True
        if isinstance(sub.get("required"), list):
            required.extend(sub["required"])
        if isinstance(sub.get("patternProperties"), dict):
            pattern_properties.update(sub["patternProperties"])
        if additional is None and "additionalProperties" in sub:
            additional = sub["additionalProperties"]
    return ArgSurface(properties, required, pattern_properties, additional, defs, has_properties)


def declares_arg_contract(schema: Any) -> bool:
    """Whether the tool publishes an argument contract we could hold it to.

    A tool with an object schema and no violatable field (a zero-argument tool) HAS a
    contract — there is simply nothing invalid to send it. A tool with no schema at all
    has declared nothing, so it cannot reject anything: that is a robustness failure, not
    an exemption. Keeping the distinction matters because omitting schemas would otherwise
    be a way to skip the Robustness dimension entirely and score higher for it.
    """
    return isinstance(schema, dict) and schema.get("type") == "object"


def declares_arguments(schema: Any) -> bool:
    """Whether the tool takes arguments at all (as opposed to being zero-argument).

    Looks through ``allOf`` composition and at the arbitrary-key contracts, because the
    zero-argument exemption is the one path that skips scoring entirely: any shape that
    declares arguments but is missed here becomes a free perfect score.
    """
    if not isinstance(schema, dict):
        return False
    surface = arg_surface(schema)
    if surface.properties or surface.required or surface.pattern_properties:
        return True
    # `additionalProperties: false` is the canonical strict zero-argument tool; anything
    # else here (a schema, or a bare `true`) admits arguments we were never able to probe.
    return surface.additional is not None and surface.additional is not False
