"""The seam where SDK objects become our models — and the two ways it could go wrong.

`mcp` 2.0 renamed every field to snake_case. Those fields were read through
`getattr(obj, "camelCaseName", default)`, which does not raise on a rename: it returns the
default, and the check built on it then measures nothing and reports every server clean. That
is not hypothetical — the MRTR detection shipped on 2026-07-28 read only `resultType` and
would have inverted its own attribution against every modern server.

So `require()` raises where a rename would otherwise be silent. But raising has its own
failure mode, and it is worse: this project's oldest rule is that a completed evaluation must
never be discarded, and a crash mid-run loses paid LLM spend. Both directions are pinned here.
"""

from types import SimpleNamespace

import pytest

from mcp_gauntlet.adapters import SdkFieldMissing, adapter, require, sdk_version
from mcp_gauntlet.adapters.legacy import LegacyAdapter


def test_a_renamed_field_raises_instead_of_defaulting() -> None:
    """The entire point of the seam.

    A defaulting read of a renamed field is indistinguishable from a server that legitimately
    omitted it, so the check goes quiet and every server looks clean.
    """
    modern_shaped = SimpleNamespace(input_schema={"type": "object"}, name="t")
    with pytest.raises(SdkFieldMissing) as caught:
        require(modern_shaped, "inputSchema")
    # The message has to tell the next person what to do, not just what happened.
    assert "inputSchema" in str(caught.value)
    assert "do not add a default" in str(caught.value)


def test_a_default_is_honoured_where_the_protocol_says_optional() -> None:
    # A tool need not declare an outputSchema; that is not a rename and must not raise.
    assert require(SimpleNamespace(name="t"), "outputSchema", default=None) is None


def test_absent_annotations_do_not_raise() -> None:
    """`Tool.annotations` is None for most tools, and require() keys on hasattr.

    Routing the hints through require() would therefore raise on nearly every real server —
    turning "this server declared no annotations", the ordinary case, into a crashed
    evaluation. The hints are read defensively for exactly this reason.
    """
    tool = SimpleNamespace(
        name="t", description="d", inputSchema={"type": "object"}, annotations=None
    )
    info = LegacyAdapter().tool_info(tool)
    assert info.read_only_hint is None
    assert info.destructive_hint is None
    assert info.annotation_title is None


def test_hints_are_read_when_the_server_does_declare_them() -> None:
    # The inverse: losing these is a SAFETY regression, not a scoring one — the read-only
    # filter stops honouring a server's own "this tool is destructive" declaration.
    tool = SimpleNamespace(
        name="t",
        description="d",
        inputSchema={"type": "object"},
        annotations=SimpleNamespace(readOnlyHint=False, destructiveHint=True, title="Delete It"),
    )
    info = LegacyAdapter().tool_info(tool)
    assert info.read_only_hint is False
    assert info.destructive_hint is True
    assert info.annotation_title == "Delete It"


def test_tool_mapping_captures_every_scanned_surface() -> None:
    # Each of these is server-authored text that reaches a model in some client. Dropping any
    # of them at discovery makes it unreachable by the injection scan — which is precisely
    # the blind spot Batch E existed to close.
    tool = SimpleNamespace(
        name="t",
        description="does a thing",
        inputSchema={"type": "object", "properties": {}},
        title="Display Title",
        outputSchema={"type": "object"},
        annotations=SimpleNamespace(title="Annotation Title"),
        meta={"x": "y"},
    )
    info = LegacyAdapter().tool_info(tool)
    assert info.title == "Display Title"
    assert info.annotation_title == "Annotation Title"
    assert info.output_schema == {"type": "object"}
    assert info.meta == {"x": "y"}


def test_detection_picks_by_version_not_by_attribute() -> None:
    """`mcp` 2.0 still exports ClientSession and mcp.types — verified against the release.

    So probing for an attribute cannot distinguish the eras and would silently select the
    wrong adapter. Only the package version can.
    """
    version = sdk_version()
    assert version and version != "unknown"
    expected = "modern" if int(version.split(".")[0]) >= 2 else "legacy"
    assert adapter().era == expected


def test_the_adapter_is_resolved_once() -> None:
    # It is consulted in hot loops (every tool, every page); resolving per call would mean
    # an importlib.metadata lookup each time.
    assert adapter() is adapter()


def test_live_result_reads_never_raise_on_an_unfamiliar_shape() -> None:
    """The rule that separates discovery from live calls.

    `require()` raises so a renamed field cannot pass silently — right during discovery,
    which happens before any spend. It is wrong on a live result: robustness.py's read runs
    LAST, after the whole agentic eval, so a raise there discards a run already paid for.
    That is R2's rule, and it is why these read defensively instead.
    """
    sdk = LegacyAdapter()
    alien = SimpleNamespace()  # nothing we recognise at all
    assert sdk.result_is_error(alien) is False
    assert sdk.result_content(alien) == []
    assert sdk.result_structured(alien) is None
    assert sdk.asks_for_input(alien) is False


def test_live_result_reads_accept_either_era_spelling() -> None:
    # The era is chosen by SDK version, so the canonical name is right — but a mis-detected
    # era has to produce a suspicious number, not a lost report.
    legacy = SimpleNamespace(isError=True, structuredContent={"a": 1}, resultType="input_required")
    modern = SimpleNamespace(
        is_error=True, structured_content={"a": 1}, result_type="input_required"
    )
    sdk = LegacyAdapter()
    for shape in (legacy, modern):
        assert sdk.result_is_error(shape) is True
        assert sdk.result_structured(shape) == {"a": 1}
        assert sdk.asks_for_input(shape) is True


def test_the_protocol_error_type_resolves_to_a_real_exception() -> None:
    """Robustness treats this class as control flow, so losing it is not a scoring bug.

    A JSON-RPC error is the CORRECT way for a server to reject malformed input; if the class
    cannot be resolved, every correct rejection becomes an unhandled crash instead.

    Resolved through `adapter()` rather than a fixed era, because the two eras disagree: 2.0
    renamed `McpError` to `MCPError` and kept the module name, so the failure is an
    ImportError on a name rather than a missing module. That is invisible from a 1.x-only
    environment, and it shipped in the modern adapter until a real 2.0 environment ran this.
    """
    error_type = adapter().protocol_error_type()
    assert isinstance(error_type, type)
    assert issubclass(error_type, BaseException)


# Every 1.x SDK field name that 2.0 renamed. Named explicitly rather than matched by shape,
# because the shape-based version of this guard had a hole big enough to drive a bug
# through: it looked for `getattr(x, "camelCase")` and so could not see `page.camelCase`,
# and a plain attribute read of `resourceTemplates` sat in client.py the whole time. Under
# 2.0 that raised AttributeError into a broad `except` that logs at debug — so template
# discovery returned nothing and "no templates" became indistinguishable from "could not
# read them".
#
# A list is the right instrument here where a regex was not. Widening the regex to all
# camelCase attribute access would have matched `logging.getLogger`, `logger.setLevel` and
# `logger.addHandler`, and buying precision with an exemption list gives you a grep nobody
# reads. These names are finite, knowable, and exactly the thing that must not be read
# outside the seam.
_RENAMED_SDK_FIELDS = (
    "inputSchema",
    "outputSchema",
    "isError",
    "structuredContent",
    "resultType",
    "inputRequests",
    "nextCursor",
    "serverInfo",
    "protocolVersion",
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
    "mimeType",
    "uriTemplate",
    "resourceTemplates",
    "listChanged",
)


def test_no_sdk_shaped_read_survives_outside_the_adapters() -> None:
    """The seam is only real if nothing bypasses it.

    An SDK field read anywhere else is exactly what goes silently null when the SDK renames
    it — the read does not raise, it returns a default (or, for a plain attribute access,
    raises into whichever `except` happens to be nearest), and the check built on it then
    measures nothing while reporting every server clean.

    Both access forms are checked, because the bug that motivated this used the one the
    original guard could not see.
    """
    import ast
    from pathlib import Path

    # Parsed, not grepped. `drift.py` explains the `tools.listChanged` capability in its
    # docstring and names it in a user-facing message, and a regex cannot tell that prose
    # from a read. Chasing that with more regex is how a guard accretes exemptions until
    # nobody trusts it; the AST simply does not see inside a string.
    root = Path(__file__).resolve().parent.parent
    renamed = set(_RENAMED_SDK_FIELDS)
    offenders: list[str] = []

    for area in ("src/mcp_gauntlet", "tests"):
        for path in (root / area).rglob("*.py"):
            if "adapters" in path.parts or path.name == "sdk_shapes.py":
                continue  # the seam itself, and the test helper that builds both spellings
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                hit: str | None = None
                if isinstance(node, ast.Attribute) and node.attr in renamed:
                    hit = node.attr
                elif (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "getattr"
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value in renamed
                ):
                    hit = str(node.args[1].value)
                if hit is not None:
                    line = getattr(node, "lineno", 0)
                    offenders.append(f"{path.relative_to(root)}:{line} ({hit})")

    assert not offenders, "SDK fields read outside adapters/: " + ", ".join(offenders)


# --------------------------------------------------------------- both eras, one model
#
# The plan called this the strongest guarantee available, and it is the one that would
# alone have caught both bugs found so far: an adapter reading the wrong spelling, and an
# adapter forgetting a field its counterpart maps. Neither shows up testing one era.
#
# These use stand-in objects rather than real SDK types because the two SDKs cannot be
# installed together — 2.0 moves to httpx2 — so no single environment can import both.
# What is being pinned is the MAPPING, and the field names on the left of each pair were
# read off the released 1.29.0 and 2.0.0 rather than inferred.


def _tool_pair() -> tuple[SimpleNamespace, SimpleNamespace]:
    """One logical tool, spelled the way each era's SDK spells it."""
    schema = {"type": "object", "properties": {"q": {"type": "string"}}}
    legacy = SimpleNamespace(
        name="search",
        description="Search the index.",
        inputSchema=schema,
        outputSchema={"type": "object"},
        title="Search",
        annotations=SimpleNamespace(
            title="Read-only search", readOnlyHint=True, destructiveHint=False
        ),
        meta={"category": "query"},
    )
    modern = SimpleNamespace(
        name="search",
        description="Search the index.",
        input_schema=schema,
        output_schema={"type": "object"},
        title="Search",
        annotations=SimpleNamespace(
            title="Read-only search", read_only_hint=True, destructive_hint=False
        ),
        meta={"category": "query"},
    )
    return legacy, modern


def test_both_eras_map_the_same_tool_to_the_same_model() -> None:
    from mcp_gauntlet.adapters.modern import ModernAdapter

    legacy, modern = _tool_pair()
    assert LegacyAdapter().tool_info(legacy) == ModernAdapter().tool_info(modern)


def test_both_eras_map_the_same_handshake_to_the_same_model() -> None:
    from mcp_gauntlet.adapters.modern import ModernAdapter

    legacy = SimpleNamespace(
        serverInfo=SimpleNamespace(name="srv", version="1.0", title="Srv"),
        protocolVersion="2025-11-25",
        instructions="be helpful",
    )
    modern = SimpleNamespace(
        server_info=SimpleNamespace(name="srv", version="1.0", title="Srv"),
        protocol_version="2025-11-25",
        instructions="be helpful",
    )
    assert LegacyAdapter().server_info(legacy) == ModernAdapter().server_info(modern)


def test_both_eras_map_the_same_resource_to_the_same_model() -> None:
    from mcp_gauntlet.adapters.modern import ModernAdapter

    legacy = SimpleNamespace(
        name="doc", uri="file:///a", mimeType="text/plain", description="d", title="D", meta={}
    )
    modern = SimpleNamespace(
        name="doc", uri="file:///a", mime_type="text/plain", description="d", title="D", meta={}
    )
    assert LegacyAdapter().resource_info(
        legacy, is_template=False
    ) == ModernAdapter().resource_info(modern, is_template=False)

    legacy_t = SimpleNamespace(
        name="doc", uriTemplate="file:///{p}", mimeType=None, description=None, title=None, meta={}
    )
    modern_t = SimpleNamespace(
        name="doc",
        uri_template="file:///{p}",
        mime_type=None,
        description=None,
        title=None,
        meta={},
    )
    assert LegacyAdapter().resource_info(
        legacy_t, is_template=True
    ) == ModernAdapter().resource_info(modern_t, is_template=True)


def test_pointing_an_adapter_at_the_wrong_era_raises_rather_than_defaults() -> None:
    """The inverse of the equivalence, and the reason require() exists.

    A mis-detected era must fail at discovery — before any spend — not quietly produce a
    tool with no schema, which every downstream check would read as a server that declared
    none.
    """
    from mcp_gauntlet.adapters.modern import ModernAdapter

    legacy, modern = _tool_pair()
    with pytest.raises(SdkFieldMissing):
        ModernAdapter().tool_info(legacy)
    with pytest.raises(SdkFieldMissing):
        LegacyAdapter().tool_info(modern)


def test_neither_era_is_missing_a_method_the_other_has() -> None:
    """A method absent from one adapter is a check that exists in one era only.

    Protocol conformance is structural at type-check time; this makes it fail at runtime
    too, since a missing method surfaces as an AttributeError deep inside an evaluation.
    """
    from mcp_gauntlet.adapters.modern import ModernAdapter

    legacy_api = {n for n in dir(LegacyAdapter) if not n.startswith("_")}
    modern_api = {n for n in dir(ModernAdapter) if not n.startswith("_")}
    assert legacy_api == modern_api, f"asymmetric: {legacy_api ^ modern_api}"


def test_both_eras_read_the_template_list_off_a_page() -> None:
    """The container field, not the entries — the one list whose name changed.

    `resources`, `prompts` and `tools` all kept their names; `resourceTemplates` became
    `resource_templates`. Nothing tested the extraction itself, only the mapping of an
    individual entry, so a plain `page.resourceTemplates` in client.py went unnoticed in
    both eras: correct on 1.x, and on 2.0 an AttributeError swallowed by a broad `except`
    that logs at debug. Template discovery returned nothing and the report read clean.
    """
    from mcp_gauntlet.adapters.modern import ModernAdapter

    entry = SimpleNamespace(name="doc")
    legacy_page = SimpleNamespace(resourceTemplates=[entry])
    modern_page = SimpleNamespace(resource_templates=[entry])
    assert LegacyAdapter().resource_templates(legacy_page) == [entry]
    assert ModernAdapter().resource_templates(modern_page) == [entry]


def test_reading_the_template_list_from_the_wrong_era_raises() -> None:
    # The property that was missing. An empty list means "this server publishes no
    # templates"; it must never also mean "we could not find the field".
    from mcp_gauntlet.adapters.modern import ModernAdapter

    with pytest.raises(SdkFieldMissing):
        ModernAdapter().resource_templates(SimpleNamespace(resourceTemplates=[]))
    with pytest.raises(SdkFieldMissing):
        LegacyAdapter().resource_templates(SimpleNamespace(resource_templates=[]))
