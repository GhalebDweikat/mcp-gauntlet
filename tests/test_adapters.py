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
