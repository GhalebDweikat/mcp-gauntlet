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
    # Robustness treats it as control flow — a JSON-RPC error is the CORRECT way for a server
    # to reject malformed input — and the class moved package in mcp 2.0.
    error_type = LegacyAdapter().protocol_error_type()
    assert isinstance(error_type, type)
    assert issubclass(error_type, BaseException)


def test_no_sdk_shaped_read_survives_outside_the_adapters() -> None:
    """The seam is only real if nothing bypasses it.

    A camelCase getattr anywhere else is an SDK field being read directly, which is precisely
    what goes silently null when the SDK renames it. Scoped to camelCase literals rather than
    all getattr calls, because plenty of legitimate ones exist (exception groups, pydantic
    errors, content-block unions) and a grep with standing exemptions is a grep nobody reads.
    """
    import re
    from pathlib import Path

    src = Path(__file__).resolve().parent.parent / "src" / "mcp_gauntlet"
    pattern = re.compile(r'getattr\([^,]+,\s*"[a-z]+[A-Z]')
    offenders = [
        f"{path.relative_to(src)}:{n}"
        for path in src.rglob("*.py")
        if "adapters" not in path.parts
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if pattern.search(line)
    ]
    assert not offenders, "SDK fields read outside adapters/: " + ", ".join(offenders)
