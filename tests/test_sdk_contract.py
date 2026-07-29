"""The SDK field names this harness reads, asserted so a rename cannot pass silently.

Nearly every SDK field is read through `getattr(obj, "camelCaseName", default)`. That is
defensive against an *older* SDK, and dangerous against a newer one: `mcp` 2.0 renames these
to snake_case, and a defaulting getattr does not raise — it returns the default. The check
built on it then measures nothing and reports every server as clean.

The consequences are not uniform, so they are spelled out per field below. The worst is
`destructiveHint`: losing it does not just skew a score, it means the read-only filter stops
honouring a server's own "this tool is destructive" declaration and the harness executes it.

This test exists to fail on the day the SDK renames them, which is the entire point.
"""

from mcp import types


def _fields(model: type) -> set[str]:
    return set(getattr(model, "model_fields", {}))


def test_tool_fields_the_scanner_depends_on() -> None:
    fields = _fields(types.Tool)
    # inputSchema  -> Schema Health, Robustness probes, and the x-mcp-header check later
    # outputSchema -> the output-schema poisoning scan (Batch E's entire subject)
    # annotations  -> the read-only filter's most trustworthy signal
    for name in ("name", "description", "inputSchema", "outputSchema", "annotations"):
        assert name in fields, (
            f"types.Tool no longer has {name!r} — a check reading it is now blind"
        )


def test_annotation_fields_the_read_only_filter_depends_on() -> None:
    fields = _fields(types.ToolAnnotations)
    # Losing these is a SAFETY regression, not a scoring one: the filter falls back to
    # guessing from names and executes tools the server itself flagged as destructive.
    for name in ("readOnlyHint", "destructiveHint", "title"):
        assert name in fields, f"types.ToolAnnotations no longer has {name!r} — writes may run"


def test_result_fields_the_agent_and_response_scan_depend_on() -> None:
    fields = _fields(types.CallToolResult)
    # isError -> Tool Reliability; structuredContent -> Response Safety's second surface
    for name in ("content", "isError", "structuredContent"):
        assert name in fields, f"types.CallToolResult no longer has {name!r}"


def test_pagination_and_handshake_fields() -> None:
    # nextCursor: losing it stops pagination after page one, so tools on page two are
    # never discovered and never scanned — silently, and the server looks small.
    assert "nextCursor" in _fields(types.ListToolsResult)
    # protocolVersion: the report records which revision a score was measured against.
    assert "protocolVersion" in _fields(types.InitializeResult)
    assert "serverInfo" in _fields(types.InitializeResult)


def test_resource_and_prompt_fields() -> None:
    assert "mimeType" in _fields(types.Resource)
    assert "resourceTemplates" in _fields(types.ListResourceTemplatesResult)
    assert "messages" in _fields(types.GetPromptResult)
