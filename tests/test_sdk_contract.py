"""The SDK field names this harness reads, asserted so a rename cannot pass silently.

Nearly every SDK field is read through `getattr(obj, "camelCaseName", default)`. That is
defensive against an *older* SDK, and dangerous against a newer one: `mcp` 2.0 renames these
to snake_case, and a defaulting getattr does not raise — it returns the default. The check
built on it then measures nothing and reports every server as clean.

The consequences are not uniform, so they are spelled out per field below. The worst is the
destructive hint: losing it does not just skew a score, it means the read-only filter stops
honouring a server's own "this tool is destructive" declaration and the harness executes it.

Every assertion carries **both** spellings and picks by the installed era, so this test is
meaningful on either SDK rather than failing by construction on one of them. It also asserts
the *other* era's spelling is absent — which is what makes it a contract rather than a
tautology: if both names were present the adapters' whole premise would be wrong, and if the
wrong one were present the era detection would be picking the wrong adapter.
"""

from mcp import types

from mcp_gauntlet.adapters import adapter

ERA = adapter().era


def _fields(model: type) -> set[str]:
    return set(getattr(model, "model_fields", {}))


def _expect(model: type, legacy: str, modern: str, why: str) -> None:
    fields = _fields(model)
    wanted, other = (modern, legacy) if ERA == "modern" else (legacy, modern)
    assert wanted in fields, (
        f"types.{model.__name__} no longer has {wanted!r} on the {ERA} SDK — {why}"
    )
    if other != wanted:
        assert other not in fields, (
            f"types.{model.__name__} has BOTH {wanted!r} and {other!r}. The adapters assume "
            f"exactly one spelling exists per era; two means the era split is not what the "
            f"adapters are built on."
        )


def test_tool_fields_the_scanner_depends_on() -> None:
    # input schema  -> Schema Health, Robustness probes, and the x-mcp-header check later
    # output schema -> the output-schema poisoning scan (Batch E's entire subject)
    # annotations   -> the read-only filter's most trustworthy signal
    for legacy, modern in (("name", "name"), ("description", "description")):
        _expect(types.Tool, legacy, modern, "a check reading it is now blind")
    _expect(types.Tool, "inputSchema", "input_schema", "Schema Health goes blind")
    _expect(types.Tool, "outputSchema", "output_schema", "the output-schema scan goes blind")
    _expect(types.Tool, "annotations", "annotations", "the read-only filter loses its signal")


def test_annotation_fields_the_read_only_filter_depends_on() -> None:
    # Losing these is a SAFETY regression, not a scoring one: the filter falls back to
    # guessing from names and executes tools the server itself flagged as destructive.
    _expect(types.ToolAnnotations, "readOnlyHint", "read_only_hint", "writes may run")
    _expect(types.ToolAnnotations, "destructiveHint", "destructive_hint", "writes may run")
    _expect(types.ToolAnnotations, "title", "title", "the poisoned-title surface goes unscanned")


def test_result_fields_the_agent_and_response_scan_depend_on() -> None:
    _expect(types.CallToolResult, "content", "content", "every response scan goes blind")
    _expect(types.CallToolResult, "isError", "is_error", "Tool Reliability miscounts")
    _expect(
        types.CallToolResult,
        "structuredContent",
        "structured_content",
        "Response Safety loses its second surface",
    )


def test_pagination_and_handshake_fields() -> None:
    # Losing the cursor stops pagination after page one, so tools on page two are never
    # discovered and never scanned — silently, and the server merely looks small.
    _expect(types.ListToolsResult, "nextCursor", "next_cursor", "pagination stops at page one")
    _expect(
        types.InitializeResult,
        "protocolVersion",
        "protocol_version",
        "the report cannot say which revision a score was measured against",
    )
    _expect(types.InitializeResult, "serverInfo", "server_info", "the server loses its identity")


def test_resource_and_prompt_fields() -> None:
    _expect(types.Resource, "mimeType", "mime_type", "resource scanning loses its type")
    _expect(
        types.ListResourceTemplatesResult,
        "resourceTemplates",
        "resource_templates",
        "templates are never scanned",
    )
    _expect(types.GetPromptResult, "messages", "messages", "the poisoned-prompt scan goes blind")


def test_the_http_transport_resolves_in_this_era() -> None:
    """The remote-server path, which no test imported until it shipped broken.

    `streamablehttp_client` is a 1.x alias that `mcp` 2.0 removed. Widening the pin to
    `mcp<3` therefore made every http/https spec fail before touching the network, with an
    ImportError, on a fresh install. The cross-era fixture probe exercises stdio servers and
    the dual-SDK suite runs the tests — so a transport import sitting outside the adapter
    seam, referenced by no test, was invisible to both.

    Asserted by importing rather than by name-matching: the point is that the symbols this
    module actually uses resolve on the installed SDK.
    """
    from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

    assert callable(streamable_http_client)
    # Headers are how a credentialed remote server authenticates, and the 2.0 transport
    # takes an http_client rather than `headers=` — so losing this helper would silently
    # drop `--header` rather than fail loudly.
    assert callable(create_mcp_http_client)


def test_the_client_module_imports_no_removed_transport_alias() -> None:
    # A direct check on the source, because the import above only proves the NEW names work;
    # it would still pass if client.py went on using the removed one.
    import re
    from pathlib import Path

    source = (
        Path(__file__).resolve().parent.parent / "src" / "mcp_gauntlet" / "client.py"
    ).read_text(encoding="utf-8")
    offenders = [
        n
        for n, line in enumerate(source.splitlines(), 1)
        if re.search(r"\bstreamablehttp_client\b", line) and not line.strip().startswith("#")
    ]
    assert not offenders, f"client.py uses the 1.x-only transport alias at line(s) {offenders}"
