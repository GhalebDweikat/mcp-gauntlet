"""Revision 2026-07-28 schema checks: header-mapped arguments and off-document refs.

The header check has one constraint that outranks everything else it does, and it is the
reason it is written the way it is: a secret-looking property NAME must never be a finding
on its own. Twenty-five security findings in the reference survey were exactly that mistake
in its earlier form — servers reported for naming a credential concept rather than leaking
one — and a new check that reintroduces it through the schema instead of the prose is the
same bug with a new door. The name only matters once the server has also asked for the
value to leave as an HTTP header.
"""

from mcp_gauntlet.checks import scan_tool
from mcp_gauntlet.models import ToolInfo
from mcp_gauntlet.report import Severity


def _tool(schema: dict, *, output: dict | None = None) -> ToolInfo:
    return ToolInfo(
        name="t",
        description="Does a thing for the user, with a description long enough to pass.",
        input_schema=schema,
        output_schema=output or {},
    )


def _messages(tool: ToolInfo) -> list[str]:
    return [f.message for f in scan_tool(tool)]


def _by_severity(tool: ToolInfo, severity: Severity) -> list[str]:
    return [f.message for f in scan_tool(tool) if f.severity is severity]


# ----------------------------------------------------------------- the guard


def test_a_secret_named_argument_alone_is_not_a_finding() -> None:
    """The rule the twenty-five false positives bought.

    An authenticated server is *supposed* to have a parameter called api_key. Nothing has
    left the request body here, so there is nothing to report.
    """
    tool = _tool(
        {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": "Your API key."},
                "password": {"type": "string", "description": "Account password."},
            },
        }
    )
    assert not [m for m in _messages(tool) if "header" in m]


def test_a_secret_named_argument_mapped_to_a_header_is_reported() -> None:
    # Now the value the model supplies leaves as an HTTP header, where proxies log what they
    # do not log from a body. Reported for a human, not capped.
    tool = _tool(
        {
            "type": "object",
            "properties": {
                "api_key": {
                    "type": "string",
                    "description": "Your API key.",
                    "x-mcp-header": "X-Api-Key",
                }
            },
        }
    )
    hits = _by_severity(tool, Severity.MEDIUM)
    assert any("secret-named argument 'api_key'" in m and "X-Api-Key" in m for m in hits)


def test_an_ordinary_argument_mapped_to_a_header_is_only_recorded() -> None:
    tool = _tool(
        {
            "type": "object",
            "properties": {
                "region": {"type": "string", "description": "Region.", "x-mcp-header": "X-Region"}
            },
        }
    )
    assert any(
        "sent as the 'X-Region' request header" in m for m in _by_severity(tool, Severity.INFO)
    )
    assert not _by_severity(tool, Severity.MEDIUM)


# ------------------------------------------------- placements the spec rejects


def test_an_annotation_off_the_pure_properties_chain_is_invalid() -> None:
    """Reachability is the spec's rule, and it is why this check does not reuse arg_surface.

    arg_surface merges allOf and resolves $ref so the injection scanner can see every string
    a model might read. Applying that here would declare valid precisely the placement the
    spec calls invalid, because after flattening it looks like an ordinary property.
    """
    tool = _tool(
        {
            "type": "object",
            "allOf": [
                {
                    "properties": {
                        "token": {"type": "string", "x-mcp-header": "X-Token"},
                    }
                }
            ],
        }
    )
    assert any("must drop this tool" in m for m in _by_severity(tool, Severity.MEDIUM))


def test_an_annotation_on_a_non_primitive_property_is_invalid() -> None:
    tool = _tool(
        {
            "type": "object",
            "properties": {
                "filters": {"type": "object", "x-mcp-header": "X-Filters"},
            },
        }
    )
    assert any("must drop this tool" in m for m in _by_severity(tool, Severity.MEDIUM))


def test_a_header_name_that_is_not_a_token_is_invalid() -> None:
    tool = _tool(
        {
            "type": "object",
            "properties": {"q": {"type": "string", "x-mcp-header": "not a token"}},
        }
    )
    assert any("must drop this tool" in m for m in _by_severity(tool, Severity.MEDIUM))


def test_two_properties_claiming_one_header_is_invalid() -> None:
    # Case-insensitively unique, per the spec — so this is a collision, not two mappings.
    tool = _tool(
        {
            "type": "object",
            "properties": {
                "a": {"type": "string", "x-mcp-header": "X-Dup"},
                "b": {"type": "string", "x-mcp-header": "x-dup"},
            },
        }
    )
    assert any("already claimed" in (f.detail or "") for f in scan_tool(tool))


def test_a_nested_pure_properties_chain_is_still_valid() -> None:
    # Nesting through `properties` only is reachable, so this is a real mapping and must be
    # reported as one rather than as an invalid placement.
    tool = _tool(
        {
            "type": "object",
            "properties": {
                "auth": {
                    "type": "object",
                    "properties": {
                        "token": {"type": "string", "x-mcp-header": "X-Token"},
                    },
                }
            },
        }
    )
    hits = _by_severity(tool, Severity.MEDIUM)
    assert any("auth.token" in m for m in hits)
    assert not any("must drop this tool" in m for m in hits)


# ------------------------------------------------------------ off-document $ref


def test_a_ref_to_a_network_uri_is_reported() -> None:
    tool = _tool(
        {
            "type": "object",
            "properties": {"row": {"$ref": "https://attacker.example/schema.json"}},
        }
    )
    assert any("outside the document" in m for m in _by_severity(tool, Severity.MEDIUM))


def test_a_local_ref_is_not_reported() -> None:
    # The ordinary shape every pydantic-generated schema uses.
    tool = _tool(
        {
            "type": "object",
            "properties": {"row": {"$ref": "#/$defs/Row"}},
            "$defs": {"Row": {"type": "object", "properties": {"n": {"type": "string"}}}},
        }
    )
    assert not [m for m in _messages(tool) if "outside the document" in m]


def test_an_off_document_ref_in_the_output_schema_is_reported_too() -> None:
    # The output schema is serialized into the model's context exactly like the input one,
    # and was a blind spot once already.
    tool = _tool(
        {"type": "object", "properties": {}},
        output={"type": "object", "properties": {"row": {"$ref": "http://169.254.169.254/x"}}},
    )
    assert any("output schema" in m for m in _by_severity(tool, Severity.MEDIUM))
