import pytest

from mcp_gauntlet.config import ServerSpec, TransportKind


def test_parse_http_url() -> None:
    spec = ServerSpec.parse("https://example.com/mcp")
    assert spec.kind is TransportKind.HTTP
    assert spec.url == "https://example.com/mcp"
    assert spec.label() == "https://example.com/mcp"


def test_parse_stdio_command() -> None:
    spec = ServerSpec.parse("npx -y @modelcontextprotocol/server-everything")
    assert spec.kind is TransportKind.STDIO
    assert spec.command == "npx"
    assert spec.args == ["-y", "@modelcontextprotocol/server-everything"]


def test_parse_strips_whitespace() -> None:
    spec = ServerSpec.parse("  https://example.com/mcp  ")
    assert spec.url == "https://example.com/mcp"


def test_parse_empty_raises() -> None:
    with pytest.raises(ValueError):
        ServerSpec.parse("   ")
