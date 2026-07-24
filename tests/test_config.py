import pytest

from mcp_gauntlet import config
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


def test_parse_windows_backslash_path(monkeypatch: pytest.MonkeyPatch) -> None:
    # POSIX shlex eats backslashes (C:\Users\me -> C:Usersme); non-POSIX preserves them.
    monkeypatch.setattr(config.os, "name", "nt")
    spec = ServerSpec.parse(r"python C:\Users\me\srv.py")
    assert spec.command == "python"
    assert spec.args == [r"C:\Users\me\srv.py"]


def test_parse_windows_quoted_path_with_spaces(monkeypatch: pytest.MonkeyPatch) -> None:
    # Non-POSIX shlex keeps the quotes on a spaced path; we strip the matched pair.
    monkeypatch.setattr(config.os, "name", "nt")
    spec = ServerSpec.parse(r'node "C:\Program Files\srv.js" --flag')
    assert spec.command == "node"
    assert spec.args == [r"C:\Program Files\srv.js", "--flag"]


def test_parse_posix_unaffected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.os, "name", "posix")
    spec = ServerSpec.parse("npx -y @scope/pkg /tmp/data")
    assert spec.command == "npx"
    assert spec.args == ["-y", "@scope/pkg", "/tmp/data"]
