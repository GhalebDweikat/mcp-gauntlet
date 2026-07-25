import pytest

from mcp_gauntlet import config
from mcp_gauntlet.config import ServerSpec, TransportKind, parse_env_args, parse_header_args


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


# --- Batch B: --env / --header credential plumbing ---------------------------------


def test_parse_env_args_pulls_from_environment() -> None:
    environ = {"GITHUB_TOKEN": "ghp_secretvalue"}
    assert parse_env_args(["GITHUB_TOKEN"], environ) == {"GITHUB_TOKEN": "ghp_secretvalue"}


def test_parse_env_args_inline_value() -> None:
    # NAME=VALUE sets it explicitly; an empty value (NAME=) is allowed.
    assert parse_env_args(["A=1", "B="], {}) == {"A": "1", "B": ""}


def test_parse_env_args_unset_bare_name_raises() -> None:
    # Silently dropping an unset var would send an unauthenticated call that looks authorized.
    with pytest.raises(ValueError, match="not set"):
        parse_env_args(["MISSING_TOKEN"], {})


def test_parse_env_args_empty_name_raises_without_echoing_the_value() -> None:
    # The error can reach a CI log, so it must not contain the secret VALUE from NAME=VALUE.
    with pytest.raises(ValueError, match="empty variable name") as exc:
        parse_env_args(["=supersecretvalue"], {})
    assert "supersecretvalue" not in str(exc.value)


def test_parse_header_args_malformed_does_not_echo_the_entry() -> None:
    with pytest.raises(ValueError, match="malformed") as exc:
        parse_header_args(["Authorization Bearer sk-secrettoken"])
    assert "sk-secrettoken" not in str(exc.value)


def test_parse_header_args() -> None:
    headers = parse_header_args(["Authorization: Bearer xyz", "X-Api-Key:  k123 "])
    assert headers == {"Authorization": "Bearer xyz", "X-Api-Key": "k123"}


def test_parse_header_args_rejects_malformed() -> None:
    with pytest.raises(ValueError, match="expected 'Name: Value'"):
        parse_header_args(["no-colon-here"])


def test_secret_values_collects_credentials_over_a_length_floor() -> None:
    spec = ServerSpec.parse("python -m srv")
    spec.env = {"TOKEN": "ghp_longsecret", "SHORT": "ab"}  # "ab" is below the length floor
    spec.headers = {"Authorization": "Bearer abcdef"}
    assert spec.secret_values() == frozenset({"ghp_longsecret", "Bearer abcdef"})


def test_credentials_never_appear_in_label_or_raw() -> None:
    spec = ServerSpec.parse("python -m srv")
    spec.env = {"TOKEN": "ghp_secret"}
    spec.headers = {"Authorization": "Bearer tok"}
    assert "ghp_secret" not in spec.label()
    assert "ghp_secret" not in spec.raw
    assert "Bearer tok" not in spec.label()
