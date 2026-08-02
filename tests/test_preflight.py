"""The credential pre-flight decides whether a server gets scored at all.

That makes its false positives worse than its false negatives: refusing to score a working
server is a louder mistake than scoring one we should have skipped. The marker set is
therefore narrow on purpose, and these tests pin both directions.
"""

from types import SimpleNamespace
from typing import Any, cast

from mcp import ClientSession

from mcp_gauntlet.models import ToolInfo
from mcp_gauntlet.preflight import (
    _probe_candidates,
    looks_like_missing_credentials,
    probe_credentials,
)

_FREE = ToolInfo(name="list_things", description="list things", input_schema={"type": "object"})


class _Session:
    """Answers every call_tool with one scripted result."""

    def __init__(self, *, is_error: bool, text: str, raises: Exception | None = None) -> None:
        self._is_error, self._text, self._raises = is_error, text, raises
        self.calls: list[str] = []

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        self.calls.append(name)
        if self._raises:
            raise self._raises
        return SimpleNamespace(
            isError=self._is_error,
            content=[SimpleNamespace(type="text", text=self._text)],
            structuredContent=None,
        )


def test_recognizes_a_server_that_wants_an_account() -> None:
    for text in (
        "Error: missing API key. Set OPENWEATHER_API_KEY environment variable.",
        "401 Unauthorized",
        "Authentication required.",
        "Invalid token supplied.",
        "Sign up at example.com to use this tool",
        "subscription required",
        "credentials not found",
    ):
        assert looks_like_missing_credentials(text), text


def test_does_not_mistake_a_correct_refusal_for_a_missing_credential() -> None:
    """The failure mode that would make this feature harmful.

    A sandboxed filesystem server says exactly these things when asked for a path outside
    its root — that is it working properly. A read-only database says them about a write.
    Marking those servers unevaluable would repeat, inverted, the very unfairness the
    pre-flight exists to prevent.
    """
    for text in (
        "Access denied - path outside allowed directories",
        "Error: Permission denied",
        "403 Forbidden",
        "Operation not permitted: the database is read-only",
        "ENOENT: no such file or directory",
        "Rate limit exceeded, retry in 30s",
    ):
        assert not looks_like_missing_credentials(text), text


async def test_a_server_that_answers_is_scored_normally() -> None:
    session = _Session(is_error=False, text="three things")
    assert await probe_credentials(cast(ClientSession, session), [_FREE]) is None


async def test_a_server_that_demands_a_key_is_not_scored() -> None:
    session = _Session(is_error=True, text="Error: missing API key for this service")
    reason = await probe_credentials(cast(ClientSession, session), [_FREE])
    assert reason is not None
    assert "needs credentials" in reason


async def test_an_ordinary_error_is_not_a_credential_problem() -> None:
    # A tool erroring for its own reasons is a real signal about the server, and Tool
    # Reliability is where it belongs — not a reason to stop evaluating.
    session = _Session(is_error=True, text="the requested record does not exist")
    assert await probe_credentials(cast(ClientSession, session), [_FREE]) is None


async def test_one_success_clears_the_server_even_if_another_tool_errors() -> None:
    class _Mixed(_Session):
        async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
            self.calls.append(name)
            error = name == "needs_auth"
            text = "401 Unauthorized" if error else "ok"
            return SimpleNamespace(
                isError=error,
                content=[SimpleNamespace(type="text", text=text)],
                structuredContent=None,
            )

    tools = [
        ToolInfo(name="needs_auth", input_schema={"type": "object"}),
        ToolInfo(name="works", input_schema={"type": "object"}),
    ]
    session = _Mixed(is_error=False, text="")
    assert await probe_credentials(cast(ClientSession, session), tools) is None


async def test_a_transport_failure_is_not_read_as_missing_credentials() -> None:
    session = _Session(is_error=False, text="", raises=RuntimeError("connection reset by peer"))
    assert await probe_credentials(cast(ClientSession, session), [_FREE]) is None


async def test_no_probeable_tool_means_no_conclusion() -> None:
    # Every tool needs an argument. Inventing one is how task generation ended up asking
    # servers about directories that never existed; the probe declines rather than guess.
    tools = [
        ToolInfo(
            name="fetch",
            input_schema={"type": "object", "properties": {"url": {}}, "required": ["url"]},
        )
    ]
    session = _Session(is_error=True, text="401 Unauthorized")
    assert await probe_credentials(cast(ClientSession, session), tools) is None
    assert session.calls == []  # nothing was called at all


def test_probe_candidates_skip_tools_that_look_mutating() -> None:
    # The probe executes real calls against a real server. A zero-argument `delete_all`
    # is exactly the tool never to poke at, credentials or not.
    tools = [
        ToolInfo(name="list_items", input_schema={"type": "object"}),
        ToolInfo(name="delete_everything", input_schema={"type": "object"}),
    ]
    assert [t.name for t in _probe_candidates(tools)] == ["list_items"]


def test_an_enum_is_never_chosen_by_position() -> None:
    """The harness picked the destructive branch itself, with no attacker anywhere:

        "action": {"enum": ["delete_all_customers", "refund_every_order", "list_customers"]}

    Bland name, bland description, no annotations — and a schema-VALID call that a real
    server executes normally. `["delete","list"]`, `["overwrite","append"]` and
    `["production","staging"]` are orderings someone writes without thinking.

    Any destructive-looking member disqualifies the whole tool rather than just that member:
    "which member is harmless" is a guess from the same word list that missed `shutdown`, and
    guessing wrong executes a destructive branch on a run whose premise was that nothing
    writes. Declining costs one probe candidate.
    """
    from mcp_gauntlet.preflight import minimal_valid_args

    destructive = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["delete_all_customers", "refund_every_order", "list_customers"],
            }
        },
        "required": ["action"],
    }
    assert minimal_valid_args(destructive) is None

    harmless = {
        "type": "object",
        "properties": {"fmt": {"type": "string", "enum": ["json", "csv"]}},
        "required": ["fmt"],
    }
    assert minimal_valid_args(harmless) == {"fmt": "json"}


def test_a_declared_default_is_honoured() -> None:
    """`dry_run: {type: boolean, default: true}` was sent as `false`, because booleans got a
    blanket placeholder — the author's explicit "don't actually do it", read and reversed."""
    from mcp_gauntlet.preflight import minimal_valid_args

    schema = {
        "type": "object",
        "properties": {
            "dry_run": {"type": "boolean", "default": True},
            "confirm": {"type": "boolean", "default": False},
        },
        "required": ["dry_run", "confirm"],
    }
    assert minimal_valid_args(schema) == {"dry_run": True, "confirm": False}
