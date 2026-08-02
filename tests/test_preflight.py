"""The credential pre-flight decides whether a server gets scored at all.

That makes its false positives worse than its false negatives: refusing to score a working
server is a louder mistake than scoring one we should have skipped. These tests pin both
directions.

They also pin the shape of the decision, which is the point of G13. Prose alone decides
nothing now — a machine-readable rejection decides on its own, and auth-shaped wording has to
recur across two tools (or come from a tool we sent nothing to) before it counts. A word list
cannot tell "this server rejected my token" from "this server is telling me about a token",
and both halves of that failure are represented below.
"""

from types import SimpleNamespace
from typing import Any, cast

from mcp import ClientSession

from mcp_gauntlet.models import ToolInfo
from mcp_gauntlet.preflight import (
    _probe_candidates,
    looks_like_missing_credentials,
    machine_auth_code,
    probe_credentials,
    rejected_the_caller,
)

_FREE = ToolInfo(name="list_things", description="list things", input_schema={"type": "object"})


def _needs_arg(name: str) -> ToolInfo:
    """A probeable tool that takes an argument — so a complaint MIGHT be about our input."""
    return ToolInfo(
        name=name,
        description=f"{name} something",
        input_schema={
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"],
        },
    )


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


class _Scripted:
    """Answers each tool differently: a text, an exception, or structured content."""

    def __init__(self, script: dict[str, Any]) -> None:
        self._script = script
        self.calls: list[str] = []

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        self.calls.append(name)
        answer = self._script[name]
        if isinstance(answer, Exception):
            raise answer
        text, structured = answer if isinstance(answer, tuple) else (answer, None)
        return SimpleNamespace(
            isError=text is not None,
            content=[SimpleNamespace(type="text", text=text or "ok")],
            structuredContent=structured,
        )


class _Status(Exception):
    """An httpx-shaped failure: the status is on `.response`, as the real one is."""

    def __init__(self, status: int, headers: dict[str, str] | None = None) -> None:
        super().__init__(f"Server error '{status}'")
        self.response = SimpleNamespace(status_code=status, headers=headers or {})


class _Rpc(Exception):
    """An `McpError`-shaped failure: an `ErrorData` on `.error`."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.error = SimpleNamespace(code=code, message=message, data=data)


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
    assert "authentication error" in reason
    # A neutral observation, not a verdict. The engine knows whether credentials were
    # supplied and this does not, and framing it here produced a finding that contradicted
    # itself: "failed despite the credentials supplied … needs credentials that were not
    # supplied". It also has to say how many tools it actually saw, having previously
    # announced "every tool call was rejected" over a single probe.
    assert "needs credentials" not in reason
    assert "the one probeable tool" in reason


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


# --------------------------------------------------------------- G13: read the channel


async def test_a_401_decides_alone_and_needs_no_english() -> None:
    """The whole point of keying on the channel.

    This server's message is in Japanese, so no vocabulary of any size would have caught it —
    and it is a single tool that takes an argument, the case prose is not trusted for. The
    status decides, exactly as it should.
    """
    session = _Scripted({"search": _Status(401)})
    reason = await probe_credentials(cast(ClientSession, session), [_needs_arg("search")])
    assert reason is not None
    assert "HTTP 401" in reason
    assert "protocol level" in reason


async def test_a_bare_403_is_still_a_server_enforcing_its_own_boundary() -> None:
    """A sandboxed filesystem server 403s a path outside its root. That is it working."""
    session = _Scripted({"read_file": _Status(403)})
    assert await probe_credentials(cast(ClientSession, session), [_needs_arg("read_file")]) is None


async def test_a_403_that_challenges_you_is_a_credential_problem() -> None:
    """A scope-expired OAuth token is a 403 at most providers — but it comes with a challenge,
    which is what separates it from the sandboxed server above."""
    session = _Scripted(
        {"search": _Status(403, {"www-authenticate": 'Bearer error="insufficient_scope"'})}
    )
    reason = await probe_credentials(cast(ClientSession, session), [_needs_arg("search")])
    assert reason is not None
    assert "insufficient_scope" in reason


async def test_the_jsonrpc_error_channel_is_read_at_all() -> None:
    """Previously invisible: the old check read `str(exc)` and nothing else, so a refusal
    delivered over `error` rather than as an `isError` result said nothing however plainly it
    said it. Three of four wrongly-credentialed servers in one scan came back A 100.0."""
    session = _Scripted({"search": _Rpc(-32603, "内部エラー", {"error": "invalid_auth"})})
    reason = await probe_credentials(cast(ClientSession, session), [_needs_arg("search")])
    assert reason is not None
    assert "invalid_auth" in reason


async def test_a_positive_code_in_the_jsonrpc_code_field_is_an_http_status() -> None:
    """JSON-RPC reserves -32768..-32000 and every other negative code is application-defined,
    so a POSITIVE 401 there is unambiguously a server echoing a status — which several do."""
    session = _Scripted({"search": _Rpc(401, "nope")})
    reason = await probe_credentials(cast(ClientSession, session), [_needs_arg("search")])
    assert reason is not None
    assert "JSON-RPC error 401" in reason


async def test_structured_content_carrying_a_code_decides() -> None:
    session = _Scripted({"search": ("request failed", {"error": {"type": "ExpiredToken"}})})
    reason = await probe_credentials(cast(ClientSession, session), [_needs_arg("search")])
    assert reason is not None
    assert "ExpiredToken" in reason


def test_a_machine_code_must_be_a_whole_value_not_a_sentence() -> None:
    """The distinction the old check could not draw. `invalid_token` as the value of an error
    field is a machine saying your credential is bad; the same words inside a sentence may be
    a linter describing line 4."""
    assert machine_auth_code({"error": "invalid_token"}) == "invalid_token"
    assert machine_auth_code({"detail": {"code": "ExpiredTokenException"}}) is not None
    assert machine_auth_code({"message": "the invalid_token you passed is at line 4"}) is None
    assert machine_auth_code({"error": "not_found"}) is None
    assert machine_auth_code(None) is None


def test_a_status_on_something_that_is_not_an_error_is_not_read() -> None:
    assert rejected_the_caller(RuntimeError("connection reset by peer")) is None
    assert rejected_the_caller(_Status(500)) is None


def test_the_wrapper_anyio_puts_round_everything_is_seen_past() -> None:
    """Every one of these fields arrives inside `unhandled errors in a TaskGroup`."""
    group = BaseExceptionGroup("unhandled errors in a TaskGroup", [_Status(401)])
    assert rejected_the_caller(group) == "HTTP 401"


def test_the_sdks_own_error_type_is_read_not_a_stand_in() -> None:
    """The stand-ins above are hand-shaped, and a hand-shaped mock is exactly how a check
    goes on passing after the SDK renames the field it reads — the failure `adapters.py`
    exists to prevent.

    The eras genuinely differ here: 1.x's `McpError` wraps an `ErrorData` on `.error`, and
    2.0's `MCPError` takes the fields directly. Both spellings are read, and this asserts
    POSITIVELY against whichever class the installed era raises — because if neither
    resolved, `rejected_the_caller` would return None and the whole check would go silently
    blind on that era rather than fail.
    """
    from mcp.types import ErrorData

    from mcp_gauntlet.adapters import adapter

    def _build(code: int, message: str, data: Any = None) -> BaseException:
        error_type = adapter().protocol_error_type()
        if adapter().era == "modern":
            return error_type(code=code, message=message, data=data)  # type: ignore[call-arg]
        return error_type(ErrorData(code=code, message=message, data=data))

    assert (
        rejected_the_caller(_build(-32603, "内部エラー", {"error": "invalid_auth"}))
        == "JSON-RPC error data: invalid_auth"
    )
    assert rejected_the_caller(_build(401, "nope")) == "JSON-RPC error 401"
    assert rejected_the_caller(_build(-32602, "Invalid params")) is None


# ----------------------------------------------------- G13: prose is corroboration only


def test_the_vocabulary_covers_what_services_actually_say() -> None:
    """Every one of these was missed by the shipped phrase list. They are quoted from real
    services rather than invented, because the invented corpus is what made the old check
    look sound: I wrote the examples that the check I had already written would catch."""
    for text in (
        "token expired",  # "expired" was not in the vocabulary in this word order
        "Bad credentials",  # GitHub's own 401 body
        "invalid_auth",  # Slack
        "ExpiredTokenException",  # AWS
        "Not authenticated",
        "This endpoint requires authentication",
        "Authorization header missing",
        "your access token has been revoked",
        "insufficient_scope",
    ):
        assert looks_like_missing_credentials(text), text


def test_prose_that_is_plainly_about_the_input_is_vetoed() -> None:
    """Honest servers whose ordinary errors carry the vocabulary. Each is a real shape:
    a JSON linter, a parser, a test runner quoting a subject, a signature verifier — where
    "authentication" means authentication OF A MESSAGE, a different sense of the word."""
    for text in (
        "invalid token at line 4",
        "unexpected token at position 12",
        "expected 401 Unauthorized, got 200 OK",
        "authentication failed for message digest",
        "parse error: malformed json, invalid token",
    ):
        assert not looks_like_missing_credentials(text), text


async def test_one_tool_complaining_in_words_does_not_condemn_a_server() -> None:
    """A schema validator handed `q="test"` says `Invalid API key format`. It is describing
    what we gave it. With no status, no machine code, and no second tool saying the same
    thing, that is not enough to refuse to score a server — there is no allowlist to rescue
    one this convicts wrongly."""
    session = _Scripted({"validate": "Invalid API key format", "describe": None})
    tools = [_needs_arg("validate"), _needs_arg("describe")]
    assert await probe_credentials(cast(ClientSession, session), tools) is None


async def test_the_same_refusal_from_two_tools_is_a_wall() -> None:
    """A credential wall is uniform; a complaint about content is specific to the content."""
    session = _Scripted({"search": "401 Unauthorized", "lookup": "401 Unauthorized"})
    tools = [_needs_arg("search"), _needs_arg("lookup")]
    reason = await probe_credentials(cast(ClientSession, session), tools)
    assert reason is not None
    assert "every probed tool" in reason


async def test_a_tool_sent_no_arguments_can_condemn_alone() -> None:
    """Nothing of ours went in, so whatever it is complaining about, it is not our input."""
    session = _Scripted({"list_things": "Bad credentials"})
    reason = await probe_credentials(cast(ClientSession, session), [_FREE])
    assert reason is not None


async def test_a_partial_refusal_says_so_rather_than_saying_every() -> None:
    session = _Scripted(
        {"search": "401 Unauthorized", "lookup": "401 Unauthorized", "stat": "no such record"}
    )
    tools = [_needs_arg("search"), _needs_arg("lookup"), _needs_arg("stat")]
    reason = await probe_credentials(cast(ClientSession, session), tools)
    assert reason is not None
    assert "2 of 3 probed tools" in reason


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
