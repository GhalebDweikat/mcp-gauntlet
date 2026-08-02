import sys
from types import SimpleNamespace
from typing import Any, cast

import anyio
import pytest
from mcp import ClientSession
from mcp.types import ErrorData

from mcp_gauntlet.adapters import adapter
from mcp_gauntlet.client import open_session
from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.models import ToolInfo
from mcp_gauntlet.report import Severity
from mcp_gauntlet.robustness import declares_arguments, malformed_args, run_robustness_probes

# 2.0 renamed `McpError` to `MCPError` and kept the module name, so importing the old name
# is an ImportError rather than a missing module. Resolved through the adapter, which is the
# one place that knows which era is installed — and is what robustness.py itself uses.
McpError = adapter().protocol_error_type()

# --- malformed_args (pure) --------------------------------------------------


def test_wrong_type_on_required_field() -> None:
    schema = {"type": "object", "properties": {"a": {"type": "integer"}}, "required": ["a"]}
    payload = malformed_args(schema)
    assert payload is not None
    assert not isinstance(payload["a"], int)


def test_missing_required_when_untyped() -> None:
    assert malformed_args({"type": "object", "properties": {"a": {}}, "required": ["a"]}) == {}


def test_wrong_type_on_first_property() -> None:
    payload = malformed_args({"type": "object", "properties": {"s": {"type": "string"}}})
    assert payload is not None
    assert not isinstance(payload["s"], str)


def test_none_when_nothing_to_violate() -> None:
    assert malformed_args({}) is None
    assert malformed_args({"type": "object", "properties": {}}) is None
    assert malformed_args({"type": "string"}) is None


def test_wrong_type_on_nullable_type_array() -> None:
    # zod-to-json-schema and many servers emit ["string", "null"] for a nullable field.
    # A list type is unhashable, so the old `prop_type in _WRONG` membership test raised
    # TypeError and crashed the whole probe run; we must pick the violatable branch.
    schema = {
        "type": "object",
        "properties": {"a": {"type": ["string", "null"]}},
        "required": ["a"],
    }
    payload = malformed_args(schema)
    assert payload is not None
    assert not isinstance(payload["a"], str)


def test_nullable_type_array_with_only_null_is_unviolatable() -> None:
    # ["null"] has no concrete type to wrong-type; skip it rather than crash.
    assert malformed_args({"type": "object", "properties": {"a": {"type": ["null"]}}}) is None


def test_required_with_non_string_entry_does_not_crash() -> None:
    # `required` is server data and may hold non-strings (unhashable dict/list) that would
    # crash props.get(name). Skip them and fall back to omitting required fields.
    schema = {
        "type": "object",
        "required": [{"x": 1}, ["a"]],
        "properties": {"a": {"type": "string"}},
    }
    assert malformed_args(schema) == {}  # no crash; omit-required violation


def test_required_mixes_junk_and_a_valid_string_name() -> None:
    schema = {
        "type": "object",
        "required": [{"bad": 1}, "a"],
        "properties": {"a": {"type": "integer"}},
    }
    payload = malformed_args(schema)
    assert payload is not None
    assert "a" in payload and not isinstance(payload["a"], int)


# --- run_robustness_probes classification (mocked session) ------------------


class _Session:
    def __init__(self, handler: Any) -> None:
        self._handler = handler

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        result = self._handler(name, arguments)
        if isinstance(result, Exception):
            raise result
        return result


def _session(handler: Any) -> ClientSession:
    return cast(ClientSession, _Session(handler))


_TOOL = ToolInfo(
    name="t",
    input_schema={"type": "object", "properties": {"a": {"type": "integer"}}, "required": ["a"]},
)


_TOOL2 = ToolInfo(
    name="u",
    input_schema={"type": "object", "properties": {"b": {"type": "string"}}, "required": ["b"]},
)


async def test_accepted_bad_input_scores_below_100() -> None:
    dim = await run_robustness_probes(
        _session(lambda n, a: SimpleNamespace(isError=False)), [_TOOL]
    )
    assert dim is not None
    assert dim.score < 100
    assert any("accepted" in f.message for f in dim.findings)


async def test_accepts_everything_scores_near_zero() -> None:
    # A server that validates nothing must score ~0 (a robustness F), not 88.
    dim = await run_robustness_probes(
        _session(lambda n, a: SimpleNamespace(isError=False)), [_TOOL, _TOOL2]
    )
    assert dim is not None
    assert dim.score == 0.0


async def test_robustness_score_is_rejection_fraction() -> None:
    # One tool rejects, one accepts -> the dimension is the % that reject.
    handler = lambda n, a: SimpleNamespace(isError=(n == "t"))  # noqa: E731 - terse test stub
    dim = await run_robustness_probes(_session(handler), [_TOOL, _TOOL2])
    assert dim is not None
    assert dim.score == 50.0


async def test_unexpected_error_scores_zero_not_inflated() -> None:
    # An ungraceful (non-McpError) failure scores 0, so an early error+break can only be
    # conservative -- it must not inflate the dimension to 88 like the old MEDIUM did.
    dim = await run_robustness_probes(_session(lambda n, a: RuntimeError("boom")), [_TOOL, _TOOL2])
    assert dim is not None
    assert dim.score == 0.0


async def test_is_error_result_counts_as_rejection() -> None:
    dim = await run_robustness_probes(_session(lambda n, a: SimpleNamespace(isError=True)), [_TOOL])
    assert dim is not None
    assert dim.score == 100.0


def _protocol_error(code: int, message: str) -> BaseException:
    """One JSON-RPC error, built the way the installed SDK builds them.

    1.x takes a single `ErrorData`; 2.0 takes the fields directly. Constructed rather than
    faked because Robustness keys on the exception TYPE — a stand-in would assert nothing
    about the class it actually catches.
    """
    error_type = adapter().protocol_error_type()
    if adapter().era == "modern":
        return error_type(code=code, message=message)  # type: ignore[call-arg]
    return error_type(ErrorData(code=code, message=message))


async def test_mcp_error_counts_as_rejection() -> None:
    err = _protocol_error(-32602, "invalid params")
    dim = await run_robustness_probes(_session(lambda n, a: err), [_TOOL])
    assert dim is not None
    assert dim.score == 100.0


async def test_a_server_that_answers_NOTHING_is_not_credited_for_refusing() -> None:
    """The general case the auth check was only a special case of.

    This dimension credits 100 for "the server rejected malformed input", and that claim
    needs the server to be able to answer ANYTHING. Three tools all raising
    `connection refused` scored Robustness 100.0 and graded A 99.3 — a report byte-identical
    to the healthy original. A tester put it exactly right: a regression suite that cannot
    tell a dead server from a live one should not have "regression" on the tin.

    Keyed on the pre-flight rather than on the error TEXT, which is what makes it work in any
    language: the same wall answering in Japanese scored 100 because the auth vocabulary is
    English.
    """
    dead = _session(lambda n, a: SimpleNamespace(isError=True))
    dim = await run_robustness_probes(dead, [_TOOL, _TOOL2], server_answered=False)
    assert dim is not None
    assert dim.score == 0.0
    assert any(f.severity is Severity.HIGH for f in dim.findings)
    # It must NOT name a cause it cannot see. Reporting a broken database as a credential
    # problem is the same wrong verdict, pointed at a different server.
    message = dim.findings[0].message
    assert "well-formed" in message
    assert "credential" not in message and "authentication" not in message


async def test_a_server_that_DOES_answer_is_still_credited_for_refusing() -> None:
    # The other direction, and the one that matters for every honest server: a live server
    # rejecting malformed input is exactly what this dimension is for.
    alive = _session(lambda n, a: SimpleNamespace(isError=True))
    dim = await run_robustness_probes(alive, [_TOOL, _TOOL2], server_answered=True)
    assert dim is not None
    assert dim.score == 100.0

    # …and with no pre-flight evidence at all (`--no-probe`, or nothing safe to call) the
    # answer is unknown, not False. Acting as if it were False would fail honest servers on
    # the strength of a measurement never taken.
    unknown = await run_robustness_probes(alive, [_TOOL, _TOOL2], server_answered=None)
    assert unknown is not None
    assert unknown.score == 100.0


async def test_the_auth_wall_finding_says_only_true_things() -> None:
    """A tester found three false statements in one sentence.

        HIGH  all 3 probed tool(s) were rejected for authentication — the credentials
              supplied are wrong, expired, or lack the required scope, so nothing about
              this server was actually measured

    No credential had been supplied. Four tools were probed, not three — the denominator was
    derived from the rejected list, so the one that disproved the finding dropped out of its
    own count. And `ping_status` had returned `upstream reachable`.
    """
    wall = _session(
        lambda n, a: SimpleNamespace(
            isError=True,
            content=[SimpleNamespace(type="text", text="401 Unauthorized: Bad credentials")],
            structuredContent=None,
        )
    )

    dim = await run_robustness_probes(wall, [_TOOL, _TOOL2], credentials_supplied=False)
    assert dim is not None
    message = dim.findings[0].message
    assert "credentials supplied are wrong" not in message
    assert "--env" in message  # says what to DO instead

    supplied = await run_robustness_probes(wall, [_TOOL, _TOOL2], credentials_supplied=True)
    assert supplied is not None
    assert "credentials supplied are wrong" in supplied.findings[0].message


async def test_a_protocol_error_that_rejects_the_CALLER_is_not_credited() -> None:
    """Same channel, opposite meaning — and it scored 100 for two releases.

    "Rejected the malformed input" is what earns 100 here. A wrongly-credentialed server
    refuses everything identically before it ever looks at the payload, so crediting that is
    how a bad token produced a report byte-identical to a good one. The `isError` branch below
    already guarded against it; this branch read neither the error's code nor its data, so the
    guard depended on which channel the refusal happened to arrive on.
    """
    error_type = adapter().protocol_error_type()
    if adapter().era == "modern":
        err: BaseException = error_type(  # type: ignore[call-arg]
            code=-32603, message="内部エラー", data={"error": "invalid_auth"}
        )
    else:
        err = error_type(
            ErrorData(code=-32603, message="内部エラー", data={"error": "invalid_auth"})
        )

    dim = await run_robustness_probes(_session(lambda n, a: err), [_TOOL, _TOOL2])
    assert dim is not None
    assert dim.score == 0.0
    assert any(f.severity is Severity.HIGH for f in dim.findings)
    assert any("authentication" in f.message for f in dim.findings)


async def test_timeout_is_high_severity() -> None:
    dim = await run_robustness_probes(_session(lambda n, a: TimeoutError()), [_TOOL])
    assert dim is not None
    assert dim.score < 100
    assert any(f.severity is Severity.HIGH for f in dim.findings)


async def test_zero_arg_tools_still_report_the_dimension() -> None:
    # A zero-argument tool genuinely has nothing to violate, so it isn't penalized — but
    # the dimension must still be REPORTED. Omitting it shrinks the weighted-mean
    # denominator and raises the overall, which would make being unprobeable a winning move.
    unprobeable = ToolInfo(name="np", input_schema={"type": "object", "properties": {}})
    dim = await run_robustness_probes(
        _session(lambda n, a: SimpleNamespace(isError=True)), [unprobeable]
    )
    assert dim is not None
    assert dim.score == 100.0
    assert any("nothing to probe" in f.message for f in dim.findings)


async def test_none_only_when_there_are_no_tools() -> None:
    assert await run_robustness_probes(_session(lambda n, a: None), []) is None


async def test_missing_schema_counts_as_a_robustness_failure() -> None:
    # The gaming vector: publishing NO schema used to make a tool unprobeable, dropping the
    # whole dimension and RAISING the overall. A server that declares no argument contract
    # cannot reject anything, so it scores like one that accepts every violation.
    no_schema = ToolInfo(name="loose", input_schema={})
    dim = await run_robustness_probes(
        _session(lambda n, a: SimpleNamespace(isError=True)), [no_schema]
    )
    assert dim is not None
    assert dim.score == 0.0
    assert any("no usable input schema" in f.message for f in dim.findings)


def test_enum_and_const_are_violatable() -> None:
    # pydantic/zod emit enums with no `type`, so a type-only prober skipped them entirely.
    payload = malformed_args(
        {"type": "object", "properties": {"q": {"enum": ["a", "b"]}}, "required": ["q"]}
    )
    assert payload is not None and payload["q"] not in ("a", "b")
    payload = malformed_args({"type": "object", "properties": {"q": {"const": "fixed"}}})
    assert payload is not None and payload["q"] != "fixed"


def test_ref_is_resolved_through_defs() -> None:
    schema = {
        "type": "object",
        "properties": {"who": {"$ref": "#/$defs/Person"}},
        "$defs": {"Person": {"type": "object", "properties": {"n": {"type": "string"}}}},
        "required": ["who"],
    }
    payload = malformed_args(schema)
    assert payload is not None and not isinstance(payload["who"], dict)


def test_cyclic_ref_terminates() -> None:
    schema = {
        "type": "object",
        "properties": {"node": {"$ref": "#/$defs/Node"}},
        "$defs": {"Node": {"$ref": "#/$defs/Node"}},
    }
    assert malformed_args(schema) is None  # bounded recursion, no RecursionError


def test_any_of_violates_every_branch() -> None:
    schema = {
        "type": "object",
        "properties": {"v": {"anyOf": [{"type": "string"}, {"type": "number"}]}},
        "required": ["v"],
    }
    payload = malformed_args(schema)
    assert payload is not None
    assert not isinstance(payload["v"], str | int | float)  # violates BOTH branches


def test_any_of_accepting_every_type_is_unviolatable() -> None:
    branches = [{"type": t} for t in ("string", "number", "boolean", "array", "object")]
    schema = {"type": "object", "properties": {"v": {"anyOf": branches}}}
    assert malformed_args(schema) is None  # honestly nothing invalid to send


def test_all_of_composition_is_probed() -> None:
    # An ordinary composed schema declares a required, typed argument one level down.
    # Reading only the top level left it unprobed AND treated as zero-argument, which
    # handed it a free perfect score.
    payload = malformed_args(
        {
            "type": "object",
            "allOf": [{"properties": {"q": {"type": "string"}}, "required": ["q"]}],
        }
    )
    assert payload is not None and not isinstance(payload["q"], str)


def test_all_of_through_a_ref_is_probed() -> None:
    payload = malformed_args(
        {
            "type": "object",
            "allOf": [{"$ref": "#/$defs/A"}],
            "$defs": {"A": {"properties": {"q": {"type": "string"}}, "required": ["q"]}},
        }
    )
    assert payload is not None and not isinstance(payload["q"], str)


def test_arbitrary_key_contracts_are_probed() -> None:
    # A key not named in `properties` is validated against patternProperties /
    # additionalProperties, so violating one of those is a genuine probe.
    payload = malformed_args({"type": "object", "patternProperties": {"^.*$": {"type": "string"}}})
    assert payload is not None and not isinstance(next(iter(payload.values())), str)

    payload = malformed_args({"type": "object", "additionalProperties": {"type": "string"}})
    assert payload is not None and not isinstance(next(iter(payload.values())), str)


def test_declares_arguments_sees_through_composition() -> None:
    assert declares_arguments({"type": "object", "allOf": [{"properties": {"q": {}}}]})
    assert declares_arguments({"type": "object", "patternProperties": {"^x$": {}}})
    assert declares_arguments({"type": "object", "additionalProperties": {"type": "string"}})
    assert declares_arguments({"type": "object", "additionalProperties": True})
    # `additionalProperties: false` IS the canonical strict zero-argument tool.
    assert not declares_arguments(
        {"type": "object", "properties": {}, "additionalProperties": False}
    )
    assert not declares_arguments({"type": "object", "properties": {}})


async def test_composed_schemas_cannot_dodge_the_dimension() -> None:
    # Every shape that declares arguments somewhere other than the top level used to reach
    # the zero-argument exemption and score 100. None may now beat an honest schema.
    honest = ToolInfo(
        name="honest",
        input_schema={
            "type": "object",
            "properties": {"a": {"type": "integer"}},
            "required": ["a"],
        },
    )
    accepts_everything = _session(lambda n, a: SimpleNamespace(isError=False))
    honest_dim = await run_robustness_probes(accepts_everything, [honest])
    assert honest_dim is not None
    for dodge in (
        {"type": "object", "allOf": [{"properties": {"q": {"type": "string"}}, "required": ["q"]}]},
        {
            "type": "object",
            "allOf": [{"$ref": "#/$defs/A"}],
            "$defs": {"A": {"properties": {"q": {"type": "string"}}, "required": ["q"]}},
        },
        {"type": "object", "patternProperties": {"^.*$": {"type": "string"}}},
        {"type": "object", "additionalProperties": {"type": "string"}},
        {"type": "object", "additionalProperties": True},
    ):
        dim = await run_robustness_probes(
            accepts_everything, [ToolInfo(name="d", input_schema=dodge)]
        )
        assert dim is not None, dodge
        assert dim.score <= honest_dim.score, dodge


async def test_open_any_of_branch_is_not_a_false_accusation() -> None:
    # anyOf containing `{}` accepts everything, so any value we send is VALID. Reporting
    # the server for "accepting schema-violating input" would be a false claim about its
    # behaviour — treat it as an unenforceable declaration instead.
    schema = {"type": "object", "properties": {"q": {"anyOf": [{"type": "string"}, {}]}}}
    assert malformed_args(schema) is None
    dim = await run_robustness_probes(
        _session(lambda n, a: SimpleNamespace(isError=False)),
        [ToolInfo(name="t", input_schema=schema)],
    )
    assert dim is not None
    assert not any("accepted schema-violating" in f.message for f in dim.findings)
    assert any("too loose" in f.message for f in dim.findings)


async def test_loose_optional_args_are_scored_not_exempted() -> None:
    # The dodge that scoring "nothing probeable" as 100 would have REWARDED: declare
    # optional arguments too loosely to violate and skip the dimension entirely. A tool
    # that takes arguments is never exempt — only a genuinely zero-argument one is.
    loose = ToolInfo(name="loose", input_schema={"type": "object", "properties": {"q": {}}})
    dim = await run_robustness_probes(_session(lambda n, a: SimpleNamespace(isError=True)), [loose])
    assert dim is not None
    assert dim.score == 0.0
    assert any("too loose" in f.message for f in dim.findings)


async def test_loose_args_cannot_outscore_an_honest_schema() -> None:
    # The published-board fairness statement: no way of declaring arguments may beat a
    # server that declares them properly, even one that then fails to enforce them.
    honest = ToolInfo(
        name="honest",
        input_schema={
            "type": "object",
            "properties": {"a": {"type": "integer"}},
            "required": ["a"],
        },
    )
    accepts_everything = _session(lambda n, a: SimpleNamespace(isError=False))
    honest_dim = await run_robustness_probes(accepts_everything, [honest])
    assert honest_dim is not None
    for dodge in (
        {"type": "object", "properties": {"q": {}}},  # untyped optional
        {"type": "object", "properties": {"q": {"description": "no constraints"}}},
        {},  # no schema at all
        {"type": "string"},  # not an object schema
    ):
        dim = await run_robustness_probes(
            accepts_everything, [ToolInfo(name="d", input_schema=dodge)]
        )
        assert dim is not None, dodge
        assert dim.score <= honest_dim.score, dodge


async def test_one_honest_tool_cannot_launder_nine_dodges() -> None:
    # Mixed servers must not hide their unprobeable tools behind one that passes.
    honest = ToolInfo(
        name="honest",
        input_schema={
            "type": "object",
            "properties": {"a": {"type": "integer"}},
            "required": ["a"],
        },
    )
    dodges = [
        ToolInfo(name=f"d{i}", input_schema={"type": "object", "properties": {"q": {}}})
        for i in range(9)
    ]
    dim = await run_robustness_probes(
        _session(lambda n, a: SimpleNamespace(isError=True)), [honest, *dodges]
    )
    assert dim is not None
    assert dim.score == 10.0  # 1 of 10 tools actually enforced anything


async def test_no_schema_cannot_outscore_a_declared_schema() -> None:
    # End-to-end statement of R15: dodging the dimension must not beat publishing a real
    # schema, even one the server then fails to enforce.
    honest = ToolInfo(
        name="honest",
        input_schema={
            "type": "object",
            "properties": {"a": {"type": "integer"}},
            "required": ["a"],
        },
    )
    gamed = ToolInfo(name="gamed", input_schema={})
    accepts_everything = _session(lambda n, a: SimpleNamespace(isError=False))
    honest_dim = await run_robustness_probes(accepts_everything, [honest])
    gamed_dim = await run_robustness_probes(accepts_everything, [gamed])
    assert honest_dim is not None and gamed_dim is not None
    assert gamed_dim.score <= honest_dim.score


# --- integration: a real, well-behaved server rejects malformed input -------


async def test_good_fixture_rejects_malformed() -> None:
    spec = ServerSpec.parse(f"{sys.executable} -m mcp_gauntlet.fixtures.good_server")
    async with open_session(spec) as (session, _init, _interactions):
        listed = await session.list_tools()
        # Through the adapter, not by hand: building a ToolInfo here meant naming an SDK
        # field, and the name it chose was the 1.x one — so this test read `inputSchema` off
        # a 2.0 Tool and died. The guard test greps for `getattr(x, "camelCase"` and cannot
        # see a plain attribute access like this one.
        tools = [adapter().tool_info(t) for t in listed.tools]
        dim = await run_robustness_probes(session, tools)
    assert dim is not None
    assert dim.score == 100.0


class _SlowSession:
    """A server that answers every probe correctly, just slowly."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.calls = 0

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        self.calls += 1
        await anyio.sleep(self.delay)
        return SimpleNamespace(isError=True)


async def test_probe_budget_stops_a_slow_server() -> None:
    # Each call finishes well inside `timeout_s`, so no per-call timeout ever fires — yet
    # enough of them together used to outrun the caller's per-server budget, and when THAT
    # fired the whole report was lost. The aggregate bound is what keeps the report.
    tools = [
        ToolInfo(
            name=f"t{i}",
            input_schema={
                "type": "object",
                "properties": {"a": {"type": "integer"}},
                "required": ["a"],
            },
        )
        for i in range(20)
    ]
    session = _SlowSession(delay=0.02)
    dim = await run_robustness_probes(
        cast(ClientSession, session), tools, timeout_s=5.0, budget_s=0.05
    )
    assert dim is not None
    assert session.calls < len(tools)  # stopped early rather than probing all 20
    assert any("stopped probing after" in f.message for f in dim.findings)
    assert any("unprobed" in f.message for f in dim.findings)
    # The unprobed tools must COUNT. Latency and tool order are both server-controlled, so
    # scoring only what got probed would let one slow-but-correct tool at the front cut the
    # probe short before the broken ones were reached — turning a bad score into a perfect
    # one. Stopping early must only ever lower the score.
    assert dim.score < 100.0


async def test_budget_stop_cannot_inflate_the_score() -> None:
    # The concrete inversion: tool 0 answers correctly but slowly; every other tool
    # silently accepts malformed input. Truncating after tool 0 must not report 100.
    good = ToolInfo(name="slow_good", input_schema=_TOOL.input_schema)
    bad = [ToolInfo(name=f"bad{i}", input_schema=_TOOL.input_schema) for i in range(19)]

    class _FirstSlowThenAccepting:
        def __init__(self) -> None:
            self.calls = 0

        async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
            self.calls += 1
            if name == "slow_good":
                # Comfortably longer than the budget, not marginally. The original 0.06s
                # against a 0.05s budget was a 10ms margin, and Windows' timer granularity
                # is ~15ms — so under full-suite load the elapsed reading landed on the wrong
                # side and a second tool got probed. Flaky in the suite, passing in isolation,
                # which is the worst combination.
                await anyio.sleep(0.5)
                return SimpleNamespace(isError=True)  # correct rejection
            return SimpleNamespace(isError=False)  # silently accepts

    session = _FirstSlowThenAccepting()
    dim = await run_robustness_probes(
        cast(ClientSession, session), [good, *bad], timeout_s=5.0, budget_s=0.05
    )
    assert dim is not None
    assert session.calls == 1  # budget cut it short right after the slow good tool
    assert dim.score <= 5.0  # 1 correct out of 20 — NOT 100


async def test_probe_budget_does_not_fire_on_a_fast_server() -> None:
    tools = [ToolInfo(name=f"t{i}", input_schema=_TOOL.input_schema) for i in range(5)]
    session = _SlowSession(delay=0.0)
    dim = await run_robustness_probes(cast(ClientSession, session), tools, budget_s=30.0)
    assert dim is not None
    assert session.calls == len(tools)
    assert not any("stopped probing" in f.message for f in dim.findings)


async def test_probe_budget_always_probes_at_least_one_tool() -> None:
    # A zero budget must not produce an empty, meaningless dimension.
    tools = [ToolInfo(name=f"t{i}", input_schema=_TOOL.input_schema) for i in range(3)]
    session = _SlowSession(delay=0.01)
    dim = await run_robustness_probes(cast(ClientSession, session), tools, budget_s=0.0)
    assert dim is not None
    assert session.calls == 1


# ---------------------------------------------- stopping early must never raise the score


def _probeable(count: int) -> list[ToolInfo]:
    schema = {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]}
    return [ToolInfo(name=f"t{i}", description="d", input_schema=schema) for i in range(count)]


class _StopsAtSecondTool:
    """One correct rejection, then a stall, then eight tools that would have scored 0."""

    def __init__(self, failure: BaseException) -> None:
        self.n = 0
        self._failure = failure

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        index, self.n = self.n, self.n + 1
        if index == 0:
            return SimpleNamespace(isError=True)  # correct rejection -> 100
        if index == 1:
            raise self._failure
        return SimpleNamespace(isError=False)  # silently ACCEPTS malformed input -> 0


@pytest.mark.parametrize(
    "failure", [TimeoutError(), RuntimeError("transport blew up")], ids=["timeout", "error"]
)
async def test_an_early_exit_scores_the_tools_it_never_reached(failure: BaseException) -> None:
    """The budget path always did this; the timeout and error paths did not.

    They appended a single 0.0 and broke, dropping every later tool from the mean — and the
    dropped tools are exactly the ones that would have scored 0, so the score went UP.
    Measured before the fix: 50.0 where the honest score is 10.0.

    It is a controllable exchange, not a rounding error: the server chooses both the order
    its tools are listed in and how slow each one is, so "stall on the second tool" was a
    way to buy a 5x score improvement over being probed honestly.
    """
    dim = await run_robustness_probes(
        cast(ClientSession, _StopsAtSecondTool(failure)), _probeable(10)
    )
    assert dim is not None
    assert dim.score == 10.0, f"early exit inflated the score to {dim.score}"
    # And the reader is told how much went unmeasured, not just that it stopped.
    assert any("went unprobed" in f.message for f in dim.findings)


async def test_an_early_exit_on_the_last_tool_adds_nothing() -> None:
    # The off-by-one guard: with nothing after it, the count is 0 and the score is just the
    # tools actually probed.
    dim = await run_robustness_probes(
        cast(ClientSession, _StopsAtSecondTool(TimeoutError())), _probeable(2)
    )
    assert dim is not None
    assert dim.score == 50.0  # [100, 0], and no phantom zeros appended
