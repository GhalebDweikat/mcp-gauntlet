from types import SimpleNamespace
from typing import Any, cast

from mcp import ClientSession
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData

from mcp_gauntlet.client import open_session
from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.models import ToolInfo
from mcp_gauntlet.report import Severity
from mcp_gauntlet.robustness import malformed_args, run_robustness_probes

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


async def test_mcp_error_counts_as_rejection() -> None:
    err = McpError(ErrorData(code=-32602, message="invalid params"))
    dim = await run_robustness_probes(_session(lambda n, a: err), [_TOOL])
    assert dim is not None
    assert dim.score == 100.0


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
    spec = ServerSpec.parse("python -m mcp_gauntlet.fixtures.good_server")
    async with open_session(spec) as (session, _init):
        listed = await session.list_tools()
        tools = [
            ToolInfo(name=t.name, description=t.description, input_schema=dict(t.inputSchema or {}))
            for t in listed.tools
        ]
        dim = await run_robustness_probes(session, tools)
    assert dim is not None
    assert dim.score == 100.0
