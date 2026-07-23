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


async def test_accepted_bad_input_scores_below_100() -> None:
    dim = await run_robustness_probes(
        _session(lambda n, a: SimpleNamespace(isError=False)), [_TOOL]
    )
    assert dim is not None
    assert dim.score < 100
    assert any("accepted" in f.message for f in dim.findings)


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


async def test_none_when_no_probeable_tools() -> None:
    unprobeable = ToolInfo(name="np", input_schema={"type": "object", "properties": {}})
    dim = await run_robustness_probes(
        _session(lambda n, a: SimpleNamespace(isError=True)), [unprobeable]
    )
    assert dim is None


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
