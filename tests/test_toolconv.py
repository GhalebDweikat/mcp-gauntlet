from mcp_gauntlet.models import ToolInfo
from mcp_gauntlet.toolconv import build_tool_bridge


def test_sanitizes_and_maps_names() -> None:
    tools = [
        ToolInfo(
            name="get-annotated.message",
            description="d",
            input_schema={"type": "object", "properties": {}},
        )
    ]
    bridge = build_tool_bridge(tools)
    fn = bridge.tools[0]["function"]
    assert fn["name"] == "get-annotated_message"  # dot sanitized, hyphen kept
    assert bridge.original("get-annotated_message") == "get-annotated.message"


def test_schema_passes_through() -> None:
    schema = {
        "type": "object",
        "properties": {"a": {"type": "integer"}},
        "required": ["a"],
    }
    tools = [ToolInfo(name="add", description="Add", input_schema=schema)]
    bridge = build_tool_bridge(tools)
    assert bridge.tools[0]["function"]["parameters"] == schema
    assert bridge.tools[0]["type"] == "function"


def test_empty_schema_gets_object_default() -> None:
    tools = [ToolInfo(name="noop", input_schema={})]
    bridge = build_tool_bridge(tools)
    assert bridge.tools[0]["function"]["parameters"] == {"type": "object", "properties": {}}


def test_names_unique_after_sanitize() -> None:
    tools = [ToolInfo(name="a.b", input_schema={}), ToolInfo(name="a_b", input_schema={})]
    bridge = build_tool_bridge(tools)
    names = [t["function"]["name"] for t in bridge.tools]
    assert len(set(names)) == 2
    assert bridge.original(names[0]) == "a.b"
    assert bridge.original(names[1]) == "a_b"
