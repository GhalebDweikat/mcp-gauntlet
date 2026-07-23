from pathlib import Path

from mcp_gauntlet.models import ServerInfo, ToolInfo
from mcp_gauntlet.taskcache import cache_file, load_tasks, save_tasks, server_key
from mcp_gauntlet.tasks import EvalTask


def test_server_key_is_order_insensitive() -> None:
    server = ServerInfo(name="Demo Server", version="1.0")
    key_ab = server_key(server, [ToolInfo(name="a"), ToolInfo(name="b")])
    key_ba = server_key(server, [ToolInfo(name="b"), ToolInfo(name="a")])
    assert key_ab == key_ba


def test_server_key_changes_with_tool_set() -> None:
    server = ServerInfo(name="Demo Server", version="1.0")
    key_two = server_key(server, [ToolInfo(name="a"), ToolInfo(name="b")])
    key_one = server_key(server, [ToolInfo(name="a")])
    assert key_two != key_one


def test_save_load_roundtrip(tmp_path: Path) -> None:
    path = cache_file(tmp_path, "k")
    tasks = [EvalTask(description="do x", rubric="x is done", expected_tools=["a"])]
    save_tasks(path, tasks)
    loaded = load_tasks(path)
    assert loaded is not None
    assert loaded[0].description == "do x"
    assert loaded[0].expected_tools == ["a"]


def test_load_missing_returns_none(tmp_path: Path) -> None:
    assert load_tasks(cache_file(tmp_path, "nope")) is None
