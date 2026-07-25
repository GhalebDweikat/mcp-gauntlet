import json
from pathlib import Path
from typing import Any, cast

import pytest
from openai import AsyncOpenAI

from mcp_gauntlet import engine
from mcp_gauntlet.models import DiscoveryResult, ServerInfo, ToolInfo
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


def test_load_wrong_shape_json_returns_none(tmp_path: Path) -> None:
    # A cache that is valid JSON but a top-level array (not our {"tasks": [...]} object)
    # must degrade to a miss, not crash with AttributeError on data.get("tasks").
    path = cache_file(tmp_path, "arr")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert load_tasks(path) is None


def test_load_skips_non_dict_task_items(tmp_path: Path) -> None:
    # A tasks list with junk entries loads the valid ones and drops the rest, rather than
    # crashing on EvalTask(**"junk").
    path = cache_file(tmp_path, "mixed")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"tasks": ["junk", {"description": "do x", "rubric": "r"}, 5]}),
        encoding="utf-8",
    )
    loaded = load_tasks(path)
    assert loaded is not None
    assert [t.description for t in loaded] == ["do x"]


async def test_resolve_tasks_redacts_secrets_before_caching(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A generated task can echo a credential the server pasted into a tool description.
    # It must be scrubbed before it reaches the persisted cache (or a committed --tasks-file).
    secret = "ghp_cached_secret_1234"

    async def fake_generate(
        client: AsyncOpenAI, model: str, tools: list[ToolInfo], n: int
    ) -> list[EvalTask]:
        return [
            EvalTask(description=f"use {secret}", rubric=f"expect {secret}", expected_tools=["a"])
        ]

    monkeypatch.setattr(engine, "generate_tasks", fake_generate)
    tools = [ToolInfo(name="a")]
    discovery = DiscoveryResult(server=ServerInfo(name="s", version="1"), tools=tools)
    tasks = await engine._resolve_tasks(
        client=cast(AsyncOpenAI, cast(Any, None)),
        model="m",
        tools=tools,
        discovery=discovery,
        n_tasks=1,
        tasks_file=None,
        refresh_tasks=True,
        cache_dir=tmp_path,
        secrets=frozenset({secret}),
    )
    assert secret not in tasks[0].description
    assert secret not in tasks[0].rubric
    cached = cache_file(tmp_path, server_key(discovery.server, tools))
    assert secret not in cached.read_text(encoding="utf-8")
