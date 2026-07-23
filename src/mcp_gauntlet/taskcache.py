"""Cache generated task sets per server so repeated runs are reproducible.

Task generation is non-deterministic (even at temperature 0), so scores would
drift run to run. We generate once, key the task set to the server's identity +
exposed tools, and reuse it thereafter. ``--refresh-tasks`` regenerates;
``--tasks-file`` pins an explicit, committable set.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from mcp_gauntlet.models import ServerInfo, ToolInfo
from mcp_gauntlet.tasks import EvalTask

DEFAULT_CACHE_DIR = Path(".gauntlet") / "tasks"


def server_key(server: ServerInfo, tools: list[ToolInfo]) -> str:
    """A stable id from the server name/version and the exposed tool set."""
    name = server.name or "server"
    version = server.version or "0"
    tool_names = ",".join(sorted(tool.name for tool in tools))
    digest = hashlib.sha256(f"{name}|{version}|{tool_names}".encode()).hexdigest()[:12]
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "server"
    return f"{slug}-{digest}"


def cache_file(base_dir: Path, key: str) -> Path:
    return base_dir / f"{key}.json"


def load_tasks(path: Path) -> list[EvalTask] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return [EvalTask(**item) for item in data.get("tasks", [])]
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def save_tasks(path: Path, tasks: list[EvalTask]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"tasks": [task.model_dump() for task in tasks]}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
