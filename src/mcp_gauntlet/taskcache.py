"""Cache generated task sets per server so repeated runs are reproducible.

Task generation is non-deterministic (even at temperature 0), so scores would
drift run to run. We generate once, key the task set to the server's identity +
exposed tools, and reuse it thereafter. ``--refresh-tasks`` regenerates;
``--tasks-file`` pins an explicit, committable set.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mcp_gauntlet.models import ServerInfo, ToolInfo
from mcp_gauntlet.naming import slugify
from mcp_gauntlet.tasks import PROMPT_VERSION, EvalTask

DEFAULT_CACHE_DIR = Path(".gauntlet") / "tasks"


def server_key(server: ServerInfo, tools: list[ToolInfo], context: str = "") -> str:
    """A stable id from the server name/version, the exposed tool set, the prompt, and the
    grounding context.

    The generator's prompt is part of the key because a cached set is only interchangeable
    with a freshly generated one if the same prompt would have produced it. Without this a
    prompt fix looks like a no-op on every server already in the cache — it keeps serving
    the tasks the old prompt wrote.

    The grounding context is part of the key for exactly the same reason, and it was missing.
    It carries the server's launch arguments and URL into the prompt as ground truth ("paths
    among them are real"), so two invocations of one package —

        server-filesystem /data/alpha        and        server-filesystem /data/beta

    — share a name, a version and a tool set, and therefore shared a cache key. The second
    run was handed tasks naming the first run's paths, every call failed, and the SERVER wore
    it: Tool Reliability toward 0, Task Success toward 0, a published D or F earned entirely
    by this cache. That is the original "invented paths, blamed the server" incident coming
    back through a different door. Hashed rather than stored, since it can run to kilobytes
    of resource URIs.

    Note the drift baseline already keys on the full spec label, which is why this reads as
    an oversight rather than a decision.
    """
    name = server.name or "server"
    version = server.version or "0"
    tool_names = ",".join(sorted(tool.name for tool in tools))
    grounding = hashlib.sha256(context.encode()).hexdigest()[:12]
    digest = hashlib.sha256(
        f"{name}|{version}|{tool_names}|p{PROMPT_VERSION}|g{grounding}".encode()
    ).hexdigest()[:12]
    slug = slugify(name)
    return f"{slug}-{digest}"


def cache_file(base_dir: Path, key: str) -> Path:
    return base_dir / f"{key}.json"


def load_tasks(path: Path) -> list[EvalTask] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):  # a valid-JSON-but-not-object cache (e.g. [1,2,3])
            return None
        items = data.get("tasks", [])
        return [EvalTask(**item) for item in items if isinstance(item, dict)]
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def save_tasks(path: Path, tasks: list[EvalTask]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"tasks": [task.model_dump() for task in tasks]}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
