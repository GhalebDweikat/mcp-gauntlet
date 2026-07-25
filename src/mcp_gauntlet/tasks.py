"""Generate gradeable evaluation tasks from a server's tools, using the LLM."""

from __future__ import annotations

import json
from typing import Any

from openai import AsyncOpenAI
from pydantic import BaseModel, Field, ValidationError

from mcp_gauntlet.llm import chat_completion
from mcp_gauntlet.models import ToolInfo

_PROMPT = """\
You are designing an evaluation for an MCP (Model Context Protocol) server. Below \
are the tools the server exposes. Produce exactly {n} realistic, self-contained \
tasks that a user might ask an agent to perform, each solvable using one or more of \
these tools.

Rules:
- Only reference tools from the list below.
- Each task description must be concrete and unambiguous, including any specific \
input values the agent needs (e.g. exact strings or numbers). Do not require \
information the agent cannot know.
- Prefer read-only / non-destructive tasks.
- The rubric must be objective and check the *substantive outcome* — correct \
values/results and appropriate tool use — that a grader can verify from the \
transcript. Do not require an exact output string unless producing that exact \
string is the point of the task.

Tools:
{tools}

Respond with JSON only, in this exact shape:
{{"tasks": [{{"description": "...", "rubric": "...", "expected_tools": ["tool_name"]}}]}}
"""


class EvalTask(BaseModel):
    description: str
    rubric: str = ""
    expected_tools: list[str] = Field(default_factory=list)


def _tools_blurb(tools: list[ToolInfo]) -> str:
    lines: list[str] = []
    for tool in tools:
        props: dict[str, Any] = {}
        if isinstance(tool.input_schema, dict):
            raw_props = tool.input_schema.get("properties")
            if isinstance(raw_props, dict):  # `or {}` wouldn't catch a truthy non-dict (a list)
                props = raw_props
        params = ", ".join(props.keys())
        desc = (tool.description or "").strip().replace("\n", " ")[:200]
        lines.append(f"- {tool.name}({params}): {desc}")
    return "\n".join(lines)


async def generate_tasks(
    client: AsyncOpenAI, model: str, tools: list[ToolInfo], n_tasks: int
) -> list[EvalTask]:
    prompt = _PROMPT.format(n=n_tasks, tools=_tools_blurb(tools))
    try:
        completion = await chat_completion(
            client,
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            response_format={"type": "json_object"},
        )
    except Exception:  # noqa: BLE001 - a task-gen rate-limit/transport failure degrades to
        return []  # no tasks (→ inconclusive agentic eval); it must not crash the whole run
    if not completion.choices:
        return []
    content = completion.choices[0].message.content or "{}"
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):  # model returned a top-level array/scalar, not an object
        return []

    valid_names = {tool.name for tool in tools}
    tasks: list[EvalTask] = []
    raw_tasks = data.get("tasks")  # the model may emit a dict/scalar here, not a list
    for raw in (raw_tasks if isinstance(raw_tasks, list) else [])[:n_tasks]:
        if not isinstance(raw, dict):
            continue
        raw_expected = raw.get("expected_tools")  # may be null/scalar, not a list
        expected = [
            n for n in (raw_expected if isinstance(raw_expected, list) else []) if n in valid_names
        ]
        try:
            tasks.append(
                EvalTask(
                    description=str(raw["description"]),
                    rubric=str(raw.get("rubric", "")),
                    expected_tools=expected,
                )
            )
        except (KeyError, ValidationError):
            continue
    return tasks
