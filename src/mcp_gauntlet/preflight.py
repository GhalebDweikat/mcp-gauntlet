"""Decide whether a server is even usable before paying to evaluate it.

A large share of publicly listed MCP servers are hosted commercial products. They install,
connect, and answer ``tools/list`` perfectly — and then fail every actual call because no
account was supplied. Scored naively that is Tool Reliability 0 and a published D or F for a
server that is fine, blamed for a configuration *we* declined to provide. That is the same
mistake as generating tasks about directories that do not exist, one level up, and it would
land on named third parties.

So: make one cheap call before the LLM spend starts. If the server says it needs
credentials, say so and score nothing.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from mcp import ClientSession

from mcp_gauntlet.adapters import adapter
from mcp_gauntlet.content import block_text
from mcp_gauntlet.models import ToolInfo

_log = logging.getLogger(__name__)

# Deliberately narrow. Each of these says "you did not give me a credential"; none of them
# is something a correctly-functioning server says about a legitimate request.
#
# Explicitly NOT included: bare "forbidden", "403", "permission denied", "access denied".
# Those are what a sandboxed filesystem server correctly says when asked for a path outside
# its root, and what a read-only database says about a write. Treating them as missing
# credentials would mark well-behaved servers unevaluable — the precise failure this module
# exists to prevent, inverted.
_AUTH_MARKERS = re.compile(
    r"""(?ix)
    \bapi[\s_-]?key\b
  | \bunauthenti(?:cated|cation)\b
  | \bauthenticat(?:ion|e)\s+(?:required|failed|error)\b
  | \b(?:missing|invalid|expired|no)\s+(?:api\s+)?(?:token|credential|credentials|key)\b
  | \bcredentials?\s+(?:not\s+found|required|missing)\b
  | \b401\b
  | \b(?:sign\s?up|log\s?in|sign\s?in)\s+(?:required|to\s+use|at\b)
  | \bsubscription\s+required\b
  | \b(?:payment\s+required|402)\b
  | \bset\s+the\s+\w*_?(?:key|token|secret)\w*\s+environment\s+variable\b
  | \bbearer\s+token\s+(?:required|missing)\b
    """
)


def looks_like_missing_credentials(text: str) -> bool:
    """Whether an *error* from a tool call reads as "you never authenticated".

    Only ever apply this to text from a call that actually failed. A search or fetch tool
    can legitimately *return* a document mentioning an API key, and flagging that would
    make a working server unevaluable on the strength of its own content.
    """
    return bool(_AUTH_MARKERS.search(text))


_PLACEHOLDER_BY_TYPE: dict[str, Any] = {
    "string": "test",
    "integer": 1,
    "number": 1,
    "boolean": False,
    "array": [],
    "object": {},
}


def minimal_valid_args(schema: dict[str, Any]) -> dict[str, Any] | None:
    """Trivially schema-valid arguments, or None if one cannot be constructed confidently.

    Only ever used to find out whether a call fails for AUTHENTICATION reasons. The result
    is otherwise discarded, which is what makes inventing values acceptable here: a server
    answering "no such directory" is not auth-shaped and is ignored, so a wrong guess costs
    a wasted call rather than a wrong verdict.

    Declines on anything it cannot satisfy honestly — an enum with no members, an unknown
    type, a required property the schema does not describe. A probe that gives up says
    nothing; a probe that guesses badly would say something false.
    """
    required = schema.get("required") or []
    if not isinstance(required, list):
        return None
    if not required:
        # Nothing is required, so `{}` already satisfies the schema — and this is the
        # zero-argument case the probe has always handled. Demanding a `properties` dict
        # here regressed it to "no candidates at all".
        return {}
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return None
    args: dict[str, Any] = {}
    for name in required:
        spec = properties.get(name)
        if not isinstance(spec, dict):
            return None
        if isinstance(spec.get("enum"), list) and spec["enum"]:
            args[name] = spec["enum"][0]
            continue
        declared = spec.get("type")
        if isinstance(declared, list):  # a union — take the first usable member
            declared = next((d for d in declared if d in _PLACEHOLDER_BY_TYPE), None)
        if declared not in _PLACEHOLDER_BY_TYPE:
            return None
        args[name] = _PLACEHOLDER_BY_TYPE[declared]
    return args


def _probe_candidates(tools: list[ToolInfo]) -> list[ToolInfo]:
    """Tools this probe can call without doing damage, and without guessing wildly.

    Originally zero-required-argument tools only, on the reasoning that inventing an
    argument is how the task generator ended up asking servers about directories that never
    existed. That reasoning holds for SCORING a result and not for this: here the only
    question asked of the answer is "was this an auth failure", and an invented path
    produces a not-found error, which is not auth-shaped and is ignored.

    Restricting to zero-argument tools had a real cost. A server whose every tool takes a
    parameter — most servers — could not be probed at all, so a WRONG or EXPIRED credential
    was undetectable: the malformed-input probe hits the SDK's own argument validation
    before it ever reaches the server's auth check, and reads as a healthy rejection.
    """
    from mcp_gauntlet.safety import looks_mutating

    out = []
    for tool in tools:
        if looks_mutating(tool):
            continue  # never invent arguments for something that might write
        if minimal_valid_args(tool.input_schema) is None:
            continue
        out.append(tool)
    return out


async def probe_credentials(
    session: ClientSession, tools: list[ToolInfo], *, max_calls: int = 3
) -> str | None:
    """Return a reason string if this server needs credentials it was not given, else None.

    Conservative in both directions. It concludes "needs credentials" only when a call
    genuinely failed *and* the failure names an authentication problem; a single success
    anywhere clears the server outright. Anything else — no probeable tool, ordinary errors,
    a transport failure — returns None and the evaluation proceeds as usual, because
    refusing to score a server is itself a judgment that should need evidence.
    """
    candidates = _probe_candidates(tools)
    if not candidates:
        return None

    reasons: list[str] = []
    for tool in candidates[:max_calls]:
        try:
            result: Any = await session.call_tool(
                tool.name, minimal_valid_args(tool.input_schema) or {}
            )
        except Exception as exc:  # noqa: BLE001 - a probe must never break the evaluation
            if looks_like_missing_credentials(str(exc)):
                reasons.append(f"{tool.name}: {str(exc)[:160]}")
            continue
        sdk = adapter()
        text = " ".join(t for block in sdk.result_content(result) if (t := block_text(block)))
        if not sdk.result_is_error(result):
            return None  # something worked without credentials — the server is usable
        if looks_like_missing_credentials(text):
            reasons.append(f"{tool.name}: {text.strip()[:160]}")

    if not reasons:
        return None
    _log.debug("credential pre-flight declined to score this server: %s", reasons[0])
    return (
        "needs credentials that were not supplied — "
        f"every probed tool reported an authentication error ({reasons[0]})"
    )
