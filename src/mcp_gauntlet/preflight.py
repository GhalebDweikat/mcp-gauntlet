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


def _probe_candidates(tools: list[ToolInfo]) -> list[ToolInfo]:
    """Tools callable while knowing nothing — no required arguments, not mutating.

    Restricted to zero-required-argument tools on purpose: inventing an argument to probe
    with is how the task generator ended up asking servers about directories that never
    existed. If a server offers no such tool the probe simply declines to conclude anything.
    """
    from mcp_gauntlet.safety import looks_mutating

    out = []
    for tool in tools:
        required = tool.input_schema.get("required") or []
        if isinstance(required, list) and required:
            continue
        if looks_mutating(tool):
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
            result: Any = await session.call_tool(tool.name, {})
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
