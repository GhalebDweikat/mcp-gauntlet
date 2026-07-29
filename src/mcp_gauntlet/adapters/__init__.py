"""Pick the adapter matching the installed SDK, once, at import.

Selection is by package **version**, not attribute probing: `mcp` 2.0 still exports
`ClientSession`, `StdioServerParameters` and `mcp.types`, so `hasattr` cannot tell the eras
apart — verified against the released 2.0.0. Only the version can. Pre-releases like
`2.0.0b2` parse by major like anything else.

There is deliberately no user-facing switch. One environment holds one SDK — 2.0 moves to
`httpx2`, so the two cannot coexist — which would make a flag a way to request something
impossible.
"""

from __future__ import annotations

import functools
import importlib.metadata

from mcp_gauntlet.adapters.base import SdkAdapter, SdkFieldMissing, meta_of, require
from mcp_gauntlet.adapters.legacy import LegacyAdapter

__all__ = [
    "SdkAdapter",
    "SdkFieldMissing",
    "adapter",
    "meta_of",
    "require",
    "sdk_version",
]


def sdk_version() -> str:
    """The installed `mcp` version.

    Recorded on every report: a score is only interpretable against the era that produced
    it, and until now nothing on the board said which SDK was used.
    """
    try:
        return importlib.metadata.version("mcp")
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover - mcp is a hard dep
        return "unknown"


@functools.lru_cache(maxsize=1)
def adapter() -> SdkAdapter:
    head = sdk_version().split(".", 1)[0]
    if head.isdigit() and int(head) >= 2:
        from mcp_gauntlet.adapters.modern import ModernAdapter

        return ModernAdapter()
    return LegacyAdapter()
