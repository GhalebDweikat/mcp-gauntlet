"""Turn an exception into something a reader can act on.

anyio runs every session inside a task group, so almost anything that goes wrong on the way
to a server arrives wrapped: ``unhandled errors in a TaskGroup (1 sub-exception)``. That
string names no server, no cause, and no remedy. On a published survey it is worse than
useless — a row saying a server "could not be evaluated: unhandled errors in a TaskGroup"
reads as the harness shrugging, and the reader cannot tell a broken server from a broken
scanner.

The cause is always in there. It just has to be unwrapped.
"""

from __future__ import annotations

_MAX_CAUSES = 3


def _leaves(exc: BaseException) -> list[BaseException]:
    """Flatten nested exception groups down to the exceptions that actually happened."""
    inner = getattr(exc, "exceptions", None)
    if not inner:
        return [exc]
    out: list[BaseException] = []
    for sub in inner:
        out.extend(_leaves(sub))
    return out


def describe(exc: BaseException, limit: int = 200) -> str:
    """A one-line description naming the real cause, not the wrapper.

    Includes the exception type, because the message alone is often empty or ambiguous —
    a bare ``FileNotFoundError`` says nothing without its class, and several SDK errors
    stringify to "". Distinct causes are joined so a server failing two ways says both.
    """
    causes = _leaves(exc)
    seen: list[str] = []
    for cause in causes:
        text = str(cause).strip() or cause.__class__.__name__
        # `ExceptionGroup("...", [...])` stringifies to its own label; prefer the type when
        # the message would just repeat the wrapper we are trying to see past.
        if not str(cause).strip():
            text = cause.__class__.__name__
        elif type(cause).__name__ not in text:
            text = f"{type(cause).__name__}: {text}"
        if text not in seen:
            seen.append(text)
        if len(seen) >= _MAX_CAUSES:
            break
    joined = " | ".join(seen) if seen else f"{type(exc).__name__}: {exc}"
    return joined[:limit]
