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


def explain_remote_failure(url: str, exc: BaseException) -> str:
    """A remote connection failure that names the URL and what went wrong.

    The stdio path's messages are the best thing in this tool — "no such executable: '...'
    (resolved from <cwd>)" tells a user exactly what to do. The remote path was nowhere near
    that bar: a refused port and a nonexistent host produced the SAME message, with no URL in
    it, so a user could not tell whether the server was down, the hostname was wrong, or the
    harness was broken. (It was often the harness: the transport was dead on `mcp` 2.0 for
    two releases and this message is what people saw.)

    Classified by the cause's text rather than by exception type, because the transport
    stack wraps httpx errors in its own types and the concrete classes differ across SDK
    eras — the same reason the stdout check keys on the exception type rather than the
    wording, done in reverse, and for the same reason: pick whichever is the more stable
    signal for the specific thing being read.
    """
    detail = describe(exc, 200)
    lowered = detail.lower()
    if "getaddrinfo" in lowered or "name or service not known" in lowered:
        hint = "the hostname does not resolve — check the spelling and your DNS"
    elif "timeout" in lowered or "timed out" in lowered:
        hint = "the host accepted nothing in time — it may be firewalled or overloaded"
    elif "connection attempts failed" in lowered or "refused" in lowered:
        hint = "nothing is listening there — check the port, and that the server is running"
    elif "certificate" in lowered or "ssl" in lowered or "tls" in lowered:
        hint = "the TLS handshake failed — check the certificate, or use http:// for a local server"
    else:
        hint = "the transport did not come up"
    return f"could not reach {url} — {hint} ({detail})"
