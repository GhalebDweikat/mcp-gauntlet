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

from typing import Any

_MAX_CAUSES = 3


def causes(exc: BaseException) -> list[BaseException]:
    """Flatten nested exception groups down to the exceptions that actually happened.

    Public because reading a *structured* field off the real cause — an HTTP status, a
    JSON-RPC error code — is the only way to tell "the server rejected my credential" from
    "the server is describing a credential", and every one of those fields is behind the
    same anyio wrapper this module exists to see past.
    """
    inner = getattr(exc, "exceptions", None)
    if not inner:
        return [exc]
    out: list[BaseException] = []
    for sub in inner:
        out.extend(causes(sub))
    return out


_leaves = causes  # historical name, kept so nothing in-tree breaks on the rename


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


def http_status(exc: BaseException) -> tuple[int, Any] | None:
    """The HTTP status of the real cause, with the response it came from, or None.

    Its own function because two very different places need it and neither can read it
    naively: the status is on `.response` of an httpx error buried under anyio's task group,
    and a wrong-credential failure shows up at *both* — as a refused tool call mid-session,
    and as a 401 that stops the session opening at all. The second used to be reported as
    "the transport did not come up", which sends a reader to check their firewall.
    """
    # What the transport recorded off the wire, when it recorded anything. This is the only
    # source that works on `mcp` 2.0, which catches httpx's `HTTPStatusError` and re-raises an
    # `MCPError` carrying no response at all — see `client._StatusWatcher`.
    for holder in (exc, *causes(exc)):
        recorded = getattr(holder, "mcp_gauntlet_http_status", None)
        if isinstance(recorded, tuple) and isinstance(recorded[0], int):
            return recorded[0], recorded[1]

    for cause in causes(exc):
        response = getattr(cause, "response", None)
        status = getattr(response, "status_code", None)
        if not isinstance(status, int):
            status = getattr(cause, "status_code", None)
            response = None
        if isinstance(status, int):
            return status, response
    return None


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
    status = http_status(exc)
    if status is not None and status[0] in (401, 403, 407):
        # Read from the status rather than from the wording, because this is the one remote
        # failure whose *cause is the caller* — and a reader told "the transport did not come
        # up" goes and checks their firewall. It is also the commonest way a wrong credential
        # presents on a hosted server: the session never opens, so the credential pre-flight
        # never runs and nothing else in the harness gets a chance to say so.
        return (
            f"could not reach {url} — the server rejected the request with HTTP {status[0]}: "
            "the credentials are missing, wrong, or lack the required scope. Supply them with "
            f"--header 'Authorization: Bearer ...' ({detail})"
        )
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
