"""Parsing of a user-supplied MCP server specification.

A server spec is either an http(s) URL (Streamable HTTP transport) or a shell
command that launches a stdio server, e.g. ``npx -y @scope/some-server /tmp``.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from enum import StrEnum


def _split_command(s: str) -> list[str]:
    """Split a stdio launch command into tokens.

    On Windows use non-POSIX mode so backslash paths survive — POSIX ``shlex`` treats
    ``\\`` as an escape, mangling ``C:\\Users\\me\\srv.py`` into ``C:Usersmesrv.py`` — then
    strip the surrounding quotes non-POSIX mode leaves on a quoted path-with-spaces.
    """
    if os.name == "nt":
        tokens = shlex.split(s, posix=False)
        return [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'" else t for t in tokens]
    return shlex.split(s)


class TransportKind(StrEnum):
    STDIO = "stdio"
    HTTP = "http"


@dataclass
class ServerSpec:
    kind: TransportKind
    command: str | None = None
    args: list[str] = field(default_factory=list)
    url: str | None = None
    raw: str = ""
    # Credentials for reaching a server that needs auth. Kept OUT of ``raw``/``label`` so
    # they never reach a report, a log line, or the leaderboard. ``env`` is passed to a
    # stdio child (merged over a minimal safe base environment by the SDK); ``headers`` is
    # sent with each HTTP request. Populated from --env / --header, never from the spec text.
    env: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def parse(cls, spec: str) -> ServerSpec:
        s = spec.strip()
        if not s:
            raise ValueError("empty server spec")
        if s.startswith(("http://", "https://")):
            return cls(kind=TransportKind.HTTP, url=s, raw=s)
        tokens = _split_command(s)
        if not tokens:
            raise ValueError(f"could not parse server command: {spec!r}")
        return cls(kind=TransportKind.STDIO, command=tokens[0], args=tokens[1:], raw=s)

    def label(self) -> str:
        """A short human-readable identifier for the server (never includes credentials)."""
        return self.url or self.raw

    def secret_values(self) -> frozenset[str]:
        """The credential values to redact from any published output.

        Bounded to values of length >= 4 so a pathological one-character token can't turn
        every digit in a report into ``***``; real tokens are far longer.
        """
        return frozenset(v for v in (*self.env.values(), *self.headers.values()) if len(v) >= 4)


def parse_env_args(entries: list[str], environ: dict[str, str]) -> dict[str, str]:
    """Resolve ``--env`` entries into name→value for a stdio child.

    ``NAME`` pulls the value from the parent environment (so a secret never appears on the
    command line); ``NAME=VALUE`` sets it explicitly. An unset bare ``NAME`` is an error —
    silently dropping it would send an unauthenticated server a call that looks authorized.
    """
    resolved: dict[str, str] = {}
    for entry in entries:
        name, sep, value = entry.partition("=")
        name = name.strip()
        if not name:
            # Never echo the entry: for NAME=VALUE it carries the secret VALUE, and this
            # error can reach a CI log.
            raise ValueError(
                "an --env entry has an empty variable name (expected NAME or NAME=VALUE)"
            )
        if sep:
            # `NAME=` with an explicit empty value is honoured: the user said so.
            resolved[name] = value
        elif environ.get(name):
            resolved[name] = environ[name]
        else:
            # `.get(name)` rather than `name in environ`, so a variable that is SET BUT
            # EMPTY counts as absent. That is not a corner case: on GitHub Actions a fork
            # PR expands `${{ secrets.TOKEN }}` to an empty string, so the variable exists
            # and carries nothing. Treating it as present handed the server a blank
            # credential, which it rejected — and the run was then recorded as "could not
            # evaluate" (exit 3), the one code the docs tell you NOT to fail a build on. A
            # whole scan reported healthy while every credentialed server in it went
            # unchecked. Use NAME= to mean an intentionally empty value.
            detail = "set but empty" if name in environ else "not set in the environment"
            raise ValueError(f"--env {name}: {detail} (use NAME=VALUE to inline a value)")
    return resolved


def parse_header_args(entries: list[str]) -> dict[str, str]:
    """Resolve ``--header 'Name: Value'`` entries into a header map for an HTTP server."""
    headers: dict[str, str] = {}
    for entry in entries:
        name, sep, value = entry.partition(":")
        name = name.strip()
        if not sep or not name:
            # A malformed header (no colon) may be a bare token — don't echo it; a valid
            # 'Name: Value' would also carry the secret VALUE. Report only that it's malformed.
            raise ValueError("an --header entry is malformed (expected 'Name: Value')")
        headers[name] = value.strip()
    return headers
