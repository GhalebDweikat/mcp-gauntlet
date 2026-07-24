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
        """A short human-readable identifier for the server."""
        return self.url or self.raw
