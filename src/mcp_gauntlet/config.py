"""Parsing of a user-supplied MCP server specification.

A server spec is either an http(s) URL (Streamable HTTP transport) or a shell
command that launches a stdio server, e.g. ``npx -y @scope/some-server /tmp``.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from enum import StrEnum


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
        tokens = shlex.split(s)
        if not tokens:
            raise ValueError(f"could not parse server command: {spec!r}")
        return cls(kind=TransportKind.STDIO, command=tokens[0], args=tokens[1:], raw=s)

    def label(self) -> str:
        """A short human-readable identifier for the server."""
        return self.url or self.raw
