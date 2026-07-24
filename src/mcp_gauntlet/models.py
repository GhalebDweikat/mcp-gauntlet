"""Typed data models shared across the harness."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ToolInfo(BaseModel):
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    # MCP tool annotation *hints* (server-declared, advisory). Only ever trusted in the
    # conservative direction — see mcp_gauntlet.safety — never to mark a tool safe.
    read_only_hint: bool | None = None
    destructive_hint: bool | None = None


class ServerInfo(BaseModel):
    name: str | None = None
    version: str | None = None
    # The server's init "instructions" string — fed to the model as system context by many
    # clients, so it's a server-authored prompt-injection surface (scanned in checks).
    instructions: str | None = None


class DiscoveryResult(BaseModel):
    server: ServerInfo
    tools: list[ToolInfo] = Field(default_factory=list)
