"""Typed data models shared across the harness."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ToolInfo(BaseModel):
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    # Every server-authored string below reaches a model's context in some client, so each
    # is a tool-poisoning surface and must be scanned. Capturing only name/description/
    # input_schema left a payload placed in a display title or an output schema invisible to
    # the very check whose premise is "scan every string the model sees".
    title: str | None = None  # display title (MCP 2025-06-18+), shown in place of the name
    annotation_title: str | None = None  # annotations.title, the older display-name slot
    output_schema: dict[str, Any] = Field(default_factory=dict)
    # MCP tool annotation *hints* (server-declared, advisory). Only ever trusted in the
    # conservative direction — see mcp_gauntlet.safety — never to mark a tool safe.
    read_only_hint: bool | None = None
    destructive_hint: bool | None = None


class ServerInfo(BaseModel):
    name: str | None = None
    version: str | None = None
    # Shown in place of the name by clients that support it — the server-level twin of
    # ToolInfo.title, and the same injection surface.
    title: str | None = None
    # The server's init "instructions" string — fed to the model as system context by many
    # clients, so it's a server-authored prompt-injection surface (scanned in checks).
    instructions: str | None = None


class DiscoveryResult(BaseModel):
    server: ServerInfo
    tools: list[ToolInfo] = Field(default_factory=list)
