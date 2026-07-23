"""Typed data models shared across the harness."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ToolInfo(BaseModel):
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)


class ServerInfo(BaseModel):
    name: str | None = None
    version: str | None = None


class DiscoveryResult(BaseModel):
    server: ServerInfo
    tools: list[ToolInfo] = Field(default_factory=list)
