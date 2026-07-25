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
    # Free-form server-authored metadata. Not rendered by every client, but some (OpenAI's
    # Apps SDK among them) read namespaced keys out of it and put the strings in front of
    # the model, so it is scanned — as literal data, never allowed to cap.
    meta: dict[str, Any] = Field(default_factory=dict)


class ServerInfo(BaseModel):
    name: str | None = None
    version: str | None = None
    # Shown in place of the name by clients that support it — the server-level twin of
    # ToolInfo.title, and the same injection surface.
    title: str | None = None
    # The MCP revision this session negotiated. Recorded because the protocol is changing:
    # a score is only interpretable against the spec the server was speaking, and this is
    # the field that will tell us which servers moved when it does.
    protocol_version: str | None = None
    # The server's init "instructions" string — fed to the model as system context by many
    # clients, so it's a server-authored prompt-injection surface (scanned in checks).
    instructions: str | None = None


class PromptArgumentInfo(BaseModel):
    name: str
    description: str | None = None
    required: bool = False


class PromptInfo(BaseModel):
    """A server-authored prompt template.

    The most direct injection surface MCP has: a ``prompts/get`` response is placed in the
    model's context *verbatim*, with none of the framing a tool result gets.
    """

    name: str
    title: str | None = None
    description: str | None = None
    arguments: list[PromptArgumentInfo] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)
    # Filled in only when the prompt was actually rendered; each entry is one message's text.
    messages: list[str] = Field(default_factory=list)
    result_description: str | None = None  # GetPromptResult.description, NOT a message
    result_meta: dict[str, Any] = Field(default_factory=dict)
    # Whether prompts/get actually ran, and if not, why. An unrendered prompt has had its
    # real surface — the messages — examined not at all, so it must be reported as a gap
    # rather than counted as clean: declaring one required argument would otherwise exempt
    # a payload from the scan for the cost of a single JSON field.
    rendered: bool = False
    unrendered_reason: str = ""


class ResourceInfo(BaseModel):
    """A resource or resource template the server advertises.

    The contents aren't read — that is unbounded and closer to passthrough — but the
    metadata is shown to users and models when choosing what to attach, so it is scanned.
    """

    name: str
    title: str | None = None
    uri: str = ""
    description: str | None = None
    mime_type: str | None = None
    is_template: bool = False
    meta: dict[str, Any] = Field(default_factory=dict)


class DiscoveryResult(BaseModel):
    server: ServerInfo
    tools: list[ToolInfo] = Field(default_factory=list)
    prompts: list[PromptInfo] = Field(default_factory=list)
    resources: list[ResourceInfo] = Field(default_factory=list)
