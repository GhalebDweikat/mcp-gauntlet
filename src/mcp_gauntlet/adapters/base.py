"""The one place SDK objects become mcp-gauntlet's own models.

Everything downstream of discovery — all eight dimensions, the scanner, the scorer, the
board — speaks only `ToolInfo`/`ServerInfo`/`PromptInfo`/`ResourceInfo` and never touches an
SDK object. So supporting a second protocol era is one module per era mapping into those,
and every check, every bugfix and every new dimension is written once.

**Why this exists at all.** `mcp` 2.0 renamed every field to snake_case: `inputSchema` ->
`input_schema`, `isError` -> `is_error`, `nextCursor` -> `next_cursor`. Those were read
through `getattr(obj, "camelCaseName", default)`, which does not raise on a rename — it
returns the default. The check built on it then measures nothing and reports every server
clean. That is not hypothetical: the MRTR detection shipped on 2026-07-28 read only
`resultType`, so against the modern servers it was written for it returned None and charged
the harness's own declined interaction to the server's reliability score.

So the rule here is: **a missing field is an error, not a default.**
"""

from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable

from mcp_gauntlet.models import PromptInfo, ResourceInfo, ServerInfo, ToolInfo

_MISSING = object()


class SdkFieldMissing(RuntimeError):
    """An SDK object lacked every field name we know it by.

    Raised rather than defaulted, because defaulting is how a renamed field turns a check
    into a no-op that scores every server as clean.
    """


def require(obj: Any, *names: str, default: Any = _MISSING) -> Any:
    """Read the first of ``names`` that exists on ``obj``, or raise.

    Pass ``default`` ONLY where the *protocol* says the field is optional — a tool need not
    declare an ``outputSchema``. Never pass one as insurance against a rename: that
    reintroduces exactly the silence this module exists to remove.
    """
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    if default is not _MISSING:
        return default
    raise SdkFieldMissing(
        f"{type(obj).__name__} has none of {names!r}. The SDK's shape changed, so a check "
        f"reading this field is now blind. Fix the adapter — do not add a default."
    )


def meta_of(obj: Any) -> dict[str, Any]:
    """A server's `_meta` block, which is scanned like any other server-authored text."""
    meta = getattr(obj, "meta", None)
    return dict(meta) if isinstance(meta, dict) else {}


@runtime_checkable
class SdkAdapter(Protocol):
    """What each protocol era must be able to produce.

    Deliberately phrased as "give me our model", not "wrap the SDK": the point is that no
    caller ever holds an SDK object long enough to read a field off it.
    """

    era: Literal["legacy", "modern"]
    # protocol.py attaches a log handler to this to detect stdout pollution. It is on the
    # adapter because if the SDK moves the module, the handler attaches to a logger nothing
    # writes to and the check silently reports every server clean.
    stdio_logger_name: str

    def tool_info(self, tool: Any) -> ToolInfo: ...

    def server_info(self, init: Any) -> ServerInfo: ...

    # Split in two, because rendering is a separate round trip that often does not happen:
    # the listing entry always exists, the prompts/get result only sometimes.
    def prompt_info(self, prompt: Any) -> PromptInfo: ...

    def prompt_result(self, result: Any) -> tuple[list[str], str | None, dict[str, Any]]:
        """(message texts, result description, result `_meta`) from one prompts/get."""
        ...

    def resource_info(self, resource: Any, *, is_template: bool) -> ResourceInfo: ...

    def next_cursor(self, page: Any) -> str | None: ...

    def page_params(self, cursor: str | None) -> dict[str, Any]: ...

    def list_changed(self, init: Any) -> bool: ...

    def advertises_logging(self, init: Any) -> bool:
        """Whether the server declares the `logging` capability.

        Deprecated as of revision 2026-07-28 (SEP-2577) — the SDK marks its own
        `set_logging_level` and `send_log_message` with a deprecation warning. Note this is
        the ONLY deprecated capability a *server* can advertise: `sampling` and `roots` are
        client capabilities and appear nowhere in `ServerCapabilities`, so a check looking
        for them on a server would have been looking for something that cannot be there.
        """
        ...

    # ------------------------------------------------------------- live results
    # These read a CallToolResult during an evaluation, so none of them may raise:
    # `robustness.py`'s read runs last, after the whole agentic eval, and a raise there
    # would discard a run already paid for. They default instead, and each reads both
    # spellings — the era is chosen by SDK version, so the canonical name is right, but a
    # mis-detected era must degrade to a wrong-looking number rather than a lost report.

    def result_is_error(self, result: Any) -> bool: ...

    def result_content(self, result: Any) -> list[Any]: ...

    def result_structured(self, result: Any) -> Any: ...

    def asks_for_input(self, result: Any) -> bool:
        """Whether the server answered "I need something from a human" (MRTR).

        Revision 2026-07-28 forbids a server pushing elicitation or sampling at the client;
        it returns `result_type: "input_required"` inside an ordinary result instead. The
        harness declines that exactly as it declined the pushed form — but it has to be seen
        first, and it arrives where nothing was looking.
        """
        ...

    def protocol_error_type(self) -> type[BaseException]:
        """The SDK's protocol-error class, which Robustness treats as a correct rejection."""
        ...
