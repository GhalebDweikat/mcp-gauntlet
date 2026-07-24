"""Heuristic read-only classification.

The harness runs an autonomous agent that executes real tool calls, so by default
we keep it away from tools that *look* like they mutate state. This is a
**best-effort heuristic, not a guarantee** — it recognizes mutating verbs by name
and description, and a server whose tool uses an unrecognized verb (or no verb at
all) can still slip through. Two other layers back it up: task generation is told to
prefer read-only tasks, and ``--allow-writes`` is required before anything the filter
excludes is exercised. Treat this as "reduce the odds of an unwanted side effect,"
not "prove there are none."

Signals, both used only to *exclude* (never to wave a tool through):
  * inflection- and separator-aware matching of mutating verbs in the tool name and
    description — real descriptions are third-person ("Creates a file") and names are
    snake_case ("delete_file"), so we match creates/creating/created and normalize
    ``-``/``_``/camelCase before matching, not just the bare stem;
  * the server's own MCP annotation hints, but only when the server *self-declares*
    non-read-only behavior. Per the MCP spec, a ``readOnlyHint`` from an untrusted
    server must never be used to decide a tool is safe, so hints can only make us more
    conservative, never less.
"""

from __future__ import annotations

import re

from mcp_gauntlet.models import ToolInfo

# Base mutating verbs; _inflections() expands each to its common forms. Intentionally
# broad (over-exclusion is the safe direction), but note some entries double as nouns
# (set/post/start/charge/…) so read-only tools that use them get excluded too — an
# accepted best-effort trade; --allow-writes runs everything.
_MUTATING_VERBS = (  # noqa: SIM905 - one whitespace-delimited string reads better than 90 items
    "create delete remove update write set put post send toggle drop insert modify "
    "patch rename move upload publish reset revoke grant execute trigger append edit "
    "clear purge destroy kill stop start enable disable run commit push merge deploy "
    "overwrite truncate purchase charge transfer save cancel approve archive register "
    "provision install uninstall terminate restart rollback wipe submit "
    "refund withdraw deposit pay place mint burn suspend ban void redeem unsubscribe "
    "subscribe expire invalidate rotate decommission deprovision checkout abort reboot "
    "encrypt decrypt empty flush lock unlock disconnect deactivate activate notify "
    "issue revoke release apply"
).split()


def _inflections(verb: str) -> set[str]:
    """Base verb plus common third-person / gerund / past forms.

    Handles the e-drop (create -> creating), y->ies (empty -> empties) and
    single-consonant doubling (drop -> dropping, commit -> committed) rules so
    inflected forms in real descriptions are matched, not just the bare stem.
    """
    forms = {verb}
    if verb.endswith(("s", "x", "z", "ch", "sh")):
        forms.update({verb + "es", verb + "ing", verb + "ed"})  # push -> pushes/pushing/pushed
    elif verb.endswith("e"):
        forms.update({verb + "s", verb[:-1] + "ing", verb + "d"})  # create -> creating/created
    elif verb.endswith("y") and len(verb) > 2 and verb[-2] not in "aeiou":
        forms.update({verb[:-1] + "ies", verb[:-1] + "ied", verb + "ing"})  # empty -> empties
    else:
        forms.update({verb + "s", verb + "ing", verb + "ed"})
        if (
            len(verb) >= 3
            and verb[-1] not in "aeiouwxy"
            and verb[-2] in "aeiou"
            and verb[-3] not in "aeiou"
        ):
            forms.update({verb + verb[-1] + "ing", verb + verb[-1] + "ed"})
    return forms


_WRITE_HINTS = re.compile(
    r"\b(" + "|".join(sorted({f for v in _MUTATING_VERBS for f in _inflections(v)})) + r")\b",
    re.IGNORECASE,
)


def _normalize(text: str) -> str:
    """Split snake_case / kebab-case / camelCase so verbs in tool names are matchable
    (``\\b`` treats ``_`` as a word char, so ``delete_file`` never matches ``delete``)."""
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)  # camelCase -> camel Case
    return re.sub(r"[-_./]+", " ", text)


def _hint_says_mutating(tool: ToolInfo) -> bool:
    """True when the server *self-declares* non-read-only behavior. Trusted only in
    this (conservative) direction: a self-incriminating hint is safe to believe; a
    ``readOnlyHint=True`` from an untrusted server is not, so it never appears here."""
    return tool.destructive_hint is True or tool.read_only_hint is False


def looks_mutating(tool: ToolInfo) -> bool:
    if _hint_says_mutating(tool):
        return True
    return bool(_WRITE_HINTS.search(_normalize(f"{tool.name} {tool.description or ''}")))


def filter_read_only(tools: list[ToolInfo]) -> tuple[list[ToolInfo], list[str]]:
    """Return (kept read-only tools, names of excluded possibly-mutating tools)."""
    kept: list[ToolInfo] = []
    excluded: list[str] = []
    for tool in tools:
        if looks_mutating(tool):
            excluded.append(tool.name)
        else:
            kept.append(tool)
    return kept, excluded
