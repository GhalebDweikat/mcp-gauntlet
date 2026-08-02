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
  * the server's own MCP annotation hints. A self-incriminating hint
    (``destructiveHint: true``, ``readOnlyHint: false``) is always believed. A
    ``readOnlyHint: true`` overrides the NAME guess for a CONTEXTUAL verb — `deploy`,
    `sync`, `send` all appear in ordinary getters — but never for an irredeemable one:
    `wipe_database` claiming to be read-only is refused. Without that split, a maintainer
    whose read-only tool happened to contain a write verb had no correct move at all.
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
    "issue revoke release apply "
    # Moved here from the qualifier-gated list, which required a name of 2+ tokens. That
    # requirement is sound for `add` — bare `add` really is arithmetic — but these have no
    # benign bare reading, and a zero-argument tool named exactly `sync` or `restore` is a
    # "do it all now" button. Measured before the move: `sync`, `restore`, `init`, `attach`
    # and `assign` all passed the filter as read-only and would have been executed.
    "sync restore attach assign init import"
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


# Verbs a `readOnlyHint: true` may NOT override. Everything in `_MUTATING_VERBS` is a guess
# from a NAME; these are the subset where the guess is strong enough that a server's claim to
# the contrary is not credible. `wipe_database` asserting it is read-only is exactly the claim
# this filter exists to refuse, and believing it would be reckless.
#
# The rest are CONTEXTUAL — `deploy`, `sync`, `send`, `run`, `apply` all appear in the names of
# perfectly ordinary getters (`search_deploys`, `get_sync_status`, `list_running_jobs`). There,
# an explicit annotation from the server's author is better evidence than a substring, and
# refusing it left a maintainer of a read-only server with no correct move at all.
_IRREDEEMABLE_VERBS = (  # noqa: SIM905 - matches the style of _MUTATING_VERBS above
    "delete remove drop destroy wipe purge truncate erase kill terminate "
    "revoke uninstall decommission deprovision burn "
    "charge refund withdraw transfer pay purchase"
).split()
_IRREDEEMABLE = re.compile(
    r"\b(" + "|".join(sorted({f for v in _IRREDEEMABLE_VERBS for f in _inflections(v)})) + r")\b",
    re.IGNORECASE,
)


def _normalize(text: str) -> str:
    """Split snake_case / kebab-case / camelCase so verbs in tool names are matchable
    (``\\b`` treats ``_`` as a word char, so ``delete_file`` never matches ``delete``)."""
    # Two boundaries, not one. The first alternative needs a lowercase-or-digit before the
    # capital, so an ACRONYM prefix was never split: `S3DeleteObject` worked only because
    # the `3` satisfied it, while `DBDeleteRow` came through as one token and was executed.
    # Half-present is worse than absent, because it reads as covered.
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", text)
    return re.sub(r"[-_./]+", " ", text)


# Known limit, left deliberately: a RUN-TOGETHER name with no separator (`sendmail`) is one
# token, so `\b` cannot isolate the verb. A prefix rule would catch it and would also exclude
# `settings` (starts with `set`) and `startup_info` (starts with `start`) — both read-only —
# which costs evaluation coverage to chase a name shape whose ordinary description ("Sends an
# email…") the description hint already catches. Only a name AND description that both hide
# the write get through, and at that point the annotation hints and the injection scan are
# the defences that apply.
def _hint_says_mutating(tool: ToolInfo) -> bool:
    """True when the server *self-declares* non-read-only behavior. Trusted only in
    this (conservative) direction: a self-incriminating hint is safe to believe; a
    ``readOnlyHint=True`` from an untrusted server is not, so it never appears here."""
    return tool.destructive_hint is True or tool.read_only_hint is False


# Verbs that mutate only when they take an object. `add` is the reason this exists: it is one
# of the commonest write verbs in tool names (`add_observations`, `add_note`, `add_record`) and
# also the commonest *compute* verb (`add(a, b)` adds two numbers), so it cannot go in the
# unconditional list without excluding arithmetic tools from execution entirely — the
# fail-open trade-off this filter deliberately makes. Requiring a following word separates
# them: `add_note` mutates, bare `add` does not. `_normalize` has already split snake_case and
# camelCase by the time this runs, so `addNote` reads as `add Note`.
_QUALIFIED_WRITE_VERBS = frozenset(f for v in ("add",) for f in _inflections(v))


def _compound_write_name(tool: ToolInfo) -> bool:
    """Whether the tool's NAME is a compound built on an ambiguous write verb.

    Applied to the name and display titles only, never the description. `add`'s own
    description is "Add two integers and return their sum" — prose that any word-following
    rule would match, which would exclude arithmetic tools from execution and gut the
    fail-open trade-off. A *name* is terser and more reliable: `add_note` and `git_add` are
    compounds and mutate; a tool named exactly `add` is arithmetic.
    """
    for text in (tool.name, tool.title, tool.annotation_title):
        tokens = _normalize(text or "").lower().split()
        if len(tokens) > 1 and any(token in _QUALIFIED_WRITE_VERBS for token in tokens):
            return True
    return False


def looks_mutating(tool: ToolInfo) -> bool:
    if _hint_says_mutating(tool):
        return True
    # An explicit `readOnlyHint: true` beats the NAME heuristic. A first-run tester wrote a
    # server of five pure getters, saw "no read-only tools to probe", made the
    # standards-correct fix — annotating every tool — and got byte-identical output, because
    # `search_deploys` matched a write verb in its name. There was no correct move left
    # except `--allow-writes`, the flag the report itself says to point at a disposable
    # target. The README meanwhile claimed the filter "trusts a server's own
    # readOnlyHint/name"; it trusted the name and ignored the hint.
    #
    # This does NOT weaken the filter's actual guarantee, because it never had one against a
    # hostile server: a malicious tool named `search_notes` was always executed. The name
    # rule protects HONEST servers from an accident, and it is the same source of truth as
    # the annotation — just a guess about it rather than a statement. A self-incriminating
    # hint still wins above, so `destructiveHint: true` cannot be overridden this way.
    if tool.read_only_hint is True and not _IRREDEEMABLE.search(
        _normalize(" ".join(p for p in (tool.name, tool.title, tool.annotation_title) if p))
    ):
        return False
    # Include the display titles: a tool named `entry_op` whose title reads "Delete Entry"
    # declares its own mutating verb in the field a human reads, and the filter exists to
    # keep the harness from autonomously executing exactly that.
    surface = " ".join(
        part for part in (tool.name, tool.title, tool.annotation_title, tool.description) if part
    )
    return bool(_WRITE_HINTS.search(_normalize(surface)) or _compound_write_name(tool))


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
