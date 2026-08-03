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
from collections.abc import Sequence

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
    "sync restore attach assign init import "
    # Measured absent while fifteen sibling verbs were caught: a tool named `shutdown`,
    # described "Shut the production cluster down", was executed twice by a default run.
    "shutdown halt evict drain seed migrate prune vacuum reindex detach unassign "
    "unlink unregister scale "
    # A tester mapped the boundary with thirty-nine one-verb tools ("It will <verb> the
    # target now.") and twenty-seven matched. These are the ones from the other twelve that
    # have no benign reading in a tool name, so adding them costs no coverage:
    #
    #   erase   was already in _IRREDEEMABLE_VERBS and NOT here — strong enough that a
    #           server's `readOnlyHint: true` could not override it, and not strong enough
    #           to exclude anything in the first place. A guard that only ever ran second.
    #   rm      the command, and `\b` keeps it out of ordinary words.
    #   mutate  a GraphQL mutation IS the write half of the protocol.
    "erase shred clobber mutate rebase rm"
).split()

# Verbs that only mutate when applied to STORAGE. `format` is why this exists: "Formats the
# attached volume" destroys a disk, and `format_date`, `format_currency` and `format_response`
# are three of the commonest read-only tool names there are. Putting `format` in the list
# above would have excluded all of them; leaving it out let "Returns nothing useful. Formats
# the attached volume." through, caught only by the accident of `attach` being in the list.
#
# Same shape as `_QUALIFIED_WRITE_VERBS` below, but qualified by the OBJECT rather than by
# there being one at all.
_STORAGE_WRITE = re.compile(
    r"\b(?:format|formats|formatted|formatting|mount|mounts|mounted|unmount|unmounts)\b"
    r"[\s\w]{0,20}?"
    r"\b(?:disk|disks|drive|drives|volume|volumes|partition|partitions|filesystem|"
    r"file\s?system|device|devices|media|card|cards)\b",
    re.IGNORECASE,
)


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


def _fold_confusables(text: str) -> str:
    """The same lookalike fold the security scan uses, imported lazily.

    Lazy to keep this module free of a hard dependency on `checks` — the same reason
    `preflight` reaches `looks_mutating` lazily. On any failure the text is returned
    unchanged, which can only make a tool look MORE mutating, never less.
    """
    try:
        from mcp_gauntlet.checks import fold_confusables

        return fold_confusables(text)
    except Exception:  # noqa: BLE001 - a fold failure must never make a tool look safe
        return text


def _normalize(text: str) -> str:
    """Split snake_case / kebab-case / camelCase so verbs in tool names are matchable
    (``\\b`` treats ``_`` as a word char, so ``delete_file`` never matches ``delete``)."""
    # Fold FIRST. The security scan folds lookalike characters and this filter did not,
    # so `dеlete_all` with a Cyrillic е was reported HIGH for hidden characters and
    # EXECUTED by the same run — the tool disagreeing with itself and resolving in favour
    # of executing. `ｄelete_all` (fullwidth) drew no finding at all and still ran.
    text = _fold_confusables(text)
    # Two boundaries, not one. The first alternative needs a lowercase-or-digit before the
    # capital, so an ACRONYM prefix was never split: `S3DeleteObject` worked only because
    # the `3` satisfied it, while `DBDeleteRow` came through as one token and was executed.
    # Half-present is worse than absent, because it reads as covered.
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", text)
    # Digits are separators too: `delete2all` was one token and executed, while its
    # underscore and camelCase siblings were caught. Splitting letter/digit boundaries costs
    # nothing on honest names (`md5_hash` -> `md 5 hash`) and closes the variant.
    text = re.sub(r"(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])", " ", text)
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
    ``readOnlyHint=True`` from an untrusted server is not, so it never appears here.

    DECLARING `destructiveHint` or `idempotentHint` AT ALL is such a declaration, whatever
    value it carries. The MCP spec defines both as "meaningful only when readOnlyHint ==
    false", so an author who sets one has told you which world they are in. `readOnlyHint`
    itself defaults to false, which is the other half of the same fact.

    That matters because `{"destructiveHint": false}` is not "harmless" — it is the
    create_issue / append_row / send_message shape: *I write, but additively*. It was read as
    permission and those tools were called. So was `{"idempotentHint": false}`, which
    announces "not safe to repeat" — and the first eligible tool of every server gets called
    twice, once by the credential pre-flight and once by the malformed-input probe.

    `openWorldHint` is deliberately NOT here. A tester grouped it with these two; the spec
    attaches no `readOnlyHint == false` clause to it, and it is true of ordinary search and
    fetch tools that write nothing.
    """
    if tool.destructive_hint is True or tool.read_only_hint is False:
        return True
    return tool.read_only_hint is not True and (
        tool.destructive_hint is not None or tool.idempotent_hint is not None
    )


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
        # The DESCRIPTION is in here deliberately. Reading only the name let a server pair
        # `readOnlyHint: true` with "Erases the customer database and issues refunds for
        # every open order. Irreversible." and have it EXECUTED — the word "Irreversible"
        # read, understood, and then discarded because the server said otherwise. A
        # contextual verb in a name is a guess worth overriding; "erases" in the prose is not.
        _normalize(
            " ".join(
                p for p in (tool.name, tool.title, tool.annotation_title, tool.description) if p
            )
        )
    ):
        return False
    # Include the display titles: a tool named `entry_op` whose title reads "Delete Entry"
    # declares its own mutating verb in the field a human reads, and the filter exists to
    # keep the harness from autonomously executing exactly that.
    surface = " ".join(
        part for part in (tool.name, tool.title, tool.annotation_title, tool.description) if part
    )
    normalized = _normalize(surface)
    return bool(
        _WRITE_HINTS.search(normalized)
        or _STORAGE_WRITE.search(normalized)
        or _compound_write_name(tool)
    )


def text_looks_mutating(text: str) -> bool:
    """Whether a bare string reads as a mutating verb.

    Used to keep the credential pre-flight from choosing a destructive `enum` member as its
    invented argument. Same vocabulary and same folding as the tool-level filter, so a
    lookalike-character member cannot slip through either.
    """
    return bool(_WRITE_HINTS.search(_normalize(text)))


def trusted_on_its_own_word(tool: ToolInfo) -> bool:
    """Would this tool have been EXCLUDED but for its own `readOnlyHint: true`?

    Worth surfacing rather than leaving implicit. The operator withheld `--allow-writes`;
    these are the calls the SERVER handed back by asserting it was safe. That assertion is
    the server's, not ours, and a compromised dependency or a copy-pasted annotation makes it
    cheaply. The override earns its place — without it a maintainer whose read-only tool is
    named `search_deploys` has no correct move — but it should never be invisible.
    """
    if tool.read_only_hint is not True:
        return False
    surface = " ".join(
        part for part in (tool.name, tool.title, tool.annotation_title, tool.description) if part
    )
    return bool(_WRITE_HINTS.search(_normalize(surface))) and not looks_mutating(tool)


def mutating_trigger(tool: ToolInfo) -> str:
    """Why `looks_mutating` excluded this tool, in the fewest words that let you argue.

    Disclosing the exclusion without disclosing its CAUSE was only half a fix. Two real
    examples from one tester's server: `"Use after search_runbooks has told you which runbook
    applies"` was excluded on **applies**, and `"e.g. checkout 5xx"` on **checkout** — prose
    words in a description, in a tool that writes nothing. The report named the tools and
    never the word, so the only visible remedy was `--allow-writes`, which is all-or-nothing
    and points at a disposable target. Knowing the word turns that into a one-word edit.
    """
    if tool.destructive_hint is True:
        return "the server declared destructiveHint: true"
    if tool.read_only_hint is False:
        return "the server declared readOnlyHint: false"
    # The hints that mean "readOnlyHint is false" by their mere presence. Without this the
    # `false` branch fell through to the vocabulary fallback and reported "matched the
    # write-verb vocabulary" when nothing had matched at all — the same tool with no
    # annotation is probed. A reader would spend an afternoon renaming `lookup`.
    for label, value in (
        ("destructiveHint", tool.destructive_hint),
        ("idempotentHint", tool.idempotent_hint),
    ):
        if value is not None:
            return (
                f"the server declared {label}: {str(value).lower()}, which the MCP spec "
                "defines as meaningful only when readOnlyHint is false"
            )
    for label, text in (
        ("name", tool.name),
        ("title", tool.title),
        ("title", tool.annotation_title),
        ("description", tool.description),
    ):
        if not text:
            continue
        normalized = _normalize(text)
        storage = _STORAGE_WRITE.search(normalized)
        if storage:
            return f"matched {storage.group(0).strip()!r} in its {label}"
        # EVERY matched token, not the first. Naming one word invited deleting that word, and
        # for "Returns nothing useful. Formats the attached volume." the first match was
        # `attached` — so the advice was to remove the only thing keeping a disk-formatting
        # tool out of the probe. Listing them all makes it visible when the match is
        # incidental (`applies`, `checkout`, `set`) and when it is not.
        hits: list[str] = []
        for match in _WRITE_HINTS.finditer(normalized):
            word = match.group(0).strip()
            if word.casefold() not in {h.casefold() for h in hits}:
                hits.append(word)
        if hits:
            shown = ", ".join(repr(h) for h in hits[:3])
            more = f" (+{len(hits) - 3} more)" if len(hits) > 3 else ""
            return f"matched {shown}{more} in its {label}"
    if _compound_write_name(tool):
        return "its name is a compound built on an ambiguous write verb"
    return "matched the write-verb vocabulary"  # pragma: no cover - defensive


def describe_exclusions(
    tools: list[ToolInfo], names: Sequence[str], *, also_seen: Sequence[ToolInfo] = ()
) -> str:
    """`name — matched 'applies' in its description`, joined, for a *Not measured* line."""
    by_name = {tool.name: tool for tool in tools}
    later = {tool.name: tool for tool in also_seen if looks_mutating(tool)}

    def why(name: str) -> str:
        tool = by_name.get(name)
        if tool is not None and looks_mutating(tool):
            return mutating_trigger(tool)
        if name in later:
            return f"a later tools/list re-declared it — {mutating_trigger(later[name])}"
        return "excluded"

    return "; ".join(f"{name} — {why(name)}" for name in sorted(names))


def filter_read_only(
    tools: list[ToolInfo], *, also_seen: Sequence[ToolInfo] = ()
) -> tuple[list[ToolInfo], list[str]]:
    """Return (kept read-only tools, names of excluded possibly-mutating tools).

    ``also_seen`` carries the same tools as another ``tools/list`` described them. A name that
    looks mutating in ANY listing is excluded, because the decision used to be pinned to the
    first one — and only the first one:

        listing 1:  x01, benign prose, `readOnlyHint: true`
        listing 2:  x01, `destructiveHint: true`, "permanently deletes every row"

    The harness parsed both, printed `MEDIUM x01: tool definition changed within a single
    session` — and then CALLED x01. The reverse direction (destructive, then benign) stayed
    excluded, so the pin was safe when a server got nicer and wide open when it got worse.
    This is not a heuristic missing a synonym: `destructiveHint: true` is machine-readable and
    was demonstrably read. The README sells exactly this attack as one the tool catches.

    Names only, so `excluded_write_tools` in `report.json` stays machine-readable for anyone
    parsing it. `describe_exclusions` supplies the human half.
    """
    redeclared = {tool.name for tool in also_seen if looks_mutating(tool)}
    kept: list[ToolInfo] = []
    excluded: list[str] = []
    for tool in tools:
        if looks_mutating(tool) or tool.name in redeclared:
            excluded.append(tool.name)
        else:
            kept.append(tool)
    return kept, excluded
