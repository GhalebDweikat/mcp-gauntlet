"""Decide whether a server is even usable before paying to evaluate it.

A large share of publicly listed MCP servers are hosted commercial products. They install,
connect, and answer ``tools/list`` perfectly — and then fail every actual call because no
account was supplied. Scored naively that is Tool Reliability 0 and a published D or F for a
server that is fine, blamed for a configuration *we* declined to provide. That is the same
mistake as generating tasks about directories that do not exist, one level up, and it would
land on named third parties.

So: make a few cheap calls before the LLM spend starts. If the server turns out to be a wall,
say so and score nothing.

**Why this is not a word list.** It was one, and a word list cannot tell "this server
rejected my token" from "this server is telling me about a token". It missed `token expired`,
`Bad credentials`, `invalid_auth`, `ExpiredToken` and every non-English message — three of
four wrongly-credentialed servers in one adversarial scan came back A 100.0, exit 0 — while
convicting a JSON linter that said `invalid token at line 4`. Both failures are the same
failure: prose is not a channel.

What decides now, in order:

1. **A machine-readable rejection.** An HTTP 401/407, or a JSON-RPC error carrying an
   identifier-shaped auth code (`invalid_token`, `ExpiredToken`, `invalid_auth`). These are
   protocol artefacts, not sentences, and no honest server emits one about your *input*.
   Any one of them decides on its own, in any language.
2. **A wall, not a complaint.** Failing that, auth-shaped prose has to appear for at least
   *two different tools* — or for a tool we sent no arguments to at all. A credential wall is
   uniform; a complaint about content is specific to the content. The linter passes because
   its other tools work, and one success anywhere still clears the server outright.

The prose vocabulary survives as corroboration, and the residual is documented in
`docs/known-gaps.md` G13 rather than claimed as closed.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from mcp import ClientSession

from mcp_gauntlet.adapters import adapter
from mcp_gauntlet.content import block_text
from mcp_gauntlet.errors import causes, http_status
from mcp_gauntlet.models import ToolInfo

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------- machine-readable signals

# Statuses that mean the CALLER was not accepted. 403 is deliberately absent: it is what a
# sandboxed filesystem server correctly says about a path outside its root. A 403 only counts
# when it arrives with a `WWW-Authenticate` challenge or an OAuth code beside it — which is
# how a scope-expired token actually presents, and how it stays distinguishable from a
# server enforcing its own boundary.
_HTTP_AUTH_STATUSES = frozenset({401, 407})
_HTTP_AUTH_STATUSES_NEEDING_SUPPORT = frozenset({403})

# Identifier-shaped codes, matched against a WHOLE structured value rather than searched for
# inside prose. That distinction is the entire point: `invalid_token` as the value of an
# error field is a machine saying "your credential is bad"; the same two words inside a
# sentence may be a linter describing line 4. Stored pre-normalised — see `_normalise_code`.
_MACHINE_AUTH_CODES = frozenset(
    {
        # RFC 6749 / 6750, i.e. anything speaking OAuth
        "invalidtoken",
        "expiredtoken",
        "invalidgrant",
        "invalidclient",
        "unauthorizedclient",
        "insufficientscope",
        "invalidbearertoken",
        # Slack, and the many APIs that copied its vocabulary
        "invalidauth",
        "notauthed",
        "tokenexpired",
        "tokenrevoked",
        "accountinactive",
        "missingscope",
        # AWS
        "expiredtokenexception",
        "invalidclienttokenid",
        "unrecognizedclientexception",
        "invalidaccesskeyid",
        "signaturedoesnotmatch",
        "authfailure",
        "missingauthenticationtoken",
        # generic, but only ever meaningful as a whole machine value
        "unauthenticated",
        "unauthorized",
        "authenticationerror",
        "authenticationfailed",
        "authenticationrequired",
        "invalidapikey",
        "invalidcredentials",
        "missingcredentials",
        "permissiondenied",
    }
)


def _normalise_code(text: str) -> str:
    """Fold an identifier to comparable form: `Invalid_Token` and `invalid-token` agree."""
    return re.sub(r"[^a-z0-9]", "", text.casefold())


def _walk_strings(value: Any, *, depth: int = 0) -> Iterator[str]:
    """Every string inside a JSON-ish blob, bounded so a hostile payload cannot spin us."""
    if depth > 4:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in list(value.values())[:32]:
            yield from _walk_strings(item, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in list(value)[:32]:
            yield from _walk_strings(item, depth=depth + 1)


def machine_auth_code(data: Any) -> str | None:
    """An identifier-shaped auth code carried in a JSON-RPC error's structured `data`.

    Whole-value only, and length-capped: a 300-character sentence is prose whatever words it
    contains, and prose is what the old check could not read correctly.
    """
    for raw in _walk_strings(data):
        if len(raw) > 48:
            continue
        if _normalise_code(raw) in _MACHINE_AUTH_CODES:
            return raw
    return None


_CHALLENGE_ERROR = re.compile(r'error\s*=\s*"?([A-Za-z0-9_.-]+)"?')


def _challenge_code(response: Any) -> str | None:
    """The `error=` parameter of a `WWW-Authenticate` challenge, per RFC 6750 §3."""
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    try:
        challenge = headers.get("www-authenticate") or headers.get("WWW-Authenticate")
    except Exception:  # noqa: BLE001 - a header mapping we do not recognise tells us nothing
        return None
    if not isinstance(challenge, str):
        return None
    match = _CHALLENGE_ERROR.search(challenge)
    return match.group(1) if match else "challenge"


def rejected_the_caller(exc: BaseException) -> str | None:
    """A protocol-level "your credential was not accepted", or None.

    Reads the CHANNEL — HTTP status, JSON-RPC error code, structured error data — so it works
    on a server whose messages are in Japanese, and does not fire on a server whose messages
    happen to be about tokens. Everything it inspects is behind anyio's task-group wrapper,
    hence `causes`.
    """
    found = http_status(exc)
    if found is not None:
        status, response = found
        if status in _HTTP_AUTH_STATUSES:
            return f"HTTP {status}"
        if status in _HTTP_AUTH_STATUSES_NEEDING_SUPPORT:
            challenge = _challenge_code(response)
            if challenge:
                return f"HTTP {status} with a WWW-Authenticate challenge ({challenge})"

    for leaf in causes(exc):
        error = _error_payload(leaf)
        if error is None:
            continue
        # JSON-RPC reserves -32768..-32000; every other negative code is application-defined.
        # A POSITIVE 401 in that field is unambiguously a server echoing an HTTP status,
        # which several MCP servers do, and is the one numeric reading that is safe.
        code = getattr(error, "code", None)
        if isinstance(code, int) and code in _HTTP_AUTH_STATUSES:
            return f"JSON-RPC error {code}"
        machine = machine_auth_code(getattr(error, "data", None))
        if machine:
            return f"JSON-RPC error data: {machine}"
    return None


def _error_payload(exc: BaseException) -> Any:
    """The JSON-RPC error carried by an SDK protocol exception, however it is spelled.

    1.x's `McpError` wraps an `ErrorData` on `.error`; 2.0's `MCPError` takes `code` and
    `message` directly (see `_protocol_error` in the robustness tests). Both spellings are
    read, and `test_the_sdks_own_error_type_is_read_not_a_stand_in` asserts positively against
    whichever class the installed era actually raises — because if neither shape resolved,
    this would return None and the credential check would go quietly blind on that era, which
    is the failure `adapters.py` exists to prevent.
    """
    wrapped = getattr(exc, "error", None)
    if wrapped is not None and isinstance(getattr(wrapped, "code", None), int):
        return wrapped
    if isinstance(getattr(exc, "code", None), int) and hasattr(exc, "message"):
        return exc
    return None


# ------------------------------------------------------------------- corroborating prose

# Deliberately narrow. Each of these says "you did not give me a credential"; none of them
# is something a correctly-functioning server says about a legitimate request.
#
# Explicitly NOT included: bare "forbidden", "403", "permission denied", "access denied".
# Those are what a sandboxed filesystem server correctly says when asked for a path outside
# its root, and what a read-only database says about a write. Treating them as missing
# credentials would mark well-behaved servers unevaluable — the precise failure this module
# exists to prevent, inverted.
#
# No longer decisive on its own; see the module docstring. That is what made it safe to widen
# from the seven phrases it shipped with to the real-world vocabulary below.
_AUTH_MARKERS = re.compile(
    r"""(?ix)
    \bapi[\s_-]?key\b
  | \bunauthenti(?:cated|cation)\b
  | \bnot\s+authenticated\b
  | \bauthenticat(?:ion|e)\s+(?:required|failed|error)\b
  | \brequires?\s+authenti(?:cation|cating)\b
  | \bauthorization\s+(?:required|header\s+(?:missing|required))\b
  | \b(?:missing|invalid|expired|revoked|bad|no)\s+
      (?:api\s+|access\s+|bearer\s+|auth\s+)?(?:token|credential|credentials|key)\b
  | \b(?:token|credentials?|api[\s_-]?key|session|access[\s_-]?token)\s+
      (?:(?:has|have|is|are|was|were)\s+)?(?:been\s+)?(?:expired|revoked|invalid|not\s+valid)\b
  | \bcredentials?\s+(?:not\s+found|required|missing|rejected)\b
  | \b401\b
  | \b(?:sign\s?up|log\s?in|sign\s?in)\s+(?:required|to\s+use|at\b)
  | \bsubscription\s+required\b
  | \b(?:payment\s+required|402)\b
  | \bset\s+the\s+\w*_?(?:key|token|secret)\w*\s+environment\s+variable\b
  | \bbearer\s+token\s+(?:required|missing)\b
  | \binsufficient[\s_-]scope\b
  | \b(?:invalid_auth|not_authed|token_expired|expired_token|invalid_token
      |invalid_grant|unauthorized_client|insufficient_scope)\b
  | \bexpiredtoken\w*\b
  | \bmissingauthenticationtoken\b
    """
)

# Prose that carries auth vocabulary while plainly being ABOUT something the server was
# handed, rather than about the caller. Each family is here because a real server behaves
# this way, not to patch a test:
#
#   * a source location — a linter saying `invalid token at line 4`, a parser saying
#     `unexpected token at position 12`. A credential wall never knows a line number.
#   * assertion prose — a test runner reporting `expected 401 Unauthorized, got 200 OK`.
#     It is quoting a subject's behaviour, not describing its own.
#   * content integrity — a signature verifier saying `authentication failed for message
#     digest`. That is authentication OF A MESSAGE, a different sense of the word.
#
# Only ever a veto over PROSE. `SignatureDoesNotMatch` as a machine code still decides,
# because AWS really does reject callers that way and an identifier is not a sentence.
_ABOUT_THE_INPUT = re.compile(
    r"""(?ix)
    \b(?:line|lines|column|col|position|offset|byte|index|char(?:acter)?)\s+\d+
  | \bat\s+(?:line|column|position|offset|index|char(?:acter)?)\b
  | \bexpected\b[^.\n]{0,80}\bgot\b
  | \bassert(?:ion)?\s+(?:failed|error)\b
  | \b(?:parse|syntax)\s*error\b
  | \bjson(?:decode)?error\b
  | \bmalformed\s+(?:json|yaml|xml|input|document)\b
  | \bunexpected\s+(?:token|character|end\s+of)\b
  | \b(?:signature|message\s+digest|checksum|hmac)\b
    """
)


def looks_like_missing_credentials(text: str) -> bool:
    """Whether an *error* from a tool call reads as "you never authenticated".

    Corroborating evidence, not a verdict — `probe_credentials` requires this to hold for
    two different tools, or for a tool it sent nothing to, before concluding anything. On its
    own it convicted a JSON linter reporting `invalid token at line 4`.

    Only ever apply it to text from a call that actually failed. A search or fetch tool can
    legitimately *return* a document mentioning an API key, and flagging that would make a
    working server unevaluable on the strength of its own content.
    """
    if _ABOUT_THE_INPUT.search(text):
        return False
    return bool(_AUTH_MARKERS.search(text))


_PLACEHOLDER_BY_TYPE: dict[str, Any] = {
    "string": "test",
    "integer": 1,
    "number": 1,
    "boolean": False,
    "array": [],
    "object": {},
}


def minimal_valid_args(schema: dict[str, Any]) -> dict[str, Any] | None:
    """Trivially schema-valid arguments, or None if one cannot be constructed confidently.

    Only ever used to find out whether a call fails for AUTHENTICATION reasons. The result
    is otherwise discarded, which is what makes inventing values acceptable here: a server
    answering "no such directory" is not auth-shaped and is ignored, so a wrong guess costs
    a wasted call rather than a wrong verdict.

    Declines on anything it cannot satisfy honestly — an enum with no members, an unknown
    type, a required property the schema does not describe. A probe that gives up says
    nothing; a probe that guesses badly would say something false.
    """
    required = schema.get("required") or []
    if not isinstance(required, list):
        return None
    if not required:
        # Nothing is required, so `{}` already satisfies the schema — and this is the
        # zero-argument case the probe has always handled. Demanding a `properties` dict
        # here regressed it to "no candidates at all".
        return {}
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return None
    args: dict[str, Any] = {}
    for name in required:
        spec = properties.get(name)
        if not isinstance(spec, dict):
            return None
        # A DECLARED DEFAULT wins. The author wrote it precisely to say what should happen
        # when the caller does not choose, and ignoring it inverted the one that matters:
        # `dry_run: {type: boolean, default: true}` was sent as `false`, because booleans got
        # a blanket placeholder. "Don't actually do it" read and reversed.
        if "default" in spec:
            args[name] = spec["default"]
            continue

        if isinstance(spec.get("enum"), list) and spec["enum"]:
            # NEVER by position. Taking `enum[0]` made the harness pick the destructive
            # branch itself, with no attacker and no mislabelling anywhere:
            #
            #     "action": {"enum": ["delete_all_customers", "refund_every_order",
            #                         "list_customers"]}
            #
            # Bland name, bland description, no annotations — and a schema-valid call that a
            # real server executes normally. `["delete","list"]`, `["overwrite","append"]`,
            # `["production","staging"]` are ordinary orderings someone writes without
            # thinking. Prefer a member that reads as harmless; if every member looks
            # mutating, decline the tool entirely rather than guess which is least bad.
            from mcp_gauntlet.safety import text_looks_mutating

            members = spec["enum"]
            safe = [m for m in members if isinstance(m, str) and not text_looks_mutating(m)]
            if len(safe) != len(members):
                # ANY destructive-looking member disqualifies the whole tool, not just that
                # member. Picking the harmless branch would usually work, but "which member
                # is harmless" is itself a guess from the same word list that missed
                # `shutdown` — and the asymmetry is stark: guessing wrong executes a
                # destructive branch on a run whose entire premise was that nothing writes,
                # while declining costs one probe candidate on one server. A tool that
                # offers `delete_all_customers` at all is a tool this probe leaves alone.
                return None
            args[name] = safe[0]
            continue
        declared = spec.get("type")
        if isinstance(declared, list):  # a union — take the first usable member
            declared = next((d for d in declared if d in _PLACEHOLDER_BY_TYPE), None)
        if declared not in _PLACEHOLDER_BY_TYPE:
            return None
        args[name] = _PLACEHOLDER_BY_TYPE[declared]
    return args


def _probe_candidates(tools: list[ToolInfo]) -> list[ToolInfo]:
    """Tools this probe can call without doing damage, and without guessing wildly.

    Originally zero-required-argument tools only, on the reasoning that inventing an
    argument is how the task generator ended up asking servers about directories that never
    existed. That reasoning holds for SCORING a result and not for this: here the only
    question asked of the answer is "was this an auth failure", and an invented path
    produces a not-found error, which is not auth-shaped and is ignored.

    Restricting to zero-argument tools had a real cost. A server whose every tool takes a
    parameter — most servers — could not be probed at all, so a WRONG or EXPIRED credential
    was undetectable: the malformed-input probe hits the SDK's own argument validation
    before it ever reaches the server's auth check, and reads as a healthy rejection.
    """
    from mcp_gauntlet.safety import looks_mutating

    out = []
    for tool in tools:
        if looks_mutating(tool):
            continue  # never invent arguments for something that might write
        if minimal_valid_args(tool.input_schema) is None:
            continue
        out.append(tool)
    return out


@dataclass(frozen=True)
class _Rejection:
    """One probed call that came back looking like an authentication failure."""

    tool: str
    detail: str
    # True for a protocol-level signal — an HTTP status, a machine-readable code. Decides on
    # its own. False for prose, which has to be corroborated before it decides anything.
    decisive: bool
    # We sent this tool nothing at all, so whatever it is complaining about, it is not our
    # input. That makes a single prose rejection trustworthy where it otherwise would not be.
    argumentless: bool


async def probe_credentials(
    session: ClientSession, tools: list[ToolInfo], *, max_calls: int = 3
) -> str | None:
    """Describe how this server refused every call, or None if it did not.

    The string is a neutral OBSERVATION — "every probed tool was refused…" — because the
    caller knows something this function does not: whether credentials were supplied at all.
    Returning "needs credentials that were not supplied" from here produced a finding reading
    "every tool call failed despite the credentials supplied … needs credentials that were
    not supplied", one sentence contradicting itself in the middle.

    Conservative in both directions, and asymmetrically so. A single success anywhere clears
    the server outright. Absent a machine-readable rejection, auth-shaped prose must recur
    across two different tools, or come from a tool that was sent no arguments — because
    a credential wall is uniform and a complaint about content is not. Anything else — no
    probeable tool, ordinary errors, a transport failure — returns None and the evaluation
    proceeds, because refusing to score a server is itself a judgment that needs evidence.
    """
    candidates = _probe_candidates(tools)
    if not candidates:
        return None

    probed = candidates[:max_calls]
    rejections: list[_Rejection] = []
    for tool in probed:
        args = minimal_valid_args(tool.input_schema) or {}
        try:
            result: Any = await session.call_tool(tool.name, args)
        except Exception as exc:  # noqa: BLE001 - a probe must never break the evaluation
            # The JSON-RPC error channel, which the old check could not see at all: it read
            # `str(exc)` and nothing else, so a server that refused over `error` rather than
            # in an `isError` result was invisible however plainly it said so.
            signal = rejected_the_caller(exc)
            if signal:
                rejections.append(_Rejection(tool.name, f"{tool.name}: {signal}", True, not args))
            elif looks_like_missing_credentials(str(exc)):
                rejections.append(
                    _Rejection(tool.name, f"{tool.name}: {str(exc)[:160]}", False, not args)
                )
            continue
        sdk = adapter()
        if not sdk.result_is_error(result):
            return None  # something worked without credentials — the server is usable
        text = " ".join(t for block in sdk.result_content(result) if (t := block_text(block)))
        machine = machine_auth_code(sdk.result_structured(result))
        if machine:
            rejections.append(_Rejection(tool.name, f"{tool.name}: {machine}", True, not args))
        elif looks_like_missing_credentials(text):
            rejections.append(
                _Rejection(tool.name, f"{tool.name}: {text.strip()[:160]}", False, not args)
            )

    return _verdict(rejections, probed=len(probed))


def _verdict(rejections: list[_Rejection], *, probed: int) -> str | None:
    """Weigh the evidence. See the module docstring for why the order is what it is."""
    if not rejections:
        return None

    decisive = next((r for r in rejections if r.decisive), None)
    if decisive is None:
        distinct = {r.tool for r in rejections}
        if len(distinct) < 2 and not rejections[0].argumentless:
            # One tool, given arguments, complaining in words that happen to be about
            # authentication. That is as consistent with a signature verifier or a schema
            # validator describing what we handed it as with a wall, and there is no
            # allowlist to rescue a server this convicts wrongly.
            _log.debug(
                "credential pre-flight saw auth-shaped prose from only %s and let it pass",
                rejections[0].tool,
            )
            return None

    lead = decisive or rejections[0]
    _log.debug("credential pre-flight declined to score this server: %s", lead.detail)
    # "every tool call was rejected" got printed when some had not been, and "every" got
    # printed when exactly one tool was probeable. Both overstate the coverage of the very
    # claim they are making, which is the kind of thing that makes a reader stop believing
    # the accurate parts too. Say how many, out of how many.
    if len(rejections) < probed:
        subject, plural = f"{len(rejections)} of {probed} probed tools", True
    elif probed == 1:
        subject, plural = "the one probeable tool", False
    else:
        subject, plural = "every probed tool", False
    if decisive:
        how = f"{'were' if plural else 'was'} refused at the protocol level"
    else:
        how = "reported an authentication error"
    return f"{subject} {how} ({lead.detail})"
