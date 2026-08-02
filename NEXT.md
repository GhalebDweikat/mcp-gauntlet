# What happens next — 0.9.3 and after

Working plan, written so it survives a context reset. Gitignored alongside `PLAN.md` and
`REVIEW.md` if you'd rather it stay private; committed is fine too.

**State as of writing:** `v0.9.2` is tagged, published and verified on PyPI — exit codes
`0/1/2/3/4` correct on `mcp` 1.29.0 and 2.0.0, malicious fixture `C 75.0 capped` on both,
matching published 0.9.1. Three rounds of black-box adversarial testing fed
`docs/known-gaps.md`, which now lists thirteen gaps.

The order below is deliberate: **fix the one dishonest claim, then the papercuts, then
release, then test.** Not the other way round — the last three rounds each found their worst
defects in code written during the round before, so testing before releasing is what makes
the round worth running.

---

## 1. G13 — make the credential check structural  ← START HERE

The last place where a claim and the behaviour do not line up, and the reason this is first.

**What it does today.** `looks_like_missing_credentials()` in `src/mcp_gauntlet/preflight.py`
matches the error TEXT against a short English phrase list (`_AUTH_MARKERS`).

**What that costs.** It misses `token expired` — the word "expired" is not in the vocabulary
at all — plus `Bad credentials` (GitHub's own 401 body), `invalid_auth` (Slack),
`ExpiredToken` (AWS), `Not authenticated`, `Requires authentication`, anything non-English,
and **any failure delivered over the JSON-RPC error channel rather than as a tool result**.
Three of four wrongly-credentialed servers in a tester's scan came back **A 100.0, exit 0**.

It also convicts honest servers whose ordinary errors carry the vocabulary: a JSON linter
saying `invalid token at line 4`, a schema validator saying `Invalid API key format`, a
signature verifier saying `authentication failed for message digest`, a test runner saying
`expected 401 Unauthorized, got 200 OK`. There is no allowlist, and `--no-probe` silences
this check and the real one together.

**The fix is a different shape, not more words.** Key on the error CHANNEL and status — a
JSON-RPC error code, an HTTP status where one is available — and demote the phrase list to
corroboration. That also kills the false positives, because a linter's *successful* result
mentioning "invalid token" is not an error at all, and today's check cannot tell the
difference.

Full detail, including the tester's verbatim corpus of what slips and what false-fires, is in
`docs/known-gaps.md` **G13**. Read it before starting; it is written to be self-contained.

**Done when:** the sweep of real-world auth error strings in G13 is caught; the four honest
server shapes in G13 stay clean; and the JSON-RPC error channel is read.

---

## 2. The smaller findings still open

All from round three's testers. Each is small; together they are most of what a new adopter
trips over.

- **The G1 finding has no location.** It reports `tool: null`, rendered as `server:`, with no
  field path — and on the bundled malicious fixture produces four byte-identical findings.
  Every *other* security check locates itself precisely (`output property 'Entry'
  description`, `second tools/list: description`). On a 40-tool server this one points at
  server `instructions` that are clean. "A finding you cannot act on is worse than no
  finding" — and this is the newest code.
- **The read-only filter drops tools on incidental prose words**, silently as to *why*.
  `"Use after search_runbooks has told you which runbook applies"` → excluded on `applies`;
  `"e.g. checkout 5xx"` → excluded on `checkout`. The exclusion IS disclosed now (0.9.2 fix),
  but the message names the tools and never the word, and the only remedy offered is
  `--allow-writes`, which is all-or-nothing. Consider naming the matched token.
- **`scan` silently ignores unknown TOP-LEVEL keys** — `{"servers":[...],"failOn":"high"}` →
  exit 0, and `{"servers":[...],"env":["TOK=v1"]}` silently discards a credential. Per-entry
  unknown keys are correctly rejected; the top level is not. Same for a `headers` entry on a
  stdio server and an `env` entry on an http server: accepted, ignored, `A 100.0`.
- **Zero tools exits 3 at `--fail-on high` but 1 at `medium`/`low`.** "Nothing was measured,
  so neither pass nor fail is honest" does not stop being true when you tighten the gate.
- **`$` cannot be escaped in a header value** (`X-Price: cost is $5.00` → exit 4 claiming the
  variable is unset), and `$VAR` in a header NAME is not expanded but reaches the wire
  literally, silently.
- **Two HIGH findings for one auth fact**, and the first concatenates contradictory clauses
  ("despite the credentials supplied … needs credentials that were not supplied"). Also
  "every tool call was rejected" fires when some tools succeeded.
- **`known-gaps` G5 understates.** A description containing both cited paraphrase examples
  produced *zero* findings, not the MEDIUM the doc implies.
- **Ctrl-C exit code on Windows is `0xC000013A`, not 130.** A tester could not verify the
  documented 130 on Windows either way; the substantive promises (no report written, child
  reaped, no orphans) did hold. Either verify on Linux or scope the claim by platform.

---

## 3. Cut 0.9.3

Same drill as 0.9.2, which worked:

1. Write the CHANGELOG entry **first**, then reproduce every claim in it before tagging.
   Three consecutive releases shipped a statement a reader could disprove in ten minutes
   (the "eight HIGH findings" count, the comparability line, the "documented" `--out`
   default). That is the failure this project is least able to afford.
2. Re-measure comparability against the **published** previous version rather than asserting
   it — `good_server`, `bad_server`, `malicious_server`, all three, both SDK eras.
3. Verify the exit contract `0/1/2/3/4` on `mcp` 1.x **and** 2.x.
4. `bash scripts/gates.sh` must exit 0 — check the exit code, not the summary line. Piping it
   into `tail` masks the status, and that has already caused one red push.
5. Tag, push, publish; then verify the **published wheel** from PyPI before declaring done.

---

## 4. Then the black-box round

Four testers, distinct lenses, each given only the built wheel and the public docs, forbidden
from reading the source tree or any `.env`. The standing brief is in
`~/.claude/.../memory/feedback-black-box-testers-before-release.md`.

Lenses that have earned their place: **side-effect safety** (what does the harness execute
without `--allow-writes`), **adversarial security** (both directions — evasion AND false
positives on honest servers), **credentials/`scan`**, **fresh-eyes adopter** (run every
documented command exactly as written; reproduce every CHANGELOG claim).

Two instructions that produced the best findings, worth repeating verbatim: ask each tester
to state **in one sentence what the tool is for**, and to **reproduce the CHANGELOG's specific
claims**. The second has caught a false claim in every round.

---

## 5. Popularization

`research/07-gtm-plan.md` exists but is **stale** — its centrepiece was the public leaderboard
that 0.9.0 deleted. A subagent is rebuilding it at `research/12-gtm-plan-v2.md`, covering: who
the concrete user is, zero-budget channels ranked by expected return, which single artifact to
build first, what must be true before promoting at all, and a dated 30-day sequence.

Read that before doing any promotion.

---

## The v1.0 bar, for reference

`METHODOLOGY.md` sets it as **stable for one server across two consecutive releases** —
unchanged server, unchanged verdict. 0.9.1 → 0.9.2 is one clean data point, measured. One more
release without moving an unchanged server's grade and v1.0 is earned rather than declared.

The other three bars: every check documented and actionable; no new false-positive class found
in that window (adversarial testing against honest servers, including non-English, is part of
the release rather than a follow-up); and the gate is severity-based with exit codes as a
contract.
