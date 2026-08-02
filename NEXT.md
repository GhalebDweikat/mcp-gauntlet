# What happens next — after 0.9.4

**Test BEFORE tagging, not after.** Round four ran against the published 0.9.3 wheel and
found two defects *in that release*: a line break switched every capping security check off,
and a server that failed every call scored Robustness 100.0 and graded A. Both had shipped.
The plan said to release then test; that order was wrong and the next round runs first.

Everything below this line was written before 0.9.4 and still holds, except that the
comparability baseline is now published 0.9.4 and the stability bar has **three** consecutive
clean data points rather than two.

---

# What happened after 0.9.3

Working plan, written so it survives a context reset.

**State as of writing (2026-08-02):** `v0.9.3` is tagged, released and on PyPI. The wheel was
verified on `mcp` 1.29.0 and 2.0.0 before tagging — exit codes `0/1/2/3/4` correct on both,
malicious fixture `C 75.0` on both — and the publish workflow's own `verify-published` job
passed on Linux and Windows. All five bundled fixtures score identically to published 0.9.2,
dimension by dimension: **that is the second consecutive release with no movement on an
unchanged server**, which is the `METHODOLOGY.md` v1.0 stability bar.

A fourth black-box round ran against the 0.9.3 wheel. Its findings are the input to whatever
comes next.

---

## The thing that went wrong this release, and must not repeat

**CI was red for twelve consecutive commits — including `Cut 0.9.2` — while
`scripts/gates.sh` exited 0 on the machine each of them was pushed from.** Nobody looked at
the actual runs. Two causes, both environment-dependent:

- Nine assertions searched for a word in console output. Rich emits colour when it thinks it
  is being watched, which a CI runner is and a developer's captured test output is not, and
  its highlighter splits a token into separately-styled runs — so `--fail-under` is genuinely
  not a substring of the coloured render of a message containing it.
- `tempfile.TemporaryFile` is typed differently per platform in typeshed, so a `type: ignore`
  that is *required* on Windows is *unused* on Linux, where `warn_unused_ignores` fails.

Fixed both, and `gates.sh` now exports `FORCE_COLOR=1` so the local run reproduces the colour
half. **The platform half cannot be reproduced locally at all.** So the rule is now:

> A green local gate is evidence about one machine. Before tagging, read the actual CI run.

```bash
gh run list --workflow=CI --limit 3
```

`gh` is installed and authenticated; the release can be driven end to end with it.

---

## The release drill that worked, in order

1. **Write the CHANGELOG entry first, then reproduce every claim in it** against the built
   wheel — not the source tree. Three consecutive releases shipped a statement a reader could
   disprove in ten minutes. That is the failure this project is least able to afford.
2. **Re-measure comparability against the *published* previous version** rather than
   asserting it. `scratchpad/compare_releases.sh` does this: every bundled fixture, run under
   `uvx mcp-gauntlet@<previous>` and under this tree, compared dimension by dimension.
3. **Verify the exit contract `0/1/2/3/4` from the BUILT WHEEL in a bare environment, on both
   SDK eras.** `scratchpad/exit_contract.sh` does this — it builds a throwaway venv per era,
   because 1.x and 2.x cannot share an interpreter.
4. **`bash scripts/gates.sh` must exit 0** — check the exit *code*, not the summary line.
   Piping it into `tail` masks the status and has already caused one red push.
5. **Read the CI run** (see above). New, and the reason this list exists.
6. Tag, push, `gh release create`; the publish workflow does PyPI via OIDC and then verifies
   the published wheel on both platforms. Check that job too.

---

## The v1.0 bar, and where it stands

`METHODOLOGY.md` sets four conditions.

- **Stable for one server across two consecutive releases** — **met**, measured, twice:
  0.9.1 → 0.9.2 and 0.9.2 → 0.9.3, all five fixtures, no movement.
- **Every check documented and actionable** — close. `docs/known-gaps.md` runs G1–G13, and
  0.9.3 gave the last unlocated finding a location.
- **No new false-positive class found in the release window** — the black-box round is what
  decides this, and adversarial testing against *honest* servers is part of the release
  rather than a follow-up.
- **The gate is severity-based with exit codes as a contract** — met and verified per release.

The largest thing still missing is not on that list: **there is no suppression mechanism.**
No `--ignore`, no `--baseline`, no allowlist. `known-gaps.md` says so twice, in G7 and G13,
because it is the escape hatch that both of those gaps need. A CI gate that cannot be told it
is wrong gets commented out. The official MCP conformance suite already ships
`--expected-failures`. This is probably the next feature, not the next fix.

---

## Popularization

`research/12-gtm-plan-v2.md` (gitignored, local only). Read it before doing any promotion.
The three findings that changed the plan:

- **PyData Global's CFP closes 3 August 2026.** `docs/eight-times-i-measured-something-else.md`
  is already a complete 30-minute talk; the abstract then feeds four more open CFPs.
- **Show HN is dead for this pitch specifically.** 1,313 Show HN posts mentioning MCP since
  March; 18 cleared 30 points. Every MCP *testing tool* scored 1–7 — including one whose
  pitch is nearly verbatim this project's, at 2 points. HN is very much alive for MCP
  *findings*: the essay as an ordinary story, never with the `Show HN:` prefix.
- **The 0.9.0 positioning is occupied.** `KryptosAI/mcp-observatory` — CI-native security
  testing, attack simulation, schema drift detection, GitHub Action, SARIF — 190★. The README
  line "Static scanners read your code. This runs your server." is falsifiable in ninety
  seconds now.

Front doors fixed already: the PyPI `Leaderboard` link that 404'd is gone, and the GitHub
description, homepage and topics are current.
