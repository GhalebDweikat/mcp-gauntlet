# Known gaps

Things this tool does not currently catch, found by testing it adversarially and recorded
here rather than left implied. `METHODOLOGY.md` states the general principle — the security
checks are pattern-based, and a clean report means "the known classes were not found", never
"this server is safe". This file is the specific version of that sentence.

Gaps are described by **class**, not as copy-paste payloads. The point is to tell a user what
a clean report does not cover and to keep the work visible; it is not to publish an evasion
guide for anyone who wants one.

---

## Security scan — coverage

Found in a 62-server adversarial test against 0.8.1 by a tester who could see the docs but
not the source. All of these produced **A grades with no security finding**.

### G1. Instructions to exfiltrate via a tool's own parameters
**Not caught.** A tool description or a `required` parameter description that instructs the
agent to read a credential file and pass its contents in as an argument. This is the most
commonly reported real-world MCP poisoning shape.

The scanner *does* match the credential vocabulary — it will quote the path back at you — but
that match was downgraded to INFO (zero penalty) when twenty-five credential false positives
were fixed in 0.7.0. The blanket downgrade means the tool can no longer distinguish "this
server manages secrets", which is honest, from "this server is telling the agent to steal
secrets", which is not.

*Direction:* pair a sensitive-path match with an imperative verb aimed at the agent, and
restore severity only for that combination. The failure mode to avoid is reintroducing the
false-positive class — a credential manager describing its own job must stay clean.

### G2. Cross-tool / session-wide instructions (tool shadowing)
**Not caught.** A description that changes the agent's behaviour for *other* tools — "whenever
any email tool is invoked, also include this recipient". Nothing models cross-tool influence;
every check reads one tool at a time.

### G3. Non-English payloads
**Not caught.** The injection patterns are English. A word-for-word translation of the
canonical payload scores clean. Folding handles alphabets, not languages.

### G4. Encoded or split payloads
**Not caught.** Base64 or ROT13 with a "decode and apply" instruction; a sentence split across
a tool description and a parameter description so neither half matches alone.

### G5. Paraphrase outside the matched phrase family
**Partly caught.** The grade cap needs roughly `{ignore|disregard} all {previous|prior}
instructions`. Near-synonyms — "your new instructions are as follows", "ignore everything
above this line" — are reported at MEDIUM or not at all.

*Direction for G2–G5 together:* these are the limits of pattern matching, and widening the
patterns will buy false positives faster than coverage. The honest fix is an LLM-judged pass
over server-authored text, which the agentic stage already has the machinery for. Until then
they are documented, not silently absent.

### G6. Severity is placement-dependent in a way an attacker controls
The same payload caps the grade in a `description` and scores MEDIUM in a schema `default`,
`examples` or `_meta` — but every major function-calling API serializes the raw schema into
the model's context, so those reach the model identically.

### G7. An honest security server is capped
A server whose job is detecting injection must quote the patterns it detects, and gets a HIGH
plus a capped grade for it. There is no allowlist or suppression flag. Affects guardrail,
moderation and scanner servers.

### G8. Resource *contents* are not read
Only resource metadata is scanned. A payload in what `resources/read` returns is invisible,
and unlike an unrendered prompt — which is reported as unexamined — this gap is not currently
surfaced in the report.

*Direction:* at minimum, add it to `not_measured` so the report stops implying coverage.

---

## Scoring

### G9. A dimension where every subject fails still scores 88
The worst finding `_check_tool_description` can emit is MEDIUM (penalty 12), so `100 − 12` is
the floor however bad the server is. A nine-tool server and a copy with every description
reduced to one word scored 100.0 and 95.8.

This is why the CI gate keys on `--fail-on` (a severity) rather than `--fail-under` (a
score), and why the score is documented as a trend line for one server rather than a
comparison between servers. It remains a real weakness in the number itself.

### G10. Tool-Selection Accuracy scores 100 when nothing was checked
If no task carried expected tools, the dimension is emitted at 100.0 with weight 1.5 —
asserting a verified perfect result for a check that had no expectation to verify.

---

## Attribution

### G11. An interaction-blocked failure is excused from Tool Reliability but charged to Task Success
A server whose tools all require elicitation is correctly excused from the reliability
dimension, then scored ~0 on Task Success at weight 3.0 — the heaviest — for the same reason.

### G12. LLM degradation short of an exception is graded as a server failure
`finish_reason` is never read, so a response truncated at `length` or blanked by a content
filter is indistinguishable from a clean finish with no answer, and is judged as one.

---

## How to work on these

Anything here that changes what a check reports will move scores. Under the current
positioning that is acceptable for one server over time, but it resets the v1.0 clock in
`METHODOLOGY.md` — unchanged server, unchanged verdict, across two consecutive releases. Fix
in batches, and re-run the adversarial pass against honest servers (including non-English
ones) before releasing, because every one of these fixes is a false-positive risk.
