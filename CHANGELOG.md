# Changelog

All notable changes to mcp-gauntlet are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-07-24

A reliability and scoring-integrity release. A second adversarial review of the whole
workspace found that the harness could lose a paid evaluation to an edge-case input, hang
indefinitely on an unresponsive server, publish a ranking that favoured servers it had
never tested, and be evaded by a poisoned description written one level below where the
scanner looked. All four are closed, each with regression tests.

### Fixed

- **A hung tool can no longer hang the run.** Every agent tool call is bounded by
  `--tool-timeout` (default 60s) and recorded as a failed call against the server's Tool
  Reliability rather than stalling; one hang ends the agent evaluation, and a HIGH finding
  names the limit and the flag that raises it. A new `--timeout` on `run` (default 900s,
  `0` disables) bounds the hangs no inner timeout reaches — connect, `initialize`,
  `tools/list`.
- **The leaderboard no longer co-ranks scores that aren't comparable.** The overall is a
  weighted mean over the dimensions *present*, so a server the agent never scored skipped
  Agent Task Success (the heaviest dimension), averaged over a smaller denominator, and
  could outrank servers that earned their number. The ranked table now holds only fully
  agent-scored servers; the rest appear under **Partially evaluated** with the reason they
  weren't ranked, and a run truncated by a hang is segregated too.
- **Making a server untestable no longer raises its grade.** Robustness was skipped
  whenever nothing was probeable, and a skipped dimension *raises* a weighted mean. It is
  now always reported, tools that declare no enforceable argument contract score zero, and
  the prober understands `enum`, `const`, `anyOf`/`oneOf`, `$ref`, `allOf`,
  `patternProperties` and `additionalProperties` — the shapes pydantic and
  zod-to-json-schema actually emit, which were previously skipped in silence.
- **The injection scanner can no longer be evaded by nesting.** It read only top-level
  property descriptions, so a payload behind a `$ref`, inside an `allOf`, two levels deep,
  or in `items` was never examined. Since the whole input schema is serialized into the
  model's prompt, *every* string in it is now scanned — titles, enums, defaults, examples,
  `$defs` entries and unknown extension keywords included — with sample data and
  identifiers held to a deliberately looser standard so honest servers aren't penalised
  for naming their own credential field or pasting a sample value.
- **A zero-tool server keeps its security findings.** The N/A branch replaced the
  dimensions wholesale, discarding a poisoned `instructions` block along with the critical
  flag.
- **Reports survive a rendering failure.** The JSON/Markdown/HTML report is written before
  the console summary is drawn, and server-controlled text is escaped, so hostile markup or
  an unencodable glyph can no longer discard a completed evaluation.
- **Edge-case inputs degrade instead of crashing:** nullable type arrays, non-string
  `required` entries, wrong-shape task-cache and LLM JSON, empty `choices`, and malformed
  judge verdicts (`NaN`, `Infinity`, a non-boolean `success`) are all handled.
- A failed task generation is no longer cached, and now reports as inconclusive rather than
  as a clean skip.

### Added

- **`leaderboard --render-only`** rebuilds the site from saved results with no LLM spend.
  Each server's raw report is persisted to `servers/<name>.json`, so changing how results
  are *presented* no longer means paying to measure them again.
- **`--tool-timeout`** and **`--timeout`** flags (see above), on both `run` and
  `leaderboard`.
- `--servers` files may now be UTF-8, UTF-8-with-BOM, or UTF-16 — the encodings Windows
  shells produce — and a malformed one reports a clear error instead of a traceback.

### Changed

- `jsonschema` is now a declared dependency. It was imported directly but only reachable
  transitively, so a resolver that dropped it would have broken Schema Health at import.

## [0.2.0] — 2026-07-24

A security-hardening and correctness release. The static and dynamic checks were
adversarially reviewed and toughened throughout, and the harness gained runtime
tool-poisoning detection.

### Added

- **Response Safety — dynamic tool-poisoning detection.** The live agent run now scans
  each tool's actual **output** for prompt-injection / poisoning markers and hidden
  characters, catching a server that looks clean at list-time but poisons at call-time.
  Reported (and it lowers the score) but never caps the grade on its own, since a
  fetch/filesystem server may faithfully pass through untrusted content. The leaderboard
  shows a distinct ⚡ marker for it.
- **`--base-url`** flag on `run` / `leaderboard` / `doctor`, so any OpenAI-compatible
  endpoint (vLLM, LM Studio, a gateway) works, not just the built-in providers.
- The server's init **`instructions`** string is now scanned for injection — it's fed to
  the model as system context, so it's a server-authored poisoning surface.

### Fixed

- **Judge prompt-injection:** a malicious server could talk the LLM-judge into scoring a
  failed run as a success via crafted tool output. The judge now renders the run as one
  escaped JSON value (structural containment) with a hardened prompt; an errored tool
  call can never establish success.
- **Read-only safety filter:** now matches inflected verbs ("Creates"/"Sends") and
  snake_case / camelCase names (`delete_file`), covers financial/lifecycle verbs, and
  honors MCP `readOnlyHint` / `destructiveHint` (conservatively).
- **Injection scanner:** hardened against reworded evasions and invisible-character
  smuggling (variation selectors, combining marks, bidi overrides) while no longer
  false-capping honest servers; a latent bug where `.env`/`.ssh` file tokens never
  matched is fixed.
- **Windows** stdio server commands with backslash paths (`C:\...`) are no longer
  mangled by POSIX shell splitting.
- A server exposing **no tools** now grades **N/A**, not A/100.
- `tools/list` **pagination** is followed (bounded, deduped) instead of reading one page.
- A **hallucinated** tool call (a name the model invented) is attributed to the agent,
  not counted against the server's Tool Reliability.
- **Robustness** now scores the *fraction* of tools that reject malformed input (a server
  that validates nothing trends toward 0, not 88).
- Leaderboard filename **slug collisions** are de-duplicated.

### Changed

- CI runs a Python **3.11 / 3.12 / 3.13** matrix; the CI example pins the gauntlet version
  for reproducible gates.

## [0.1.0] — 2026-07-23

Initial release: agentic evaluation harness for MCP servers — static checks (schema,
description, security), a live agent task-success evaluation, tool-selection and
reliability signals, robustness probes, an HTML report, and a public leaderboard.
