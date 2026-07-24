# Changelog

All notable changes to mcp-gauntlet are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

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
