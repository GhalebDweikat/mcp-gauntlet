# Changelog

All notable changes to mcp-gauntlet are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.5.0] — 2026-07-25

### Fixed

- **Task generation no longer invents the identifiers it tests with, and this was
  mis-grading real servers by two letters.** The generator saw only tool *descriptions*, so
  for any server whose tools take a path, a repository or a table name it had to make one
  up — and it made plausible ones up: `/workspace/assets`, `/var/repos/data-pipeline`. Every
  call then failed "not found" and the *server* was scored for it. On the public
  leaderboard, `filesystem` graded **D 67.3** and `git` **C 72.5**; correctly grounded they
  are **A 99.4** and **A 98.9**, with agent task success going 0.0 → 100.0 on both. Servers
  whose tools are self-contained (sqlite, memory) were never affected and scored A
  throughout, which is exactly why this looked like a real difference between servers.

  Tasks may now only use identifiers the harness can state as fact — the server's own
  command-line arguments, its zero-argument tools, its published resource URIs — or must
  discover them at runtime as their first step. The task cache key includes a prompt
  version, so servers already cached don't keep serving the old prompt's tasks.

### Added

- **A credential pre-flight.** Much of the public registry is hosted commercial software:
  it installs, connects and lists its tools perfectly, then fails every call because no
  account was supplied. Scored naively that is a published D or F for a server that is fine,
  blamed for a configuration the harness declined to provide. One cheap call now runs before
  any LLM spend; a server that reports an authentication error is reported as needing
  credentials and is **not scored at all**, in its own section of the leaderboard.

  Conservative by design, because refusing to score a working server is the worse error:
  only zero-argument non-mutating tools are probed, one success clears the server, an
  ordinary error is not a credential problem, and `forbidden` / `403` / `permission denied`
  are deliberately *not* treated as auth failures — a sandboxed filesystem server says
  exactly those when correctly refusing a path outside its root.
- **A `gated_server` fixture** reproducing that shape: valid schemas, good descriptions,
  grades A on a static read, and every call fails for want of an account.

### Changed

- **Scores are not comparable with 0.4.0** for any server whose tools take a path,
  repository, or similar identifier. Those servers were scored against tasks that could not
  succeed; they now are not.
- **The leaderboard points filesystem and git at fixed, committed scan targets.** Those
  servers score whatever you aim them at, so aiming them at a working checkout scored the
  checkout: the filesystem row was flagged over a sentence in a README mentioning a
  credential filename, and the git row diffed the board's own generated HTML and read the
  previous run's findings back to itself. Neither was reproducible by anyone else.
  `scripts/make_leaderboard_fixtures.py` builds the git target; METHODOLOGY explains the
  class of server this applies to.

## [0.4.0] — 2026-07-25

### Added

- **The negotiated MCP protocol revision is recorded** on every report. A score is only
  interpretable against the spec the server was speaking, and the protocol is changing.
  mcp-gauntlet targets revision **2025-11-25**; a server requiring one this harness doesn't
  support now says so plainly instead of failing with an opaque transport error, and is
  reported as a limitation here rather than a fault in the server.
- **All three MCP primitives are now scanned.** Prompts and resources were never touched,
  which mattered most for prompts: a `prompts/get` response is placed in the model's
  context *verbatim*, with none of the framing a tool result gets, making it the most
  direct injection surface the protocol has. Prompt metadata, arguments, and the messages
  a prompt actually returns are now scanned, along with resource and template metadata and
  every `_meta` block. Prompts are rendered only when probing is enabled — `--no-probe`
  still promises to execute nothing — and only when they take no required arguments, since
  inventing values would mean calling the server with data it never asked for.
- **Definition-drift detection.** A server can pass review, get installed, and *later*
  change what its tools say — the client re-reads the definitions on every connection but
  doesn't re-prompt, so the redefinition lands in the model's context silently. Registry
  signing can't catch it: the package is unchanged and correctly signed, only the runtime
  text differs. `tools/list` is now asked twice per session and the answers compared, and
  the surface is fingerprinted and compared against the previous run (`--no-track-drift`
  opts out). A definition that changed is scanned in its own right, so a payload appearing
  only in the second listing raises its own finding rather than a bare "something moved".
  The change itself never caps a grade — MCP has a `tools.listChanged` capability and
  honest servers register tools lazily or edit descriptions without bumping a version.
- **`mcp-gauntlet --version`.** Scores are only comparable within a version and the README
  tells you to pin one, so the tool has to be able to say which one is installed.
- **A bundled malicious demo server** (`mcp_gauntlet.fixtures.malicious_server`). Every
  tool has an innocuous description, so a description scanner finds nothing; the attacks
  live in a display title, in an output schema behind a `$ref`, in what a tool returns at
  call time, and in a tool that is clean on the first `tools/list` and poisoned on the
  second. The server is fully functional — valid schemas, working tools — which is the
  point: it is flagged for what it says and returns, not for being broken.

### Changed

- **The `mcp` dependency is now upper-bounded (`>=1.9,<2`).** `mcp` 2.0.0 is targeted for
  2026-07-28 — the same day the next protocol revision finalizes — and it renames
  `FastMCP`, replaces `ClientSession` with `Client`, and moves the types into a separate
  package. An unbounded pin would have broken every fresh `uvx mcp-gauntlet` on that date,
  for a release that had worked the day before. The bound comes off once the harness is
  tested against 2.0, not before.
- **Scores in Security Signals and Response Safety are not comparable with 0.3.x.**
  Prompts, resources and `_meta` are now scanned, definition drift is folded in, and
  Response Safety is normalized differently (below). Every report and leaderboard row
  records the version that produced it, which is what that stamp is for.

### Fixed

- **A single unencodable character could discard a finished evaluation.** A lone surrogate
  is valid JSON and a valid Python string but cannot be written as UTF-8, so one anywhere
  in a server's output made the report fail to serialize — losing a run the user had
  already paid an LLM provider for. Reports are now made encodable once at build time,
  covering every writer, and the character is escaped rather than dropped so a reviewer
  still sees what the server sent.
- **Response Safety no longer punishes a server for having more tools.** The dimension
  scored every finding against a single base instead of taking the mean of its per-subject
  scores the way every other dimension does, so the penalty grew with however many tools
  the agent happened to exercise: five tools each relaying one MEDIUM scored 40 where the
  documented model gives 88. The subject is now the tool whose output was examined.
- **Response Safety no longer loses outputs when the agent's own LLM call fails.** What a
  server returned was discarded if the turn later died — and on the free tiers this
  commonly runs against, a rate limit mid-task is the ordinary case, so real payloads could
  vanish because the *agent* faltered rather than because the server was clean.
- **Lookalike letters and exotic spaces no longer evade the scan.** No normalization form
  unifies Cyrillic `а` with Latin `a` — they are different letters, not different encodings
  of one — so `Ignore аll previous instructions` read perfectly to a model and matched
  nothing. Confusable letters are now folded to ASCII before matching, and a word that
  mixes alphabets is itself reported. Likewise a non-breaking or ideographic space, which
  is visible (so the hidden-character check ignored it) and unstripped (so it broke the
  phrase): those now fold to a plain space, and one wedged *inside* a word is flagged —
  while a non-breaking space between a number and its unit stays untouched.
- **The test suite no longer needs the virtualenv on `PATH`.** Fixture servers were spawned
  with a bare `python`, which resolves to whatever the shell finds first; six tests failed
  for anyone whose `PATH` didn't happen to be right.
- **Security Signals no longer scans display titles for credential references.** A tool
  honestly called "Reset Password" or "Credentials Vault" was reported for naming a
  credential; titles are short human labels and get the same exemption schema titles
  already had.

## [0.3.2] — 2026-07-25

Audit-proofing plus the first coverage features toward evaluating the servers people
actually run — correctness and hardening fixes to survive a close outside read, honest
handling of servers that need capabilities the harness doesn't drive, and the machinery for
publishing scores about other people's servers responsibly. A new
[METHODOLOGY.md](https://github.com/GhalebDweikat/mcp-gauntlet/blob/main/METHODOLOGY.md)
documents the scoring model, what a score is *not*, the
sandbox-account requirement for credentialed runs, and the coordinated-disclosure policy
the leaderboard follows.

### Added

- **A live badge for every server on the leaderboard.** The board writes a
  [shields.io endpoint](https://shields.io/badges/endpoint-badge) document per server, so a
  server author can paste one line into their README and show their current gauntlet grade;
  it updates whenever the board is regenerated. The board prints the exact snippet, and
  `--board-url` sets the public URL it points at. A badge for a server the board no longer
  publishes is retired rather than left advertising a score that is no longer stood behind,
  and a server that fails to evaluate reads "not evaluated" rather than keeping its last
  grade.
- **Every score now says when and by what it was measured.** Each leaderboard row carries
  the date its score was *measured* (distinct from when the page was last rebuilt), and
  reports record the gauntlet version that produced them. Scoring changes between releases,
  so the board names the versions behind its numbers — including, explicitly, rows scored
  before the version was recorded — rather than implying one methodology.
- **Evaluate credential-needing servers.** `--env NAME` (or `NAME=VALUE`) passes an
  allow-listed environment variable to a stdio server, and `--header 'Name: Value'` sends an
  auth header to a remote one — so a server that needs a token (GitHub, Slack, a database)
  can finally be evaluated. A bare `--env NAME` pulls the value from your environment so it
  never touches the command line, and only the vars you name are forwarded (the child still
  gets a minimal safe base environment, not your whole shell). Credential values are
  **redacted** from every persisted report, the console summary, the task cache, and error
  messages — scrubbed from the data before it is serialized, so a token containing a quote
  or backslash can't survive as its escaped form. Evaluate untrusted credentialed servers
  only against sandbox/throwaway accounts.
- **Honest handling of servers that request interactive capabilities.** mcp-gauntlet drives
  no user (elicitation) or server-side LLM (sampling), so a tool that needs one of those to
  finish can't complete here. Such requests are now counted and declined cleanly; a tool
  call that failed *only* because of a declined interaction is no longer charged to the
  server's Tool Reliability, the task failure is attributed to the harness's limit rather
  than the agent, and the report carries a note explaining it. (A bundled
  `interactive_server` fixture demonstrates the path.)
- **`--api-key`** flag on `run` / `leaderboard` / `doctor`, and a keyless `--base-url`
  endpoint (a local vLLM / LM Studio / a gateway that needs no auth) now works with no key
  configured at all — the README's "any OpenAI-compatible endpoint" claim finally holds.
- **Bounded retry with backoff on transient LLM failures** (HTTP 429/408/5xx and connection
  errors). Groq's free tier — the default backend — rate-limits bursty runs; without a
  retry every 429 voided a repeat (or a whole task set). Retries honor a `Retry-After`
  header unless it is long enough to mean an exhausted daily quota, in which case the run
  degrades to inconclusive rather than sleeping uselessly against the evaluation's timeout.

### Fixed

- **report.md no longer renders untrusted text as Markdown or HTML.** Server- and
  LLM-authored strings (tool names, finding text, task labels) are sanitized before they
  land in the committed, GitHub-rendered report — whitespace is flattened so a value can't
  open a new block, and `<`, backticks, pipes, and link/image brackets are escaped so a
  hostile name can't inject a `<img onerror=…>`, break a table row, or plant a phishing
  link. The HTML report already escaped; the Markdown one didn't.
- **A malformed-arguments tool call is attributed to the agent, not the server.** When the
  model emits arguments that aren't a JSON object, the call is no longer dispatched as `{}`
  and the server's rejection no longer counts against its Tool Reliability.
- **A hallucinated tool name earns no tool-selection credit.** A call to a tool the server
  never offered is excluded from the selection score, so inventing the expected tool's name
  can't score 100.
- **Score bars match the grade they represent.** The bar color drifted from the grade
  thresholds (a 78 dimension wore a B-green bar while grading C); both now derive from one
  set of bands.

### Changed

- The README's competitive framing was corrected — the previously cited static tools were
  not the real comparison — and the security claim narrowed to what holds: no *evaluator*
  folds a runtime scan of live tool output into a CI-gateable score.
- **METHODOLOGY.md** now states the scoring model, the comparability rules, the limits of
  the score, and the policies for publishing results about third-party servers: private
  notice with a 14-day window before naming a server in a HIGH security finding, advance
  notice to anyone published with a low score, free disputes and re-runs, and no
  pay-to-play.

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
