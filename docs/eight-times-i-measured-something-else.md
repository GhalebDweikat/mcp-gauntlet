# Eight times my evaluator measured something other than the server

I built an evaluation harness for [MCP](https://modelcontextprotocol.io) servers. It points a
live LLM agent at a server, watches whether the agent can actually accomplish generated tasks
with that server's tools, scans everything the server says for prompt-injection markers, and
folds it all into one graded score you can gate CI on.

Then I published two leaderboards: eleven well-known reference servers, and later a survey of
fifty drawn from the official MCP registry.

Across five days and two boards I found eight bugs. My first draft of this piece claimed they
were all one pattern. They are not — that was me tidying, in an essay about not tidying. They
fall into three families:

- **It measured my environment and billed the server** — §2, §3, §4.
- **It measured something real, but not the thing it claimed to** — §1, §5, §6.
- **Nothing was measured at all, though it looked like it had been** — §7, §8.

Two third-party projects were published with grades two and three letters below what they
deserved before I noticed. This is the write-up of all eight, because the families are more
useful than any single fix, and because I think they generalise to any eval system.

---

## 1. It invented the paths it tested with

The harness generates its own tasks: it reads a server's tool descriptions, asks an LLM for
realistic things a user might want, and grades whether the agent achieved them.

For a filesystem server it generated:

> *"Search for all PNG image files in `/workspace/assets` matching pattern `*.png`."*

`/workspace/assets` does not exist. It never did. The model was shown a tool called
`search_files` that takes a `path`, and nothing else — so it invented a plausible path, every
call failed with "not found", and the **server** was scored for it.

The published board said `filesystem` was a **D (67.3)** and `git` was a **C (72.5)**.
Correctly grounded, they are **A (99.4)** and **A (98.9)**. Agent task success went from 0.0
and 16.7 respectively to 100.0 on both.

What made it invisible for weeks: servers whose tools are *self-contained* were unaffected.
`sqlite` can answer "list all tables" with no invented identifier, so it scored an A. `memory`
scored an A. The failure correlated perfectly with a property of the tools — do they take an
environment-specific identifier? — and therefore looked exactly like a real difference in
server quality.

**The fix wasn't a better prompt.** It was inverting the prompt's policy. It used to say
"include any specific input values the agent needs", which for these servers *requires*
invention. Now it forbids inventing an identifier at all: a task must either use a value the
harness can state as fact — the server's own command-line arguments, its zero-argument tools,
its published resource URIs — or make its first step a discovery call. *"Discover which
directories the server allows, then list the files in one of them."*

**The trap inside the fix:** task sets are cached per server. Every server already in the cache
would have kept serving the tasks the *old* prompt wrote, so the fix would have looked like a
no-op on precisely the servers it was written for. The cache key now includes a prompt version.

---

## 2. The git server diffed my leaderboard and read its own findings back

The board evaluated a git server, pointed at `--repository .` — the harness's own checkout.

The agent called `git_diff_unstaged`. That returned the working tree's diff, which at that
moment contained the leaderboard's own generated HTML being rewritten. Inside that HTML were
the *previous run's* security findings. The scanner read them, found the phrases it looks for,
and flagged the git server for relaying sensitive-looking content.

The evaluator caught itself and filed a report about the server.

## 3. The filesystem server was flagged for a sentence I wrote

Same class, one step further. I moved the filesystem server off the checkout and onto a
committed sandbox directory, and wrote a `README.md` in there explaining why:

> *"…whatever happens to be there — a `.env`, a credential file, private notes — is one
> generated task away from being read and published."*

The agent read that file. The scanner saw `.env` and `credential`, and flagged the filesystem
server for "references sensitive files or secrets."

I had written the payload myself, in the file explaining why payloads are dangerous.

---

## 4. An abandoned process held a port, and the server took the blame

A server called `ankimcp` bridges to a local Anki instance. It also binds `127.0.0.1:3000` on
startup.

An earlier interrupted run had left one alive. Every subsequent evaluation of that server
therefore failed with `EADDRINUSE: address already in use` — and got published as a server
defect.

The leak is real and it is mine: the SDK does kill the child's process group on exit, but with
an `await`, and the cancellation that ends a timed-out evaluation cancels that await before the
kill lands.

**The obvious fix does not work**, and this is the part worth knowing. Shielding the teardown
fails with `Attempted to exit a cancel scope that isn't the current tasks's current cancel
scope` — anyio's typo, not mine, pasted verbatim, because a quoted error you cannot grep for is
worse than no quote — anyio requires a cancel scope to be exited in the task that entered it, and an
`@asynccontextmanager` being finalised under cancellation does not satisfy that. Fixing it
properly means restructuring the session into a class-based context manager so `__aexit__` runs
in the caller's task. So it is recorded as an `xfail` test that spawns a deliberately hanging
server, times it out, and checks whether the process survived. When the restructure lands, the
test starts passing.

---

## 5. Forty-one security findings, all false

The security scanner flags "references to sensitive files or secrets". On the survey board it
produced twenty-six of those in tool descriptions and properties, and fifteen more in outputs,
prompt messages and server instructions — forty-one in total. I audited every one before
publishing.

Every one was a false positive, in three shapes.

**Servers doing their job.** `logout` — *"Remove stored authentication credentials."*

**Servers documenting good practice**, which is the perverse one:

> *"env VALUES are NOT exfiltrated"* — a deployment tool
> *"(secret). Encrypted into the credentials cipher; never returned."* — a feature-flag server
> *"dotfiles, credentials, and node_modules are always excluded"* — a file-transfer tool

Every one marked down for stating that it does the safe thing.

**Servers telling you where to get your API key.** One email server had five findings, four of
them matching the same string: a link to its own API-keys settings page.

And the one that settled it: `mcpcap` is a **PCAP forensics tool**. Its prompts discuss "data
exfiltration via DNS" because that is what network forensics *is*. It was losing points for its
subject matter. It no longer does.

**No narrowing fixes this.** The vocabulary is shared between an attacker and an honest
credential manager; the difference is intent, which a regex cannot see. Both signals are now
INFO — recorded for a human, worth zero points.

**And a correction I had to make to my own changelog.** I wrote that these findings were
"deciding published grades". Re-running measured it: at most two and a half points, on one
static-only server with few dimensions to average over. On the lowest-graded server it was
about a tenth of a point — that grade came from the agent failing tasks, not from the scanner.
Scoring on noise was still wrong. My claim about the consequence was not.

---

## 6. I pinned to the registry's version, and published grades for code nobody runs

To make the survey reproducible I pinned every package to the version the official MCP registry
recorded. Reproducibility is good. This was not.

| package | registry says | npm actually ships |
|---|---|---|
| `@adeu/mcp-server` | 1.7.1 | **1.30.0** |
| `@oobe-protocol-labs/sap-mcp-server` | 0.7 | **0.9.52** |

Pinning meant scanning code the maintainer shipped long ago and has since fixed. Two servers
that scored **A** on latest failed outright on the recorded version — one timed out, one died
on a module-resolution error.

That is worse than unreproducible. It is unfair. Reverted: scan what a user actually gets, and
keep provenance from the version each server *self-reports* over the protocol.

**But I published the board anyway.** I committed that retraction — the one calling those two
results unfair — and published the board containing them **twenty-two minutes later**. The
board was generated from the pinned run and I never re-ran it. So the headline was wrong by my own git log: at least three of those rows were mine, not
theirs — and I have not finished auditing the rest, because the pin touched **every** row. Nor
was it two servers: every grade on that board, the A's included, measured a version the registry
recorded rather than the one a user gets.

That is the failure I am least comfortable with, because the analysis was already correct and
written down. The gap was between knowing and acting.

---

## 7. I argued for two rounds about something that took thirty minutes to measure

MCP shipped a new protocol revision, and the Python SDK shipped a 2.0 that renames every field
to snake_case. I planned an eleven-step port, wrote a design doc, had an adversarial reviewer
attack it, and rewrote it. Two rounds of argument about how urgent it was, with a plausible case
on each side.

Then I built a trivial server on the 2.0 SDK, pointed the current client at it, and looked.

**The handshake succeeded.** The 2.0 server negotiated *down* to the older revision. Every tool
came through with its description and both schemas intact. The urgency case — that any server
whose author bumps a dependency would silently drop off the board — was simply false, because
the new SDK's server side is dual-era by default.

Thirty minutes of measurement, after two rounds of argument, on a project whose entire purpose
is measuring things.

---

---

## 8. A green test run that wasn't, three minutes after I committed this essay

I finished the draft above, ran the suite, and pushed. The command was:

```
uv run pytest -q 2>&1 | tail -3 && git commit ...
```

A pipeline's exit status is its **last** command's. `tail` always succeeds. So `&&` proceeded
past a failing test whose name I had just printed to my own screen, and I pushed a red suite
alongside an essay arguing that a check which stops working reports success.

The failing test was itself in the family: `budget_s=0.05` against `anyio.sleep(0.06)` — a 10 ms
margin, on a platform whose timer granularity is about 15 ms. It measured my machine's clock
resolution rather than the property it named, so it passed alone and failed under load, which is
the worst arrangement because it reads as *"something else broke it."*

Two failures, one commit, both of them the thing the essay is about. I have stopped piping
pytest.

## The three lessons

The families are the diagnosis. These are the part I would actually hand to someone else
building an eval system:

**A check that stops working reports success.** This is the one that keeps recurring. Nearly
every SDK field was read through `getattr(obj, "camelCaseName", default)` — defensive against
an *older* library and dangerous against a newer one, because a renamed field does not raise,
it returns the default. The check built on it measures nothing and every subject scores clean.
I shipped a fix for the new protocol's interaction pattern and *the fix had the same bug*: it
read `resultType` where 2.0 says `result_type`, so against the only servers that would ever
exercise it, it *would have* silently inverted the very attribution it was written to protect.
No modern server was ever evaluated, so nothing actually inverted — but a latent inversion is
the point. Every SDK field now goes through one adapter, with a test asserting no legacy-spelled
SDK read survives outside it. That guard greps for camelCase only, so it cannot see a
modern-spelled read: a smaller net than it sounds.

**Your assertions have to be tight enough to fail.** The good fixture's test asserted only `grade in
("A","B")`. A regression from 98.3 to 92 passes it. "The refactor
changed nothing" was an unverifiable claim until I recorded an exact snapshot of every fixture's
score *and* every tool's drift fingerprint — the fingerprints because they digest how fields are
read, so a `{}`-versus-`None` difference would silently mark every tool on the board as
redefined. I then tampered with the snapshot to confirm it actually fails, because a guard you
haven't seen fail is not a guard.

**Separate "loud" from "fatal".** The natural fix for silent defaults is to raise instead. But
one of those reads happens in the robustness prober, which runs *last* — after the full paid
agent evaluation. A raise there discards a completed run. So raising is confined to discovery,
which happens before any spend; live-result reads keep their defaults and file a finding
instead. Loud in the report, never loud in the process.

---

## Where this leaves the tool

The leaderboards are down, deliberately, and the reasoning is
[published in their place](https://ghalebdweikat.github.io/mcp-gauntlet/). Publishing scores
about named third parties is the highest-stakes thing this project does, my methodology document
promises those servers advance notice before they appear with a low score, and that notice was
never sent. They come back at v1.0: scoring stable across two consecutive releases with no new
false-positive class found, provenance recorded on every row, and the disclosure process actually
exercised first.

One result from the survey is worth stating even so, because it is about a first-party artifact
rather than anyone's hobby code: **of fifty servers the official registry lists as installable
and requiring no credentials, twenty-three could not be started at all — and at least three of
those were my fault, not theirs.** Among the rest: four npm packages declare no executable, so
`npx` has nothing to run; four demand an environment variable the registry never declared; four
died without writing anything to stderr; three never answered inside two minutes; and the
remainder failed for reasons from an unresolvable `workspace:*` dependency to a missing system
binary.
And across the twenty-seven that started — 571 tools — the security scan found **zero**
high-severity findings. I went looking
for tool poisoning in the wild and did not find any. That is a negative result, and I trust it
more now than I would have a week ago — not because the scanner got stronger, but because I know
much more precisely what it was measuring.

The code, the methodology, and every one of these eight fixes with its reasoning:
[github.com/GhalebDweikat/mcp-gauntlet](https://github.com/GhalebDweikat/mcp-gauntlet).
