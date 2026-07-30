# Seven times my MCP evaluator graded my own environment instead of the server

I built an evaluation harness for [MCP](https://modelcontextprotocol.io) servers. It points a
live LLM agent at a server, watches whether the agent can actually accomplish generated tasks
with that server's tools, scans everything the server says for prompt-injection markers, and
folds it all into one graded score you can gate CI on.

Then I pointed it at fifty real servers and published the grades.

Over the next three days I found seven bugs. Every one of them was the same bug wearing a
different hat: **the evaluator was measuring something about my machine, or about itself, and
attributing it to the server under test.** Two named third-party projects were published with
grades two and three letters below what they deserved before I noticed.

This is the write-up of all seven, because the pattern is more useful than any single fix, and
because I think it generalises to every eval system anyone is building right now.

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
to 100.0 on both.

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
fails with `Attempted to exit a cancel scope that isn't the current task's current cancel
scope` — anyio requires a cancel scope to be exited in the task that entered it, and an
`@asynccontextmanager` being finalised under cancellation does not satisfy that. Fixing it
properly means restructuring the session into a class-based context manager so `__aexit__` runs
in the caller's task. So it is recorded as an `xfail` test that spawns a deliberately hanging
server, times it out, and checks whether the process survived. When the restructure lands, the
test starts passing.

---

## 5. Twenty-five security findings, all false

The security scanner flags "references to sensitive files or secrets". Across fifty servers it
produced twenty-five of these. I audited every one before publishing.

All twenty-five were false positives, in three shapes.

**Servers doing their job.** `logout` — *"Remove stored authentication credentials."*

**Servers documenting good practice**, which is the perverse one:

> `percher_reproduce` — *"env VALUES are **NOT** exfiltrated"*
> `shipeasy` `apiKey` — *"(secret). Encrypted into the credentials cipher; **never returned**."*
> `justdrop` — *"dotfiles, credentials and node_modules are **always excluded**"*

Every one marked down for stating that it does the safe thing.

**Servers telling you where to get your API key.** `radmail` had five findings, all matching
`https://app.radmail.ai/settings/api-keys`. Its own documentation link.

And the one that settled it: `mcpcap` is a **PCAP forensics tool**. Its prompts discuss "data
exfiltration via DNS" because that is what network forensics *is*. It lost points for its
subject matter.

**No narrowing fixes this.** The vocabulary is shared between an attacker and an honest
credential manager; the difference is intent, which a regex cannot see. Both signals are now
INFO — recorded for a human, worth zero points.

**And a correction I had to make to my own changelog.** I wrote that these findings were
"deciding published grades". Re-running measured it: about two points. The D-grade server's
security dimension went to 100 and its grade barely moved, because its D came from the agent
failing tasks, not from the scanner. Scoring on noise was still wrong. My claim about the
consequence was not.

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
board was generated from the pinned run and I never re-ran it. So the headline "23 of 50 could
not be started" was wrong by my own git log: three of those rows were mine, not theirs. Twenty.

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

## The pattern

Seven bugs, one shape: **the evaluator's own environment leaking into the measurement, and the
subject getting the blame.** The path is always via something that looks like the server's
output — a generated task, a diff, a file on disk, a bound port, a version string, a phrase in
a description.

Three things I would tell anyone building an eval system:

**A check that stops working reports success.** This is the one that keeps recurring. Nearly
every SDK field was read through `getattr(obj, "camelCaseName", default)` — defensive against
an *older* library and dangerous against a newer one, because a renamed field does not raise,
it returns the default. The check built on it measures nothing and every subject scores clean.
I shipped a fix for the new protocol's interaction pattern and *the fix had the same bug*: it
read `resultType` where 2.0 says `result_type`, so against the only servers that would ever
exercise it, it silently inverted the very attribution it was written to protect. Every SDK
field now goes through one adapter, with a test asserting nothing bypasses it — and a separate
test that fails the day the field names change.

**Your assertions have to be tight enough to fail.** The fixture tests asserted `grade in
("A","B")` and `overall_score <= 75`. A regression from 99.4 to 92 passes both. "The refactor
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
and requiring no credentials, twenty could not be started at all** — six published with no
runnable entry point at all (four npm packages declaring no `bin`, two Python packages whose
console script does not match the package name), three demanding an environment variable the
registry never declared, and six that never answered inside two minutes.
And across all fifty, the security scan found **zero** high-severity findings. I went looking
for tool poisoning in the wild and did not find any. That is a negative result, and I trust it
more now than I would have a week ago — not because the scanner got stronger, but because I know
much more precisely what it was measuring.

The code, the methodology, and every one of these seven fixes with its reasoning:
[github.com/GhalebDweikat/mcp-gauntlet](https://github.com/GhalebDweikat/mcp-gauntlet).
