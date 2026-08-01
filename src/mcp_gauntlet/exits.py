"""What each exit code means, in one place, because CI keys on nothing else.

Every failure used to exit 1: a server that failed the gate, a server that would not start,
a wall-clock timeout, an unwritable `--out`, a transport defect in this harness. A platform
engineer building a gate found six distinct situations behind that one code and had to
reverse-engineer the only working discriminator — a broken run writes no `report.json`,
a failing gate does. That was never documented and was never meant to be load-bearing.

It matters more than it sounds. A gate that cannot tell "your server regressed" from "the
runner had a bad day" gets switched off the first week it flakes, and everything the tool
found goes with it. So the distinction is now in the exit code itself:

    0   the run completed and the gate passed
    1   the run completed and the GATE FAILED — a real verdict about the server
    2   command-line usage error (typer's own, unchanged)
    3   the evaluation could not run: the server did not start, timed out, the transport
        failed, or `--agentic` was asked for and the LLM backend errored on every attempt.
        NOT a verdict about quality; retry or fix the environment
    4   configuration error: something the invocation asked for is impossible, e.g.
        `--agentic` with no API key configured at all, or an `--out` directory that cannot
        be written

The split between 3 and 4 for a broken LLM key is about WHEN it is discoverable, not about
whose fault it is: no key at all is caught before the run starts, so it is configuration; a
key that exists but is revoked, exhausted or pointed at the wrong endpoint is not discovered
until the first API call, so it lands with the other mid-run failures. Both are non-zero and
neither is 1, which is the property a gate actually needs.

Only 1 should ever fail a build on quality grounds. A CI job that treats 3 as a failing
gate is reporting infrastructure noise as a regression, which is the specific way these
tools lose their users' trust.
"""

from __future__ import annotations

from enum import IntEnum


class Exit(IntEnum):
    OK = 0
    GATE_FAILED = 1
    USAGE = 2  # typer raises this itself for a bad flag; listed so the set is complete
    UNEVALUABLE = 3
    CONFIG = 4


# Rendered into `--help` and the docs from the same source as the code above, so the two
# cannot drift — the previous help text described none of this.
EXIT_CODE_HELP = (
    "Exit codes: 0 passed · 1 gate failed (a verdict about the server) · "
    "2 usage error · 3 could not evaluate (server did not start, timed out, transport "
    "failed — not a quality verdict) · 4 configuration error."
)
