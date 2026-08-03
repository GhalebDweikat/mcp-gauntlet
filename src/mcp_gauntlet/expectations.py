"""Tell the gate about a finding you have already read and decided about.

Every false-positive class this tool has found is currently inescapable. A security server
must quote the attacks it detects and is capped at C for it ([G7](docs/known-gaps.md)); a
German server using soft hyphens is capped for hidden characters; a documentation server
over the OWASP LLM Top 10 is capped for describing prompt injection. There is no allowlist
and no suppression flag, so the only remedies are `--allow-writes`-style blunt instruments or
deleting the gate — and a CI gate that cannot be told it is wrong gets deleted the first week
it is wrong. The official `modelcontextprotocol/conformance` suite ships
`--expected-failures` for exactly this reason.

**This is the easiest place in the codebase to build the defect the whole project is about.**
A suppression mechanism is, structurally, a check that reports success when it stops working.
So five rules, and none of them is negotiable:

1. **An expected finding is still reported.** It keeps its severity, stays in `report.json`,
   stays on the console, and is labelled. It stops deciding the exit code and nothing else.
2. **Every run says how many were expected.** Silence is how a file of forty suppressions
   becomes invisible.
3. **An expectation that matched nothing is itself reported.** Otherwise the file rots: a
   finding's wording changes, the entry quietly stops applying, and nobody learns until the
   thing it was hiding matters.
4. **`reason` is required.** A suppression with no justification is one nobody can review,
   including the person who wrote it.
5. **Matching is EXACT**, never a substring. The two failure directions are not symmetric:
   an entry that stops matching turns the build red, which is loud and fixable in a minute,
   while an entry that matches too much hides real findings and says nothing. Exactness
   costs churn when a message is reworded; substring matching costs correctness.

The file:

    {
      "expected": [
        {
          "tool": "sanitise",
          "message": "description attempts to override prior instructions",
          "reason": "this tool's job is to quote injection patterns — known-gaps G7"
        }
      ]
    }

`tool` is omitted for a server-level finding. Nothing else is accepted, by name, for the same
reason `servers.json` rejects unknown keys: a silently-dropped key reads as a wired-up
configuration.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from mcp_gauntlet.jsonio import read_json_text
from mcp_gauntlet.report import DimensionResult, Finding, GauntletReport, redact

_ENTRY_KEYS = {"tool", "message", "reason"}
_TOP_LEVEL_KEYS = {"expected"}


class ExpectationsError(ValueError):
    """The `--expect` file could not be read or is not shaped like an expectation list."""


@dataclass(frozen=True)
class Expectation:
    message: str
    reason: str
    tool: str | None = None

    @property
    def key(self) -> tuple[str | None, str]:
        return (self.tool, self.message)

    def describe(self) -> str:
        where = f"{self.tool}: " if self.tool else ""
        return f"{where}{self.message}"


@dataclass
class Applied:
    """What an `--expect` file did to one report."""

    matched: int = 0
    unused: list[Expectation] = field(default_factory=list)


def load_expectations(path: Path) -> list[Expectation]:
    """Read an expectation file, rejecting anything it cannot honour."""
    try:
        data = json.loads(read_json_text(path))
    except OSError as exc:
        raise ExpectationsError(f"could not read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ExpectationsError(f"{path} is not UTF-8 or UTF-16 text: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ExpectationsError(f"{path} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("expected"), list):
        raise ExpectationsError(f'{path} must be an object with an "expected" list')
    stray = sorted(set(data) - _TOP_LEVEL_KEYS)
    if stray:
        raise ExpectationsError(
            f'{path} has unknown top-level key(s) {", ".join(stray)}; the only key is "expected"'
        )

    out: list[Expectation] = []
    for index, raw in enumerate(data["expected"], 1):
        where = f"{path}: expectation #{index}"
        if not isinstance(raw, dict):
            raise ExpectationsError(f"{where} must be an object")
        unknown = sorted(set(raw) - _ENTRY_KEYS)
        if unknown:
            raise ExpectationsError(
                f"{where} has unknown key(s) {', '.join(unknown)}; "
                f"allowed: {', '.join(sorted(_ENTRY_KEYS))}"
            )
        for key in ("message", "reason"):
            value = raw.get(key)
            if not isinstance(value, str) or not value.strip():
                # `reason` is as required as `message`. An expectation nobody can review is
                # how a suppression file becomes forty lines of institutional amnesia.
                raise ExpectationsError(f'{where}: "{key}" must be a non-empty string')
        tool = raw.get("tool")
        if tool is not None and (not isinstance(tool, str) or not tool.strip()):
            raise ExpectationsError(f'{where}: "tool" must be a non-empty string when present')
        out.append(
            Expectation(
                message=raw["message"].strip(),
                reason=raw["reason"].strip(),
                tool=tool.strip() if isinstance(tool, str) else None,
            )
        )
    return out


def apply_expectations(
    report: GauntletReport,
    expectations: list[Expectation],
    secrets: frozenset[str] = frozenset(),
) -> Applied:
    """Mark the findings an operator has already decided about. Returns what it did.

    Mutates the report's findings in place — they are marked, never removed. The caller is
    responsible for saying what happened; `Applied` carries everything needed to say it.

    `secrets` exists because the text a user can SEE is redacted and the text matched here is
    not. Passing `--env PGDATABASE=greet` against a server with a tool called `greet` prints
    `HIGH ***REDACTED***: description contains hidden characters` — and an expectation copied
    from that line could never match, while the line that would match is printed nowhere.
    Both forms are accepted, so whichever string the user copied works.
    """
    if not expectations:
        return Applied()

    by_key: dict[tuple[str | None, str], Expectation] = {e.key: e for e in expectations}
    used: set[tuple[str | None, str]] = set()
    matched = 0

    for dimension in report.dimensions:
        updated: list[Finding] = []
        for finding in dimension.findings:
            expectation = _match(by_key, finding, secrets)
            if expectation is None:
                updated.append(finding)
                continue
            used.add(expectation.key)
            matched += 1
            updated.append(
                finding.model_copy(update={"expected": True, "expected_reason": expectation.reason})
            )
        _replace_findings(dimension, updated)

    applied = Applied(matched=matched, unused=[e for e in expectations if e.key not in used])
    # Onto the report, so the Markdown and HTML renderers carry it too. The console was the
    # only place this appeared, and the console is not what a reviewer opens three days later.
    report.expected_suppressed = applied.matched
    report.expectations_unused = [e.describe() for e in applied.unused]
    return applied


def _match(
    by_key: dict[tuple[str | None, str], Expectation],
    finding: Finding,
    secrets: frozenset[str],
) -> Expectation | None:
    """The expectation for this finding, matched against the raw OR the redacted text.

    Never a substring, in either form — see rule 5. The redacted form is a second exact key,
    not a loosening: it is the string the operator was actually shown.
    """
    direct = by_key.get((finding.tool, finding.message))
    if direct is not None or not secrets:
        return direct
    shown = (
        redact(finding.tool, secrets) if finding.tool else None,
        redact(finding.message, secrets),
    )
    return by_key.get(shown)


def _replace_findings(dimension: DimensionResult, findings: list[Finding]) -> None:
    """Swap a dimension's findings, whether the model is frozen or not."""
    try:
        dimension.findings = findings
    except (TypeError, ValueError):  # pragma: no cover - a frozen model
        object.__setattr__(dimension, "findings", findings)


def summarize(applied: Applied) -> list[str]:
    """Lines the caller must print. Never empty when an expectation file was in play.

    Rule 2 and rule 3 of the module docstring live here: what was suppressed is stated on
    every run, and an expectation that matched nothing is reported rather than left to rot
    into a blind spot.
    """
    lines: list[str] = []
    if applied.matched:
        lines.append(
            f"{applied.matched} finding(s) matched --expect and did not fail the gate "
            "(they are still in the report, with their real severity)"
        )
    for expectation in applied.unused:
        lines.append(
            f"--expect entry matched nothing: {expectation.describe()!r}. Either the finding "
            "is gone — delete the entry — or its wording changed and this is no longer "
            "suppressing what you think it is"
        )
    return lines
