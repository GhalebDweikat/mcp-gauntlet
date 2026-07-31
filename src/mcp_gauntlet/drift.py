"""Detect a server that redefines its tools after you approved them.

The attack this exists for: a server passes review, gets installed, and *later* changes
what its tools say. The MCP client re-reads the definitions on every connection but does
not re-prompt the user, so the redefinition lands in the model's context silently. It is
the failure mode registry signing cannot address — the package is unchanged and correctly
signed; only the text it serves at runtime differs — and MCP's own Security Interest Group
has said as much.

Two independent checks:

* **Within one session.** ``tools/list`` is asked twice and the answers compared, and any
  definition that changed is then *scanned in its own right* — that scan is what catches a
  server serving clean definitions to whoever asks first and poisoned ones after, because
  it raises the payload's own finding rather than merely noting that something moved. The
  change itself is reported at INFO when the server declares ``tools.listChanged`` (a
  documented MCP capability that the reference servers all advertise, so a mid-session
  change from such a server is expected) and MEDIUM when it does not.
* **Across runs.** The tool surface is fingerprinted and stored, then compared on the next
  run of the same server. Here severity turns on whether the server *said* it changed: a
  definition that moved while the advertised version stayed put is a silent redefinition
  (MEDIUM); the same change alongside a version bump is an ordinary update (INFO, recorded
  so the trail exists but nothing is penalised).

Neither check caps a grade on its own. Both describe a *change*, and a change is not proof
of intent — honest servers register tools lazily, gate them on auth, and edit descriptions
without bumping a static version. What caps is a payload, found by scanning the changed
definition like any other text. Note also that the version a Python MCP server reports
defaults to the installed ``mcp`` SDK version unless its author sets one, so the
"did it admit the change?" axis is a weaker signal than it looks.

The stored baseline is keyed on the server *spec*, deliberately not on its tools: keying on
the tool set — as the task cache does, correctly, for its own purpose — would give a
redefined server a brand-new key and no baseline to contradict it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from mcp_gauntlet.adapters import adapter
from mcp_gauntlet.jsonio import read_json_text
from mcp_gauntlet.models import ServerInfo, ToolInfo
from mcp_gauntlet.naming import slugify
from mcp_gauntlet.report import Finding, Severity


def spec_key(spec_label: str) -> str:
    """A stable id for the server ITSELF, independent of what it currently exposes.

    The digest covers the whole spec so two similar servers can't share a baseline, but the
    readable part is taken only from the portion before any ``?`` or ``#`` and with
    ``user:pass@`` removed. Several hosted MCP servers carry their token in the URL, and
    this is the first artifact to put a spec into a *filename* — where it would outlive the
    run, sit in a directory listing, and appear in any backup.
    """
    digest = hashlib.sha256(spec_label.encode("utf-8")).hexdigest()[:12]
    readable = re.split(r"[?#]", spec_label, maxsplit=1)[0]
    readable = re.sub(r"//[^/@\s]*@", "//", readable)  # strip userinfo from a URL
    slug = slugify(readable)[:40]
    return f"{slug}-{digest}"


def fingerprint(tool: ToolInfo) -> str:
    """A digest of everything about a tool that a model reads or a filter trusts.

    Covers the description and both display titles (the text the model is steered by), both
    schemas (serialized into its context), and the annotation hints (which decide whether
    the harness will execute the tool at all). A change to any of them is a change to what
    was approved.
    """
    payload = json.dumps(
        {
            "description": tool.description,
            "title": tool.title,
            "annotation_title": tool.annotation_title,
            "input_schema": tool.input_schema,
            "output_schema": tool.output_schema,
            "read_only_hint": tool.read_only_hint,
            "destructive_hint": tool.destructive_hint,
            # `_meta` is scanned, so it is part of what was approved: a rug-pull relocated
            # there would otherwise be invisible to both drift checks.
            "meta": tool.meta,
        },
        sort_keys=True,
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def fingerprint_all(tools: list[ToolInfo]) -> dict[str, str]:
    return {tool.name: fingerprint(tool) for tool in tools}


@dataclass
class Baseline:
    version: str | None = None
    recorded_at: str = ""
    tools: dict[str, str] = field(default_factory=dict)
    # Which SDK era produced these fingerprints. A digest is only comparable against one
    # recorded the same way — see `era_changed`.
    era: str = ""

    def to_json(self) -> str:
        return json.dumps(
            {
                "version": self.version,
                "recorded_at": self.recorded_at,
                "era": self.era,
                "tools": self.tools,
            },
            indent=2,
        )


def era_changed(baseline: Baseline) -> bool:
    """Whether this baseline was recorded by a different SDK era than the one running now.

    `fingerprint()` digests `output_schema`, both hints and `_meta`. Those are read through
    the adapter, and the two eras can legitimately produce different values for the same
    server — an absent output schema is `{}` on one path and `None` on another, and either
    changes the digest. So the FIRST run after an SDK upgrade would find every tool's
    fingerprint different and report every one of them as a silent redefinition: MEDIUM
    findings, on the weight-2.0 grade-capping dimension, for servers that did not change at
    all. On a published board that is a fabricated rug-pull accusation against every server
    at once.

    A baseline with no recorded era is treated as legacy rather than as a mismatch. That is
    not a guess: every version published before this stamp existed pinned `mcp<2`, so an
    unstamped baseline cannot have been recorded under a modern SDK. Treating them as
    unknown would reset every existing user's baseline — switching the drift check off for a
    run — for nothing.
    """
    return (baseline.era or "legacy") != adapter().era


def baseline_file(base_dir: Path, key: str) -> Path:
    return base_dir / f"{key}.json"


class UnreadableBaseline(Exception):
    """A baseline exists but could not be parsed — the comparison cannot run."""


def load_baseline(path: Path) -> Baseline | None:
    """The recorded surface, or None if there is nothing recorded yet.

    Raises :class:`UnreadableBaseline` when a file exists but can't be understood. That is
    deliberately not the same as "no baseline": silently treating a corrupt or
    wrongly-encoded file as a first run would turn the drift check off while the report
    still read clean, and a security check that disables itself quietly is worse than one
    that isn't there.
    """
    if not path.exists():
        return None
    try:
        data = json.loads(read_json_text(path))
    except (OSError, ValueError) as exc:
        raise UnreadableBaseline(str(exc)) from exc
    if not isinstance(data, dict) or not isinstance(data.get("tools"), dict):
        raise UnreadableBaseline("not a baseline document")
    tools = {str(k): str(v) for k, v in data["tools"].items()}
    version = data.get("version")
    return Baseline(
        version=str(version) if version is not None else None,
        recorded_at=str(data.get("recorded_at") or ""),
        tools=tools,
        era=str(data.get("era") or ""),
    )


def save_baseline(path: Path, server: ServerInfo, tools: list[ToolInfo]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    baseline = Baseline(
        version=server.version,
        recorded_at=datetime.now(UTC).isoformat(timespec="seconds"),
        tools=fingerprint_all(tools),
        era=adapter().era,
    )
    path.write_text(baseline.to_json(), encoding="utf-8")


def _f(tool: str | None, severity: Severity, message: str, detail: str | None = None) -> Finding:
    return Finding(tool=tool, severity=severity, message=message, detail=detail)


def compare_to_baseline(
    baseline: Baseline, server: ServerInfo, tools: list[ToolInfo]
) -> list[Finding]:
    """Findings for how the tool surface changed since it was last recorded.

    Severity turns on whether the server announced the change, but tops out at MEDIUM: a
    redefinition under an unchanged version is the rug-pull signature, yet plenty of honest
    servers iterate on their descriptions while reporting a static version, so it is
    reported and it lowers the score without capping the grade. That follows the rule the
    rest of the scanner is built on: only near-certain signals cap, and "the text changed"
    is not one. A change alongside a version bump is an ordinary release, recorded at INFO.
    """
    current = fingerprint_all(tools)
    # Normalize BOTH sides: a stored empty string is the same "no version" as None, and
    # comparing one normalized value against one raw one made every later change look like a
    # declared release ("? -> ?"), permanently downgrading a server that once reported "".
    silent = (server.version or None) == (baseline.version or None)
    since = f" (baseline recorded {baseline.recorded_at})" if baseline.recorded_at else ""

    if silent:
        severity, new_severity = Severity.MEDIUM, Severity.LOW
        how = "without changing its advertised version"
    else:
        severity = new_severity = Severity.INFO
        how = f"alongside a version change ({baseline.version or '?'} -> {server.version or '?'})"

    findings: list[Finding] = []
    for name, digest in current.items():
        previous = baseline.tools.get(name)
        if previous is None:
            findings.append(
                _f(
                    name,
                    new_severity,
                    f"tool is new since the last run {how}",
                    detail=f"A tool the model was not previously offered{since}.",
                )
            )
        elif previous != digest:
            findings.append(
                _f(
                    name,
                    severity,
                    f"tool definition changed since the last run {how}",
                    detail="The description, title, schema or safety hints a model reads "
                    f"are not the ones recorded for this server{since}.",
                )
            )
    for name in baseline.tools:
        if name not in current:
            findings.append(
                _f(
                    name,
                    Severity.INFO,
                    f"tool has disappeared since the last run {how}",
                    detail=f"It was offered when this server was last evaluated{since}.",
                )
            )
    return findings


def changed_within_session(first: list[ToolInfo], second: list[ToolInfo]) -> list[ToolInfo]:
    """The second listing's tools whose definitions differ from the first listing's.

    These need scanning in their own right: reporting only that a definition *moved* leaves
    a reviewer unable to tell a typo fix from an instruction to exfiltrate SSH keys, and
    lets a payload that appears only in the second listing escape the injection scan
    entirely — the first listing is the one everything else is built from.
    """
    before = fingerprint_all(first)
    return [tool for tool in second if before.get(tool.name) not in (None, fingerprint(tool))]


def compare_within_session(
    first: list[ToolInfo], second: list[ToolInfo], *, declared_list_changed: bool = False
) -> list[Finding]:
    """Findings for a server that answered two ``tools/list`` calls differently.

    Severity turns on whether the server *declared* that its list can change. MCP has a
    ``tools.listChanged`` capability for exactly this, and the reference servers all
    advertise it, so a mid-session change from such a server is documented behaviour, not
    evidence of anything — treating it as an attack would fail an honest server that
    registers tools lazily or gates them on auth. A server that changes its list while
    declaring no such capability is contradicting itself, which is worth reporting but is
    not the near-certainty this project requires before capping a grade.

    What actually catches a malicious flip is the *content*: the changed definitions are
    scanned like any others, so a payload appearing in the second listing raises its own
    HIGH and caps through the normal mechanism.
    """
    before, after = fingerprint_all(first), fingerprint_all(second)
    if before == after:
        return []
    if declared_list_changed:
        severity = Severity.INFO
        why = " (the server declares tools.listChanged, so this is expected)"
    else:
        severity = Severity.MEDIUM
        why = " (the server does not declare tools.listChanged)"

    findings: list[Finding] = []
    for name, digest in after.items():
        if name not in before:
            findings.append(
                _f(name, severity, f"tool appeared midway through a single session{why}")
            )
        elif before[name] != digest:
            findings.append(
                _f(
                    name,
                    severity,
                    f"tool definition changed within a single session{why}",
                    detail="The server described this tool differently to two consecutive "
                    "tools/list requests on one connection. The changed definition is "
                    "scanned in its own right; any finding against it appears separately.",
                )
            )
    for name in before:
        if name not in after:
            findings.append(
                _f(name, severity, f"tool disappeared midway through a single session{why}")
            )
    return findings
