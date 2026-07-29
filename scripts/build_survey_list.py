"""Select the public servers for the survey, mechanically, from the official registry.

"I scanned 50 public MCP servers" only means something if the 50 were not chosen to make a
point. So selection is a script that ships with the results, and anyone can re-run it.

    python scripts/build_survey_list.py --out survey.servers.json --limit 50

Criteria, in order:

* **Installable over stdio.** An npm or PyPI package, run by `npx`/`uvx`. Remote hosted
  servers are excluded — they need accounts, and their behaviour is not attributable to
  a version anyone can pin.
* **Declares no required credential.** No `isRequired`/`isSecret` environment variable,
  argument, or header. This is the registry's own metadata, and it is frequently wrong —
  most of what survives is still commercial software that fails every call without an
  account. Catching that is the credential pre-flight's job at scan time, and the count is
  a finding worth publishing rather than a filtering failure to hide.
* **Latest revision, not deleted or deprecated.**
* **At most `--per-publisher` servers from any one namespace.** Sixteen of the candidates
  are one vendor's near-identical `@agentutility/*` cluster; letting them be a third of the
  sample would describe that vendor, not the ecosystem.

Entries are emitted in registry order, not shuffled or ranked, so re-running gives the same
list and there is no scoring-adjacent judgment hidden in the ordering.
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.request
from collections import Counter
from typing import Any

BASE = "https://registry.modelcontextprotocol.io/v0/servers"
STDIO_REGISTRIES = {"npm": "npx -y", "pypi": "uvx"}

# Servers whose advertised purpose is to DO something irreversible in the world: move money,
# book travel, place calls, send mail, deploy or publish. These are scanned statically and
# never executed.
#
# The read-only filter is not sufficient protection here and METHODOLOGY says so plainly: it
# is a best-effort heuristic that trusts server-declared hints it cannot verify. On an
# ordinary server a mislabeled tool means a wrong number; on a payments server it means a
# real transfer. The credential pre-flight would stop most of them for want of an account,
# but that is protection by accident — it only concludes anything when a zero-argument tool
# returns an auth error, and a payments server may expose none.
#
# Deliberately matched against the server's OWN description. Over-matching costs a static
# scan instead of a full one; under-matching costs somebody's money.
_REAL_WORLD_ACTION = re.compile(
    r"""(?ix)
    \b(?:pay|pays|paid|payment|payments|invoice|billing|charge|fiat|money|funds)\b
    # `transfer` needs a financial object: "file transfer" moves bytes, not money.
  | \b(?:remit|payout|wallet|crypto|defi|solana|stripe|x402)\b
  | \btransfers?\s+(?:of\s+)?(?:funds|money|balance|assets)\b
  | \b(?:funds|money|wire)\s+transfers?\b
  | \b(?:trade|trades|trading|order|orders|checkout|purchase|buy)\b
  | \b(?:book|books|booking|flight|flights|hotel|hotels|reservation)\b
    # NOT bare `call`: "via MCP tool calls" is close to the commonest phrase in an MCP
    # server description, and matching it put a 3D scene viewer in the never-execute
    # bucket. Telephony has to be named, or the verb has to take a call as its object.
  | \b(?:telephony|sms|dial|dials|dialing)\b
  | \b(?:place|places|placing|make|makes|making)\s+(?:a\s+|an\s+|the\s+)?(?:phone\s+)?calls?\b
  | \b(?:email|inbox|mail)\b
  | \b(?:deploy|deploys|deployment|publish|hosting|domain|domains)\b
    # Creating accounts somewhere on the user's behalf is as irreversible as a purchase,
    # and it happens on a third party's system. `trusty-squire` advertises exactly this and
    # the first draft of this pattern missed it.
  | \bsigns?[\s/-]*(?:up|in)\b | \bsign[\s-]?up\b | \bregisters?\s+(?:an?\s+)?account\b
    # Proxies and gateways re-expose tools from OTHER servers. The blast radius is
    # unbounded by construction: we cannot classify what we cannot see at selection time,
    # and the tools that appear at runtime were never in this list at all.
  | \b(?:proxy|proxies|proxied|proxying|gateway|passthrough|re-?exposes?)\b
    # Infrastructure control. "Full API coverage" over a reverse proxy means certificates,
    # routing and access rules — a wrong call is an outage, not a bad score.
  | \b(?:nginx|dns|ssl|tls|certificate|firewall|kubernetes|terraform|infrastructure)\b
    """
)


def takes_real_world_actions(text: str) -> bool:
    return bool(_REAL_WORLD_ACTION.search(text))


def _readable_name(identifier: str) -> str:
    """A row name a reader can map back to something installable.

    Derived from the PACKAGE, not the registry namespace: naming from the namespace tail
    turned `@rapay/mcp-server` into `mcp-server-3` and `@aetherwealth/mcp` into `mcp`, which
    on a public board naming third parties is worse than useless — it obscures which server
    a finding is about.
    """
    name = identifier.lstrip("@").replace("/", "-")
    return re.sub(r"[^a-z0-9._-]+", "-", name.lower()).strip("-") or "server"


def _fetch(url: str) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-gauntlet-survey"})
    with urllib.request.urlopen(req, timeout=30) as fh:
        data: dict[str, Any] = json.load(fh)
    return data


def _requires_secret(pkg: dict[str, Any]) -> bool:
    for field in ("environmentVariables", "runtimeArguments", "packageArguments", "headers"):
        for item in pkg.get(field) or []:
            if item.get("isRequired") or item.get("isSecret"):
                return True
    return False


def fetch_all(max_pages: int = 60) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(max_pages):
        page = _fetch(BASE + "?limit=100" + (f"&cursor={cursor}" if cursor else ""))
        batch = page.get("servers") or []
        out.extend(batch)
        cursor = (page.get("metadata") or {}).get("nextCursor")
        if not cursor or not batch:
            break
    return out


def select(entries: list[dict[str, Any]], limit: int, per_publisher: int) -> list[dict[str, Any]]:
    seen_pkg: set[str] = set()
    seen_name: set[str] = set()
    by_publisher: Counter[str] = Counter()
    chosen: list[dict[str, Any]] = []

    for wrapper in entries:
        # Registry entries are WRAPPED: {"server": {...}, "_meta": {...}}.
        server = wrapper.get("server") or {}
        official = (wrapper.get("_meta") or {}).get(
            "io.modelcontextprotocol.registry/official"
        ) or {}
        if official.get("status") in {"deleted", "deprecated"}:
            continue
        if official.get("isLatest") is False:
            continue

        registry_name = str(server.get("name") or "")
        publisher = registry_name.split("/")[0] or "unknown"
        if by_publisher[publisher] >= per_publisher:
            continue

        for pkg in server.get("packages") or []:
            runner = STDIO_REGISTRIES.get(str(pkg.get("registryType") or "").lower())
            identifier = pkg.get("identifier")
            if not runner or not identifier or _requires_secret(pkg):
                continue
            if identifier in seen_pkg:
                continue

            # The leaderboard keys pages, badges and saved results by name, so a duplicate
            # would silently overwrite another server's row.
            short = _readable_name(str(identifier))
            name = short
            suffix = 2
            while name in seen_name:
                name, suffix = f"{short}-{suffix}", suffix + 1

            # NOT pinned to the registry's version, though it records one — TRIED IT, and
            # reverted. The registry's version field lags the published package badly:
            # `@adeu/mcp-server` records 1.7.1 while npm ships 1.30.0, `@oobe-protocol-labs/
            # sap-mcp-server` records 0.7 against 0.9.52. Pinning therefore scanned code the
            # maintainer shipped long ago and has since fixed, and published a grade for a
            # version nobody runs. Two servers that scored A on latest failed outright on the
            # recorded version.
            #
            # Scanning what a user actually gets is both fairer and more useful, and
            # provenance is not lost: every server self-reports its version over the
            # protocol, and the report records it (all 27 scored servers did).
            spec_id = str(identifier)

            seen_pkg.add(str(identifier))
            seen_name.add(name)
            by_publisher[publisher] += 1
            chosen.append(
                {
                    "name": name,
                    "spec": f"{runner} {spec_id}",
                    "_registry_name": registry_name,
                    "_publisher": publisher,
                    "_repository": (server.get("repository") or {}).get("url") or "",
                    "_description": str(server.get("description") or "")[:160],
                    "_real_world_actions": takes_real_world_actions(
                        f"{registry_name} {server.get('description') or ''}"
                    ),
                }
            )
            break  # one package per server: two runtimes of the same thing is one server

        if len(chosen) >= limit:
            break
    return chosen


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="survey.servers.json")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--per-publisher", type=int, default=2)
    args = ap.parse_args()

    entries = fetch_all()
    chosen = select(entries, args.limit, args.per_publisher)

    # Split by blast radius. The executable list gets the full treatment; the other is
    # scanned and never called, because no score is worth booking somebody a flight.
    safe = [c for c in chosen if not c["_real_world_actions"]]
    hazardous = [c for c in chosen if c["_real_world_actions"]]

    static_out = args.out.removesuffix(".json") + ".static-only.json"
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump({"servers": safe}, fh, indent=2)
    with open(static_out, "w", encoding="utf-8") as fh:
        json.dump({"servers": hazardous}, fh, indent=2)

    publishers = Counter(c["_publisher"] for c in chosen)
    print(f"registry entries fetched : {len(entries)}")
    print(f"selected                 : {len(chosen)}")
    print(f"distinct publishers      : {len(publishers)}")
    print(f"most from one publisher  : {publishers.most_common(1)[0] if publishers else '-'}")
    print(f"fully evaluated  ({len(safe):>2}) : {args.out}")
    print(f"static scan only ({len(hazardous):>2}) : {static_out}")
    print("   (these advertise irreversible real-world actions — scanned, never executed)")
    for c in hazardous:
        print(f"   ! {c['name'][:30]:32} {c['_description'][:56]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
