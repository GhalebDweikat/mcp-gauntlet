#!/usr/bin/env bash
# Run the public-server survey inside the isolated VM.
#
# This is the ONLY step that needs isolation: it executes ~50 arbitrary npm and PyPI
# packages. Everything else — building the list, triaging findings, rendering and publishing
# the board — happens on the host from the JSON this writes.
#
#   ./run-survey.sh survey.servers.json                 # full run
#   ./run-survey.sh survey.servers.json --pilot 5       # first 5 only, to prove it works
#
# Results land in ./survey-out. Copy that directory back to the host when done.
set -euo pipefail

LIST="${1:?usage: run-survey.sh <servers.json> [--pilot N]}"
shift || true

VERSION="${MCP_GAUNTLET_VERSION:-0.6.0}"
OUT="${SURVEY_OUT:-survey-out}"

# How to invoke the harness. Default is the published wheel, pinned.
#
# MCP_GAUNTLET_FROM=local runs this checkout instead, for when the version you want to
# survey with is tagged but not yet on PyPI. That stays reproducible ONLY from a clean
# checkout at a tag — `git checkout v0.6.0 && git status` must be empty. Running a dirty
# tree stamps every row with a version number nobody else can reproduce, which is the one
# thing the stamp exists to prevent.
if [ "${MCP_GAUNTLET_FROM:-}" = "local" ]; then
  REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  GAUNTLET=(uv run --directory "$REPO" mcp-gauntlet)
  if [ -n "$(git -C "$REPO" status --porcelain 2>/dev/null)" ]; then
    echo "WARNING: running a DIRTY checkout. Scores will be stamped with a version" >&2
    echo "         nobody can reproduce. Commit, or check out a tag, before surveying." >&2
  fi
else
  GAUNTLET=(uvx "mcp-gauntlet@${VERSION}")
fi
TASKS="${SURVEY_TASKS:-3}"
REPEATS="${SURVEY_REPEATS:-2}"

# Which LLM drives the agent. Defaults to Gemini Flash only because it is cheap enough to
# scan fifty servers for a few dollars — nothing here depends on the provider. Override for
# any OpenAI-compatible backend, including a local one:
#
#   SURVEY_PROVIDER=groq SURVEY_MODEL=llama-3.3-70b-versatile ./run-survey.sh list.json
#
PROVIDER="${SURVEY_PROVIDER:-gemini}"
MODEL="${SURVEY_MODEL:-gemini-flash-latest}"
# The env var mcp-gauntlet reads for this provider (GEMINI_API_KEY, GROQ_API_KEY, ...).
KEY_VAR="${SURVEY_KEY_VAR:-$(printf '%s' "$PROVIDER" | tr '[:lower:]-' '[:upper:]_')_API_KEY}"

PILOT=0
if [ "${1:-}" = "--pilot" ]; then PILOT="${2:?--pilot needs a count}"; fi

# ---------------------------------------------------------------- preconditions
if [ -z "${!KEY_VAR:-}" ]; then
  echo "$KEY_VAR is not set (provider: $PROVIDER)." >&2
  echo "Export it in THIS SHELL only — not in a dotfile. You are about to run untrusted" >&2
  echo "code on this machine, and anything on disk is readable by it." >&2
  exit 1
fi
if [ ! -f "$LIST" ]; then echo "no such server list: $LIST" >&2; exit 1; fi

command -v uvx >/dev/null || { echo "uvx not found — run survey-vm-setup.sh first" >&2; exit 1; }
command -v npx >/dev/null || { echo "npx not found — run survey-vm-setup.sh first" >&2; exit 1; }

if [ "$PILOT" -gt 0 ]; then
  LIST_TO_RUN="$(mktemp)"
  python3 - "$LIST" "$PILOT" "$LIST_TO_RUN" <<'PY'
import json, sys
src, n, dst = sys.argv[1], int(sys.argv[2]), sys.argv[3]
data = json.load(open(src, encoding="utf-8"))
json.dump({"servers": data["servers"][:n]}, open(dst, "w", encoding="utf-8"), indent=2)
PY
  echo "PILOT: first $PILOT server(s) only"
else
  LIST_TO_RUN="$LIST"
fi

COUNT=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1],encoding='utf-8'))['servers']))" "$LIST_TO_RUN")

cat <<EOF
--------------------------------------------------------------------------------
mcp-gauntlet survey
  harness   : ${GAUNTLET[*]}
  servers   : $COUNT
  model     : $PROVIDER:$MODEL  ($TASKS tasks x $REPEATS repeats)
  output    : $OUT
  estimate  : ~\$$(python3 -c "print(f'{$COUNT*0.09:.2f}')") at ~\$0.09/server
--------------------------------------------------------------------------------
Each server is downloaded and EXECUTED. Confirm this VM is snapshotted.
EOF
read -r -p "Continue? [y/N] " reply
[ "$reply" = "y" ] || [ "$reply" = "Y" ] || { echo "aborted"; exit 1; }

# ---------------------------------------------------------------- the run
# --timeout bounds a server that hangs on connect; --tool-timeout bounds one slow call.
# Both matter far more here than on a curated list: these packages are unvetted, and one
# that never returns would otherwise stall the whole survey.
set +e
"${GAUNTLET[@]}" leaderboard \
  --servers "$LIST_TO_RUN" \
  --out "$OUT" \
  --provider "$PROVIDER" \
  --model "$MODEL" \
  --tasks "$TASKS" \
  --repeats "$REPEATS" \
  --timeout 300 \
  --tool-timeout 45 \
  2>&1 | tee "survey-run.log"
status=${PIPESTATUS[0]}
set -e

# ------------------------------------------------- the servers we refuse to execute
# Some listed servers advertise irreversible real-world actions — sending payments, booking
# travel, placing calls, deploying sites. They are still worth SCANNING: the security
# findings are the point, and reading a server's tool definitions is safe. Executing one is
# not. --no-agentic stops the agent; --no-probe stops the robustness prober, which also
# calls tools. Both are required — either alone still executes something.
STATIC_LIST="${LIST%.json}.static-only.json"
if [ "$PILOT" -eq 0 ] && [ -f "$STATIC_LIST" ]; then
  n=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1],encoding='utf-8'))['servers']))" "$STATIC_LIST")
  if [ "$n" -gt 0 ]; then
    echo
    echo "==> static-only pass: $n server(s) that take real-world actions (never executed)"
    set +e
    "${GAUNTLET[@]}" leaderboard \
      --servers "$STATIC_LIST" \
      --out "$OUT" \
      --no-agentic \
      --no-probe \
      --timeout 300 \
      2>&1 | tee -a "survey-run.log"
    set -e
    # Both passes wrote into $OUT/servers/. Each run rewrote index.html from only its own
    # results, so rebuild the page from every saved result — free, no LLM calls.
    "${GAUNTLET[@]}" leaderboard --out "$OUT" --render-only >/dev/null
    echo "merged both passes into $OUT/index.html"
  fi
fi

echo
echo "exit status: $status"
echo "results    : $OUT/servers/*.json  ($(ls -1 "$OUT/servers" 2>/dev/null | wc -l) file(s))"
echo "log        : survey-run.log"
cat <<'EOF'

Next:
  1. Copy the results to the host — the JSON is what matters; the HTML is regenerated
     there for free with `mcp-gauntlet leaderboard --render-only`:

         tar czf survey-results.tgz survey-out survey-run.log

  2. Roll this VM back to its snapshot, and revoke the API key you used here.
EOF
