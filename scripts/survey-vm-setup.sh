#!/usr/bin/env bash
# Prepare a disposable Linux VM to run the public-server survey.
#
# Targets a Debian/Ubuntu base (it uses apt). On another distribution, install git, curl,
# Node and uv however that distribution does it — nothing below is load-bearing except
# having those four available.
#
# WHY A VM: the survey executes ~50 arbitrary npm and PyPI packages. That is remote code
# execution by design — it is the product — and it does not belong on a machine holding
# real credentials, SSH keys, or source you care about. mcp-gauntlet already refuses to pass
# the parent environment to stdio child servers, so a scanned server never inherits your API
# key; but a package can still read files, open sockets, and persist. Containment is the VM,
# not the env scrubbing.
#
# BEFORE RUNNING: snapshot the VM (whatever your hypervisor calls it). Roll back to that
# snapshot when the survey finishes, and treat anything that was in the VM as exposed.
#
#   ./survey-vm-setup.sh          # install toolchain + mcp-gauntlet
#   ./survey-vm-setup.sh --check  # verify only
#
set -euo pipefail

VERSION="${MCP_GAUNTLET_VERSION:-0.7.0}"

have() { command -v "$1" >/dev/null 2>&1; }

check() {
  echo "--- versions ---"
  for c in python3 node npx uv git; do
    if have "$c"; then printf '%-8s %s\n' "$c" "$("$c" --version 2>&1 | head -1)";
    else printf '%-8s MISSING\n' "$c"; fi
  done
  echo
  if have uvx; then
    echo "mcp-gauntlet: $(uvx "mcp-gauntlet@${VERSION}" --version 2>&1 | tail -1)"
  fi
  echo
  echo "--- key hygiene ---"
  key_var="${SURVEY_KEY_VAR:-$(printf '%s' "${SURVEY_PROVIDER:-gemini}" | tr '[:lower:]-' '[:upper:]_')_API_KEY}"
  key_val="${!key_var:-}"
  if [ -n "$key_val" ]; then
    # Length only. Printing the key would write it into your scrollback and any log of
    # this run, on a machine you are about to hand to fifty unvetted packages.
    echo "$key_var is set (${#key_val} chars) — value not printed"
  else
    echo "$key_var is NOT set. The survey needs a key for its agent; see the note below."
  fi
}

if [ "${1:-}" = "--check" ]; then check; exit 0; fi

echo "==> apt prerequisites"
sudo apt-get update -qq
sudo apt-get install -y -qq curl git ca-certificates

echo "==> Node (for npx-based servers)"
if ! have node; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
  sudo apt-get install -y -qq nodejs
fi

echo "==> uv (for uvx-based servers and for mcp-gauntlet itself)"
if ! have uv; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  # shellcheck disable=SC1091
  . "$HOME/.local/bin/env" 2>/dev/null || export PATH="$HOME/.local/bin:$PATH"
fi

echo "==> mcp-gauntlet ${VERSION} (pinned: the board records the version that produced it)"
uvx "mcp-gauntlet@${VERSION}" --version

echo
check

cat <<'NOTE'

--------------------------------------------------------------------------------
Before you run the survey
--------------------------------------------------------------------------------
1. SNAPSHOT the VM now if you have not. Roll back when the survey finishes.

2. Use a SEPARATE, revocable API key here — not the one from your host. The
   survey runs untrusted code on this machine; assume anything reachable from
   this filesystem is compromised, and plan to revoke the key afterwards.

       export GEMINI_API_KEY=...        # or GROQ_API_KEY, OPENAI_API_KEY, ...
                                        # this shell only, never a dotfile

   Putting it in ~/.bashrc or a committed .env leaves it on disk for every
   package you are about to execute to read.

3. Keep the VM's shared folders DISABLED while scanning. Copy results out
   afterwards over a one-off channel (scp, or re-enable the share at the end).

4. Sanity-check the toolchain against the bundled fixtures before spending
   anything — no API key needed, no third-party code involved:

       uvx mcp-gauntlet@VERSION run "python3 -m mcp_gauntlet.fixtures.good_server" --no-agentic
       uvx mcp-gauntlet@VERSION run "python3 -m mcp_gauntlet.fixtures.malicious_server" --no-agentic

   The first should grade A; the second C, capped, with findings across all five
   attacks. If those two are right, the harness is working.
NOTE
