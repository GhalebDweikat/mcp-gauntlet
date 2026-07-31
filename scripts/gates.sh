#!/usr/bin/env bash
# Every check that must pass before a push, in one command, with honest exit codes.
#
# This exists because of a specific mistake. The habit it replaces was a shell chain:
#
#     uv run ruff check . && uv run ruff format --check . >/dev/null && uv run pytest -q
#
# which has two independent ways to lie. The `>/dev/null` hides a failure's output, and
# `&&` stops the chain there — so the later checks never run, and nothing says so. Worse,
# reading a result through a pipe (`pytest -q | tail -3`) reports the exit status of
# `tail`, which always succeeds. A red suite pushed green exactly this way.
#
# So: no check's output is discarded, every check runs even after one fails (you want the
# whole list, not the first item), each exit code is printed next to its name, and the
# script exits non-zero if any of them failed.
#
# Usage:  ./scripts/gates.sh          run everything
#         ./scripts/gates.sh -q       summary lines only, full output on failure

set -uo pipefail  # deliberately NOT -e: a failing gate must not abort the remaining ones

QUIET=0
[ "${1:-}" = "-q" ] && QUIET=1

FAILED=()
ORDER=()

run_gate() {
  local name="$1"
  shift
  ORDER+=("$name")
  local log
  log="$(mktemp)"

  # Capture rather than pipe: piping would hand us the exit status of the pipe's last
  # stage, which is the whole bug this script exists to prevent.
  "$@" >"$log" 2>&1
  local rc=$?

  if [ $rc -eq 0 ]; then
    printf '  %-14s ok\n' "$name"
    [ $QUIET -eq 0 ] && sed 's/^/      /' "$log"
  else
    printf '  %-14s FAILED (exit %d)\n' "$name" "$rc"
    sed 's/^/      /' "$log" # always shown, quiet or not
    FAILED+=("$name")
  fi
  rm -f "$log"
  return 0
}

echo "Running gates..."
run_gate ruff-check   uv run ruff check .
run_gate ruff-format  uv run ruff format --check .
run_gate mypy         uv run mypy
run_gate snapshot     uv run python scripts/snapshot_fixtures.py
run_gate pytest       uv run pytest -q

echo
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "All ${#ORDER[@]} gates passed."
  exit 0
fi
echo "${#FAILED[@]} of ${#ORDER[@]} gates failed: ${FAILED[*]}"
exit 1
