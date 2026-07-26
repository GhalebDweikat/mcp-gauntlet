"""Build the scratch targets the leaderboard's filesystem and git rows are pointed at.

Why this exists: those two servers are scored on whatever directory or repository you aim
them at, so aiming them at the working checkout scores the *checkout*, not the server. On
the published board that produced two junk findings — the filesystem row flagged a sentence
in a README that happened to mention a credential filename, and the git row diffed the
board's own generated HTML and read the previous run's findings back to itself. Neither is
reproducible by anyone else, and both leak fragments of one operator's working tree onto a
public page.

The filesystem row reads `leaderboard-sandbox/`, which is committed. The git row needs a
repository, and a nested `.git` inside this one would be a mess (git walks upward and would
find the parent), so it lives outside the tree under `.gauntlet-fixtures/` — gitignored,
rebuilt from here on demand.

    python scripts/make_leaderboard_fixtures.py
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT / ".gauntlet-fixtures" / "git-repo"

FILES = {
    "README.md": "# Sample project\n\nA small project used as a fixed scan target.\n",
    "main.py": 'def greet(name):\n    return f"hello, {name}"\n\n\nprint(greet("world"))\n',
    "data.csv": "region,quarter,revenue\nnorth,Q1,120400\nsouth,Q1,98750\n",
}
SECOND_COMMIT = {"main.py": FILES["main.py"] + '\n\nprint(greet("again"))\n'}


def git(*args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    )


def main() -> int:
    if REPO.exists():
        print(f"already present: {REPO}  (delete it to rebuild)")
        return 0
    REPO.mkdir(parents=True)
    git("init", "-q", "-b", "main")
    # Local identity only — never touches the user's global config.
    git("config", "user.email", "fixtures@mcp-gauntlet.invalid")
    git("config", "user.name", "mcp-gauntlet fixtures")
    for name, body in FILES.items():
        (REPO / name).write_text(body, encoding="utf-8")
    git("add", ".")
    git("commit", "-q", "-m", "Initial commit")
    for name, body in SECOND_COMMIT.items():
        (REPO / name).write_text(body, encoding="utf-8")
    git("add", ".")
    git("commit", "-q", "-m", "Call greet a second time")
    # Leave one unstaged edit so `git_diff_unstaged` has something bounded to return.
    (REPO / "README.md").write_text(
        FILES["README.md"] + "\nA second paragraph, edited but not staged.\n", encoding="utf-8"
    )
    print(f"built {REPO}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
