"""The console must survive a legacy codepage.

Windows hands a process the ANSI codepage rather than UTF-8, and cp1252 cannot
encode the warning sign the CLI prints on every run — nor the Cyrillic and Greek
letters that a homoglyph finding consists of. Both crashed with UnicodeEncodeError
in every release up to 0.7.0, which meant the confusable check took the run down
at exactly the moment it caught something.

These spawn subprocesses because the bug lives in the encoding of the real stdout;
pytest's capture replaces that stream, so an in-process test cannot see it.
"""

import os
import subprocess
import sys

# Cyrillic a, e, o, r, s — the substitutions the confusable check exists to catch.
HOMOGLYPHS = "аеорс"
WARNING_SIGN = "⚠"


def _cp1252_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "cp1252"
    return env


def test_homoglyph_output_survives_a_legacy_codepage() -> None:
    """A finding made of Cyrillic must print on a console that cannot encode it."""
    code = (
        "from mcp_gauntlet.cli import console\n"
        f"console.print('tool: {HOMOGLYPHS} {WARNING_SIGN}')\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", code],
        env=_cp1252_env(),
        capture_output=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    assert b"UnicodeEncodeError" not in done.stderr
    # Not merely uncrashed: the characters must still arrive intact.
    assert HOMOGLYPHS in done.stdout.decode("utf-8", "replace")


def test_demo_command_survives_a_legacy_codepage() -> None:
    """The command on the landing page, under the encoding most Windows boxes use."""
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcp_gauntlet.cli",
            "run",
            f"{sys.executable} -m mcp_gauntlet.fixtures.malicious_server",
            "--no-agentic",
        ],
        env=_cp1252_env(),
        capture_output=True,
        timeout=300,
    )
    combined = done.stdout + done.stderr
    assert b"UnicodeEncodeError" not in combined, combined.decode("utf-8", "replace")[-2000:]
    assert done.returncode == 0, combined.decode("utf-8", "replace")[-2000:]
