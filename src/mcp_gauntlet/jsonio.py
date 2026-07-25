"""Reading JSON files that Windows shells wrote.

PowerShell emits UTF-16LE from a plain ``>`` redirect and UTF-8-with-BOM from
``Out-File``/``Set-Content -Encoding utf8``, so the two most natural ways to author or edit
one of this tool's JSON files on the platform both fail a strict ``utf-8`` read. That has
already cost this project twice, and the second time it silently disabled a check rather
than raising — which is the worse outcome, so the tolerant read lives in one place.
"""

from __future__ import annotations

from pathlib import Path


def read_json_text(path: Path) -> str:
    """Decode a JSON file written as UTF-8, UTF-8-with-BOM, or UTF-16."""
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")
