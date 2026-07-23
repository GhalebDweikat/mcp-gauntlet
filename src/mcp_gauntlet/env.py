"""Load a local ``.env`` file so API keys don't have to be exported manually.

Values already present in the real environment win over the file, so a shell
export or CI secret always overrides ``.env``.
"""

from __future__ import annotations

from dotenv import find_dotenv, load_dotenv


def load_env() -> None:
    path = find_dotenv(usecwd=True)
    if path:
        load_dotenv(path, override=False)
