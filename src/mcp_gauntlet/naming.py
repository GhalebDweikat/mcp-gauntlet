"""Turning a server-supplied name into something safe to put in a path or a URL."""

from __future__ import annotations

import re


def slugify(name: str) -> str:
    """Reduce an arbitrary name to lowercase ASCII words joined by hyphens.

    Server names are attacker-controlled: they reach this function on their way to becoming
    a cache filename, a baseline filename, and a public badge URL. Allow-listing
    ``[a-z0-9-]`` — rather than escaping what looks dangerous — is what keeps a name
    containing ``..``, a path separator, a URL query, or a lone surrogate from ever becoming
    part of a path. The empty result gets a name of its own so a server called ``"***"``
    does not produce a dotfile.

    Deliberately not length-capped here: callers that need a bound apply their own, because
    the leaderboard's slugs are pasted into other people's READMEs as badge URLs and must
    not shift when an unrelated caller changes its mind about a limit.
    """
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "server"
