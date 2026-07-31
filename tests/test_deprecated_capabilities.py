"""A capability the negotiated revision has deprecated.

Only `logging` can ever appear here. `sampling` and `roots` are CLIENT capabilities with no
place in `ServerCapabilities`, so a check hunting for them on a server would be hunting for
something that cannot exist — the plan called for all three, and two of them were a
category error.

The version gate is the part worth testing hardest. Reporting this against a server that
negotiated 2025-11-25 would manufacture a finding against every correct server built before
the deprecation existed, which is the same shape as the twenty-five false positives.
"""

from types import SimpleNamespace

from sdk_shapes import shape

from mcp_gauntlet.engine import _deprecated_capability_findings
from mcp_gauntlet.report import Severity


def _init(*, logging: object) -> object:
    return shape(capabilities=SimpleNamespace(logging=logging, tools=None))


def test_a_modern_server_advertising_logging_is_noted() -> None:
    findings = _deprecated_capability_findings(_init(logging={}), "2026-07-28")
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO  # a note for the author, not a defect
    assert "logging" in findings[0].message


def test_a_server_on_an_older_revision_is_not_reported() -> None:
    """The gate. Advertising `logging` in 2025-11-25 is correct behaviour, not a finding."""
    assert _deprecated_capability_findings(_init(logging={}), "2025-11-25") == []
    assert _deprecated_capability_findings(_init(logging={}), "2025-06-18") == []


def test_a_server_that_does_not_advertise_logging_is_not_reported() -> None:
    assert _deprecated_capability_findings(_init(logging=None), "2026-07-28") == []


def test_an_unknown_protocol_version_is_not_reported() -> None:
    # No negotiated version means no basis for saying the deprecation applies to it.
    assert _deprecated_capability_findings(_init(logging={}), None) == []
    assert _deprecated_capability_findings(_init(logging={}), "") == []


def test_a_later_revision_still_reports() -> None:
    # The gate is "at or after", not "exactly" — a 2027 revision has not un-deprecated it.
    assert len(_deprecated_capability_findings(_init(logging={}), "2027-01-01")) == 1
