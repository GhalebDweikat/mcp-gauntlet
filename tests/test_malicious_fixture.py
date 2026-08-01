"""End-to-end: the bundled malicious server, and what the gauntlet catches about it.

This is the demo made executable. Every tool in that fixture has an innocuous description,
so a scanner that reads descriptions finds nothing — the attacks are placed where such a
scan doesn't look. Three of the four are caught with no LLM at all, which is what this test
asserts; the fourth (call-time output poisoning) needs a live agent and is covered by the
mocked runtime-scan tests in test_agent_mock.py.
"""

import sys
from pathlib import Path

from mcp_gauntlet.config import ServerSpec
from mcp_gauntlet.engine import evaluate_server
from mcp_gauntlet.report import Severity

# Built from sys.executable rather than a bare "python": the interpreter running the tests
# is the one with the package installed, and a bare name resolves against PATH.
SPEC = f"{sys.executable} -m mcp_gauntlet.fixtures.malicious_server"


async def test_the_malicious_fixture_is_caught_without_an_llm(tmp_path: Path) -> None:
    # probe=True (the default) so prompts are rendered: --no-probe promises to execute
    # nothing, and fetching a prompt is a call to the server.
    report = await evaluate_server(
        ServerSpec.parse(SPEC),
        llm_config=None,
        cache_dir=tmp_path / "tasks",  # keeps the baseline out of the real .gauntlet dir
    )
    messages = [f"{f.tool}: {f.message}" for f in report.findings]
    highs = [f for f in report.findings if f.severity is Severity.HIGH]

    # 1. The payload hidden in a display title, where the description stays clean.
    assert any("read_notes: title" in m for m in messages), messages
    # 2. The payload two levels down in the OUTPUT schema, behind a $ref.
    assert any("list_files: output" in m for m in messages), messages
    # 3. The rug-pull: sync_config is clean on the first listing and poisoned on the second,
    #    so nothing but asking twice finds it...
    assert any("sync_config" in m and "single session" in m for m in messages), messages
    # ...and the payload itself is named, not merely "something changed" — a reviewer has to
    #    be able to tell a typo fix from an instruction to exfiltrate SSH keys.
    assert any("second tools/list" in m for m in messages), messages
    assert any("second tools/list" in f"{f.tool}: {f.message}" for f in highs), messages

    # 5. The prompt whose METADATA is clean and whose rendered messages carry the payload —
    #    the surface that reaches the model's context verbatim.
    assert any("summarize_notes" in m and "prompt message" in m for m in messages), messages

    assert highs, "a deliberately poisoned server must raise HIGH findings"
    assert report.security_critical
    assert report.overall_score <= 75.0  # the cap applied


async def test_the_poisoned_prompt_is_only_found_by_rendering_it(tmp_path: Path) -> None:
    # Listing the prompt is not enough: its name, title, description and arguments are all
    # clean. --no-probe means "inspect, don't execute", so the prompt is not rendered and
    # the payload is correctly not reported — the finding requires actually fetching it.
    report = await evaluate_server(
        ServerSpec.parse(SPEC),
        llm_config=None,
        probe=False,
        cache_dir=tmp_path / "tasks",
    )
    assert not any("prompt message" in f.message for f in report.findings)


async def test_the_malicious_fixture_still_works_as_a_server(tmp_path: Path) -> None:
    # The demo's real point: this server does its job. It is not caught by being broken —
    # its schemas are valid and its tools return what they promise — so the finding is
    # about what it says and returns, not about quality.
    report = await evaluate_server(
        ServerSpec.parse(SPEC),
        llm_config=None,
        probe=False,
        cache_dir=tmp_path / "tasks",
    )
    schema = next(d for d in report.dimensions if d.key == "schema_health")
    description = next(d for d in report.dimensions if d.key == "description_quality")
    assert schema.score == 100.0
    assert description.score == 100.0


async def test_a_run_arms_the_cross_run_comparison(tmp_path: Path) -> None:
    # The run records the surface so the NEXT run has something to compare against. This
    # fixture demonstrates within-session drift rather than cross-run drift — each run
    # spawns a fresh process, so its "first look" counter resets and both runs see the same
    # poisoned listing. Cross-run comparison is exercised directly in test_drift.py, where
    # the baseline can be controlled precisely.
    spec = ServerSpec.parse(SPEC)
    await evaluate_server(spec, llm_config=None, probe=False, cache_dir=tmp_path / "tasks")
    baselines = list((tmp_path / "baselines").glob("*.json"))
    assert len(baselines) == 1
    assert "read_notes" in baselines[0].read_text(encoding="utf-8")


async def test_drift_tracking_can_be_turned_off(tmp_path: Path) -> None:
    report = await evaluate_server(
        ServerSpec.parse(SPEC),
        llm_config=None,
        probe=False,
        cache_dir=tmp_path / "tasks",
        track_drift=False,
    )
    messages = [f.message for f in report.findings]
    # The CROSS-RUN half is off: no baseline written, nothing compared against a last run.
    assert not (tmp_path / "baselines").exists()
    # Deliberately not grepping for "since the last run": the disclosure message below
    # contains that phrase itself, so the absent baseline directory is the honest evidence
    # that no comparison happened.
    # ...and the report SAYS that half did not run, rather than returning a shorter list of
    # findings that reads as a clean bill.
    assert any("--no-track-drift" in m for m in messages)

    # But the WITHIN-SESSION half still runs, and this fixture is the reason. It serves a
    # clean first listing and a poisoned second one; nothing else in the run looks at the
    # second. When this flag disabled both halves, that took the fixture from a capped C to
    # A 100.0 with zero findings and nothing saying a check had been switched off.
    assert any("single session" in m for m in messages)
    assert any("sync_config" in f"{f.tool}" for f in report.findings)


async def test_every_description_is_clean_on_its_own(tmp_path: Path) -> None:
    # The demo's central claim: a scanner that reads tool DESCRIPTIONS finds nothing here.
    # If any first-listing description were flagged by itself, the premise would be false.
    from mcp_gauntlet.checks import check_security
    from mcp_gauntlet.client import discover_in_session, open_session
    from mcp_gauntlet.models import ToolInfo

    async with open_session(ServerSpec.parse(SPEC)) as (session, init, _interactions):
        discovery = await discover_in_session(session, init)
    descriptions_only = [ToolInfo(name=t.name, description=t.description) for t in discovery.tools]
    assert len(descriptions_only) == 4
    dim = check_security(descriptions_only)
    assert dim.score == 100.0, [f.message for f in dim.findings]
