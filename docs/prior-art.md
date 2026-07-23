# Prior art & competitive landscape

Research snapshot as of 2026-07-23. This is the "why does mcp-gauntlet deserve to
exist" evidence, and doubles as source material for the README's positioning.

## Direct competitors — static MCP analyzers (all shipped)

| Tool | Where | What it does | Type |
|------|-------|--------------|------|
| `mcp-lighthouse` | PyPI v0.2.0 (Jun 2026) | 21 conformance checks across protocol adherence, schema quality, robustness, best practices, performance; Lighthouse-style compliance score | **Static** |
| `mcp-scorecard` | PyPI v0.1.1 | Pre-flight checks: passive token footprint, use-case scoping, security, name safety | **Static** |
| `mcp-checkup` | PyPI v1.0.0 (stable) | Health check: context-window token consumption + security hygiene; auto-discovers Claude Desktop/Code/Cursor/Windsurf/VS Code configs | **Static** |

**The shared gap:** every one of these inspects the server *at rest* — schemas,
token counts, description linting, protocol conformance. None of them run an LLM
agent against the server to measure whether it can actually **accomplish tasks**.
That dynamic, agent-in-the-loop evaluation is mcp-gauntlet's headline.

## Adjacent tools (different problem)

| Tool | What it is | Why it's not us |
|------|-----------|-----------------|
| Invariant Labs `mcp-scan` | Security scanner: tool poisoning, rug pulls, cross-origin escalation, prompt injection | Security-only, static; we borrow its threat model for dimension 7 but don't compete on scanning |
| Cisco / eSentire `mcp-scanner` | Multi-layer security scanner (keyword + semantic + LLM) | Same — security scanning, not task-success eval |
| MCP-Atlas / MCP-Universe | Benchmarks scoring how well **models** use tools (1000+ tasks, real servers) | They rank *models*; we evaluate *a server*. Opposite subject. |
| MCPJam | CI platform: conformance + e2e + LLM-based checks wired into GitHub Actions | Heavyweight platform play; we're a single-command CLI focused on agent task-success |

## Supporting evidence for the "agent usability" thesis

- **"Docstring Engineering" (arXiv 2508.13774)** empirically shows that the
  quality of a tool's *description* materially changes whether an agent can use
  the server correctly. No shipped tool measures this against actual agent
  behavior — dimensions 2 (description quality) and 4 (tool-selection accuracy)
  target exactly that.

## Key sources

- mcp-lighthouse — https://pypi.org/project/mcp-lighthouse/
- mcp-scorecard — https://pypi.org/pypi/mcp-scorecard/json
- mcp-checkup — https://pypi.org/pypi/mcp-checkup/json
- Invariant Labs mcp-scan — https://invariantlabs.ai/blog/introducing-mcp-scan
- MCP-Atlas — https://arxiv.org/html/2602.00933v3
- Docstring Engineering — https://arxiv.org/pdf/2508.13774
- MCP server testing guide — https://yaw.sh/mcp-in-production/mcp-server-testing/
