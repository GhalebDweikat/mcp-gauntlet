"""A hand-rolled stdio MCP server that logs to stdout on every tools/call.

Deliberately NOT built on the SDK. Both SDK eras rebind `sys.stdout` inside their stdio
transport precisely so a server's own `print` cannot corrupt the protocol stream — which is
good for real servers and makes it impossible to write this test with them. Every attempt to
reproduce mid-session pollution through the fixtures' shim produced a clean stream, because
the SDK was quietly catching the mistake the check is supposed to find in servers that are
NOT built on it (a NestJS banner, a Go server's default logger, anything hand-rolled).

So this speaks the wire itself. It is the smallest thing that answers `initialize`,
`tools/list` and `tools/call`, and writes one non-protocol line to real stdout each time a
tool is called — a per-request logger, which is the common shape of the defect. A startup
banner was always caught; this one was not, because the transport log was read straight
after discovery and every tool call happens later.
"""

from __future__ import annotations

import json
import sys

PROTOCOL_VERSION = "2025-06-18"

TOOLS = [
    {
        "name": "lookup",
        "description": "Look a record up by its identifier and return the stored record.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string", "description": "The record identifier."}},
            "required": ["id"],
        },
    }
]


def _send(payload: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def _result(request_id: object, result: dict[str, object]) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "result": result})


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        method = message.get("method")
        request_id = message.get("id")

        if method == "initialize":
            _result(
                request_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "wire-noise", "version": "1.0.0"},
                },
            )
        elif method == "tools/list":
            _result(request_id, {"tools": TOOLS})
        elif method == "tools/call":
            # THE POINT: a log line on the channel that carries JSON-RPC framing, emitted
            # per request rather than once at startup. A conforming client skips it, so the
            # server appears to work and its author never sees the problem.
            sys.stdout.write("[info] tool call served\n")
            sys.stdout.flush()
            _result(request_id, {"content": [{"type": "text", "text": "ok"}]})
        elif request_id is not None:
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                }
            )
        # Notifications (no id) get no response, per JSON-RPC.


if __name__ == "__main__":
    main()
