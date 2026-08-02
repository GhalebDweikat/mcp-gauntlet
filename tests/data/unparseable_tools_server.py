"""A hand-rolled stdio MCP server that answers tools/list with a chosen malformed shape.

Hand-rolled because the SDK will not SERVE a tool definition its own model rejects — it
validates on the way out as well as the way in. The defect only exists on the wire, so the
fixture has to write the wire.

Which shapes are actually unparseable differs by era: `mcp` 2.0's model is stricter than
1.x's, and rejects `{}` and `{"type": "objekt"}` that 1.x accepts. The test asserts the
OUTCOME is uniform rather than pinning per-shape behaviour to one SDK.

Usage: python unparseable_tools_server.py <shape>
"""

from __future__ import annotations

import json
import sys

PROTOCOL_VERSION = "2025-06-18"

_VALID_SCHEMA = {
    "type": "object",
    "properties": {"id": {"type": "string", "description": "The record identifier."}},
    "required": ["id"],
}

# name -> the tool object this shape puts on the wire.
SHAPES: dict[str, dict] = {
    "ok": {"name": "lookup", "description": "Look a record up.", "inputSchema": _VALID_SCHEMA},
    "empty": {"name": "lookup", "description": "Look a record up.", "inputSchema": {}},
    "badtype": {
        "name": "lookup",
        "description": "Look a record up.",
        "inputSchema": {"type": "objekt", "properties": {}},
    },
    "proplist": {
        "name": "lookup",
        "description": "Look a record up.",
        "inputSchema": {"type": "object", "properties": []},
    },
    "missing": {"name": "lookup", "description": "Look a record up."},
    "notobject": {"name": "lookup", "description": "Look a record up.", "inputSchema": "nope"},
    "nameless": {"description": "Look a record up.", "inputSchema": _VALID_SCHEMA},
}


def _send(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def main(shape: str) -> None:
    tool = SHAPES[shape]
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        method, request_id = message.get("method"), message.get("id")

        if method == "initialize":
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "unparseable-tools", "version": "1.0.0"},
                    },
                }
            )
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": [tool]}})
        elif method == "tools/call":
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"content": [{"type": "text", "text": "ok"}]},
                }
            )
        elif request_id is not None:
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                }
            )


if __name__ == "__main__":
    main(sys.argv[1])
