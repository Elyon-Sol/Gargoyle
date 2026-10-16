"""A stand-in upstream MCP server for the proxy tests: stdio JSON-RPC with
one tool, `echo`, that returns its arguments. It also emits a notification
after initialize (which the proxy must drop) and answers `fixture/calls`
with everything tools/call has received, so a test can see exactly what
reached it."""
import json
import sys

calls = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    method, msg_id = msg.get("method"), msg.get("id")
    if method == "initialize":
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/message",
                                     "params": {"level": "info", "data": "upstream chatter"}}) + "\n")
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "echo-upstream", "version": "0.0.1"}}
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        result = {"tools": [{"name": "echo", "description": "Return the arguments."}]}
    elif method == "tools/call":
        calls.append(msg.get("params"))
        result = {"content": [{"type": "text", "text": "echo:" + json.dumps(msg["params"].get("arguments"), sort_keys=True)}],
                  "isError": False, "_meta": {"upstream": "seen"}}
    elif method == "fixture/calls":
        result = {"calls": calls}
    elif method == "ping":
        result = {}
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "nope"}}) + "\n")
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
    sys.stdout.flush()
