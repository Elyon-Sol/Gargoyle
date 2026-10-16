"""An MCP server that executes a tool call only when it carries a valid receipt.

JSON-RPC 2.0 over stdio: initialize, tools/list, tools/call. This server is
the executor, not the issuer. An agent obtains a signed receipt from the
issuer (gargoyle.issuer.issue) and sends it in tools/call params._meta under
"gargoyle/envelope". The server rebuilds the call from the actual tool name
and arguments plus the principal it serves and asks a gargoyle.consumer
.Consumer (signature, policy pin, binding, expiry, then the single-use
claim on decision_id). The tool fires only after a positive verdict; every
other path leaves it unfired.

The principal: a stdio server has exactly one client, the process that
spawned it, and that client's identity is established by whoever wired the
server up, not by anything on the wire. GARGOYLE_MCP_PRINCIPAL names it. A
receipt issued to any other principal is refused (REF_VERIFY_PRINCIPAL_MISMATCH),
so a receipt obtained by one agent cannot be spent through another agent's
server.

Run as a stdio MCP server:  python3 -m gargoyle.mcp_server
"""

import json
import sys
from typing import Any, Dict, List, Optional

from gargoyle.consumer import REF_TARGET_NOT_CONFIGURED, Consumer
from gargoyle.envelope import valid_principal
from gargoyle.published_source import anchor_sha256
from gargoyle.replay_cache import InMemoryReplayCache

# MCP protocol version this server speaks (a real MCP revision string).
PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "gargoyle", "version": "0.1.0"}

# The _meta key the receipt rides under in tools/call params (the MCP
# counterpart of the HTTP X-Gargoyle-Envelope header).
ENVELOPE_META_KEY = "gargoyle/envelope"
EXECUTED_META_KEY = "gargoyle/executed"
REASON_META_KEY = "gargoyle/reason"

# JSON-RPC error codes (subset).
JSONRPC_PARSE_ERROR = -32700
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_NOT_INITIALIZED = -32002

# Example tools advertised by tools/list. tools/call does not restrict to this
# set: the receipt's binding to the tool name is the control, so a receipt for
# tool A presented for tool B fails the binding check whether or not either is
# listed.
ADVERTISED_TOOLS = [
    {"name": "transfer_funds", "description": "Move funds between accounts (gated)."},
    {"name": "delete_database", "description": "Delete a database (gated)."},
]

# Out-of-band configuration, read from the environment (see config_from_env).
ENV_GATE_KEY_ID = "GARGOYLE_MCP_GATE_KEY_ID"
ENV_GATE_PUBLIC_KEY_HEX = "GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX"
ENV_TARGET_ID = "GARGOYLE_MCP_TARGET_ID"
ENV_RECORD_PATH = "GARGOYLE_MCP_RECORD_PATH"
ENV_PRINCIPAL = "GARGOYLE_MCP_PRINCIPAL"


def call_for(tool: str, args: Any, principal: str) -> Dict[str, Any]:
    """The call a receipt must bind to execute `tool` with `args` through a
    server serving `principal`: the same three fields the issuer bound."""
    return {"tool": tool, "args": args, "principal": principal}


class ServerState:
    """The executor's out-of-band trust material (issuer keys, record anchor,
    target id, the principal it serves) as a Consumer, and the list of tool
    calls actually executed. `config` None, or a config without a usable
    principal, means unconfigured: every tools/call is refused with
    REF_TARGET_NOT_CONFIGURED."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]],
        replay_cache: Optional[InMemoryReplayCache] = None,
    ) -> None:
        self.config = config
        self.consumer: Optional[Consumer] = None
        if config is not None and valid_principal(config.get("principal")):
            self.consumer = Consumer(
                target_id=config["target_id"],
                pinned_public_keys=config["pinned_public_keys"],
                record_bytes=config["record_bytes"],
                pinned_root=config["pinned_root"],
                replay_cache=replay_cache,
            )
        self.executed: List[Dict[str, Any]] = []
        self.initialized = False


def gate_tool_call(state: ServerState, params: Dict[str, Any]) -> (bool, str):
    """Decide and, if honored, execute one tools/call. Returns (executed,
    reason). The side effect (appending to state.executed) happens only after
    the consumer honored the receipt, which includes its single-use claim."""
    if state.consumer is None:
        return False, REF_TARGET_NOT_CONFIGURED

    name = params.get("name")
    args = params.get("arguments", {})
    meta = params.get("_meta") or {}
    envelope = meta.get(ENVELOPE_META_KEY)

    verdict = state.consumer.check(envelope, call_for(name, args, state.config["principal"]))
    if not verdict.honored:
        return False, verdict.reason

    state.executed.append({"tool": name, "args": args})  # THE side effect
    return True, verdict.reason


def _success(msg_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def handle_message(state: ServerState, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Dispatch one JSON-RPC message. Returns a response dict, or None for a notification (a
    message with no `id`, e.g. notifications/initialized)."""
    method = msg.get("method")
    msg_id = msg.get("id")
    is_notification = "id" not in msg
    params = msg.get("params") or {}

    if method == "initialize":
        # The handshake completes when the client sends notifications/initialized;
        # tools are served only after that.
        return _success(
            msg_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            },
        )

    if method == "notifications/initialized":
        state.initialized = True
        return None

    if method == "ping":
        return _success(msg_id, {})

    if method == "gargoyle/executed_count":
        # Read-only observability: how many tool calls actually fired. Not part
        # of admission; it discloses only a count, so a test driving the stdio
        # server can confirm exactly-once across the process boundary.
        return _success(msg_id, {"count": len(state.executed)})

    if method in ("tools/list", "tools/call") and not state.initialized:
        if is_notification:
            return None
        return _error(msg_id, JSONRPC_NOT_INITIALIZED, "server not initialized")

    if method == "tools/list":
        return _success(msg_id, {"tools": ADVERTISED_TOOLS})

    if method == "tools/call":
        executed, reason = gate_tool_call(state, params)
        text = ("executed %s" % params.get("name")) if executed else ("refused: %s" % reason)
        result = {
            "content": [{"type": "text", "text": text}],
            "isError": (not executed),
            "_meta": {EXECUTED_META_KEY: executed, REASON_META_KEY: reason},
        }
        return _success(msg_id, result)

    if is_notification:
        return None
    return _error(msg_id, JSONRPC_METHOD_NOT_FOUND, "method not found: %s" % method)


def config_from_env() -> Optional[Dict[str, Any]]:
    """The executor's configuration from the environment, or None (then every
    tool call is refused). GARGOYLE_MCP_GATE_KEY_ID and
    GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX pin the issuer's public key;
    GARGOYLE_MCP_TARGET_ID is the identity receipts bind to;
    GARGOYLE_MCP_PRINCIPAL is the client this server serves (see the module
    docstring); the published record (the live policy pin) is read from
    GARGOYLE_MCP_RECORD_PATH and anchored on its own bytes. All five are
    required; there is no default record."""
    import os

    key_id = os.environ.get(ENV_GATE_KEY_ID)
    key_hex = os.environ.get(ENV_GATE_PUBLIC_KEY_HEX)
    target_id = os.environ.get(ENV_TARGET_ID)
    principal = os.environ.get(ENV_PRINCIPAL)
    record_path = os.environ.get(ENV_RECORD_PATH)
    if not (key_id and key_hex and target_id and principal and record_path):
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
        with open(record_path, "rb") as f:
            record_bytes = f.read()
    except Exception:
        return None
    return {
        "pinned_public_keys": {key_id: public_key},
        "record_bytes": record_bytes,
        "pinned_root": anchor_sha256(record_bytes),
        "target_id": target_id,
        "principal": principal,
    }


def serve_stdio(state: ServerState, stdin=None, stdout=None) -> None:
    """The MCP stdio transport: newline-delimited JSON-RPC in on stdin, responses
    out on stdout. A parse error yields a JSON-RPC parse error; a notification
    yields no line."""
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            stdout.write(json.dumps(_error(None, JSONRPC_PARSE_ERROR, "parse error")) + "\n")
            stdout.flush()
            continue
        response = handle_message(state, msg)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


if __name__ == "__main__":
    serve_stdio(ServerState(config_from_env()))
