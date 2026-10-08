"""An MCP server that executes a tool call only when it carries a valid receipt.

JSON-RPC 2.0 over stdio: initialize, tools/list, tools/call. This server is
the executor, not the issuer. An agent obtains a signed receipt from the
issuer (gargoyle.issuer.issue) and sends it in tools/call params._meta under
"gargoyle/envelope". The server rebuilds the expected call from the actual
tool name and arguments, runs verify_envelope (signature, policy pin,
binding, expiry), then claims decision_id in the replay cache. The tool
fires only after a positive verdict and a fresh claim; every other path
leaves it unfired.

Run as a stdio MCP server:  python3 -m gargoyle.mcp_server
"""

import hashlib
import json
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from gargoyle.envelope import canonical_json
from gargoyle.policy import manifest_sha256, load_manifest, resolve_required_sets
from gargoyle.published_source import anchor_sha256, load_record_from_bytes
from gargoyle.replay_cache import InMemoryReplayCache
from gargoyle.reference_target import (
    REF_TARGET_ANCHOR_MISMATCH,
    REF_TARGET_NOT_CONFIGURED,
)
from gargoyle.verifier import verify_envelope, REF_VERIFY_REPLAY

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


# Tool name -> manifest interaction_type. Under a manifest with
# interaction_types, a tool declares its type's required tokens, so a benign
# tool declares fewer and need not be held. Under a flat manifest the type is
# ignored. An unknown tool gets no type and so the full top-level token set,
# which a typed manifest holds for approval (fail toward oversight). Keep this
# table in step with the deployed manifest's types.
_BENIGN_TOOLS = frozenset(
    {"read", "list", "get", "status", "inspect", "read_file", "list_files", "healthz"}
)
_SENSITIVE_TOOLS = frozenset(
    {"transfer", "transfer_funds", "delete", "delete_database", "rotate",
     "rotate_key", "write", "write_file", "deploy"}
)


def _interaction_type_for_tool(tool: str):
    """A tool's manifest interaction_type, or None for an unknown tool."""
    if tool in _BENIGN_TOOLS:
        return "read"
    if tool in _SENSITIVE_TOOLS:
        return "transfer"
    return None


def interaction_for(tool: str, args: Any) -> Dict[str, Any]:
    """Encode a tool call as the interaction a receipt binds to. The tool name
    and a SHA-256 of its canonical arguments go in `context`, so a receipt
    covers exactly this call. AP/OP are the tokens ManifestPolicy checks:
    the tool type's required sets under a typed manifest, else the top-level
    sets. This ties the server to ManifestPolicy's call shape."""
    manifest = load_manifest()
    base = {
        "context": {
            "tool": tool,
            "args_sha256": hashlib.sha256(
                canonical_json(args).encode("utf-8")
            ).hexdigest(),
        },
        "expected_manifest_version": manifest.get("version", "1.0"),
        "expected_manifest_sha256": manifest_sha256(),
    }
    itype = _interaction_type_for_tool(tool)
    types = manifest.get("interaction_types")
    if isinstance(types, dict) and itype in types:
        AR, R = resolve_required_sets(manifest, {"interaction_type": itype})
        if AR is not None and R is not None:
            return {"AP": sorted(AR), "OP": sorted(R),
                    "interaction_type": itype, **base}
    # Flat manifest, or unknown or absent type: top-level tokens, no type.
    return {"AP": ["identity", "role"], "OP": ["session", "request"], **base}


class ServerState:
    """The executor's out-of-band trust material, its replay cache and the list
    of tool calls actually executed. `config` None means unconfigured: every
    tools/call is refused with REF_TARGET_NOT_CONFIGURED."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]],
        replay_cache: Optional[InMemoryReplayCache] = None,
    ) -> None:
        self.config = config
        self.replay_cache = replay_cache if replay_cache is not None else InMemoryReplayCache()
        self.executed: List[Dict[str, Any]] = []
        self.initialized = False


def _parse_not_after(envelope: Dict[str, Any]) -> Optional[datetime]:
    na = envelope.get("not_after")
    if isinstance(na, str):
        try:
            return datetime.fromisoformat(na)
        except ValueError:
            return None
    return None


def gate_tool_call(state: ServerState, params: Dict[str, Any]) -> (bool, str):
    """Decide and, if honored, execute one tools/call. Returns (executed,
    reason). The side effect (appending to state.executed) happens only after
    a positive verdict and a fresh replay claim."""
    if state.config is None:
        return False, REF_TARGET_NOT_CONFIGURED

    name = params.get("name")
    args = params.get("arguments", {})
    meta = params.get("_meta") or {}
    envelope = meta.get(ENVELOPE_META_KEY)
    if not isinstance(envelope, dict):
        envelope = None  # absent or not an object: an unattested call

    record = load_record_from_bytes(
        state.config["record_bytes"], state.config["pinned_root"]
    )
    if record is None:
        return False, REF_TARGET_ANCHOR_MISMATCH

    expected = interaction_for(name, args)
    result = verify_envelope(
        envelope,
        expected,
        state.config["target_id"],
        record_source=record,
        pinned_public_keys=state.config["pinned_public_keys"],
    )
    if not result["accepted"]:
        return False, result["reason"]

    # Exactly once over the validity window. decision_id is signed, so it cannot
    # be altered. NOTE: a receipt with no decision_id skips this claim here,
    # unlike ExecutorGate, which refuses it.
    decision_id = envelope.get("decision_id")
    if decision_id is not None:
        if not state.replay_cache.check_and_claim(
            decision_id, _parse_not_after(envelope)
        ):
            return False, REF_VERIFY_REPLAY

    state.executed.append({"tool": name, "args": args})  # THE side effect
    return True, result["reason"]


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
    GARGOYLE_MCP_TARGET_ID is the identity receipts bind to; the published
    record is read from GARGOYLE_MCP_RECORD_PATH and anchored on its own
    bytes."""
    import os

    key_id = os.environ.get(ENV_GATE_KEY_ID)
    key_hex = os.environ.get(ENV_GATE_PUBLIC_KEY_HEX)
    target_id = os.environ.get(ENV_TARGET_ID)
    record_path = os.environ.get(ENV_RECORD_PATH, "EVIDENCE/published_hashes.json")
    if not (key_id and key_hex and target_id):
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
