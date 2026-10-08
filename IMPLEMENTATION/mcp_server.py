"""
Real MCP server with the Elyon-Sol admissibility gate on tool execution
(docs/restructure/17_mcp_server_spec.md, increment VL-077, artifact 13 Phase B step B4).

Promotes the in-process wedge demo (EVIDENCE/proofs/wedge_agent_toolcall_001_runner.py, VL-066)
to a REAL MCP server: JSON-RPC 2.0 over stdio, the MCP `initialize` handshake, `tools/list`, and
`tools/call`, with the production admissibility gate on tool execution. The demo proved the
executor-side wedge SEMANTICS but stated its fidelity gap ("no initialize handshake, capability
negotiation, or stdio transport"); this module closes it.

This server is the EXECUTOR, not the gate. Admission is still performed by pep.py: the agent
calls the gate to obtain a signed envelope, then calls a tool here carrying it. The server
reconstructs the expected interaction from the ACTUAL call and runs the production
`verify_envelope` (signature -> reassert/currency -> binding -> freshness), then the VL-076
`ReplayCache` seam for exactly-once. No gate logic is re-implemented; no new reason code is added
on the verify path. The tool side effect fires ONLY on a positive verdict followed by a fresh
replay claim - every undecidable path fails closed (canon section 9) and leaves the tool unfired.

No new canonical invariant (canon section 14): the server consumes the target-side revalidation
step (canon section 13); it changes WHERE the gate runs (a real MCP surface), not WHAT it
decides. Build-then-wire: no caller on the default pep.py path; this is the first real consumer
of the VL-076 replay seam.

Run as a real stdio MCP server:  PYTHONPATH=. python3 -m IMPLEMENTATION.mcp_server
"""

import hashlib
import json
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from IMPLEMENTATION.envelope import canonical_json
from IMPLEMENTATION.evaluator import manifest_sha256, load_manifest, resolve_required_sets
from IMPLEMENTATION.published_source import anchor_sha256, load_record_from_bytes
from IMPLEMENTATION.replay_cache import InMemoryReplayCache
from IMPLEMENTATION.reference_target import (
    REF_TARGET_ANCHOR_MISMATCH,
    REF_TARGET_NOT_CONFIGURED,
)
from IMPLEMENTATION.verifier import verify_envelope, REF_VERIFY_REPLAY

# MCP protocol version this server speaks (a real MCP revision string).
PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "elyon-sol-gated-tools", "version": "0.1.0"}

# The _meta key the admissibility envelope rides under in tools/call params
# (the MCP-idiomatic parallel of the HTTP X-Elyon-Sol-Envelope header).
ENVELOPE_META_KEY = "elyon-sol/envelope"
EXECUTED_META_KEY = "elyon-sol/executed"
REASON_META_KEY = "elyon-sol/reason"

# JSON-RPC error codes (subset).
JSONRPC_PARSE_ERROR = -32700
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_NOT_INITIALIZED = -32002

# Representative tools advertised by tools/list. tools/call does NOT restrict by
# this set: the envelope's binding to the tool name (not a server-side registry)
# is the control, so an envelope admitted for tool A presented for tool B fails
# the binding check regardless of registration.
ADVERTISED_TOOLS = [
    {"name": "transfer_funds", "description": "Move funds between accounts (gated)."},
    {"name": "delete_database", "description": "Delete a database (gated)."},
]

# Out-of-band configuration environment variable names (parallel reference_target).
ENV_GATE_KEY_ID = "ELYON_MCP_GATE_KEY_ID"
ENV_GATE_PUBLIC_KEY_HEX = "ELYON_MCP_GATE_PUBLIC_KEY_HEX"
ENV_TARGET_ID = "ELYON_MCP_TARGET_ID"
ENV_RECORD_PATH = "ELYON_MCP_RECORD_PATH"


# Tool -> interaction-type taxonomy (typed-impact, step 8.2). A tool maps to a
# manifest interaction_type; the tokens it declares are that type's required
# sets. Under a TYPED manifest a benign tool declares the reduced (benign) set;
# under a FLAT manifest (no interaction_types) the output is BYTE-IDENTICAL to
# the pre-typed hardcoded interaction (full tokens, no interaction_type field),
# so this is default-off until a typed manifest is pinned. An unknown tool maps
# to no type -> the top-level (union) sets -> held under a typed policy (fail
# toward oversight). Edit this table when the deployed manifest's type set changes.
_BENIGN_TOOLS = frozenset(
    {"read", "list", "get", "status", "inspect", "read_file", "list_files", "healthz"}
)
_SENSITIVE_TOOLS = frozenset(
    {"transfer", "transfer_funds", "delete", "delete_database", "rotate",
     "rotate_key", "write", "write_file", "deploy"}
)


def _interaction_type_for_tool(tool: str):
    """Map a tool name to a manifest interaction_type, or None (unknown -> the
    conservative top-level path)."""
    if tool in _BENIGN_TOOLS:
        return "read"
    if tool in _SENSITIVE_TOOLS:
        return "transfer"
    return None


def interaction_for(tool: str, args: Any) -> Dict[str, Any]:
    """Encode a tool call as an admissibility interaction. AP/OP are the
    authority/operation sets the gate evaluates; the tool identity + an args
    digest ride in the free-form context (canon 11.1 C) so the envelope BINDS to
    this exact tool call.

    Typed-impact (step 8.2): under a manifest that declares `interaction_types`,
    the tool's mapped type selects the REDUCED required sets it must cover (a
    benign tool declares fewer tokens, so requires_approval need not hold it).
    Under the flat/default manifest the output is byte-identical to the pre-typed
    behavior (full tokens, no interaction_type field)."""
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
    # Flat manifest or unknown/absent type: top-level tokens, no interaction_type
    # (byte-identical to the pre-typed default-manifest interaction).
    return {"AP": ["identity", "role"], "OP": ["session", "request"], **base}


class ServerState:
    """Holds the executor's out-of-band trust material, the replay cache (the VL-076 seam), and
    the observable executed-actions list. `config` is None when the server is unconfigured, in
    which case tools/call fails closed (REF_TARGET_NOT_CONFIGURED)."""

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
    """The executor-side admissibility gate. Returns (executed, reason). The tool side effect is
    appended to state.executed ONLY on a positive verify verdict followed by a fresh replay
    claim; every other path returns (False, <reason>) and leaves the tool unfired."""
    if state.config is None:
        return False, REF_TARGET_NOT_CONFIGURED

    name = params.get("name")
    args = params.get("arguments", {})
    meta = params.get("_meta") or {}
    envelope = meta.get(ENVELOPE_META_KEY)
    if not isinstance(envelope, dict):
        envelope = None  # absent / non-object -> un-attested (A1)

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

    # Exactly-once over the freshness window via the VL-076 seam. decision_id is
    # inside the signed region (tamper-proof) and stamped by the gate.
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

    if method == "elyon-sol/executed_count":
        # Observability (read-only), parallel to reference_target's /received: how
        # many tool calls actually fired. Not part of the admission policy and not a
        # trust surface; it discloses only an integer count, letting a real-stdio
        # runner confirm exactly-once across the process boundary.
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
    """Resolve the executor's out-of-band configuration from the environment. Returns a config
    dict or None (the fail-closed signal: an unconfigured server refuses every tool call with
    REF_TARGET_NOT_CONFIGURED). The published record is read from ELYON_MCP_RECORD_PATH (default
    EVIDENCE/published_hashes.json) and anchored on its own bytes; the pinned gate public key is
    supplied as hex."""
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
    """Read line-delimited JSON-RPC messages from stdin, dispatch, write line-delimited
    responses to stdout. The real MCP stdio transport (newline-delimited JSON). A parse error
    emits a JSON-RPC parse error; a notification produces no response line."""
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
