"""The MCP server's tools/call gate: a receipt is honored once, and only if it
carries a decision_id to be single-used on."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.envelope import build_envelope, sign_envelope
from gargoyle.issuer import issue
from gargoyle.mcp_server import ENVELOPE_META_KEY, ServerState, gate_tool_call, interaction_for
from gargoyle.policy import ManifestPolicy
from gargoyle.published_source import anchor_sha256
from gargoyle.reference_target import REF_TARGET_NO_DECISION_ID
from gargoyle.verifier import REF_VERIFY_REPLAY

TARGET_ID = "mcp://tools.example.com"


def _state(key):
    record_bytes = open("EVIDENCE/published_hashes.json", "rb").read()
    return ServerState({
        "pinned_public_keys": {"k1": key.public_key()},
        "record_bytes": record_bytes,
        "pinned_root": anchor_sha256(record_bytes),
        "target_id": TARGET_ID,
    })


def _params(envelope, name="transfer", args=None):
    return {"name": name, "arguments": args or {"amount": 5}, "_meta": {ENVELOPE_META_KEY: envelope}}


def test_issued_receipt_executes_exactly_once():
    key = Ed25519PrivateKey.generate()
    state = _state(key)
    env = issue(ManifestPolicy(), TARGET_ID, interaction_for("transfer", {"amount": 5}),
                signing_key=key, key_id="k1").envelope
    assert gate_tool_call(state, _params(env))[0] is True
    assert gate_tool_call(state, _params(env)) == (False, REF_VERIFY_REPLAY)
    assert len(state.executed) == 1


def test_signed_receipt_without_decision_id_is_refused():
    """Without a decision_id there is nothing to claim, so the receipt could be
    replayed until it expires. Refuse it, as ExecutorGate and the reference
    target do."""
    key = Ed25519PrivateKey.generate()
    state = _state(key)
    env = sign_envelope(
        build_envelope(decision="ELIGIBLE", target_url=TARGET_ID,
                       normalized_interaction=interaction_for("transfer", {"amount": 5}),
                       policy_pin=ManifestPolicy().pin()),
        key, "k1",
    )
    for _ in range(2):
        assert gate_tool_call(state, _params(env)) == (False, REF_TARGET_NO_DECISION_ID)
    assert state.executed == []
