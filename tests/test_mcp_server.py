"""The MCP server's tools/call gate: a receipt is honored once, only for the
tool, arguments and principal it was issued for, and only if it carries a
decision_id to be single-used on."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from reference import MANIFEST_PATH, reference_policy, reference_record_bytes
from gargoyle.envelope import build_envelope, sign_envelope
from gargoyle.issuer import issue
from gargoyle.mcp_server import (
    ENV_GATE_KEY_ID, ENV_GATE_PUBLIC_KEY_HEX, ENV_PRINCIPAL, ENV_RECORD_PATH, ENV_TARGET_ID,
    ENVELOPE_META_KEY, ServerState, call_for, config_from_env, gate_tool_call,
)
from gargoyle.policy import ManifestPolicy, manifest_sha256
from gargoyle.published_source import anchor_sha256
from gargoyle.consumer import REF_TARGET_NO_DECISION_ID, REF_TARGET_NOT_CONFIGURED
from gargoyle.verifier import REF_VERIFY_BINDING_MISMATCH, REF_VERIFY_PRINCIPAL_MISMATCH, REF_VERIFY_REPLAY

TARGET_ID = "mcp://tools.example.com"
PRINCIPAL = "agent-7"


def _state(key, principal=PRINCIPAL):
    record_bytes = reference_record_bytes()
    config = {
        "pinned_public_keys": {"k1": key.public_key()},
        "record_bytes": record_bytes,
        "pinned_root": anchor_sha256(record_bytes),
        "target_id": TARGET_ID,
    }
    if principal is not None:
        config["principal"] = principal
    return ServerState(config)


def _claims():
    """What ManifestPolicy reads; none of it is bound into the receipt."""
    return {"AP": ["identity", "role"], "OP": ["session", "request"],
            "expected_manifest_version": "1.0", "expected_manifest_sha256": manifest_sha256(MANIFEST_PATH)}


def _issue(key, tool="transfer", args=None, principal=PRINCIPAL):
    interaction = {**call_for(tool, {"amount": 5} if args is None else args, principal), **_claims()}
    return issue(reference_policy(), TARGET_ID, interaction, signing_key=key, key_id="k1").envelope


def _params(envelope, name="transfer", args=None):
    return {"name": name, "arguments": {"amount": 5} if args is None else args,
            "_meta": {ENVELOPE_META_KEY: envelope}}


def test_issued_receipt_executes_exactly_once():
    key = Ed25519PrivateKey.generate()
    state = _state(key)
    env = _issue(key)
    assert gate_tool_call(state, _params(env))[0] is True
    assert gate_tool_call(state, _params(env)) == (False, REF_VERIFY_REPLAY)
    assert state.executed == [{"tool": "transfer", "args": {"amount": 5}}]


def test_receipt_for_other_arguments_or_tool_is_refused():
    key = Ed25519PrivateKey.generate()
    state = _state(key)
    env = _issue(key)
    assert gate_tool_call(state, _params(env, args={"amount": 5000})) == (False, REF_VERIFY_BINDING_MISMATCH)
    assert gate_tool_call(state, _params(env, name="delete_database")) == (False, REF_VERIFY_BINDING_MISMATCH)
    assert state.executed == []


def test_receipt_issued_to_another_principal_is_refused():
    """A receipt agent-8 obtained cannot be spent through agent-7's server."""
    key = Ed25519PrivateKey.generate()
    state = _state(key, principal="agent-7")
    env = _issue(key, principal="agent-8")
    assert gate_tool_call(state, _params(env)) == (False, REF_VERIFY_PRINCIPAL_MISMATCH)
    assert state.executed == []


def test_server_without_a_principal_is_unconfigured():
    key = Ed25519PrivateKey.generate()
    env = _issue(key)
    for state in (_state(key, principal=None), _state(key, principal="")):
        assert gate_tool_call(state, _params(env)) == (False, REF_TARGET_NOT_CONFIGURED)
        assert state.executed == []


def test_config_from_env_requires_principal_and_record_path(monkeypatch, tmp_path):
    key = Ed25519PrivateKey.generate()
    record = tmp_path / "record.json"
    record.write_bytes(reference_record_bytes())
    monkeypatch.setenv(ENV_GATE_KEY_ID, "k1")
    monkeypatch.setenv(ENV_GATE_PUBLIC_KEY_HEX,
                       key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    monkeypatch.setenv(ENV_TARGET_ID, TARGET_ID)
    monkeypatch.delenv(ENV_PRINCIPAL, raising=False)
    monkeypatch.delenv(ENV_RECORD_PATH, raising=False)
    assert config_from_env() is None                       # no principal, no record
    monkeypatch.setenv(ENV_PRINCIPAL, PRINCIPAL)
    assert config_from_env() is None                       # no record path: no default
    monkeypatch.setenv(ENV_RECORD_PATH, str(record))
    config = config_from_env()
    assert config["principal"] == PRINCIPAL
    assert config["record_bytes"] == reference_record_bytes()
    monkeypatch.setenv(ENV_RECORD_PATH, str(tmp_path / "missing.json"))
    assert config_from_env() is None                       # unreadable record


def test_signed_receipt_without_decision_id_is_refused():
    """Without a decision_id there is nothing to claim, so the receipt could be
    replayed until it expires. Refuse it, as every Consumer does."""
    key = Ed25519PrivateKey.generate()
    state = _state(key)
    env = sign_envelope(
        build_envelope(decision="ELIGIBLE", target_url=TARGET_ID,
                       call=call_for("transfer", {"amount": 5}, PRINCIPAL),
                       policy_pin=reference_policy().pin()),
        key, "k1",
    )
    for _ in range(2):
        assert gate_tool_call(state, _params(env)) == (False, REF_TARGET_NO_DECISION_ID)
    assert state.executed == []
