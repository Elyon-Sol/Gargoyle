"""The MCP server's tools/call gate: a receipt is honored once, only for the
tool, arguments and principal it was issued for, and only if it carries a
decision_id to be single-used on."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from reference import reference_pin, reference_policy, reference_record_bytes
from gargoyle.envelope import build_envelope, sign_envelope
from gargoyle.issuer import issue
from gargoyle.mcp_server import (
    ENV_GATE_KEY_ID, ENV_GATE_PUBLIC_KEY_HEX, ENV_PRINCIPAL, ENV_RECORD_PATH, ENV_TARGET_ID,
    ENVELOPE_META_KEY, ServerState, call_for, config_from_env, gate_tool_call,
)
from gargoyle.consumer import REF_TARGET_NO_DECISION_ID, REF_TARGET_NOT_CONFIGURED
from gargoyle.verifier import REF_VERIFY_BINDING_MISMATCH, REF_VERIFY_PRINCIPAL_MISMATCH, REF_VERIFY_REPLAY

TARGET_ID = "mcp://tools.example.com"
PRINCIPAL = "agent-7"


def _state(key, principal=PRINCIPAL):
    config = {
        "pinned_public_keys": {"k1": key.public_key()},
        "record": reference_pin(),
        "target_id": TARGET_ID,
    }
    if principal is not None:
        config["principal"] = principal
    return ServerState(config)


def _issue(key, tool="transfer", args=None, principal=PRINCIPAL):
    interaction = call_for(tool, {"amount": 5} if args is None else args, principal)
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
    assert config["record"] == reference_pin()
    monkeypatch.setenv(ENV_RECORD_PATH, str(tmp_path / "missing.json"))
    assert config_from_env() is None                       # unreadable record
    bad = tmp_path / "bad.json"; bad.write_text('{"policy_id": "x"}')
    monkeypatch.setenv(ENV_RECORD_PATH, str(bad))
    assert config_from_env() is None                       # not a pin


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


def test_flagged_receipt_executes_only_with_a_grant_in_meta():
    from datetime import datetime, timedelta, timezone
    from gargoyle.approval import build_grant, sign_grant
    from gargoyle.consumer import REF_TARGET_APPROVAL_REQUIRED
    from gargoyle.mcp_server import GRANT_META_KEY
    from gargoyle.policy import Decision, ELIGIBLE

    class FlagAll:
        def pin(self): return reference_policy().pin()
        def decide(self, target_url, interaction): return Decision(ELIGIBLE, requires_approval=True)

    key = Ed25519PrivateKey.generate(); approver = Ed25519PrivateKey.generate()
    state = _state(key)
    state.consumer.approver_public_keys = {"approver-alice": approver.public_key()}
    env = issue(FlagAll(), TARGET_ID, call_for("transfer", {"amount": 5}, PRINCIPAL),
                signing_key=key, key_id="k1").envelope
    assert gate_tool_call(state, _params(env)) == (False, REF_TARGET_APPROVAL_REQUIRED)
    grant = sign_grant(build_grant(decision_sha256=env["decision_sha256"],
                                   approval_request_id=env["approval_request_id"], grant_id="g-1",
                                   not_after=datetime.now(timezone.utc) + timedelta(minutes=5)),
                       approver, "approver-alice")
    params = _params(env); params["_meta"][GRANT_META_KEY] = grant
    assert gate_tool_call(state, params)[0] is True
    assert state.executed == [{"tool": "transfer", "args": {"amount": 5}}]


def test_config_from_env_approver_key_both_or_neither(monkeypatch, tmp_path):
    from gargoyle.mcp_server import ENV_APPROVER_KEY_ID, ENV_APPROVER_PUBLIC_KEY_HEX
    key = Ed25519PrivateKey.generate(); approver = Ed25519PrivateKey.generate()
    record = tmp_path / "record.json"; record.write_bytes(reference_record_bytes())
    monkeypatch.setenv(ENV_GATE_KEY_ID, "k1")
    monkeypatch.setenv(ENV_GATE_PUBLIC_KEY_HEX, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    monkeypatch.setenv(ENV_TARGET_ID, TARGET_ID); monkeypatch.setenv(ENV_PRINCIPAL, PRINCIPAL)
    monkeypatch.setenv(ENV_RECORD_PATH, str(record))
    monkeypatch.delenv(ENV_APPROVER_KEY_ID, raising=False); monkeypatch.delenv(ENV_APPROVER_PUBLIC_KEY_HEX, raising=False)
    assert config_from_env()["approver_public_keys"] is None
    monkeypatch.setenv(ENV_APPROVER_KEY_ID, "approver-alice")
    assert config_from_env() is None                       # id without key: a partial pin refuses
    monkeypatch.setenv(ENV_APPROVER_PUBLIC_KEY_HEX, approver.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    assert set(config_from_env()["approver_public_keys"]) == {"approver-alice"}


def test_honored_call_carries_an_execution_receipt_when_the_server_has_a_key():
    from gargoyle.execution import verify_chain
    from gargoyle.mcp_server import EXECUTION_META_KEY, handle_message
    key = Ed25519PrivateKey.generate(); executor = Ed25519PrivateKey.generate()
    state = _state(key)
    state.consumer._executor_signing_key = executor; state.consumer.executor_key_id = "executor-1"
    state.initialized = True
    env = _issue(key)
    reply = handle_message(state, {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": _params(env)})
    execution = reply["result"]["_meta"][EXECUTION_META_KEY]
    outputs = {k: v for k, v in reply["result"].items() if k != "_meta"}
    chain = verify_chain(env, execution, issuer_public_keys={"k1": key.public_key()},
                         executor_public_keys={"executor-1": executor.public_key()},
                         outputs=outputs, check_outputs=True)
    assert chain["accepted"] is True, chain
    refused = handle_message(state, {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": _params(env)})
    assert EXECUTION_META_KEY not in refused["result"]["_meta"]


def test_config_from_env_executor_key_both_or_neither(monkeypatch, tmp_path):
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
    from gargoyle.mcp_server import ENV_EXECUTOR_KEY_HEX, ENV_EXECUTOR_KEY_ID
    key = Ed25519PrivateKey.generate(); executor = Ed25519PrivateKey.generate()
    record = tmp_path / "record.json"; record.write_bytes(reference_record_bytes())
    monkeypatch.setenv(ENV_GATE_KEY_ID, "k1")
    monkeypatch.setenv(ENV_GATE_PUBLIC_KEY_HEX, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    monkeypatch.setenv(ENV_TARGET_ID, TARGET_ID); monkeypatch.setenv(ENV_PRINCIPAL, PRINCIPAL)
    monkeypatch.setenv(ENV_RECORD_PATH, str(record))
    for v in ("GARGOYLE_MCP_APPROVER_KEY_ID", "GARGOYLE_MCP_APPROVER_PUBLIC_KEY_HEX", ENV_EXECUTOR_KEY_ID, ENV_EXECUTOR_KEY_HEX):
        monkeypatch.delenv(v, raising=False)
    assert config_from_env()["executor_signing_key"] is None
    monkeypatch.setenv(ENV_EXECUTOR_KEY_ID, "executor-1")
    assert config_from_env() is None
    monkeypatch.setenv(ENV_EXECUTOR_KEY_HEX, executor.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    assert ServerState(config_from_env()).consumer.attests is True
