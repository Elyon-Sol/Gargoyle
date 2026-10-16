"""Execution receipts: the executor's signed statement that the authorized
call ran, chained to the authorization receipt, verifiable offline together
with the issuer's receipt and the approver's grant."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.approval import build_grant, sign_grant, REF_APPROVAL_KEY_UNKNOWN
from gargoyle.consumer import Consumer, build_reference_target_app
from gargoyle.envelope import canonical_json, sign_envelope
from gargoyle.execution import (
    ACCEPT_CHAIN_VERIFIED, ACCEPT_EXECUTION_BOUND, EXECUTION_VERSION, REF_EXEC_BINDING_MISMATCH,
    REF_EXEC_GRANT_MISSING, REF_EXEC_KEY_UNKNOWN, REF_EXEC_MALFORMED, REF_EXEC_OUTPUTS_MISMATCH,
    REF_EXEC_SIGNATURE_INVALID, build_execution_receipt, sign_execution_receipt,
    verify_chain, verify_execution_receipt,
)
from gargoyle.issuer import issue
from gargoyle.policy import ELIGIBLE, Decision
from gargoyle.verifier import REF_VERIFY_SIGNATURE_EXPIRED
from reference import reference_pin, reference_policy

TARGET = "https://target.example/act"
PIN = {"policy_id": "engine/1", "policy_sha256": "a" * 64}
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
RAN = NOW + timedelta(seconds=30)
issuer = Ed25519PrivateKey.generate(); executor = Ed25519PrivateKey.generate(); approver = Ed25519PrivateKey.generate()
ISSUER_KEYS = {"issuer-1": issuer.public_key()}
EXEC_KEYS = {"executor-1": executor.public_key()}
APPROVER_KEYS = {"approver-alice": approver.public_key()}
CALL = {"tool": "transfer", "args": {"amount": 5}, "principal": "agent-7"}
OUTPUTS = {"status": "ok", "transfer_id": "tx-42"}


class AllowAll:
    def __init__(self, hold=False): self.hold = hold
    def pin(self): return PIN
    def decide(self, target_url, interaction): return Decision(ELIGIBLE, requires_approval=self.hold)


def receipt(hold=False):
    return issue(AllowAll(hold), TARGET, CALL, signing_key=issuer, key_id="issuer-1", now=NOW).envelope


def execution_for(env, outputs=OUTPUTS, executed_at=RAN):
    return sign_execution_receipt(build_execution_receipt(envelope=env, outputs=outputs, executed_at=executed_at),
                                  executor, "executor-1")


def grant_for(env):
    return sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                  grant_id="g-1", not_after=NOW + timedelta(minutes=10)), approver, "approver-alice")


# ---- construction ----

def test_execution_receipt_copies_the_bound_fields_and_hashes_the_outputs():
    env = receipt()
    ex = build_execution_receipt(envelope=env, outputs=OUTPUTS, executed_at=RAN)
    assert ex["execution_version"] == EXECUTION_VERSION
    for key in ("decision_id", "decision_sha256", "policy", "target_url", "request_context"):
        assert ex[key] == env[key]
    assert ex["executed_at"] == RAN.isoformat() and len(ex["outputs_sha256"]) == 64
    assert "outputs" not in ex
    signed = execution_for(env)
    assert signed["executor_key_id"] == "executor-1" and len(bytes.fromhex(signed["executor_signature"])) == 64


def test_construction_refuses_an_unhonorable_receipt():
    env = receipt()
    no_id = {k: v for k, v in env.items() if k != "decision_id"}
    with pytest.raises(KeyError):
        build_execution_receipt(envelope=no_id, outputs=OUTPUTS)
    with pytest.raises(ValueError):
        build_execution_receipt(envelope=dict(env, decision_id=""), outputs=OUTPUTS)
    with pytest.raises(ValueError):
        build_execution_receipt(envelope=env, outputs=OUTPUTS, executed_at=datetime(2026, 10, 16, 12, 0))
    with pytest.raises(TypeError):
        build_execution_receipt(envelope=None, outputs=OUTPUTS)


# ---- verification ----

def test_genuine_execution_receipt_binds_to_its_authorization():
    env = receipt(); ex = execution_for(env)
    assert verify_execution_receipt(ex, env, EXEC_KEYS) == {"accepted": True, "reason": ACCEPT_EXECUTION_BOUND}
    assert verify_execution_receipt(ex, env, EXEC_KEYS, outputs=OUTPUTS, check_outputs=True)["accepted"] is True
    assert verify_execution_receipt(ex, env, EXEC_KEYS, outputs={"status": "ok", "transfer_id": "tx-43"},
                                    check_outputs=True)["reason"] == REF_EXEC_OUTPUTS_MISMATCH


def test_execution_receipt_refusals_in_order():
    env = receipt(); ex = execution_for(env)
    assert verify_execution_receipt("nope", env, EXEC_KEYS)["reason"] == REF_EXEC_MALFORMED
    assert verify_execution_receipt({k: v for k, v in ex.items() if k != "outputs_sha256"}, env, EXEC_KEYS)["reason"] == REF_EXEC_MALFORMED
    assert verify_execution_receipt(dict(ex, execution_version="other/9"), env, EXEC_KEYS)["reason"] == REF_EXEC_MALFORMED
    assert verify_execution_receipt(ex, env, {})["reason"] == REF_EXEC_KEY_UNKNOWN
    assert verify_execution_receipt(ex, env, {"executor-1": issuer.public_key()})["reason"] == REF_EXEC_SIGNATURE_INVALID
    tampered = dict(ex, outputs_sha256="0" * 64)
    assert verify_execution_receipt(tampered, env, EXEC_KEYS)["reason"] == REF_EXEC_SIGNATURE_INVALID
    # Signed, genuine, but for a different authorization: refused on binding.
    other = receipt()
    assert verify_execution_receipt(ex, other, EXEC_KEYS)["reason"] == REF_EXEC_BINDING_MISMATCH
    # A re-signed receipt claiming another policy pin is caught the same way.
    forged = sign_execution_receipt(dict(build_execution_receipt(envelope=env, outputs=OUTPUTS, executed_at=RAN),
                                         policy={"policy_id": "engine/2", "policy_sha256": "b" * 64}),
                                    executor, "executor-1")
    assert verify_execution_receipt(forged, env, EXEC_KEYS)["reason"] == REF_EXEC_BINDING_MISMATCH


# ---- the offline chain ----

def test_chain_verifies_authorization_release_and_execution_offline():
    env = receipt(); ex = execution_for(env)
    r = verify_chain(env, ex, issuer_public_keys=ISSUER_KEYS, executor_public_keys=EXEC_KEYS)
    assert r["accepted"] is True and r["reason"] == ACCEPT_CHAIN_VERIFIED
    assert [s[0] for s in r["steps"]] == ["authorization", "execution"]

    held = receipt(hold=True); ex2 = execution_for(held)
    r = verify_chain(held, ex2, issuer_public_keys=ISSUER_KEYS, executor_public_keys=EXEC_KEYS)
    assert (r["accepted"], r["reason"]) == (False, REF_EXEC_GRANT_MISSING)
    r = verify_chain(held, ex2, issuer_public_keys=ISSUER_KEYS, executor_public_keys=EXEC_KEYS,
                     grant=grant_for(held), approver_public_keys=APPROVER_KEYS, outputs=OUTPUTS, check_outputs=True)
    assert r["accepted"] is True
    assert [s[0] for s in r["steps"]] == ["authorization", "approval", "execution"]
    r = verify_chain(held, ex2, issuer_public_keys=ISSUER_KEYS, executor_public_keys=EXEC_KEYS,
                     grant=grant_for(held), approver_public_keys={})
    assert r["reason"] == REF_APPROVAL_KEY_UNKNOWN


def test_chain_judges_validity_at_execution_time():
    """A receipt that has expired by audit time still verifies if it was
    valid when the call ran; one that ran after its expiry does not."""
    env = receipt()                                   # not_after = NOW + 300 s
    in_time = execution_for(env, executed_at=NOW + timedelta(seconds=299))
    late = execution_for(env, executed_at=NOW + timedelta(seconds=301))
    assert verify_chain(env, in_time, issuer_public_keys=ISSUER_KEYS, executor_public_keys=EXEC_KEYS)["accepted"] is True
    r = verify_chain(env, late, issuer_public_keys=ISSUER_KEYS, executor_public_keys=EXEC_KEYS)
    assert r["reason"] == REF_VERIFY_SIGNATURE_EXPIRED
    assert verify_chain(env, dict(in_time, executed_at="yesterday"), issuer_public_keys=ISSUER_KEYS,
                        executor_public_keys=EXEC_KEYS)["reason"] == REF_EXEC_MALFORMED
    forged_issuer = sign_envelope({k: v for k, v in env.items() if k != "issuer_signature"},
                                  Ed25519PrivateKey.generate(), "issuer-1")
    assert verify_chain(forged_issuer, in_time, issuer_public_keys=ISSUER_KEYS,
                        executor_public_keys=EXEC_KEYS)["steps"][0][0] == "authorization"


# ---- the consumer attests ----

def test_consumer_attests_only_with_an_executor_key():
    env = receipt()
    plain = Consumer(target_id=TARGET, record=PIN, pinned_public_keys=ISSUER_KEYS)
    assert plain.attests is False
    with pytest.raises(ValueError):
        plain.attest(env, OUTPUTS)
    with pytest.raises(ValueError):
        Consumer(target_id=TARGET, record=PIN, pinned_public_keys=ISSUER_KEYS, executor_signing_key=executor)
    c = Consumer(target_id=TARGET, record=PIN, pinned_public_keys=ISSUER_KEYS,
                 executor_signing_key=executor, executor_key_id="executor-1")
    assert c.check(env, CALL, now=NOW).honored is True
    ex = c.attest(env, OUTPUTS, executed_at=RAN)
    assert verify_chain(env, ex, issuer_public_keys=ISSUER_KEYS, executor_public_keys=EXEC_KEYS)["accepted"] is True


def test_reference_target_returns_an_execution_receipt_when_configured(gate_signing):
    config = {"target_url": TARGET, "publisher_url": "http://pub", "pinned_root_sha256": "x",
              "pinned_public_keys": {gate_signing["key_id"]: gate_signing["public_key"]},
              "principal_header": "X-Peer",
              "executor_signing_key": executor, "executor_key_id": "executor-1"}
    app = build_reference_target_app(config_provider=lambda: config, fetch=lambda url, anchor: reference_pin())
    client = TestClient(app)
    env = issue(reference_policy(), TARGET, {**CALL, "AP": ["identity", "role"], "OP": ["session", "request"],
                                             "expected_manifest_version": "1.0",
                                             "expected_manifest_sha256": reference_pin()["policy_sha256"]},
                signing_key=gate_signing["private_key"], key_id=gate_signing["key_id"]).envelope
    r = client.post("/target", json={"tool": "transfer", "args": {"amount": 5}},
                    headers={"X-Gargoyle-Envelope": canonical_json(env), "X-Peer": "agent-7"})
    assert r.status_code == 200, r.text
    body = r.json()
    chain = verify_chain(env, body["execution"], issuer_public_keys={gate_signing["key_id"]: gate_signing["public_key"]},
                         executor_public_keys=EXEC_KEYS, outputs=body["outputs"], check_outputs=True)
    assert chain["accepted"] is True
    del config["executor_signing_key"]; del config["executor_key_id"]
    env2 = issue(reference_policy(), TARGET, {**CALL, "AP": ["identity", "role"], "OP": ["session", "request"],
                                              "expected_manifest_version": "1.0",
                                              "expected_manifest_sha256": reference_pin()["policy_sha256"]},
                 signing_key=gate_signing["private_key"], key_id=gate_signing["key_id"]).envelope
    r = client.post("/target", json={"tool": "transfer", "args": {"amount": 5}},
                    headers={"X-Gargoyle-Envelope": canonical_json(env2), "X-Peer": "agent-7"})
    assert r.status_code == 200 and "execution" not in r.json()
