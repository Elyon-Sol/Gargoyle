"""
The principal is bound into the receipt (hashed and signed) and checked by
the verifier: a receipt is spendable only by the caller it was issued to,
as authenticated by the target. The policy's inputs (the caller's claims)
are not in the receipt; the policy pin stands for them.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from reference import reference_policy
from gargoyle.envelope import build_envelope, sign_envelope
from gargoyle.consumer import Consumer
from gargoyle.issuer import ISSUE_UNBINDABLE_CALL, issue
from gargoyle.policy import ELIGIBLE, Decision, ManifestPolicy
from gargoyle.verifier import (
    ACCEPT_REASSERTED_AND_BOUND,
    REF_VERIFY_PRINCIPAL_MISMATCH,
    REF_VERIFY_SIGNATURE_INVALID,
    verify_envelope,
)

TARGET = "https://target.example.com:9443/target"
KID = "gate-ed25519-001"
priv = Ed25519PrivateKey.generate(); pub = priv.public_key()


class AllowAll:
    def pin(self):
        return {"policy_id": "allow/1", "policy_sha256": "a" * 64}

    def decide(self, target_url, interaction):
        return Decision(ELIGIBLE)


def call(principal="agent-7", **over):
    d = {"tool": "transfer", "args": {"amount": 5}, "principal": principal}
    d.update(over)
    return d


def env_for(principal="agent-7"):
    return build_envelope(
        policy_pin=reference_policy().pin(), decision="ELIGIBLE", target_url=TARGET,
        call=call(principal), timestamp_utc="2026-07-11T00:00:00+00:00")


# ---- bound into the receipt ----
def test_principal_bound_into_request_context():
    assert env_for("agent-7")["request_context"]["principal"] == "agent-7"


def test_principal_changes_decision_hash():
    assert env_for("agent-7")["decision_sha256"] != env_for("agent-8")["decision_sha256"]


def test_receipt_binds_exactly_tool_args_principal():
    rc = env_for()["request_context"]
    assert set(rc.keys()) == {"tool", "args_sha256", "principal"}


@pytest.mark.parametrize("bad", [None, "", 7, ["agent-7"], {"id": "agent-7"}])
def test_build_refuses_a_call_without_a_principal(bad):
    with pytest.raises((ValueError, TypeError)):
        build_envelope(policy_pin=reference_policy().pin(), decision="ELIGIBLE",
                       target_url=TARGET, call=call(bad))
    with pytest.raises((KeyError, ValueError, TypeError)):
        c = call(); del c["principal"]
        build_envelope(policy_pin=reference_policy().pin(), decision="ELIGIBLE",
                       target_url=TARGET, call=c)


# ---- the issuer ----
@pytest.mark.parametrize("bad", [None, "", 7])
def test_issue_refuses_an_eligible_call_without_a_principal(bad):
    r = issue(AllowAll(), TARGET, call(bad), signing_key=priv, key_id=KID)
    assert r.envelope is None and r.decision.reason == ISSUE_UNBINDABLE_CALL


def test_issue_keeps_policy_claims_out_of_the_receipt():
    """The policy saw the claims; the receipt records the call and the pin."""
    interaction = {**call(), "AP": ["identity", "role"], "OP": ["session"], "role": "admin"}
    r = issue(AllowAll(), TARGET, interaction, signing_key=priv, key_id=KID)
    assert set(r.envelope["request_context"]) == {"tool", "args_sha256", "principal"}
    assert "AP" not in str(r.envelope)


# ---- the verifier binds it ----
def test_verifier_accepts_matching_principal():
    r = verify_envelope(sign_envelope(env_for("agent-7"), priv, KID), call("agent-7"),
                        TARGET, pinned_public_keys={KID: pub}, policy=reference_policy())
    assert r["accepted"] is True and r["reason"] == ACCEPT_REASSERTED_AND_BOUND


def test_verifier_rejects_another_principal():
    r = verify_envelope(sign_envelope(env_for("agent-7"), priv, KID), call("agent-8"),
                        TARGET, pinned_public_keys={KID: pub}, policy=reference_policy())
    assert r["accepted"] is False and r["reason"] == REF_VERIFY_PRINCIPAL_MISMATCH


@pytest.mark.parametrize("nobody", [None, "", 7])
def test_verifier_rejects_an_unauthenticated_caller(nobody):
    r = verify_envelope(sign_envelope(env_for("agent-7"), priv, KID), call(nobody),
                        TARGET, pinned_public_keys={KID: pub}, policy=reference_policy())
    assert r["accepted"] is False and r["reason"] == REF_VERIFY_PRINCIPAL_MISMATCH


def test_principal_rewritten_after_signing_breaks_the_signature():
    """agent-8 cannot re-address agent-7's receipt: the principal is inside
    the signed region, so the edit fails on provenance before binding."""
    e = sign_envelope(env_for("agent-7"), priv, KID)
    e["request_context"]["principal"] = "agent-8"
    r = verify_envelope(e, call("agent-8"), TARGET, pinned_public_keys={KID: pub}, policy=reference_policy())
    assert r["accepted"] is False and r["reason"] == REF_VERIFY_SIGNATURE_INVALID


# ---- an executor checks its own peer identity, not the receipt's word ----
def test_consumer_refuses_a_receipt_issued_to_someone_else():
    e = issue(AllowAll(), TARGET, call("agent-7"), signing_key=priv, key_id=KID).envelope
    consumer = Consumer(pinned_public_keys={KID: pub}, target_id=TARGET, record=AllowAll().pin())
    assert consumer.check(e, call("agent-8")) == (False, REF_VERIFY_PRINCIPAL_MISMATCH)
    assert consumer.check(e, call("agent-7")).honored is True
