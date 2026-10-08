"""
Governance layer, Feature 1, increment 1b: the approval grant.

Spec: docs/design/governance_layer_design.md section 1.4 (with review fixes
H3/H4/H5/H7). Exercises build_grant/sign_grant/verify_grant against REAL
Ed25519 keypairs. The starred tests are the revert-catchers (proven RED on
revert in the VL-114 session before being trusted).

Build-then-wire: approval.py has NO caller on the default pep.py path this
increment; single-use (claiming grant_id) + the pending-request set are the
stateful pep wiring at 1c.
"""

import dataclasses
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from IMPLEMENTATION.approval import (
    build_grant,
    sign_grant,
    verify_grant,
    ACCEPT_GRANT_VALID,
    REF_APPROVAL_MALFORMED,
    REF_APPROVAL_MISSING_GRANT_ID,
    REF_APPROVAL_SIGNATURE_INVALID,
    REF_APPROVAL_KEY_UNKNOWN,
    REF_APPROVAL_SOD,
    REF_APPROVAL_BINDING_MISMATCH,
    REF_APPROVAL_REQUEST_MISMATCH,
    REF_APPROVAL_EXPIRED,
)

DECISION = "a" * 64           # a stand-in decision_sha256
REQ_ID = "req-0001"
GATE_KEY_ID = "ELYON_GATE_1"
APPROVER_KEY_ID = "ELYON_APPROVER_1"


def _keypair():
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key()


@pytest.fixture
def approver():
    sk, pk = _keypair()
    return sk, pk


@pytest.fixture
def trust(approver):
    _, pk = approver
    return {APPROVER_KEY_ID: pk}


def _future(seconds=300):
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


def _valid_signed(approver, not_after=None, **overrides):
    sk, _ = approver
    g = build_grant(
        decision_sha256=overrides.get("decision_sha256", DECISION),
        approval_request_id=overrides.get("approval_request_id", REQ_ID),
        grant_id=overrides.get("grant_id", "grant-abc"),
        not_after=not_after or _future(),
    )
    return sign_grant(g, sk, overrides.get("key_id", APPROVER_KEY_ID))


def _verify(grant, trust, **over):
    return verify_grant(
        grant,
        expected_decision_sha256=over.get("expected_decision_sha256", DECISION),
        expected_approval_request_id=over.get("expected_approval_request_id", REQ_ID),
        approver_public_keys=trust,
        gate_key_id=over.get("gate_key_id", GATE_KEY_ID),
        now=over.get("now"),
        clock_skew=over.get("clock_skew", timedelta(0)),
    )


# --------------------------------------------------------------------------
# happy path
# --------------------------------------------------------------------------

def test_valid_grant_accepted(approver, trust):
    res = _verify(_valid_signed(approver), trust)
    assert res["accepted"] is True
    assert res["reason"] == ACCEPT_GRANT_VALID


# --------------------------------------------------------------------------
# [FIX H4] action + request binding
# --------------------------------------------------------------------------

def test_action_binding_mismatch_REVERT_CATCHER(approver, trust):
    """star: a grant for decision A presented against decision B -> REFUSE.
    Reverting the decision_sha256 binding check would accept it. [FIX H4]"""
    grant = _valid_signed(approver, decision_sha256="b" * 64)
    res = _verify(grant, trust, expected_decision_sha256=DECISION)
    assert res["accepted"] is False
    assert res["reason"] == REF_APPROVAL_BINDING_MISMATCH


def test_request_binding_mismatch_REVERT_CATCHER(approver, trust):
    """star: a grant carrying a different approval_request_id -> REFUSE.
    Reverting the request-id binding would accept a grant minted for another
    held request. [FIX H4]"""
    grant = _valid_signed(approver, approval_request_id="req-9999")
    res = _verify(grant, trust, expected_approval_request_id=REQ_ID)
    assert res["accepted"] is False
    assert res["reason"] == REF_APPROVAL_REQUEST_MISMATCH


# --------------------------------------------------------------------------
# [FIX H3] mandatory grant_id (single-use cannot be skipped)
# --------------------------------------------------------------------------

def test_absent_grant_id_refused_REVERT_CATCHER(approver, trust):
    """star: an otherwise-valid grant with NO grant_id -> REFUSE. Reverting the
    mandatory-id requirement would accept it, and the later single-use claim
    would have no key to claim (silent replay). [FIX H3]"""
    sk, _ = approver
    g = {
        "grant_version": "1.0",
        "decision_sha256": DECISION,
        "approval_request_id": REQ_ID,
        "not_after": _future().isoformat(),
    }  # deliberately no grant_id
    signed = sign_grant(g, sk, APPROVER_KEY_ID)
    res = _verify(signed, trust)
    assert res["accepted"] is False
    assert res["reason"] == REF_APPROVAL_MALFORMED


def test_empty_grant_id_refused(approver, trust):
    sk, _ = approver
    g = {
        "grant_version": "1.0",
        "decision_sha256": DECISION,
        "approval_request_id": REQ_ID,
        "grant_id": "",  # present but empty
        "not_after": _future().isoformat(),
    }
    signed = sign_grant(g, sk, APPROVER_KEY_ID)
    res = _verify(signed, trust)
    assert res["accepted"] is False
    assert res["reason"] == REF_APPROVAL_MISSING_GRANT_ID


def test_build_grant_rejects_empty_grant_id():
    with pytest.raises(ValueError):
        build_grant(decision_sha256=DECISION, approval_request_id=REQ_ID,
                    grant_id="", not_after=_future())


# --------------------------------------------------------------------------
# [FIX H5] separation of duties
# --------------------------------------------------------------------------

def test_sod_approver_equals_gate_key_REVERT_CATCHER(approver):
    """star: an approval signed by a key whose id == the gate key id -> REFUSE,
    even though the signature is valid. Reverting the SoD check would let the
    gate mint its own approval. [FIX H5]"""
    sk, pk = approver
    grant = _valid_signed(approver, key_id=GATE_KEY_ID)  # signer IS the gate id
    res = _verify(grant, {GATE_KEY_ID: pk}, gate_key_id=GATE_KEY_ID)
    assert res["accepted"] is False
    assert res["reason"] == REF_APPROVAL_SOD


# --------------------------------------------------------------------------
# [FIX H7] freshness (reuses verifier.not_after_valid)
# --------------------------------------------------------------------------

def test_expired_grant_refused_REVERT_CATCHER(approver, trust):
    """star: a grant whose not_after is in the past -> REFUSE. Reverting the
    freshness check would honor a stale human approval indefinitely. [FIX H7]"""
    grant = _valid_signed(approver, not_after=datetime.now(timezone.utc) - timedelta(seconds=1))
    res = _verify(grant, trust)
    assert res["accepted"] is False
    assert res["reason"] == REF_APPROVAL_EXPIRED


def test_tz_naive_not_after_refused(approver, trust):
    """A tz-naive not_after string (hand-crafted) -> REFUSE (fail closed),
    parity with verify_envelope. build_grant itself rejects naive datetimes."""
    sk, _ = approver
    g = {
        "grant_version": "1.0",
        "decision_sha256": DECISION,
        "approval_request_id": REQ_ID,
        "grant_id": "grant-abc",
        "not_after": datetime.now().isoformat(),  # naive (no tzinfo)
    }
    signed = sign_grant(g, sk, APPROVER_KEY_ID)
    res = _verify(signed, trust)
    assert res["accepted"] is False
    assert res["reason"] == REF_APPROVAL_EXPIRED


def test_clock_skew_tolerates_recent_expiry(approver, trust):
    """Parity with verify_envelope: a not_after just past is honored within a
    clock_skew window (default 0 is strict)."""
    grant = _valid_signed(approver, not_after=datetime.now(timezone.utc) - timedelta(seconds=2))
    res = _verify(grant, trust, clock_skew=timedelta(seconds=30))
    assert res["accepted"] is True


# --------------------------------------------------------------------------
# provenance / tamper / structure
# --------------------------------------------------------------------------

def test_unknown_approver_key_refused(approver):
    grant = _valid_signed(approver)
    res = _verify(grant, {})  # empty trust map
    assert res["accepted"] is False
    assert res["reason"] == REF_APPROVAL_KEY_UNKNOWN


def test_tampered_field_breaks_signature(approver, trust):
    grant = dict(_valid_signed(approver))
    grant["approval_request_id"] = "req-tampered"
    res = _verify(grant, trust, expected_approval_request_id="req-tampered")
    assert res["accepted"] is False
    assert res["reason"] == REF_APPROVAL_SIGNATURE_INVALID


def test_forged_keyless_grant_refused(trust):
    """A from-scratch grant with a bogus signature and a pinned key id -> REFUSE."""
    g = {
        "grant_version": "1.0",
        "decision_sha256": DECISION,
        "approval_request_id": REQ_ID,
        "grant_id": "grant-abc",
        "not_after": _future().isoformat(),
        "approver_key_id": APPROVER_KEY_ID,
        "approver_signature": "00" * 64,
    }
    res = _verify(g, trust)
    assert res["accepted"] is False
    assert res["reason"] == REF_APPROVAL_SIGNATURE_INVALID


def test_non_dict_and_missing_keys_refused(approver, trust):
    assert _verify(None, trust)["reason"] == REF_APPROVAL_MALFORMED
    assert _verify({"grant_version": "1.0"}, trust)["reason"] == REF_APPROVAL_MALFORMED
