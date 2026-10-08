"""
interaction_type is bound into the receipt (hashed and signed) and checked by
the verifier. Untyped receipts are unchanged. The receipt is self-consistent:
re-running the policy on its request_context reproduces the typed decision.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.policy import ManifestPolicy
from gargoyle.envelope import build_envelope, sign_envelope
from gargoyle.policy import (load_manifest, manifest_sha256, safe_manifest,
                                      resolve_required_sets, authority_covered, coverage_covered)
from gargoyle.verifier import (verify_envelope, REF_VERIFY_BINDING_MISMATCH,
                                     ACCEPT_REASSERTED_AND_BOUND)

TARGET = "https://target.example.com:9443/target"
KID = "gate-ed25519-001"
priv = Ed25519PrivateKey.generate(); pub = priv.public_key()

def inter(it=None):
    d = {"AP": ["identity","role"], "OP": ["session","request"], "context": {},
         "expected_manifest_version": "1.0", "expected_manifest_sha256": manifest_sha256()}
    if it is not None:
        d["interaction_type"] = it
    return d

def env_for(it=None):
    return build_envelope(
        policy_pin=ManifestPolicy().pin(),decision="ELIGIBLE", target_url=TARGET, normalized_interaction=inter(it),
                          timestamp_utc="2026-07-11T00:00:00+00:00")

# ---- bound into the envelope ----
def test_type_bound_into_request_context():
    assert env_for("readonly")["request_context"].get("interaction_type") == "readonly"

def test_type_changes_decision_hash():
    assert env_for("readonly")["decision_sha256"] != env_for("payment")["decision_sha256"]
    assert env_for("readonly")["decision_sha256"] != env_for(None)["decision_sha256"]

def test_flat_path_byte_identical():
    rc = env_for(None)["request_context"]
    assert set(rc.keys()) == {"AP","OP","context","expected_manifest_version","expected_manifest_sha256"}

# ---- verifier binds it ----
def test_verifier_accepts_matching_type():
    r = verify_envelope(sign_envelope(env_for("readonly"), priv, KID), inter("readonly"),
                        TARGET, pinned_public_keys={KID: pub})
    assert r["accepted"] is True and r["reason"] == ACCEPT_REASSERTED_AND_BOUND

def test_verifier_rejects_type_mismatch():
    r = verify_envelope(sign_envelope(env_for("readonly"), priv, KID), inter("payment"),
                        TARGET, pinned_public_keys={KID: pub})
    assert r["accepted"] is False and r["reason"] == REF_VERIFY_BINDING_MISMATCH

def test_verifier_rejects_type_stripped_at_target():
    r = verify_envelope(sign_envelope(env_for("readonly"), priv, KID), inter(None),
                        TARGET, pinned_public_keys={KID: pub})
    assert r["accepted"] is False and r["reason"] == REF_VERIFY_BINDING_MISMATCH

def test_verifier_rejects_type_injected_on_untyped_envelope():
    r = verify_envelope(sign_envelope(env_for(None), priv, KID), inter("payment"),
                        TARGET, pinned_public_keys={KID: pub})
    assert r["accepted"] is False and r["reason"] == REF_VERIFY_BINDING_MISMATCH

def test_flat_still_accepts():
    r = verify_envelope(sign_envelope(env_for(None), priv, KID), inter(None),
                        TARGET, pinned_public_keys={KID: pub})
    assert r["accepted"] is True

# ---- self-consistency: the receipt reproduces the typed decision ----
def test_receipt_reproduces_typed_verdict():
    mfst = {"version":"1.0","AR":["identity","role"],"R":["session","request","transfer"],
            "HIGH_IMPACT":["transfer"],
            "interaction_types":{"readonly":{"AR":["identity"],"R":["session"],"high_impact":False}}}
    sm = safe_manifest(mfst); assert sm is not None
    def eligible(ctx):
        AR, R = resolve_required_sets(sm, ctx)
        return AR is not None and R is not None and authority_covered(ctx, AR) and coverage_covered(ctx, R)
    ctx = {"AP":["identity"],"OP":["session"],"context":{},"interaction_type":"readonly",
           "expected_manifest_version":"1.0","expected_manifest_sha256":"0"*64}
    e = build_envelope(
        policy_pin=ManifestPolicy().pin(),decision="ELIGIBLE", target_url=TARGET, normalized_interaction=ctx,
                       timestamp_utc="2026-07-11T00:00:00+00:00")
    assert eligible(ctx) is True
    # Fails if the receipt drops interaction_type:
    assert eligible(e["request_context"]) is True
