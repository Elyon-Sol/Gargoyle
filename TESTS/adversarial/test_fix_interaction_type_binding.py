"""SES-7 regression: interaction_type is bound into the envelope (signed + hashed)
and verified target-side; the flat/untyped path stays byte-identical; and the
receipt is now self-consistent (re-evaluation from request_context reproduces the
gate's typed verdict)."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from IMPLEMENTATION.envelope import build_envelope, sign_envelope
from IMPLEMENTATION.evaluator import (load_manifest, manifest_sha256, safe_manifest,
                                      resolve_required_sets, ac3_valid, t26_valid)
from IMPLEMENTATION.verifier import (verify_envelope, REF_VERIFY_BINDING_MISMATCH,
                                     ACCEPT_REASSERTED_AND_BOUND)

TARGET = "https://target.elyon-sol.io:9443/target"
KID = "gate-ed25519-001"
priv = Ed25519PrivateKey.generate(); pub = priv.public_key()

def inter(it=None):
    d = {"AP": ["identity","role"], "OP": ["session","request"], "context": {},
         "expected_manifest_version": "1.0", "expected_manifest_sha256": manifest_sha256()}
    if it is not None:
        d["interaction_type"] = it
    return d

def env_for(it=None):
    return build_envelope(decision="ELIGIBLE", target_url=TARGET, normalized_interaction=inter(it),
                          manifest=load_manifest(), ac3=True, t26=True, manifest_integrity=True,
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

# ---- the SES-7 self-consistency the finding was about ----
def test_receipt_reproduces_typed_verdict():
    mfst = {"version":"1.0","AR":["identity","role"],"R":["session","request","transfer"],
            "HIGH_IMPACT":["transfer"],
            "interaction_types":{"readonly":{"AR":["identity"],"R":["session"],"high_impact":False}}}
    sm = safe_manifest(mfst); assert sm is not None
    def eligible(ctx):
        AR, R = resolve_required_sets(sm, ctx)
        return AR is not None and R is not None and ac3_valid(ctx, AR) and t26_valid(ctx, R)
    ctx = {"AP":["identity"],"OP":["session"],"context":{},"interaction_type":"readonly",
           "expected_manifest_version":"1.0","expected_manifest_sha256":"0"*64}
    e = build_envelope(decision="ELIGIBLE", target_url=TARGET, normalized_interaction=ctx,
                       manifest=sm, ac3=True, t26=True, manifest_integrity=True,
                       timestamp_utc="2026-07-11T00:00:00+00:00")
    assert eligible(ctx) is True
    # BEFORE the fix this was False (receipt dropped interaction_type -> self-inconsistent):
    assert eligible(e["request_context"]) is True
