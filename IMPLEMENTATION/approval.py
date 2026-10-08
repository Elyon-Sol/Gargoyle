"""
Governance layer - approval grant (Feature 1, increment 1b).

docs/design/governance_layer_design.md section 1.4, with review fixes
[FIX H3] (mandatory grant_id; single-use cannot be skipped), [FIX H4] (bind to
decision_sha256 + approval_request_id), [FIX H5] (separation of duties as a
belt-and-braces approver_key_id != gate_key_id check), and [FIX H7] (freshness
REUSES verifier.not_after_valid, not a re-implementation) folded in.

An "approval grant" is a small signed object a HUMAN (the approver) produces
out-of-band to release a held high-impact decision. It mirrors envelope.py:
the same Ed25519 duck-typed signing/verifying, the same canonical_json
discipline - reusing, not re-implementing, the crypto. The approver identity is
SEPARATE from the gate's issuer identity.

WHAT THIS MODULE DECIDES vs WHAT pep WIRING (1c) DECIDES.
verify_grant() is a PURE function of the grant plus the trust inputs the caller
passes (the expected decision hash, the expected request id, the approver
trust map, the gate key id, the clock). It establishes the grant's
cryptographic provenance, action/request binding, separation of duties, and
freshness. It does NOT consume the grant: SINGLE-USE (claiming grant_id exactly
once via the ReplayCache seam) and the server-side pending-request set are
STATEFUL gate concerns wired in pep.governed_call at increment 1c
([FIX H3]/[FIX H4]); this module only enforces that a grant_id is PRESENT so
the later single-use claim has a non-skippable key. Build-then-wire: NO caller
on the default pep.py path this increment. Canon untouched; the grant lives
above G(I).
"""

from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from IMPLEMENTATION.envelope import canonical_json
from IMPLEMENTATION.verifier import not_after_valid


GRANT_VERSION = "1.0"

# Keys excluded from the approver-signature region. The signature covers
# everything else - including grant_id, decision_sha256, approval_request_id,
# not_after, and approver_key_id - so all of them are tamper-proof.
_SIGNATURE_EXCLUDED_KEYS = ("approver_signature",)

# Refusal vocabulary (REF_APPROVAL_* layer; parallels REF_VERIFY_* / REF_SCHEMA_*).
REF_APPROVAL_MALFORMED = "REF_APPROVAL_MALFORMED"
REF_APPROVAL_MISSING_GRANT_ID = "REF_APPROVAL_MISSING_GRANT_ID"
REF_APPROVAL_SIGNATURE_INVALID = "REF_APPROVAL_SIGNATURE_INVALID"
REF_APPROVAL_KEY_UNKNOWN = "REF_APPROVAL_KEY_UNKNOWN"
REF_APPROVAL_SOD = "REF_APPROVAL_SOD"
REF_APPROVAL_BINDING_MISMATCH = "REF_APPROVAL_BINDING_MISMATCH"
REF_APPROVAL_REQUEST_MISMATCH = "REF_APPROVAL_REQUEST_MISMATCH"
REF_APPROVAL_EXPIRED = "REF_APPROVAL_EXPIRED"
# Surfaced by the pep wiring (1c), not verify_grant: single-use of the grant
# (grant_id already claimed) and of the 202 slot (approval_request_id not in the
# gate's pending-unconsumed set / not bound to this decision).
REF_APPROVAL_REPLAY = "REF_APPROVAL_REPLAY"
REF_APPROVAL_REQUEST_UNKNOWN = "REF_APPROVAL_REQUEST_UNKNOWN"

ACCEPT_GRANT_VALID = "GRANT_VALID"

# Top-level keys a usable grant must carry before verify_grant can run.
_REQUIRED_GRANT_KEYS = (
    "grant_version",
    "decision_sha256",
    "approval_request_id",
    "grant_id",
    "not_after",
    "approver_key_id",
    "approver_signature",
)


def build_grant(
    *,
    decision_sha256: str,
    approval_request_id: str,
    grant_id: str,
    not_after: datetime,
) -> Dict[str, Any]:
    """
    Construct an UNSIGNED approval grant.

    - decision_sha256 ([FIX H4]): the exact decision being approved. Binding to
      decision_sha256 transitively binds target_url, AP, OP, context, and the
      manifest pins (all inside the envelope's hashed region), so an approval of
      action A cannot authorize a different action/args/target B.
    - approval_request_id ([FIX H4]): the id the gate issued with its 202 hold;
      since decision_sha256 is issuance-invariant, request identity is carried
      here (and consumed against the gate's pending set at 1c).
    - grant_id ([FIX H3]): a unique, MANDATORY id; the key the gate claims
      exactly once for single-use. A grant without it is rejected by
      verify_grant - single-use can never be skipped.
    - not_after ([FIX H7]): a tz-AWARE expiry (approval freshness). Naive ->
      ValueError here, mirroring sign_envelope's refusal of a naive not_after.
    """
    if not isinstance(grant_id, str) or not grant_id:
        raise ValueError("grant_id is mandatory and must be a non-empty string")
    if not_after.tzinfo is None:
        raise ValueError("not_after must be timezone-aware (UTC)")
    return {
        "grant_version": GRANT_VERSION,
        "decision_sha256": decision_sha256,
        "approval_request_id": approval_request_id,
        "grant_id": grant_id,
        "not_after": not_after.isoformat(),
    }


def sign_grant(grant: Dict[str, Any], signing_key: Any, key_id: str) -> Dict[str, Any]:
    """
    Sign a grant with the APPROVER key (Ed25519 duck-typed, like sign_envelope).

    Returns a NEW grant dict with approver_key_id + approver_signature added;
    the input is not modified. signing_key exposes .sign(bytes) -> bytes;
    approval.py does NOT import cryptography (the caller supplies the key
    object). The signature covers canonical_json(grant minus approver_signature),
    which includes approver_key_id - so the claimed signer is itself bound.
    """
    signed = dict(grant)
    signed["approver_key_id"] = key_id
    region = {k: v for k, v in signed.items() if k not in _SIGNATURE_EXCLUDED_KEYS}
    signature = signing_key.sign(canonical_json(region).encode("utf-8"))
    signed["approver_signature"] = signature.hex()
    return signed


def _reject(reason: str) -> Dict[str, Any]:
    return {"accepted": False, "reason": reason}


def _accept(reason: str = ACCEPT_GRANT_VALID) -> Dict[str, Any]:
    return {"accepted": True, "reason": reason}


def verify_grant(
    grant: Any,
    *,
    expected_decision_sha256: str,
    expected_approval_request_id: str,
    approver_public_keys: Dict[str, Any],
    gate_key_id: str,
    now: Optional[datetime] = None,
    clock_skew: timedelta = timedelta(0),
) -> Dict[str, Any]:
    """
    Decide whether an approval grant is a valid human release for the held
    decision the gate is about to forward. Returns {"accepted", "reason"}.

    Order (fail-closed, canon section 9; first failure wins):
      1. structural presence  -> REF_APPROVAL_MALFORMED
      2. mandatory grant_id    -> REF_APPROVAL_MISSING_GRANT_ID        [FIX H3]
      3. separation of duties (approver_key_id != gate_key_id)
                               -> REF_APPROVAL_SOD                     [FIX H5]
      4. known approver key    -> REF_APPROVAL_KEY_UNKNOWN
      5. signature verifies    -> REF_APPROVAL_SIGNATURE_INVALID
      6. action binding (decision_sha256)
                               -> REF_APPROVAL_BINDING_MISMATCH        [FIX H4]
      7. request binding (approval_request_id)
                               -> REF_APPROVAL_REQUEST_MISMATCH        [FIX H4]
      8. freshness (mandatory; via not_after_valid)
                               -> REF_APPROVAL_EXPIRED                 [FIX H7]
      9. accept                -> GRANT_VALID

    SoD ([FIX H5]) is checked BEFORE the signature so a grant the gate could
    mint with its own key is rejected even if technically well-signed. This is
    only the belt-and-braces id check; the load-bearing custody invariant (the
    gate cannot resolve the approver PRIVATE key, and approver provenance/role
    comes from the signed key-record chain) is a deployment/wiring property
    (1c). approver_public_keys is the trust map the caller supplies (a static
    pin now; the signed key-record view at 1c).

    Single-use is NOT enforced here (it is stateful): the gate claims grant_id
    exactly once via the ReplayCache seam at 1c. This function guarantees a
    grant_id EXISTS so that claim is non-skippable ([FIX H3]).
    """
    # 1. structural presence
    if not isinstance(grant, dict):
        return _reject(REF_APPROVAL_MALFORMED)
    for k in _REQUIRED_GRANT_KEYS:
        if k not in grant:
            return _reject(REF_APPROVAL_MALFORMED)

    # 2. mandatory grant_id [FIX H3]
    grant_id = grant.get("grant_id")
    if not isinstance(grant_id, str) or not grant_id:
        return _reject(REF_APPROVAL_MISSING_GRANT_ID)

    key_id = grant.get("approver_key_id")
    signature_hex = grant.get("approver_signature")
    if not isinstance(key_id, str) or not isinstance(signature_hex, str):
        return _reject(REF_APPROVAL_SIGNATURE_INVALID)

    # 3. separation of duties [FIX H5] - before signature: a gate-minted
    #    approval is not oversight even if well-formed.
    if key_id == gate_key_id:
        return _reject(REF_APPROVAL_SOD)

    # 4. known approver key
    public_key = approver_public_keys.get(key_id)
    if public_key is None:
        return _reject(REF_APPROVAL_KEY_UNKNOWN)

    # 5. signature verifies (duck-typed; covers everything but the signature)
    region = {k: v for k, v in grant.items() if k not in _SIGNATURE_EXCLUDED_KEYS}
    message = canonical_json(region).encode("utf-8")
    try:
        public_key.verify(bytes.fromhex(signature_hex), message)
    except Exception:
        return _reject(REF_APPROVAL_SIGNATURE_INVALID)

    # 6. action binding [FIX H4]
    if grant.get("decision_sha256") != expected_decision_sha256:
        return _reject(REF_APPROVAL_BINDING_MISMATCH)

    # 7. request binding [FIX H4]
    if grant.get("approval_request_id") != expected_approval_request_id:
        return _reject(REF_APPROVAL_REQUEST_MISMATCH)

    # 8. freshness [FIX H7] - mandatory presence, then the shared primitive.
    not_after_raw = grant.get("not_after")
    if not_after_raw is None:
        return _reject(REF_APPROVAL_EXPIRED)
    if not not_after_valid(not_after_raw, now=now, clock_skew=clock_skew):
        return _reject(REF_APPROVAL_EXPIRED)

    # 9. accept
    return _accept()
