"""Approval grants: a human's signed release of a held, high-impact call.

When a Decision has requires_approval, the receipt is held until a human
approver, using their own key on their own device, signs a grant for exactly
that decision. A grant reuses the receipt's machinery: Ed25519 signatures
over canonical_json. The approver's key is a different identity from the
issuer's key.

verify_grant() is pure: it checks provenance, binding to the held decision
and request, separation of duties, and freshness. It does not consume the
grant. Single use is stateful and belongs to whoever holds the call: claim
grant_id exactly once (a ReplayCache), and consume approval_request_id from
the pending set (gargoyle.pending_store). verify_grant only guarantees that
grant_id is present, so that claim cannot be skipped.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from gargoyle.envelope import canonical_json
from gargoyle.verifier import not_after_valid


GRANT_VERSION = "1.0"

# Keys excluded from the approver-signature region. The signature covers
# everything else - including grant_id, decision_sha256, approval_request_id,
# not_after, and approver_key_id - so all of them are tamper-proof.
_SIGNATURE_EXCLUDED_KEYS = ("approver_signature",)

# Refusal codes.
REF_APPROVAL_MALFORMED = "REF_APPROVAL_MALFORMED"
REF_APPROVAL_MISSING_GRANT_ID = "REF_APPROVAL_MISSING_GRANT_ID"
REF_APPROVAL_SIGNATURE_INVALID = "REF_APPROVAL_SIGNATURE_INVALID"
REF_APPROVAL_KEY_UNKNOWN = "REF_APPROVAL_KEY_UNKNOWN"
REF_APPROVAL_SOD = "REF_APPROVAL_SOD"
REF_APPROVAL_BINDING_MISMATCH = "REF_APPROVAL_BINDING_MISMATCH"
REF_APPROVAL_REQUEST_MISMATCH = "REF_APPROVAL_REQUEST_MISMATCH"
REF_APPROVAL_EXPIRED = "REF_APPROVAL_EXPIRED"
# Emitted by the caller that consumes grants, not by verify_grant: grant_id
# already claimed, or approval_request_id not pending or not bound to this
# decision.
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
    """Construct an unsigned approval grant.

    - decision_sha256: the exact decision approved. It covers the target,
      the call's fields and the policy pin, so approving action A cannot
      authorize a different action, argument set or target.
    - approval_request_id: the id issued with the hold. decision_sha256 is
      the same for every issuance of a decision, so the specific request is
      identified here.
    - grant_id: mandatory and unique; the key claimed exactly once for
      single use.
    - not_after: timezone-aware expiry; a naive datetime raises ValueError.
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
    """Return a copy of `grant` signed with the approver's key.

    `signing_key` is any object with .sign(bytes) -> bytes. The signature
    covers everything except approver_signature, including approver_key_id,
    so the claimed signer is bound too. The input is not modified.
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
    """Is `grant` a valid human release of the held decision?

    Returns {"accepted", "reason"}. First failure wins:
      1. structure                          -> REF_APPROVAL_MALFORMED
      2. grant_id present                   -> REF_APPROVAL_MISSING_GRANT_ID
      3. approver_key_id != gate_key_id     -> REF_APPROVAL_SOD
      4. approver key known                 -> REF_APPROVAL_KEY_UNKNOWN
      5. signature verifies                 -> REF_APPROVAL_SIGNATURE_INVALID
      6. decision_sha256 matches            -> REF_APPROVAL_BINDING_MISMATCH
      7. approval_request_id matches        -> REF_APPROVAL_REQUEST_MISMATCH
      8. not_after present and not passed   -> REF_APPROVAL_EXPIRED

    `gate_key_id` is the issuer's key id. Separation of duties is checked
    before the signature, so a grant the issuer signed with its own key is
    refused even when well-signed. That id check is only a backstop: the
    real guarantee is that the issuer cannot hold an approver's private key,
    and that `approver_public_keys` comes from a trust record the issuer's
    operator does not control.

    Single use is not enforced here; see the module docstring.
    """
    # 1. structural presence
    if not isinstance(grant, dict):
        return _reject(REF_APPROVAL_MALFORMED)
    for k in _REQUIRED_GRANT_KEYS:
        if k not in grant:
            return _reject(REF_APPROVAL_MALFORMED)

    # 2. mandatory grant_id
    grant_id = grant.get("grant_id")
    if not isinstance(grant_id, str) or not grant_id:
        return _reject(REF_APPROVAL_MISSING_GRANT_ID)

    key_id = grant.get("approver_key_id")
    signature_hex = grant.get("approver_signature")
    if not isinstance(key_id, str) or not isinstance(signature_hex, str):
        return _reject(REF_APPROVAL_SIGNATURE_INVALID)

    # 3. separation of duties, before the signature: an issuer-signed
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

    # 6. action binding
    if grant.get("decision_sha256") != expected_decision_sha256:
        return _reject(REF_APPROVAL_BINDING_MISMATCH)

    # 7. request binding
    if grant.get("approval_request_id") != expected_approval_request_id:
        return _reject(REF_APPROVAL_REQUEST_MISMATCH)

    # 8. freshness: not_after is mandatory, then the verifier's shared check.
    not_after_raw = grant.get("not_after")
    if not_after_raw is None:
        return _reject(REF_APPROVAL_EXPIRED)
    if not not_after_valid(not_after_raw, now=now, clock_skew=clock_skew):
        return _reject(REF_APPROVAL_EXPIRED)

    # 9. accept
    return _accept()
