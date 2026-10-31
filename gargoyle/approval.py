"""Approval grants: a human's signed release of a held, high-impact call.

When a Decision has requires_approval, the receipt is held until a human
approver, using their own key on their own device, signs a grant for exactly
that decision. A grant reuses the receipt's machinery: Ed25519 signatures
over canonical_json. The approver's key is a different identity from the
issuer's key.

verify_grant() is pure: it checks provenance, binding to the held decision
and request, separation of duties, and freshness. It does not consume the
grant. Single use is stateful and belongs to whoever enforces the grant:
the consumer (gargoyle.consumer) claims grant_id exactly once in its replay
cache when it honors a flagged receipt, and an issuer that holds flagged
receipts until the grant arrives consumes approval_request_id from its
pending set (gargoyle.pending_store). verify_grant only guarantees that
grant_id is present, so that claim cannot be skipped.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from gargoyle.envelope import approval_terms, canonical_json, serializer_for
from gargoyle.verifier import not_after_valid


GRANT_VERSION = "1.0"

# Keys excluded from the approver-signature region. The signature covers
# everything else - including grant_id, decision_sha256, approval_request_id,
# not_after, and approver_key_id - so all of them are tamper-proof.
# `role_attestation` is the issuer's own signed statement, attached after
# the approver signed (see attest_roles); it carries its own signature.
_SIGNATURE_EXCLUDED_KEYS = ("approver_signature", "role_attestation")

ROLE_ATTESTATION_VERSION = "1.0"
_ATTESTATION_SIGNATURE_EXCLUDED_KEYS = ("issuer_signature",)

# Refusal codes.
REF_APPROVAL_MALFORMED = "REF_APPROVAL_MALFORMED"


class _AnyOf:
    """A verifying key made of several: the signature is valid if any verifies it."""
    def __init__(self, keys: list) -> None:
        self.keys = keys

    def verify(self, signature: bytes, message: bytes) -> None:
        for key in self.keys[:-1]:
            try:
                key.verify(signature, message)
                return
            except Exception:
                continue
        self.keys[-1].verify(signature, message)
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

# verify_grants: the set does not meet the receipt's terms.
REF_APPROVAL_INSUFFICIENT = "REF_APPROVAL_INSUFFICIENT"          # fewer distinct approvers than required
REF_APPROVAL_DUPLICATE_APPROVER = "REF_APPROVAL_DUPLICATE_APPROVER"  # the same key signed twice
REF_APPROVAL_APPROVER_NOT_ELIGIBLE = "REF_APPROVAL_APPROVER_NOT_ELIGIBLE"  # a key the receipt does not name
REF_APPROVAL_ROLE_NOT_ELIGIBLE = "REF_APPROVAL_ROLE_NOT_ELIGIBLE"    # the approver holds none of the receipt's `approval.roles`
REF_APPROVAL_ROLE_UNATTESTED = "REF_APPROVAL_ROLE_UNATTESTED"        # a role-routed receipt, and the grant carries no valid issuer attestation of the role

ACCEPT_GRANT_VALID = "GRANT_VALID"
ACCEPT_GRANTS_SUFFICIENT = "GRANTS_SUFFICIENT"

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


def attest_roles(grant: Dict[str, Any], roles: List[str], signing_key: Any, key_id: str) -> Dict[str, Any]:
    """The issuer's signed statement that, when this grant was posted, the
    approver's directory token carried `roles` (the ones the receipt's
    `approval.roles` names). Bound to the grant (grant_id, hold, approver
    key id) so it cannot be moved to another; signed with the issuer's
    key, which the executor already pins. The approver's own signature is
    untouched: the attestation sits outside its region."""
    att = {"attestation_version": ROLE_ATTESTATION_VERSION, "grant_id": grant["grant_id"],
           "approval_request_id": grant["approval_request_id"], "approver_key_id": grant["approver_key_id"],
           "roles": sorted(set(roles)), "issuer_key_id": key_id}
    att["issuer_signature"] = signing_key.sign(canonical_json(att).encode("utf-8")).hex()
    return att


def verify_role_attestation(grant: Any, *, required_roles: Any, issuer_public_keys: Optional[Dict[str, Any]],
                            gate_key_id: Optional[str] = None) -> Dict[str, Any]:
    """Does `grant` carry the issuer's word that its approver held one of
    `required_roles`? Checks: the attestation is present and well-formed,
    names this grant, its hold and its approver key, is signed by a pinned
    issuer key (the receipt's own `issuer_key_id` when given), and names at
    least one required role. Without issuer keys nothing can be verified
    and the answer is REF_APPROVAL_ROLE_UNATTESTED: a role-routed hold is
    never released on the client's say-so."""
    att = grant.get("role_attestation") if isinstance(grant, dict) else None
    if (not isinstance(att, dict) or att.get("attestation_version") != ROLE_ATTESTATION_VERSION
            or not isinstance(att.get("roles"), list) or not att["roles"]
            or not all(isinstance(r, str) and r for r in att["roles"])
            or not isinstance(att.get("issuer_key_id"), str) or not isinstance(att.get("issuer_signature"), str)):
        return _reject(REF_APPROVAL_ROLE_UNATTESTED)
    if (att.get("grant_id") != grant.get("grant_id") or att.get("approval_request_id") != grant.get("approval_request_id")
            or att.get("approver_key_id") != grant.get("approver_key_id")):
        return _reject(REF_APPROVAL_ROLE_UNATTESTED)
    if gate_key_id is not None and att["issuer_key_id"] != gate_key_id:
        return _reject(REF_APPROVAL_ROLE_UNATTESTED)
    key = (issuer_public_keys or {}).get(att["issuer_key_id"])
    if key is None:
        return _reject(REF_APPROVAL_ROLE_UNATTESTED)
    region = {k: v for k, v in att.items() if k not in _ATTESTATION_SIGNATURE_EXCLUDED_KEYS}
    try:
        key.verify(bytes.fromhex(att["issuer_signature"]), canonical_json(region).encode("utf-8"))
    except Exception:
        return _reject(REF_APPROVAL_ROLE_UNATTESTED)
    if not any(r in required_roles for r in att["roles"]):
        return _reject(REF_APPROVAL_ROLE_NOT_ELIGIBLE)
    return _accept()


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
    serializer: Any = None,
) -> Dict[str, Any]:
    """Is `grant` a valid human release of the held decision? `serializer`
    is the canonical form the grant was signed under (default: the current
    one; an audit of a historical receipt passes its format's).

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
    if isinstance(public_key, (list, tuple)):
        # Several keys for one approver id: an audit of grants from before the
        # approver's browser key was replaced or revoked. Any of them may verify.
        public_key = _AnyOf(list(public_key)) if public_key else None
    if public_key is None:
        return _reject(REF_APPROVAL_KEY_UNKNOWN)

    # 5. signature verifies (duck-typed; covers everything but the signature)
    region = {k: v for k, v in grant.items() if k not in _SIGNATURE_EXCLUDED_KEYS}
    message = (serializer or canonical_json)(region).encode("utf-8")
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


def as_grant_list(grant: Any) -> List[Any]:
    """One grant or a list of them, as a list; None is the empty list."""
    if grant is None:
        return []
    if isinstance(grant, list):
        return grant
    return [grant]


def verify_grants(
    grants: Any,
    *,
    envelope: Dict[str, Any],
    approver_public_keys: Dict[str, Any],
    now: Optional[datetime] = None,
    clock_skew: timedelta = timedelta(0),
    issuer_public_keys: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Do these grants release the flagged `envelope` under its own terms?

    The receipt's `approval` member (default: one grant from any trusted
    approver) says how many distinct approvers are required and, when it
    lists `approvers`, which key ids count. Each grant is checked with
    verify_grant against the receipt's decision_sha256, approval_request_id
    and issuer_key_id; the first failing grant's reason is the answer. Then:
    a key named by no grant more than once (REF_APPROVAL_DUPLICATE_APPROVER),
    every key eligible (REF_APPROVAL_APPROVER_NOT_ELIGIBLE), when the
    receipt names `roles` every grant attested by the issuer for one of
    them (REF_APPROVAL_ROLE_UNATTESTED / REF_APPROVAL_ROLE_NOT_ELIGIBLE;
    `issuer_public_keys` verifies the attestation), and at least
    `required` of them (REF_APPROVAL_INSUFFICIENT). An empty list is
    REF_APPROVAL_INSUFFICIENT. Returns {"accepted", "reason", "grants"}
    with the grants that were counted, so the caller can claim each one."""
    terms = approval_terms(envelope)
    items = as_grant_list(grants)
    serializer = serializer_for(envelope.get("envelope_version")) or canonical_json
    seen: List[str] = []
    for grant in items:
        g = verify_grant(
            grant,
            expected_decision_sha256=envelope["decision_sha256"],
            expected_approval_request_id=envelope["approval_request_id"],
            approver_public_keys=approver_public_keys,
            gate_key_id=envelope.get("issuer_key_id"),
            now=now,
            clock_skew=clock_skew,
            serializer=serializer,
        )
        if not g["accepted"]:
            return {"accepted": False, "reason": g["reason"], "grants": []}
        key_id = grant["approver_key_id"]
        if key_id in seen:
            return {"accepted": False, "reason": REF_APPROVAL_DUPLICATE_APPROVER, "grants": []}
        if terms["approvers"] is not None and key_id not in terms["approvers"]:
            return {"accepted": False, "reason": REF_APPROVAL_APPROVER_NOT_ELIGIBLE, "grants": []}
        if terms.get("roles"):
            r = verify_role_attestation(grant, required_roles=terms["roles"], issuer_public_keys=issuer_public_keys,
                                        gate_key_id=envelope.get("issuer_key_id"))
            if not r["accepted"]:
                return {"accepted": False, "reason": r["reason"], "grants": []}
        seen.append(key_id)
    if len(seen) < terms["required"]:
        return {"accepted": False, "reason": REF_APPROVAL_INSUFFICIENT, "grants": []}
    return {"accepted": True, "reason": ACCEPT_GRANTS_SUFFICIENT, "grants": list(items)}
