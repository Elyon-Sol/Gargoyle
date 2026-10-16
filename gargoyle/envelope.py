"""Receipts: build, check against the live policy, and sign.

A receipt (historically "envelope") records one ELIGIBLE decision: which
call it was about (tool, arguments, principal, target), which policy decided
it, and when. Three operations:

- build_envelope() assembles the receipt and computes decision_sha256, a
  SHA-256 over its canonical JSON (minus the per-issuance fields listed in
  _HASH_EXCLUDED_KEYS).
- reassert() re-checks a receipt against the live policy pin:
      decision_sha256 missing or wrong   -> INVALIDATED  (tampered or corrupt)
      policy_id or policy_sha256 differs -> RE-EVALUATE-REQUIRED
      otherwise                          -> REASSERTED
  Only REASSERTED may be honored without asking the policy again.
- sign_envelope() adds the issuer key id, optional not_after, decision_id
  and approval_request_id, and an Ed25519 signature over everything except
  the signature itself and timestamp_utc.

A receipt also says whether the policy flagged the call for a human:
`requires_approval` is part of the decision (hashed and signed), so a target
can tell a held call from a free one without trusting the issuer to hold it.
A flagged receipt is only honored together with a grant (gargoyle.approval)
that names its decision_sha256 and its approval_request_id.

A receipt binds exactly what a target can observe about a call: the tool
name, a SHA-256 of the canonical arguments, and the principal, the
authenticated identity of the caller. The issuer records the principal it
authenticated; the target compares it with the identity it authenticated
itself. Whatever else the policy was shown (the caller's claims, a manifest
pin) is not in the receipt: the policy pin stands for it.

Binding a receipt to the call being executed, and checking the signature,
expiry and replay, is verifier.verify_envelope()'s job.

Canonical JSON is sort_keys=True, separators=(",", ":"), ensure_ascii=True.
canonical_json() is the one serializer for receipts, grants and records, so
every signature and hash in the package is computed over the same bytes.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from gargoyle.policy import Policy, valid_pin

REASSERTED = "REASSERTED"
INVALIDATED = "INVALIDATED"
RE_EVALUATE_REQUIRED = "RE-EVALUATE-REQUIRED"

ENVELOPE_VERSION = "gargoyle/1"

# Excluded from decision_sha256: the hash itself, and every field that varies
# per issuance of the same decision. Keeping the issuer fields, not_after and
# decision_id out means a signed receipt's decision_sha256 equals the unsigned
# one, and reassert() verifies it unchanged.
_HASH_EXCLUDED_KEYS = (
    "decision_sha256",
    "timestamp_utc",
    "issuer_key_id",
    "issuer_signature",
    "not_after",
    "decision_id",
    "approval_request_id",
)

# Excluded from the issuer signature. not_after and decision_id are NOT
# excluded: the signature must cover the validity window and the replay id, or
# a captured receipt could have its lifetime extended or its id swapped.
# timestamp_utc carries no security weight and is excluded from both regions.
_SIGNATURE_EXCLUDED_KEYS = ("issuer_signature", "timestamp_utc")


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def args_sha256(args: Any) -> str:
    """The SHA-256 a receipt binds a call's arguments by: over canonical_json,
    so key order never matters and the hash is defined for any JSON value."""
    return _sha256_text(canonical_json(args))


def valid_principal(principal: Any) -> bool:
    """A principal is a non-empty string. Anything else is unauthenticated."""
    return isinstance(principal, str) and bool(principal)


def decision_sha256_of(envelope: Dict[str, Any]) -> str:
    hashable = {k: v for k, v in envelope.items() if k not in _HASH_EXCLUDED_KEYS}
    return _sha256_text(canonical_json(hashable))


def live_pin(
    record_source: Optional[Dict[str, Any]] = None,
    policy: Optional[Policy] = None,
) -> Dict[str, str]:
    """The pin receipts are checked against: a fetched record's policy_id /
    policy_sha256 when given, else `policy.pin()`. One of the two is
    required; a checker with no live pin is misconfigured, not permissive,
    and that is a ValueError rather than a refusal."""
    if record_source is not None:
        return {
            "policy_id": record_source["policy_id"],
            "policy_sha256": record_source["policy_sha256"],
        }
    if policy is None:
        raise ValueError("live_pin needs a record_source or a policy")
    return policy.pin()


def build_envelope(
    *,
    decision: str,
    target_url: str,
    call: Dict[str, Any],
    policy_pin: Dict[str, str],
    timestamp_utc: Optional[str] = None,
    requires_approval: bool = False,
) -> Dict[str, Any]:
    """Assemble a receipt for `decision` on `call` at `target_url`, made under
    the policy identified by `policy_pin`. `requires_approval` records that
    the policy flagged the call for a human; it is part of the decision.

    `call` must carry the three bound fields: "tool" (a non-empty string),
    "args" (any JSON value; the receipt stores its args_sha256) and
    "principal" (the caller's authenticated identity, a non-empty string).
    Other keys are policy inputs and are not recorded. A missing or
    malformed bound field raises (KeyError, TypeError, ValueError); the
    issuer turns that into a refusal."""
    if not valid_pin(policy_pin):
        raise ValueError("policy_pin must be {'policy_id': str, 'policy_sha256': <64 hex>}")
    if not isinstance(requires_approval, bool):
        raise TypeError("requires_approval must be a bool")
    if not isinstance(call, dict):
        raise TypeError("call must be a dict")
    tool = call["tool"]
    if not isinstance(tool, str) or not tool:
        raise ValueError("call['tool'] must be a non-empty string")
    principal = call["principal"]
    if not valid_principal(principal):
        raise ValueError("call['principal'] must be a non-empty string")
    args_hash = args_sha256(call["args"])
    if timestamp_utc is None:
        timestamp_utc = datetime.now(timezone.utc).isoformat()

    envelope: Dict[str, Any] = {
        "envelope_version": ENVELOPE_VERSION,
        "decision": decision,
        "requires_approval": requires_approval,
        "target_url": target_url,
        "policy": {
            "policy_id": policy_pin["policy_id"],
            "policy_sha256": policy_pin["policy_sha256"],
        },
        "request_context": {
            "tool": tool,
            "args_sha256": args_hash,
            "principal": principal,
        },
        "timestamp_utc": timestamp_utc,
    }
    envelope["decision_sha256"] = decision_sha256_of(envelope)
    return envelope


def reassert(
    envelope: Dict[str, Any],
    record_source: Optional[Dict[str, Any]] = None,
    policy: Optional[Policy] = None,
) -> Dict[str, str]:
    """Check a receipt against the live policy pin (see live_pin; one of
    `record_source` / `policy` is required).

    Returns {"outcome": REASSERTED | INVALIDATED | RE_EVALUATE_REQUIRED}. The
    integrity check runs first, so a tampered receipt is INVALIDATED even if
    the policy also changed. Pure with respect to `envelope`."""
    stored = envelope.get("decision_sha256")
    if not isinstance(stored, str) or stored != decision_sha256_of(envelope):
        return {"outcome": INVALIDATED}

    pinned = envelope.get("policy")
    live = live_pin(record_source, policy)
    if (
        not isinstance(pinned, dict)
        or pinned.get("policy_id") != live["policy_id"]
        or pinned.get("policy_sha256") != live["policy_sha256"]
    ):
        return {"outcome": RE_EVALUATE_REQUIRED}

    return {"outcome": REASSERTED}


def sign_envelope(
    envelope: Dict[str, Any],
    signing_key: Any,
    key_id: str,
    not_after: Optional[datetime] = None,
    decision_id: Optional[str] = None,
    approval_request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a signed copy of `envelope` (the input is not modified).

    `signing_key` is any object with .sign(message: bytes) -> bytes, such as
    a cryptography Ed25519PrivateKey; this module does not import
    cryptography. `not_after`, when given, must be timezone-aware and bounds
    the receipt's validity; the verifier refuses it afterwards. `decision_id`
    is the per-issuance id executors de-duplicate on to refuse replay.
    `approval_request_id` is the per-issuance id a grant must name to release
    a flagged receipt; it is signed, like decision_id, and like it is not in
    the decision hash."""
    signed = dict(envelope)
    signed["issuer_key_id"] = key_id
    if not_after is not None:
        if not_after.tzinfo is None:
            raise ValueError("not_after must be timezone-aware (UTC)")
        signed["not_after"] = not_after.isoformat()
    if decision_id is not None:
        signed["decision_id"] = decision_id
    if approval_request_id is not None:
        signed["approval_request_id"] = approval_request_id
    region = {k: v for k, v in signed.items() if k not in _SIGNATURE_EXCLUDED_KEYS}
    signed["issuer_signature"] = signing_key.sign(canonical_json(region).encode("utf-8")).hex()
    return signed
