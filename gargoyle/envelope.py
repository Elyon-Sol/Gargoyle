"""Receipts: build, check against the live policy, and sign.

A receipt (historically "envelope") records one ELIGIBLE decision: which
call it was about, which policy decided it, and when. Three operations:

- build_envelope() assembles the receipt and computes decision_sha256, a
  SHA-256 over its canonical JSON (minus the per-issuance fields listed in
  _HASH_EXCLUDED_KEYS).
- reassert() re-checks a receipt against the live policy pin:
      decision_sha256 missing or wrong   -> INVALIDATED  (tampered or corrupt)
      policy_id or policy_sha256 differs -> RE-EVALUATE-REQUIRED
      otherwise                          -> REASSERTED
  Only REASSERTED may be honored without asking the policy again.
- sign_envelope() adds the issuer key id, optional not_after and decision_id,
  and an Ed25519 signature over everything except the signature itself and
  timestamp_utc.

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

from gargoyle.policy import ManifestPolicy, Policy, valid_pin

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


def decision_sha256_of(envelope: Dict[str, Any]) -> str:
    hashable = {k: v for k, v in envelope.items() if k not in _HASH_EXCLUDED_KEYS}
    return _sha256_text(canonical_json(hashable))


def live_pin(
    record_source: Optional[Dict[str, Any]] = None,
    policy: Optional[Policy] = None,
) -> Dict[str, str]:
    """The pin receipts are checked against: a fetched record's policy_id /
    policy_sha256 when given, else `policy.pin()`, else the default
    ManifestPolicy's pin."""
    if record_source is not None:
        return {
            "policy_id": record_source["policy_id"],
            "policy_sha256": record_source["policy_sha256"],
        }
    return (policy or ManifestPolicy()).pin()


def build_envelope(
    *,
    decision: str,
    target_url: str,
    normalized_interaction: Dict[str, Any],
    policy_pin: Dict[str, str],
    timestamp_utc: Optional[str] = None,
) -> Dict[str, Any]:
    """Assemble a receipt for `decision` on the call (target_url,
    normalized_interaction), made under the policy identified by
    `policy_pin`. The interaction's declared interaction_type, when present,
    is recorded too: it selected the required sets, so it is part of what was
    decided."""
    if not valid_pin(policy_pin):
        raise ValueError("policy_pin must be {'policy_id': str, 'policy_sha256': <64 hex>}")
    if timestamp_utc is None:
        timestamp_utc = datetime.now(timezone.utc).isoformat()

    request_context = {
        "AP": list(normalized_interaction["AP"]),
        "OP": list(normalized_interaction["OP"]),
        "context": normalized_interaction["context"],
        "expected_manifest_version": normalized_interaction["expected_manifest_version"],
        "expected_manifest_sha256": normalized_interaction["expected_manifest_sha256"],
    }
    itype = normalized_interaction.get("interaction_type")
    if itype is not None:
        request_context["interaction_type"] = itype

    envelope: Dict[str, Any] = {
        "envelope_version": ENVELOPE_VERSION,
        "decision": decision,
        "target_url": target_url,
        "policy": {
            "policy_id": policy_pin["policy_id"],
            "policy_sha256": policy_pin["policy_sha256"],
        },
        "request_context": request_context,
        "timestamp_utc": timestamp_utc,
    }
    envelope["decision_sha256"] = decision_sha256_of(envelope)
    return envelope


def reassert(
    envelope: Dict[str, Any],
    record_source: Optional[Dict[str, Any]] = None,
    policy: Optional[Policy] = None,
) -> Dict[str, str]:
    """Check a receipt against the live policy pin (see live_pin).

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
) -> Dict[str, Any]:
    """Return a signed copy of `envelope` (the input is not modified).

    `signing_key` is any object with .sign(message: bytes) -> bytes, such as
    a cryptography Ed25519PrivateKey; this module does not import
    cryptography. `not_after`, when given, must be timezone-aware and bounds
    the receipt's validity; the verifier refuses it afterwards. `decision_id`
    is the per-issuance id executors de-duplicate on to refuse replay."""
    signed = dict(envelope)
    signed["issuer_key_id"] = key_id
    if not_after is not None:
        if not_after.tzinfo is None:
            raise ValueError("not_after must be timezone-aware (UTC)")
        signed["not_after"] = not_after.isoformat()
    if decision_id is not None:
        signed["decision_id"] = decision_id
    region = {k: v for k, v in signed.items() if k not in _SIGNATURE_EXCLUDED_KEYS}
    signed["issuer_signature"] = signing_key.sign(canonical_json(region).encode("utf-8")).hex()
    return signed
