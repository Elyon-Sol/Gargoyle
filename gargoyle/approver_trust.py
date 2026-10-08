"""Which keys may authorize an approval: signed role, not a key-id compare.

verify_grant() refuses a grant signed under the issuer's own key id, but a
key-id compare alone cannot stop an issuer-controlled key published under a
different id. This module builds the approver trust map from the signed key
record instead (key_record_source / root_record_source), where every key
entry carries a `role` covered by the publisher's signature:

  - Only a key whose signed role is exactly "approver" may authorize an
    approval. An issuer key, or a key with any other or no role, is excluded
    from the map, so a well-signed "approval" minted by the issuer is never
    honored even under a different key id.
  - The key must not be revoked and must be inside its signed validity
    window, widened symmetrically by clock_skew, the same rule
    verify_envelope applies to issuer keys.
  - key_id != gate_key_id is kept as a cheap extra check, not the guarantee.

Pure: it consumes a trust view already validated by
key_record_source.load_key_record_from_bytes (publisher signature,
freshness, root status) and returns the {key_id: public_key} map
verify_grant expects. It never trusts a role it did not receive from that
validated view.

Limits. This controls where approver trust comes from. It does not prove the
issuing process cannot reach the approver's private key; that is a
deployment property. A key record that publishes no roles yields no approver
keys, so a deployment using signed approver trust must publish an explicit
approver role.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

# Role tokens from the signed key-record entry's `role` field. APPROVER_ROLE is
# the only value that makes a key eligible to authorize an approval. ISSUER_ROLE
# is named for symmetry; like every other value it is not an approver.
APPROVER_ROLE = "approver"
ISSUER_ROLE = "issuer"


def resolve_approver_keys(
    key_record_trust_view: Any,
    *,
    gate_key_id: Optional[str] = None,
    now: Optional[datetime] = None,
    clock_skew: timedelta = timedelta(0),
) -> Dict[str, Any]:
    """
    The {key_id: public_key} map of keys allowed to authorize an approval
    grant, from a validated key-record trust view ({key_id: {public_key, role,
    revoked, not_before, not_after}}). Pass the result to verify_grant() as
    `approver_public_keys`.

    A key is included only if all of these hold; anything else is left out,
    never raised:
      - its signed role is exactly "approver";
      - it is not revoked;
      - not_before - clock_skew <= now < not_after + clock_skew;
      - key_id != gate_key_id (the issuer's key id).

    `now` defaults to the current UTC time. A negative clock_skew would narrow
    the window, so it raises ValueError, as key_record_source does. A non-dict
    view, a non-dict entry, or missing key material contributes nothing.
    """
    if clock_skew < timedelta(0):
        raise ValueError("clock_skew must be non-negative")
    if not isinstance(key_record_trust_view, dict):
        return {}
    if now is None:
        now = datetime.now(timezone.utc)

    resolved: Dict[str, Any] = {}
    for key_id, info in key_record_trust_view.items():
        if not isinstance(key_id, str) or not isinstance(info, dict):
            continue
        # Cheap extra check; the role check below is the guarantee.
        if gate_key_id is not None and key_id == gate_key_id:
            continue
        # Only a signed "approver" role is eligible. Issuer and role-less keys are
        # excluded, which a key-id compare alone cannot do.
        if info.get("role") != APPROVER_ROLE:
            continue
        if info.get("revoked") is True:
            continue
        public_key = info.get("public_key")
        if public_key is None:
            continue
        not_before = info.get("not_before")
        not_after = info.get("not_after")
        if not isinstance(not_before, datetime) or not isinstance(not_after, datetime):
            continue
        if not (not_before - clock_skew <= now < not_after + clock_skew):
            continue
        resolved[key_id] = public_key
    return resolved
