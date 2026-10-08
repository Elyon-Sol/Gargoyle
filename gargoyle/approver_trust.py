"""
Governance layer - approver provenance + role (Feature 1, residual R1).

docs/design/governance_layer_design.md section 1.4, the [FIX H5] LOAD-BEARING
half.

[FIX H5] requires Separation of Duties to be a CUSTODY / PROVENANCE invariant,
not a key_id string compare. verify_grant() (VL-114) already enforces the cheap
belt-and-braces check (approver_key_id != gate_key_id) and pep.governed_call
(VL-115) supplies it a static approver-key pin. THIS module supplies the
load-bearing half the design scheduled: the approver public keys verify_grant
trusts must flow through the EXISTING signed key-record / root-record chain
(key_record_source / root_record_source) and carry an explicit `approver` ROLE
distinct from `issuer`. SoD then becomes ROLE-DISTINCTNESS in the SIGNED record,
not a key_id string compare:

  - Only a key whose SIGNED record-role is exactly "approver" is eligible to
    authorize an approval. The gate's issuer key (role "issuer", or any
    non-approver / absent role) is STRUCTURALLY excluded from the approver trust
    map, so a gate-minted "approval" is never honored even when it is well-signed
    and carries a different key_id - which the bare key_id compare could not stop.
  - The key must be NOT revoked and WITHIN its signed validity window (the same
    discipline verify_envelope applies to an issuer key, mirrored here including
    the VL-075 symmetric clock_skew widening).
  - key_id != gate_key_id is retained as cheap belt-and-braces, not the guarantee.

PURE and ABOVE G(I). This module consumes a trust view ALREADY validated by
key_record_source.load_key_record_from_bytes (publisher signature + freshness +
root-status gating) and returns the {key_id: public_key} map verify_grant already
expects - so approval.py and the G(I) core (evaluator/impact/envelope/verifier)
are byte-UNCHANGED. The role flows through the signed chain because the publisher
signs canonical_json(record minus signature), which includes every key entry's
`role`; this module never trusts a role it did not receive from that validated
view.

Build-then-wire: pep wires this as an OPTIONAL approver-trust source; with no
key record configured the existing static-pin path is byte-behavior-identical.

HONEST SCOPE. This delivers the PROVENANCE + ROLE half of [FIX H5] (WHERE approver
trust comes from). The CUSTODY half - a deployment proof that the gate PROCESS
cannot resolve the approver PRIVATE key - remains an operator / deployment
property, not an in-repo artifact. A key record that publishes NO roles yields NO
approver keys (fail-closed): a deployment that uses signed-chain approver trust
MUST publish an explicit approver role. White-box in-house; NOT a G5 referent; no
readiness predicate goes green on this module.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

# The role tokens. Surfaced from the signed key-record entry's `role` field
# (key_record_source carries it into the per-key trust view). APPROVER_ROLE is
# the ONLY value that makes a key eligible to authorize an approval; ISSUER_ROLE
# is named for documentation/symmetry but is treated, like every non-approver
# value, as NOT-an-approver (fail-closed).
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
    From a VALIDATED signed key-record trust view (the output of
    key_record_source.load_key_record_from_bytes - {key_id: {public_key, role,
    revoked, not_before, not_after}}), return the {key_id: public_key} map of keys
    eligible to AUTHORIZE an approval grant. The result is a drop-in for
    verify_grant()'s `approver_public_keys` argument.

    A key is eligible IFF ALL hold (each fail-closed; anything not provably an
    active approver key is excluded, never raised into an open grant):
      - its signed record-role is EXACTLY APPROVER_ROLE ("approver")
        [ROLE-DISTINCTNESS - the load-bearing SoD];
      - it is NOT revoked;
      - now is within [not_before - clock_skew, not_after + clock_skew)
        (mirrors verify_envelope's VL-075 issuer-key window);
      - key_id != gate_key_id (belt-and-braces SoD: a key sharing the gate's id
        is never an approver even if it claims the approver role).

    `now` defaults to datetime.now(timezone.utc). clock_skew must be non-negative
    (a negative value narrows the window - a config error) and raises ValueError,
    matching key_record_source. A non-dict view, a non-dict entry, or malformed
    key material contributes nothing rather than raising.
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
        # belt-and-braces SoD (cheap; the role gate below is the guarantee)
        if gate_key_id is not None and key_id == gate_key_id:
            continue
        # ROLE-DISTINCTNESS: only a signed "approver" role is eligible. An issuer
        # key (or a role-less key) is structurally excluded - this is what a bare
        # key_id compare cannot do.
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
