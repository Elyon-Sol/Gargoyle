"""Issue receipts: ask the policy, and sign the answer if it is ELIGIBLE.

    interaction = {"tool": "transfer_funds", "args": {...},
                   "principal": principal,        # who the issuer authenticated
                   **claims}                      # whatever the policy reads
    result = issue(policy, target_url, interaction,
                   signing_key=key, key_id="issuer-1")
    if result.envelope is None:
        ...                                  # refused: result.decision.reason
    else:
        send(call, headers={ENVELOPE_HEADER: json.dumps(result.envelope)})

A receipt the policy flagged (result.decision.requires_approval) is issued
with requires_approval true and a signed approval_request_id. The target
will not honor it without a human's grant for exactly that decision and
request (gargoyle.approval, presented alongside the receipt), so the issuer
may hand it out at once; an issuer that prefers to hold it until the grant
arrives records the hold in gargoyle.pending_store.

The policy sees the whole interaction; the receipt binds only "tool",
"args" (by hash) and "principal". `principal` must be the identity the
issuing service authenticated for the requester (its mTLS peer, a bearer
token's subject, an id the integrator established), never a value the
requester asserted about itself: the target compares it with the identity it
authenticates, and that comparison is only as good as this input.

Every receipt carries a fresh decision_id, so an executor can refuse a
second use, and a not_after, so a receipt that is never used still dies.
A policy that raises is a refusal, never an issuance.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from gargoyle.envelope import build_envelope, sign_envelope
from gargoyle.policy import ELIGIBLE, POLICY_INTERNAL, Decision, Policy, refuse, valid_pin

ENVELOPE_HEADER = "X-Gargoyle-Envelope"
DEFAULT_TTL_SECONDS = 300

ISSUE_POLICY_ERROR = "ISSUE_POLICY_ERROR"  # decide() or pin() returned something malformed
ISSUE_UNBINDABLE_CALL = "ISSUE_UNBINDABLE_CALL"  # eligible, but tool/args/principal are missing or malformed


@dataclass(frozen=True)
class IssueResult:
    decision: Decision
    envelope: Optional[dict] = None


def issue(
    policy: Policy,
    target_url: str,
    interaction: Mapping[str, Any],
    *,
    signing_key: Any,
    key_id: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: Optional[datetime] = None,
) -> IssueResult:
    """Decide and, on ELIGIBLE, return a signed receipt for exactly this
    call. `ttl_seconds` must be positive; there is no unbounded receipt."""
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive integer")
    if signing_key is None or not key_id:
        raise ValueError("a signing key and key id are required")

    try:
        decision = policy.decide(target_url, interaction)
        if not isinstance(decision, Decision):
            return IssueResult(refuse(ISSUE_POLICY_ERROR))
        if decision.outcome != ELIGIBLE:
            return IssueResult(decision)
        pin = policy.pin()
        if not valid_pin(pin):
            return IssueResult(refuse(ISSUE_POLICY_ERROR))
    except Exception:
        return IssueResult(refuse(POLICY_INTERNAL))

    issued_at = now or datetime.now(timezone.utc)
    try:
        envelope = build_envelope(
            decision=ELIGIBLE,
            target_url=target_url,
            call=dict(interaction),
            policy_pin=pin,
            timestamp_utc=issued_at.isoformat(),
            requires_approval=bool(decision.requires_approval),
        )
    except (KeyError, TypeError, ValueError):
        return IssueResult(refuse(ISSUE_UNBINDABLE_CALL))
    signed = sign_envelope(
        envelope,
        signing_key,
        key_id,
        not_after=issued_at + timedelta(seconds=ttl_seconds),
        decision_id=str(uuid.uuid4()),
        approval_request_id=str(uuid.uuid4()) if decision.requires_approval else None,
    )
    return IssueResult(decision, signed)
