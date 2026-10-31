"""The consumer side: everything a party that executes tool calls needs to
honor a receipt at most once.

Every consumer (the reference target below, gargoyle.mcp_server, an
integrator's own service) runs the same sequence on each call: establish
the live policy pin, establish the trusted issuer keys, verify_envelope,
demand and verify a human's grant when the receipt is flagged, then claim
the grant and the decision_id in a replay cache. `Consumer` packages it:

    from gargoyle.consumer import Consumer

    consumer = Consumer(
        target_id=TARGET_ID,                             # the identity receipts bind to
        pinned_public_keys={KEY_ID: issuer_public_key},  # or a signed key record
        record=json.load(open(RECORD_PATH)),             # the live pin, or a record source
    )

    call = {"tool": name, "args": arguments, "principal": peer_identity}
    verdict = consumer.check(envelope, call, grant=grant_or_none)
    if verdict.honored:
        outputs = do_the_side_effect()
        execution = consumer.attest(envelope, outputs)   # signed execution receipt, if a key is configured
    else:
        refuse(verdict.reason)                           # REF_VERIFY_* / REF_TARGET_*

`peer_identity` is who the executor authenticated as the presenting party;
the receipt must name the same principal (see gargoyle.verifier). The
consumer only decides; the caller performs the side effect. Every
undecidable path is honored=False. Two rules are not optional:

  - The signature check always runs. verify_envelope raises when given no
    key material; a Consumer requires issuer-key trust at construction and
    passes an empty map rather than None when a key record is the source,
    so an unsigned receipt is refused, never honored.
  - A receipt without a decision_id is refused (REF_TARGET_NO_DECISION_ID):
    single use cannot be enforced for it.
  - A receipt whose signed requires_approval is true is honored only with a
    grant (gargoyle.approval) that a trusted approver key signed for exactly
    that decision_sha256 and approval_request_id, presented alongside the
    receipt; the grant is single-use too. No grant is
    REF_TARGET_APPROVAL_REQUIRED; no approver trust configured is
    REF_TARGET_NO_APPROVER_TRUST. The human-held key is therefore required
    at the point of execution, not merely at issuance.

Live pin and issuer keys can be static (a validated record dict, a pinned
key map, a validated key-record view) or come from a source called on every
check: `record_source(last_seen_serial)` returning
{"record", "reason"} (the shape published_record_source.fetch_signed_record
returns) and `key_record_source(last_seen_serial)` returning {"trust_view",
"reason", "serial"} (key_record_source.fetch_key_record). The consumer keeps
the highest serial it has seen for each and passes it back in, so a signed
record rolled back to an older serial is refused as stale even while it is
still inside its not_after window. A source result with no record or no
trust view fails closed with the source's reason and never falls back to a
static value.

"""

import threading
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, NamedTuple, Optional

from gargoyle.approval import as_grant_list, verify_grants
from gargoyle.approver_trust import resolve_approver_keys
from gargoyle.execution import build_execution_receipt, sign_execution_receipt
from gargoyle.policy import valid_pin
from gargoyle.replay_cache import InMemoryReplayCache
from gargoyle.verifier import (
    REF_VERIFY_KEY_RECORD_INVALID,
    REF_VERIFY_PUBLISHED_RECORD_INVALID,
    REF_VERIFY_REPLAY,
    not_after_valid,
    verify_envelope,
)
from gargoyle.approval import REF_APPROVAL_REPLAY


# Refusals the consumer side emits itself. Every other refusal is the
# REF_VERIFY_* code verify_envelope returned, passed through unchanged.
REF_TARGET_NOT_CONFIGURED = "REF_TARGET_NOT_CONFIGURED"
# A receipt without a decision_id cannot be held to single use.
REF_TARGET_NO_DECISION_ID = "REF_TARGET_NO_DECISION_ID"
# The receipt is flagged for a human and no grant was presented with it.
REF_TARGET_APPROVAL_REQUIRED = "REF_TARGET_APPROVAL_REQUIRED"
# The receipt is flagged for a human and this consumer trusts no approver key.
REF_TARGET_NO_APPROVER_TRUST = "REF_TARGET_NO_APPROVER_TRUST"

# Replay-cache namespace for grant ids, so a grant id can never collide with
# a decision id.
_GRANT_CLAIM_PREFIX = "grant:"


class Verdict(NamedTuple):
    honored: bool
    reason: str


def _parse_not_after(envelope: Dict[str, Any]) -> Optional[datetime]:
    na = envelope.get("not_after")
    if isinstance(na, str):
        try:
            return datetime.fromisoformat(na)
        except ValueError:
            return None
    return None


class HighWater:
    """The highest serial seen on the signed published record and on the
    key record, so a rolled-back record is refused. One instance per
    consumer by default; share one across consumers that stand for the same
    target (the reference target builds a consumer per request and shares
    this and the replay cache). Replicas would need to share it like the
    replay cache."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.record_serial: Optional[int] = None
        self.key_record_serial: Optional[int] = None

    @staticmethod
    def _is_serial(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def advance_record(self, serial: Any) -> None:
        if self._is_serial(serial):
            with self._lock:
                if self.record_serial is None or serial > self.record_serial:
                    self.record_serial = serial

    def advance_key_record(self, serial: Any) -> None:
        if self._is_serial(serial):
            with self._lock:
                if self.key_record_serial is None or serial > self.key_record_serial:
                    self.key_record_serial = serial


class Consumer:
    """Holds a target's trust material, replay cache and serial marks, and
    decides one call at a time."""

    def __init__(
        self,
        *,
        target_id: str,
        pinned_public_keys: Optional[Dict[str, Any]] = None,
        key_record_view: Optional[Dict[str, Any]] = None,
        key_record_source: Optional[Callable[[Optional[int]], Dict[str, Any]]] = None,
        record: Optional[Dict[str, Any]] = None,
        record_source: Optional[Callable[[Optional[int]], Dict[str, Any]]] = None,
        replay_cache=None,
        clock_skew: timedelta = timedelta(0),
        high_water: Optional[HighWater] = None,
        approver_public_keys: Optional[Dict[str, Any]] = None,
        approver_key_source: Optional[Callable[[], Dict[str, Any]]] = None,
        executor_signing_key: Any = None,
        executor_key_id: Optional[str] = None,
    ) -> None:
        """The live pin comes from exactly one of `record` (a validated
        {policy_id, policy_sha256}, checked for shape here) or `record_source`
        (called with the highest serial seen). Issuer-key trust comes from
        `pinned_public_keys` (a static pin), `key_record_view` (a validated
        view, never re-validated: the caller owns its refresh) or
        `key_record_source` (called with the highest serial seen; prefer it);
        a view and a source together is a configuration error, and no trust
        at all is one too. Approver trust, needed only for flagged receipts,
        comes from a key record's `approver`-role keys when a key-record view
        or source is in use, else from the static `approver_public_keys`
        map. `executor_signing_key` and `executor_key_id`, both or neither,
        let attest() sign execution receipts (gargoyle.execution)."""
        if (record is None) == (record_source is None):
            raise ValueError("supply exactly one of record or record_source")
        if record is not None and not valid_pin(record):
            raise ValueError("record must be {policy_id, policy_sha256 (64 hex)}")
        if key_record_view is not None and key_record_source is not None:
            raise ValueError("supply key_record_view OR key_record_source, not both")
        if (pinned_public_keys is None and key_record_view is None
                and key_record_source is None):
            raise ValueError(
                "supply issuer-key trust: pinned_public_keys, key_record_view "
                "or key_record_source"
            )
        if clock_skew < timedelta(0):
            raise ValueError("clock_skew must be non-negative")
        if (executor_signing_key is None) != (executor_key_id is None):
            raise ValueError("supply executor_signing_key and executor_key_id together")
        self._executor_signing_key = executor_signing_key
        self.executor_key_id = executor_key_id
        self.target_id = target_id
        self.pinned_public_keys = pinned_public_keys
        self.key_record_view = key_record_view
        self._key_record_source = key_record_source
        self._record = record
        self._record_source = record_source
        self.replay_cache = replay_cache if replay_cache is not None else InMemoryReplayCache()
        self.clock_skew = clock_skew
        self.high_water = high_water if high_water is not None else HighWater()
        self.approver_public_keys = approver_public_keys
        # Enrolled approvers (gargoyle.approvers), fetched live by the caller's
        # function and merged over the static map at each flagged check.
        self.approver_key_source = approver_key_source

    # ----- the live policy pin -----

    def _resolve_record(self) -> Verdict | Dict[str, Any]:
        """The validated record, or the Verdict refusing the call."""
        if self._record is not None:
            return self._record
        try:
            res = self._record_source(self.high_water.record_serial)
        except Exception:
            return Verdict(False, REF_VERIFY_PUBLISHED_RECORD_INVALID)
        record = res.get("record") if isinstance(res, dict) else None
        if not isinstance(record, dict):
            reason = res.get("reason") if isinstance(res, dict) else None
            return Verdict(False, reason or REF_VERIFY_PUBLISHED_RECORD_INVALID)
        self.high_water.advance_record(record.get("serial"))
        return record

    # ----- the trusted issuer keys -----

    def _resolve_key_record_view(self) -> Verdict | Optional[Dict[str, Any]]:
        """The key-record trust view (None when trust is a static pin), or
        the Verdict refusing the call."""
        if self._key_record_source is None:
            return self.key_record_view
        try:
            kres = self._key_record_source(self.high_water.key_record_serial)
        except Exception:
            return Verdict(False, REF_VERIFY_KEY_RECORD_INVALID)
        view = kres.get("trust_view") if isinstance(kres, dict) else None
        if view is None:
            reason = kres.get("reason") if isinstance(kres, dict) else None
            return Verdict(False, reason or REF_VERIFY_KEY_RECORD_INVALID)
        self.high_water.advance_key_record(kres.get("serial"))
        return view

    @property
    def attests(self) -> bool:
        """True when this consumer can sign execution receipts."""
        return self._executor_signing_key is not None

    def attest(self, envelope: Dict[str, Any], outputs: Any,
               executed_at: Optional[datetime] = None, post_state_sha256: Optional[str] = None) -> Dict[str, Any]:
        """The signed execution receipt for a call this consumer honored and
        the caller has just run with `outputs`. Raises when no executor key
        is configured: an unsigned statement of execution is not evidence."""
        if not self.attests:
            raise ValueError("this consumer has no executor signing key; cannot attest")
        execution = build_execution_receipt(envelope=envelope, outputs=outputs, executed_at=executed_at,
                                            post_state_sha256=post_state_sha256)
        return sign_execution_receipt(execution, self._executor_signing_key, self.executor_key_id)

    def _approver_keys(self, key_record_view, gate_key_id, now) -> Dict[str, Any]:
        """The approver map for a flagged receipt: from the key record when
        one is in use (only its `approver`-role keys, unrevoked, in window),
        else the static map."""
        if key_record_view is not None:
            return resolve_approver_keys(key_record_view, gate_key_id=gate_key_id,
                                         now=now, clock_skew=self.clock_skew)
        keys = dict(self.approver_public_keys or {})
        if self.approver_key_source is not None:
            try:
                keys.update({k: v for k, v in (self.approver_key_source() or {}).items() if k != gate_key_id})
            except Exception:
                pass          # an unreachable source adds nothing; the static map stands
        return keys

    def check(
        self,
        envelope: Any,
        call: Dict[str, Any],
        *,
        grant: Any = None,
        now: Optional[datetime] = None,
        plan_release: Any = None,
    ) -> Verdict:
        """Decide whether to honor `envelope` for `call` ({"tool", "args",
        "principal"}, the principal being the one this consumer
        authenticated), with `grant` the human release presented alongside
        a flagged receipt: one grant, or a list of them when the receipt
        requires several approvers (None when none was). Fail-closed on
        every undecidable path; the caller performs the side effect only
        when honored is True."""
        if not isinstance(envelope, dict):
            envelope = None  # absent or not an object: verify_envelope refuses

        record = self._resolve_record()
        if isinstance(record, Verdict):
            return record
        key_record_view = self._resolve_key_record_view()
        if isinstance(key_record_view, Verdict):
            return key_record_view

        # The signature check always runs: an empty map (not None) satisfies
        # verify_envelope's key requirement when the key record is the source.
        pinned_public_keys = (
            self.pinned_public_keys if self.pinned_public_keys is not None else {}
        )
        result = verify_envelope(
            envelope,
            call,
            self.target_id,
            record_source=record,
            pinned_public_keys=pinned_public_keys,
            now=now,
            key_record_view=key_record_view,
            clock_skew=self.clock_skew,
        )
        if not result["accepted"]:
            return Verdict(False, result["reason"])

        # Single use. decision_id is signed, so it cannot be altered once the
        # signature verified. A receipt without one is refused, never "no id,
        # so skip the check".
        decision_id = envelope.get("decision_id")
        if not isinstance(decision_id, str) or not decision_id:
            return Verdict(False, REF_TARGET_NO_DECISION_ID)

        # A flagged receipt: the human-held key is required here, at the
        # point of execution. requires_approval and approval_request_id are
        # inside the signed region, so they are the issuer's word, not the
        # caller's. The grant is checked and claimed before the receipt is
        # claimed, so a refused grant leaves the receipt unspent.
        if envelope["requires_approval"] and plan_release is not None:
            # A scoped grant (gargoyle.plans): the plan's step is claimed once
            # in place of a per-call grant id.
            from gargoyle.plans import verify_plan_release
            approver_keys = self._approver_keys(key_record_view, envelope.get("issuer_key_id"), now)
            if not approver_keys:
                return Verdict(False, REF_TARGET_NO_APPROVER_TRUST)
            r = verify_plan_release(plan_release, envelope, call, issuer_public_keys=pinned_public_keys,
                                    approver_public_keys=approver_keys, now=now, clock_skew=self.clock_skew)
            if not r["accepted"]:
                return Verdict(False, r["reason"])
            plan = plan_release["plan"]
            try:
                plan_exp = datetime.fromisoformat(plan["not_after"]) + self.clock_skew
            except (ValueError, TypeError, KeyError):
                plan_exp = None
            if not self.replay_cache.check_and_claim("plan:%s:%d" % (plan["plan_id"], r["step"]), plan_exp, now=now):
                from gargoyle.plans import REF_PLAN_STEP_CONSUMED
                return Verdict(False, REF_PLAN_STEP_CONSUMED)
        elif envelope["requires_approval"]:
            grants = as_grant_list(grant)
            if not grants:
                return Verdict(False, REF_TARGET_APPROVAL_REQUIRED)
            approver_keys = self._approver_keys(key_record_view, envelope.get("issuer_key_id"), now)
            if not approver_keys:
                return Verdict(False, REF_TARGET_NO_APPROVER_TRUST)
            # One grant or several: the receipt's own `approval` terms say
            # how many distinct approvers, and which, must have signed.
            # The pinned issuer keys also verify the issuer's role attestation
            # on a grant for a receipt whose `approval.roles` routes it.
            g = verify_grants(grants, envelope=envelope, approver_public_keys=approver_keys,
                              now=now, clock_skew=self.clock_skew, issuer_public_keys=pinned_public_keys)
            if not g["accepted"]:
                return Verdict(False, g["reason"])
            for one in g["grants"]:
                grant_exp = None
                try:
                    grant_exp = datetime.fromisoformat(one["not_after"]) + self.clock_skew
                except (ValueError, TypeError, KeyError):
                    grant_exp = None
                if not self.replay_cache.check_and_claim(
                        _GRANT_CLAIM_PREFIX + one["grant_id"], grant_exp, now=now):
                    return Verdict(False, REF_APPROVAL_REPLAY)
        # Keep the claim for the whole window the verifier honors: it accepts
        # until not_after + clock_skew, so expiring the claim at the bare
        # not_after would let the id be claimed again inside the skew.
        exp = _parse_not_after(envelope)
        if exp is not None:
            exp = exp + self.clock_skew
        if not self.replay_cache.check_and_claim(decision_id, exp, now=now):
            return Verdict(False, REF_VERIFY_REPLAY)

        return Verdict(True, result["reason"])
