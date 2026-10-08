"""
Executor-side integration SDK (docs/restructure/18_latency_budget_and_sdk_spec.md,
increment VL-078, artifact 13 Phase B step B5).

Every Elyon-Sol-gated surface - the reference enforcing target (VL-061), the MCP server
(VL-077), the wedge demo (VL-066) - repeats the same executor sequence by hand: load +
anchor-verify the published record, call `verify_envelope`, then de-dup `decision_id` against a
replay cache. This module factors that sequence into one thin component so an integrator wires
admission in a few lines:

    from IMPLEMENTATION.executor_sdk import ExecutorGate

    gate = ExecutorGate(
        pinned_public_keys=PINNED_KEYS,                # {key_id: Ed25519PublicKey}
        target_id=TARGET_ID,                           # the identity envelopes bind to
        record_bytes=open(RECORD_PATH, "rb").read(),   # the published record
    )

    decision = gate.check(envelope, interaction)
    if decision.honored:
        do_the_side_effect()                           # act
    else:
        refuse(decision.reason)                        # REF_VERIFY_* / REF_TARGET_*

No gate logic is re-implemented: `check` composes the production `verify_envelope` (signature ->
reassert/currency -> binding -> freshness) and the VL-076 `ReplayCache` seam. The SDK never
performs the side effect; it only decides. Fail-closed (canon section 9): every undecidable path
returns `honored=False`. No new canonical invariant (canon section 14); the SDK changes WHERE the
sequence is packaged, not WHAT the gate decides.

Two fail-closed rules the SDK shares with the reference enforcing target (VL-154 open items):
  - the signature check ALWAYS runs. `verify_envelope` has an unsigned path when it is given no
    key material at all; the SDK never takes it. A gate needs issuer-key trust (a
    `pinned_public_keys` map, a `key_record_view`, or a `key_record_source`) to be constructed,
    and `check` hands the verifier an empty map rather than None, so an unsigned envelope is
    refused (`REF_VERIFY_SIGNATURE_INVALID` / `REF_VERIFY_SIGNATURE_UNKNOWN_KEY`), never honored.
  - an envelope without a `decision_id` is refused (`REF_TARGET_NO_DECISION_ID`, the
    reference target's F2 rule): single-use cannot be enforced for it, so it is not honored.

Build-then-wire: no caller on the default pep.py path this increment; the existing surfaces keep
their inline sequences until a later adopt-the-SDK refactor.
"""

from datetime import datetime, timedelta
from typing import Any, Callable, Dict, NamedTuple, Optional

from IMPLEMENTATION.published_source import anchor_sha256, load_record_from_bytes
from IMPLEMENTATION.replay_cache import InMemoryReplayCache
from IMPLEMENTATION.reference_target import (
    REF_TARGET_ANCHOR_MISMATCH,
    REF_TARGET_NO_DECISION_ID,
)
from IMPLEMENTATION.verifier import (
    verify_envelope,
    REF_VERIFY_REPLAY,
    REF_VERIFY_KEY_RECORD_INVALID,
)


class Decision(NamedTuple):
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


class ExecutorGate:
    """Holds the executor's trust material and replay cache; decides admission for one
    interaction at a time. Supply the published record either as a fetched dict
    (`record_source=`) or as raw bytes (`record_bytes=`, anchored on its own bytes unless a
    `pinned_root` is given). A `ReplayCache` is created per gate unless one is injected - inject a
    single shared cache across gates/instances for cross-instance exactly-once (the VL-076 seam)."""

    def __init__(
        self,
        *,
        pinned_public_keys: Dict[str, Any],
        target_id: str,
        record_source: Optional[Dict[str, Any]] = None,
        record_bytes: Optional[bytes] = None,
        pinned_root: Optional[str] = None,
        replay_cache=None,
        clock_skew: timedelta = timedelta(0),
        key_record_view: Optional[Dict[str, Any]] = None,
        key_record_source: Optional[Callable[[], Dict[str, Any]]] = None,
    ) -> None:
        """SES-9a (K-01, VL-110): optional SIGNED KEY-RECORD mode. When a
        `key_record_view` (a validated trust view from
        key_record_source.load_key_record_from_bytes) or a `key_record_source`
        (a zero-arg callable returning that reader's result dict
        {"trust_view", "reason"}, called per check() so freshness is
        re-validated per decision) is supplied, `check` passes the view to
        verify_envelope, which treats it as the SOLE issuer-key trust source
        (record-exclusive, VL-042): the issuer key must be present, not
        revoked, and in-window before the signature is checked, so a
        compromised or rotated gate key is revocable IN-BAND. A source whose
        result carries no trust view fails closed with the reader's
        REF_VERIFY_KEY_RECORD_* reason. Supplying BOTH is a config error
        (fail loud, parity with the record_source/record_bytes guard). With
        neither (the default), the static-pin path is byte-behavior-identical.
        A STATIC key_record_view has no per-check freshness re-validation; the
        caller owns the refresh cadence (prefer key_record_source, or rebuild
        the gate per request as authz_sidecar does)."""
        if record_source is None and record_bytes is None:
            raise ValueError("supply record_source (a fetched record) or record_bytes")
        if key_record_view is not None and key_record_source is not None:
            raise ValueError(
                "supply key_record_view OR key_record_source, not both"
            )
        if (pinned_public_keys is None and key_record_view is None
                and key_record_source is None):
            # No issuer-key trust at all would put verify_envelope on its
            # unsigned path; an executor gate must never run there.
            raise ValueError(
                "supply issuer-key trust: pinned_public_keys, key_record_view "
                "or key_record_source"
            )
        self.key_record_view = key_record_view
        self._key_record_source = key_record_source
        self.pinned_public_keys = pinned_public_keys
        self.target_id = target_id
        self._record_source = record_source
        self._record_bytes = record_bytes
        self._pinned_root = (
            pinned_root
            if pinned_root is not None or record_bytes is None
            else anchor_sha256(record_bytes)
        )
        self.replay_cache = replay_cache if replay_cache is not None else InMemoryReplayCache()
        self.clock_skew = clock_skew

    def _record(self) -> Optional[Dict[str, Any]]:
        if self._record_source is not None:
            return self._record_source
        return load_record_from_bytes(self._record_bytes, self._pinned_root)

    def check(
        self,
        envelope: Any,
        interaction: Dict[str, Any],
        *,
        now: Optional[datetime] = None,
    ) -> Decision:
        """Decide whether to honor `envelope` for `interaction`. Returns Decision(honored,
        reason). Fail-closed on every undecidable path; the caller performs the side effect only
        when honored is True."""
        if not isinstance(envelope, dict):
            envelope = None  # absent / non-object -> verify_envelope refuses (A1)

        record = self._record()
        if record is None:
            return Decision(False, REF_TARGET_ANCHOR_MISMATCH)

        # SES-9a: resolve the issuer-key trust view. A configured source is
        # called per check() (fresh, reader-revalidated); a result without a
        # trust view fails CLOSED with the reader's REF_VERIFY_KEY_RECORD_*
        # reason - never a downgrade to the static pin (canon section 9).
        key_record_view = self.key_record_view
        if self._key_record_source is not None:
            kres = self._key_record_source()
            view = kres.get("trust_view") if isinstance(kres, dict) else None
            if view is None:
                reason = kres.get("reason") if isinstance(kres, dict) else None
                return Decision(False, reason or REF_VERIFY_KEY_RECORD_INVALID)
            key_record_view = view

        # The signature check always runs: an empty map (not None) keeps
        # verify_envelope off its unsigned path, so a gate whose key map was
        # cleared after construction still refuses an unsigned envelope.
        pinned_public_keys = (
            self.pinned_public_keys if self.pinned_public_keys is not None else {}
        )
        result = verify_envelope(
            envelope,
            interaction,
            self.target_id,
            record_source=record,
            pinned_public_keys=pinned_public_keys,
            now=now,
            key_record_view=key_record_view,
            clock_skew=self.clock_skew,
        )
        if not result["accepted"]:
            return Decision(False, result["reason"])

        # Single-use (exactly-once over the freshness window). decision_id is
        # inside the signed region, so it is tamper-proof once verified; an
        # envelope WITHOUT one cannot be single-use-enforced and is refused
        # (the reference_target F2 rule) - never "no id, so skip the check".
        decision_id = envelope.get("decision_id")
        if not isinstance(decision_id, str) or not decision_id:
            return Decision(False, REF_TARGET_NO_DECISION_ID)
        # Retain the claim through the whole HONORED window: verify_envelope
        # accepts until not_after + clock_skew, so expiring the claim at the
        # bare not_after would let the id be re-claimed inside the skew (the
        # reference_target F3 rule).
        exp = _parse_not_after(envelope)
        if exp is not None:
            exp = exp + self.clock_skew
        if not self.replay_cache.check_and_claim(decision_id, exp, now=now):
            return Decision(False, REF_VERIFY_REPLAY)

        return Decision(True, result["reason"])
