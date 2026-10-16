"""Executor-side check: should this receipt be honored for this call?

Every consumer (the reference target, the MCP server, an integrator's own
service) runs the same sequence: load and anchor-verify the published
record, verify_envelope, then claim decision_id in a replay cache.
ExecutorGate packages it:

    from gargoyle.executor_sdk import ExecutorGate

    gate = ExecutorGate(
        pinned_public_keys=PINNED_KEYS,                # {key_id: Ed25519PublicKey}
        target_id=TARGET_ID,                           # the identity receipts bind to
        record_bytes=open(RECORD_PATH, "rb").read(),   # the published record
    )

    call = {"tool": name, "args": arguments, "principal": peer_identity}
    decision = gate.check(envelope, call)
    if decision.honored:
        do_the_side_effect()
    else:
        refuse(decision.reason)                        # REF_VERIFY_* / REF_TARGET_*

`peer_identity` is who the executor authenticated as the presenting party;
the receipt must name the same principal (see gargoyle.verifier).

The gate only decides; the caller performs the side effect. Every
undecidable path returns honored=False. Two rules are not optional:

  - The signature check always runs. verify_envelope has an unsigned path
    when given no key material at all; ExecutorGate never takes it. It
    requires issuer-key trust at construction and passes an empty map rather
    than None, so an unsigned receipt is refused, never honored.
  - A receipt without a decision_id is refused (REF_TARGET_NO_DECISION_ID):
    single use cannot be enforced for it.
"""

from datetime import datetime, timedelta
from typing import Any, Callable, Dict, NamedTuple, Optional

from gargoyle.published_source import anchor_sha256, load_record_from_bytes
from gargoyle.replay_cache import InMemoryReplayCache
from gargoyle.reference_target import (
    REF_TARGET_ANCHOR_MISMATCH,
    REF_TARGET_NO_DECISION_ID,
)
from gargoyle.verifier import (
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
    """Holds the executor's trust material and replay cache and decides one call
    at a time. Supply the published record as a fetched dict (`record_source=`)
    or as raw bytes (`record_bytes=`, anchored on its own bytes unless
    `pinned_root` is given). Each gate gets its own in-memory replay cache
    unless one is injected; inject one shared cache across instances for
    exactly-once across them."""

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
        """Issuer-key trust comes from `pinned_public_keys` (a static pin) or
        from a signed key record. With `key_record_view` (from
        key_record_source.load_key_record_from_bytes) or `key_record_source`
        (a zero-arg callable returning that reader's {"trust_view", "reason"},
        called on every check), the key record is the only trust source: the
        issuer key must be present, unrevoked and in its validity window
        before the signature is checked, so a compromised or rotated issuer
        key can be revoked in-band. A source result with no trust view fails
        closed with the reader's REF_VERIFY_KEY_RECORD_* reason.

        Supplying both a view and a source is a config error. A static view
        is never re-validated, so the caller owns its refresh; prefer
        `key_record_source`."""
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
        call: Dict[str, Any],
        *,
        now: Optional[datetime] = None,
    ) -> Decision:
        """Decide whether to honor `envelope` for `call` ({"tool", "args",
        "principal"}, the principal being the one this executor
        authenticated). Returns Decision(honored, reason). Fail-closed on
        every undecidable path; the caller performs the side effect only
        when honored is True."""
        if not isinstance(envelope, dict):
            envelope = None  # absent or not an object: verify_envelope refuses

        record = self._record()
        if record is None:
            return Decision(False, REF_TARGET_ANCHOR_MISMATCH)

        # Resolve the issuer-key trust view. A source is called on every
        # check; a result without a trust view fails closed with the reader's
        # reason and never falls back to the static pin.
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
            call,
            self.target_id,
            record_source=record,
            pinned_public_keys=pinned_public_keys,
            now=now,
            key_record_view=key_record_view,
            clock_skew=self.clock_skew,
        )
        if not result["accepted"]:
            return Decision(False, result["reason"])

        # Single use. decision_id is signed, so it cannot be altered once the
        # signature verified. A receipt without one is refused, never "no id,
        # so skip the check".
        decision_id = envelope.get("decision_id")
        if not isinstance(decision_id, str) or not decision_id:
            return Decision(False, REF_TARGET_NO_DECISION_ID)
        # Keep the claim for the whole window the verifier honors: it accepts
        # until not_after + clock_skew, so expiring the claim at the bare
        # not_after would let the id be claimed again inside the skew.
        exp = _parse_not_after(envelope)
        if exp is not None:
            exp = exp + self.clock_skew
        if not self.replay_cache.check_and_claim(decision_id, exp, now=now):
            return Decision(False, REF_VERIFY_REPLAY)

        return Decision(True, result["reason"])
