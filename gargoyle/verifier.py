"""Target-side receipt verification.

verify_envelope(envelope, interaction, target_url) decides whether a target
should act on a call carrying a receipt. It returns
{"accepted": bool, "reason": str} and checks, in order:

  1. Structure: the receipt has the fields the later checks read.
  2. Signature (when the target supplies trusted keys or a key-record view):
     a known, unrevoked, in-window issuer key signed the receipt, and the
     receipt's not_after has not passed. Checked before anything else, so a
     forgery is refused on provenance before any further work.
  3. Currency and integrity, via envelope.reassert(): decision_sha256
     verifies and the receipt's policy pin matches the live pin.
  4. Binding: the receipt's request_context and target_url match the call
     being executed exactly. A genuine, current receipt for call X presented
     with call Y passes reassert() and is refused here.

The verifier is pure: it performs no action and keeps no state. Refusing a
second use of the same receipt (REF_VERIFY_REPLAY) is the executing party's
job, de-duplicating on the signed decision_id (see replay_cache).

A caller that never presents a receipt is only stopped if the target refuses
unattested calls; this module makes attested calls checkable, it does not by
itself force calls through the issuer.

Comparison rules: AP and OP are sets, so both sides are de-duplicated and
sorted before comparing, and an unsorted or duplicated list never causes a
false refusal. context is compared by canonical_json equality, the same
serialization the receipt hash uses. target_url and the manifest-pin fields
are compared as exact strings.
"""

from typing import Any, Dict
from datetime import datetime, timedelta, timezone

from gargoyle.envelope import (
    INVALIDATED,
    REASSERTED,
    RE_EVALUATE_REQUIRED,
    canonical_json,
    reassert,
)


# ---------------------------------------------------------------------------
# Refusal codes. This module is the home of every REF_VERIFY_* code, including
# the ones other modules emit.
# ---------------------------------------------------------------------------

REF_VERIFY_ENVELOPE_ABSENT = "REF_VERIFY_ENVELOPE_ABSENT"
REF_VERIFY_REASSERT_INVALIDATED = "REF_VERIFY_REASSERT_INVALIDATED"
REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED = "REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED"
REF_VERIFY_BINDING_MISMATCH = "REF_VERIFY_BINDING_MISMATCH"
REF_VERIFY_SIGNATURE_INVALID = "REF_VERIFY_SIGNATURE_INVALID"
REF_VERIFY_SIGNATURE_UNKNOWN_KEY = "REF_VERIFY_SIGNATURE_UNKNOWN_KEY"
REF_VERIFY_SIGNATURE_EXPIRED = "REF_VERIFY_SIGNATURE_EXPIRED"
# Emitted by an executor that de-duplicates decision_id, never by
# verify_envelope (replay defense needs state; the verifier has none).
REF_VERIFY_REPLAY = "REF_VERIFY_REPLAY"

# Key records. RECORD_INVALID / RECORD_STALE are emitted by key_record_source;
# UNKNOWN / REVOKED / OUT_OF_WINDOW by the key lookup in verify_envelope.
REF_VERIFY_KEY_RECORD_INVALID = "REF_VERIFY_KEY_RECORD_INVALID"
REF_VERIFY_KEY_RECORD_STALE = "REF_VERIFY_KEY_RECORD_STALE"
REF_VERIFY_KEY_UNKNOWN = "REF_VERIFY_KEY_UNKNOWN"
REF_VERIFY_KEY_REVOKED = "REF_VERIFY_KEY_REVOKED"
REF_VERIFY_KEY_OUT_OF_WINDOW = "REF_VERIFY_KEY_OUT_OF_WINDOW"
# Role separation: a key whose signed record names any role other than
# "issuer" (an approver key, for example) never signs a receipt. A key with no
# role recorded is treated as an issuer key.
REF_VERIFY_KEY_ROLE_NOT_ISSUER = "REF_VERIFY_KEY_ROLE_NOT_ISSUER"

# Root records, which vouch for key records. ROOT_RECORD_INVALID /
# ROOT_RECORD_STALE are emitted by the root reader; ROOT_RETIRED /
# ROOT_REVOKED / ROOT_OUT_OF_WINDOW by key_record_source's cross-record check.
REF_VERIFY_ROOT_RECORD_INVALID = "REF_VERIFY_ROOT_RECORD_INVALID"
REF_VERIFY_ROOT_RECORD_STALE = "REF_VERIFY_ROOT_RECORD_STALE"
REF_VERIFY_ROOT_RETIRED = "REF_VERIFY_ROOT_RETIRED"
REF_VERIFY_ROOT_REVOKED = "REF_VERIFY_ROOT_REVOKED"
# The signing root's [not_before, not_after) window, widened by clock skew,
# does not cover `now` or the key record's issued_at.
REF_VERIFY_ROOT_OUT_OF_WINDOW = "REF_VERIFY_ROOT_OUT_OF_WINDOW"

# Signed published records (the policy pin a remote target checks against).
# Emitted by published_record_source, which enforces record freshness
# (now < not_after) and a monotonic serial.
REF_VERIFY_PUBLISHED_RECORD_INVALID = "REF_VERIFY_PUBLISHED_RECORD_INVALID"
REF_VERIFY_PUBLISHED_RECORD_STALE = "REF_VERIFY_PUBLISHED_RECORD_STALE"

# Accept reason (not a refusal code).
ACCEPT_REASSERTED_AND_BOUND = "REASSERTED_AND_BOUND"


# Top-level receipt keys the later checks read. Missing any of them makes
# the object unusable as a receipt -> REF_VERIFY_ENVELOPE_ABSENT.
_REQUIRED_ENVELOPE_KEYS = (
    "policy",
    "request_context",
    "decision_sha256",
    "target_url",
)

# request_context fields the binding check compares.
_REQUEST_CONTEXT_KEYS = (
    "AP",
    "OP",
    "context",
    "expected_manifest_version",
    "expected_manifest_sha256",
)

# interaction_type is optional (untyped manifests omit it), but when either
# side carries it, both must agree: it selected the required sets, so it is
# part of what was decided.
_OPTIONAL_REQUEST_CONTEXT_KEYS = ("interaction_type",)


def _normalize_set_field(value: Any) -> list:
    """De-duplicate and sort, so AP / OP compare as sets."""
    return sorted(set(value))


def _reject(reason: str) -> Dict[str, Any]:
    return {"accepted": False, "reason": reason}


def _accept(reason: str = ACCEPT_REASSERTED_AND_BOUND) -> Dict[str, Any]:
    return {"accepted": True, "reason": reason}


def not_after_valid(not_after_raw, now=None, clock_skew=timedelta(0)):
    """The one validity-window check for a signed not_after, shared by receipt
    expiry here and approval-grant expiry in approval.py.

    Returns True iff the instant is acceptable:
      - None (absent): True. No expiry was stamped; a caller may require
        presence itself (approval.py does, for grants).
      - a malformed or timezone-naive ISO-8601 string: False (fail closed).
      - a timezone-aware instant: True iff now < not_after + clock_skew.

    `now` defaults to datetime.now(timezone.utc) and is injectable for tests.
    """
    if not_after_raw is None:
        return True
    try:
        na = datetime.fromisoformat(not_after_raw)
    except (ValueError, TypeError):
        return False
    if na.tzinfo is None:
        return False
    current = now if now is not None else datetime.now(timezone.utc)
    return current < na + clock_skew


def verify_envelope(
    envelope: Any,
    interaction: Dict[str, Any],
    target_url: str,
    record_source: Dict[str, Any] = None,
    pinned_public_keys: Dict[str, Any] = None,
    now: datetime = None,
    key_record_view: Dict[str, Any] = None,
    clock_skew: timedelta = timedelta(0),
) -> Dict[str, Any]:
    """Decide whether to act on `interaction` at `target_url` given `envelope`.

    Args:
        envelope: The receipt presented with the call. May be None or
            malformed (an unattested or fabricated call).
        interaction: The call about to be executed, in the shape the issuer
            signed (AP, OP, context, expected_manifest_version,
            expected_manifest_sha256, optional interaction_type). AP / OP
            need not be sorted.
        target_url: The target the call is addressed to.
        record_source: A fetched published record whose policy pin replaces
            the local one in reassert(). None uses the local policy.
        pinned_public_keys: {key_id: public_key}. When given, a valid issuer
            signature from one of these keys is required.
        key_record_view: A validated key-record view from
            key_record_source.load_key_record_from_bytes, shape
            {key_id: {"public_key", "revoked", "not_before", "not_after",
            "role"?}}. When given it is the ONLY source of trusted issuer keys
            and pinned_public_keys is ignored: the key must be present,
            unrevoked, an issuer key, and inside its validity window.
        clock_skew: Non-negative tolerance for clock divergence between
            hosts. Widens both time checks symmetrically: the key window
            becomes not_before - skew <= now < not_after + skew, and receipt
            expiry becomes now < not_after + skew. A negative value raises
            ValueError.

    Returns:
        {"accepted": bool, "reason": str}; reason is
        ACCEPT_REASSERTED_AND_BOUND on accept, a REF_VERIFY_* code otherwise.

    With neither pinned_public_keys nor key_record_view, the signature step
    is skipped: such a target trusts any receipt whose hash verifies, which
    anyone can compute. Only use that path when transport alone
    authenticates the issuer.
    """
    # A negative skew would narrow the honored window: a configuration error,
    # so fail loudly instead of refusing every call.
    if clock_skew < timedelta(0):
        raise ValueError("clock_skew must be non-negative")

    # ----- Structure -----
    if not isinstance(envelope, dict):
        return _reject(REF_VERIFY_ENVELOPE_ABSENT)
    for key in _REQUIRED_ENVELOPE_KEYS:
        if key not in envelope:
            return _reject(REF_VERIFY_ENVELOPE_ABSENT)
    rc = envelope["request_context"]
    if not isinstance(rc, dict):
        return _reject(REF_VERIFY_ENVELOPE_ABSENT)
    for key in _REQUEST_CONTEXT_KEYS:
        if key not in rc:
            return _reject(REF_VERIFY_ENVELOPE_ABSENT)

    # ----- Signature -----
    # Required whenever the target configured trusted keys. A missing,
    # malformed or unverifiable signature, or an unknown key, is a refusal,
    # never a fall-back to the unsigned path. Duck-typed: the public key
    # object supplies .verify(signature, message) (e.g. Ed25519PublicKey).
    if pinned_public_keys is not None or key_record_view is not None:
        key_id = envelope.get("issuer_key_id")
        signature_hex = envelope.get("issuer_signature")
        if not isinstance(key_id, str) or not isinstance(signature_hex, str):
            return _reject(REF_VERIFY_SIGNATURE_INVALID)
        # The key record vouches for the key (present, unrevoked, issuer
        # role, in window); the receipt must still be signed by that key.
        if key_record_view is not None:
            entry = key_record_view.get(key_id)
            if entry is None:
                return _reject(REF_VERIFY_KEY_UNKNOWN)
            if entry.get("revoked"):
                return _reject(REF_VERIFY_KEY_REVOKED)
            if entry.get("role") not in (None, "issuer"):
                return _reject(REF_VERIFY_KEY_ROLE_NOT_ISSUER)
            current = now if now is not None else datetime.now(timezone.utc)
            key_not_before = entry.get("not_before")
            key_not_after = entry.get("not_after")
            if (key_not_before is None or key_not_after is None
                    or not (key_not_before - clock_skew <= current
                            < key_not_after + clock_skew)):
                return _reject(REF_VERIFY_KEY_OUT_OF_WINDOW)
            public_key = entry.get("public_key")
            if public_key is None:
                return _reject(REF_VERIFY_KEY_UNKNOWN)
        else:
            public_key = pinned_public_keys.get(key_id)
            if public_key is None:
                return _reject(REF_VERIFY_SIGNATURE_UNKNOWN_KEY)
        signed_region = {
            k: v
            for k, v in envelope.items()
            if k not in ("issuer_signature", "timestamp_utc")
        }
        message = canonical_json(signed_region).encode("utf-8")
        try:
            public_key.verify(bytes.fromhex(signature_hex), message)
        except Exception:
            return _reject(REF_VERIFY_SIGNATURE_INVALID)

        # ----- Receipt expiry -----
        # not_after is inside the signed region, so it cannot be extended
        # without breaking the signature. Expiry bounds how long a leaked
        # signing key stays useful without anyone having to detect the leak.
        if not not_after_valid(envelope.get("not_after"), now=now, clock_skew=clock_skew):
            return _reject(REF_VERIFY_SIGNATURE_EXPIRED)

    # ----- Currency and integrity -----
    # Any structural surprise reassert() trips over (e.g. a policy block that
    # is not a dict) fails closed.
    try:
        outcome = reassert(envelope, record_source=record_source)["outcome"]
    except Exception:
        return _reject(REF_VERIFY_ENVELOPE_ABSENT)

    if outcome == INVALIDATED:
        return _reject(REF_VERIFY_REASSERT_INVALIDATED)
    if outcome == RE_EVALUATE_REQUIRED:
        return _reject(REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED)
    if outcome != REASSERTED:
        # The outcome set is closed; anything unrecognized fails closed.
        return _reject(REF_VERIFY_REASSERT_INVALIDATED)

    # ----- Binding -----
    if not isinstance(interaction, dict):
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # Binding is exact: any field in the live call beyond the bound set is a
    # refusal, or a receipt holder could smuggle unbound data past the check.
    if set(interaction.keys()) - set(_REQUEST_CONTEXT_KEYS) - set(_OPTIONAL_REQUEST_CONTEXT_KEYS):
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # target_url: exact string equality, no URL normalization.
    if envelope["target_url"] != target_url:
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # AP / OP: set equality on both sides. A missing or non-list value on
    # either side is a binding failure.
    try:
        env_ap = _normalize_set_field(rc["AP"])
        env_op = _normalize_set_field(rc["OP"])
        live_ap = _normalize_set_field(interaction["AP"])
        live_op = _normalize_set_field(interaction["OP"])
    except (KeyError, TypeError):
        return _reject(REF_VERIFY_BINDING_MISMATCH)
    if env_ap != live_ap:
        return _reject(REF_VERIFY_BINDING_MISMATCH)
    if env_op != live_op:
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # Manifest-pin fields: exact string equality.
    if rc["expected_manifest_version"] != interaction.get("expected_manifest_version"):
        return _reject(REF_VERIFY_BINDING_MISMATCH)
    if rc["expected_manifest_sha256"] != interaction.get("expected_manifest_sha256"):
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # context: canonical_json equality. A missing live context is a mismatch.
    if "context" not in interaction:
        return _reject(REF_VERIFY_BINDING_MISMATCH)
    if canonical_json(rc["context"]) != canonical_json(interaction["context"]):
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # interaction_type: both absent, or both present and equal. A one-sided
    # declaration is a mismatch.
    if rc.get("interaction_type") != interaction.get("interaction_type"):
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    return _accept()
