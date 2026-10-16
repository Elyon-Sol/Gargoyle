"""Target-side receipt verification.

verify_envelope(envelope, interaction, target_url) decides whether a target
should act on a call carrying a receipt. It returns
{"accepted": bool, "reason": str} and checks, in order:

  1. Structure: the receipt has the fields the later checks read, including
     a boolean requires_approval and, when it is true, an
     approval_request_id.
  2. Signature: a known, unrevoked, in-window issuer key signed the receipt,
     and the receipt's not_after has not passed. Checked before anything
     else, so a forgery is refused on provenance before any further work.
     Trusted keys (a pinned map or a key-record view) are required; a
     verifier without them cannot authenticate the issuer and raises rather
     than accept hashes anyone can compute.
  3. Currency and integrity, via envelope.reassert(): decision_sha256
     verifies and the receipt's policy pin matches the live pin.
  4. Binding: the receipt's request_context and target_url match the call
     being executed exactly: same principal, same tool, same arguments
     (by args_sha256), same target. A genuine, current receipt for call X
     presented with call Y passes reassert() and is refused here.

The verifier is pure: it performs no action and keeps no state. Refusing a
second use of the same receipt (REF_VERIFY_REPLAY) is the executing party's
job, de-duplicating on the signed decision_id (see replay_cache), and so is
demanding a grant for a receipt whose requires_approval is true (see
consumer): this module only guarantees the flag is signed and well-formed.

A caller that never presents a receipt is only stopped if the target refuses
unattested calls; this module makes attested calls checkable, it does not by
itself force calls through the issuer.

The live call is {"tool", "args", "principal"} and nothing else. `principal`
is the identity the TARGET authenticated for the party presenting the call
(its mTLS peer, a bearer token's subject, an id a trusted front proxy
asserted); it is never read from the request body, or a caller could claim
any principal a stolen receipt names. The receipt's principal must equal it
(REF_VERIFY_PRINCIPAL_MISMATCH otherwise), and an unauthenticated caller
(no principal, or not a string) never matches. tool and target_url are exact
strings; args are compared by args_sha256 over canonical_json, so key order
never matters.
"""

from typing import Any, Dict, Optional
from datetime import datetime, timedelta, timezone

from gargoyle.envelope import (
    ENVELOPE_VERSION,
    INVALIDATED,
    REASSERTED,
    RE_EVALUATE_REQUIRED,
    args_sha256,
    canonical_json,
    reassert,
    valid_principal,
)
from gargoyle.policy import Policy


# ---------------------------------------------------------------------------
# Refusal codes. This module is the home of every REF_VERIFY_* code, including
# the ones other modules emit.
# ---------------------------------------------------------------------------

REF_VERIFY_ENVELOPE_ABSENT = "REF_VERIFY_ENVELOPE_ABSENT"
# A receipt in a format version this verifier does not implement.
REF_VERIFY_VERSION_UNSUPPORTED = "REF_VERIFY_VERSION_UNSUPPORTED"
REF_VERIFY_REASSERT_INVALIDATED = "REF_VERIFY_REASSERT_INVALIDATED"
REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED = "REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED"
REF_VERIFY_BINDING_MISMATCH = "REF_VERIFY_BINDING_MISMATCH"
# The receipt names a different principal than the one the target
# authenticated, or the target authenticated none.
REF_VERIFY_PRINCIPAL_MISMATCH = "REF_VERIFY_PRINCIPAL_MISMATCH"
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

# Accept reasons (not refusal codes).
ACCEPT_REASSERTED_AND_BOUND = "REASSERTED_AND_BOUND"
ACCEPT_PROVENANCE = "PROVENANCE_VERIFIED"  # verify_provenance only


# Top-level receipt keys the later checks read. Missing any of them makes
# the object unusable as a receipt -> REF_VERIFY_ENVELOPE_ABSENT.
_REQUIRED_ENVELOPE_KEYS = (
    "policy",
    "request_context",
    "decision_sha256",
    "target_url",
    "requires_approval",
)

# request_context fields the binding check compares.
_REQUEST_CONTEXT_KEYS = (
    "tool",
    "args_sha256",
    "principal",
)

# The live call's keys: exactly these, plus optionally on_behalf_of.
_CALL_KEYS = ("tool", "args", "principal")
_OPTIONAL_CALL_KEYS = ("on_behalf_of",)


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


def verify_provenance(
    envelope: Any,
    *,
    pinned_public_keys: Dict[str, Any] = None,
    key_record_view: Dict[str, Any] = None,
    now: datetime = None,
    clock_skew: timedelta = timedelta(0),
) -> Dict[str, Any]:
    """Steps 1 and 2 of verify_envelope on their own: the receipt is
    structurally usable, a trusted issuer key signed it, and it had not
    expired at `now`. No live call is needed, so an auditor can run this
    offline on a stored receipt (with `now` set to when it was presented).
    Returns {"accepted": bool, "reason": str}; the accept reason is
    ACCEPT_PROVENANCE. Currency and binding are verify_envelope's steps 3
    and 4 and are not checked here."""
    if clock_skew < timedelta(0):
        raise ValueError("clock_skew must be non-negative")
    if pinned_public_keys is None and key_record_view is None:
        raise ValueError("verify_provenance needs trusted issuer keys: pinned_public_keys or key_record_view")
    # ----- Structure -----
    if not isinstance(envelope, dict):
        return _reject(REF_VERIFY_ENVELOPE_ABSENT)
    for key in _REQUIRED_ENVELOPE_KEYS:
        if key not in envelope:
            return _reject(REF_VERIFY_ENVELOPE_ABSENT)
    if envelope.get("envelope_version") != ENVELOPE_VERSION:
        return _reject(REF_VERIFY_VERSION_UNSUPPORTED)
    rc = envelope["request_context"]
    if not isinstance(rc, dict):
        return _reject(REF_VERIFY_ENVELOPE_ABSENT)
    for key in _REQUEST_CONTEXT_KEYS:
        if key not in rc:
            return _reject(REF_VERIFY_ENVELOPE_ABSENT)
    if "on_behalf_of" in rc and not valid_principal(rc["on_behalf_of"]):
        return _reject(REF_VERIFY_ENVELOPE_ABSENT)
    # A flagged receipt names the hold a grant must release; a receipt that
    # says so without naming it is unusable.
    if not isinstance(envelope["requires_approval"], bool):
        return _reject(REF_VERIFY_ENVELOPE_ABSENT)
    if envelope["requires_approval"]:
        arid = envelope.get("approval_request_id")
        if not isinstance(arid, str) or not arid:
            return _reject(REF_VERIFY_ENVELOPE_ABSENT)

    # ----- Signature -----
    # A missing, malformed or unverifiable signature, or an unknown key, is
    # a refusal. Duck-typed: the public key object supplies
    # .verify(signature, message) (e.g. Ed25519PublicKey).
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

    return _accept(ACCEPT_PROVENANCE)


def verify_envelope(
    envelope: Any,
    call: Dict[str, Any],
    target_url: str,
    record_source: Dict[str, Any] = None,
    pinned_public_keys: Dict[str, Any] = None,
    now: datetime = None,
    key_record_view: Dict[str, Any] = None,
    clock_skew: timedelta = timedelta(0),
    policy: Optional[Policy] = None,
) -> Dict[str, Any]:
    """Decide whether to act on `call` at `target_url` given `envelope`.

    Args:
        envelope: The receipt presented with the call. May be None or
            malformed (an unattested or fabricated call).
        call: The call about to be executed: {"tool": str, "args": <JSON>,
            "principal": str, "on_behalf_of"?: str}. `principal` is the
            identity this target authenticated for the presenting party
            (see the module docstring); `on_behalf_of`, when the target
            knows it, the party that identity acts for; the other two are
            what the target is about to run.
        target_url: The target the call is addressed to.
        record_source: A fetched published record whose policy pin the
            receipt is checked against (a remote target). Takes precedence
            over `policy`.
        policy: The live Policy object, for a target that holds the policy
            itself (same process as the issuer). One of record_source /
            policy is required; neither is a ValueError, since a verifier
            with no live pin cannot check currency and must not pretend to.
        pinned_public_keys: {key_id: public_key}. A valid issuer signature
            from one of these keys is required. An empty map trusts no key
            and refuses every receipt.
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

    pinned_public_keys or key_record_view is required. Without either the
    verifier could only check a hash anyone can compute, so it raises
    ValueError (a configuration error) instead of returning a verdict.
    """
    # A negative skew would narrow the honored window, and no live pin would
    # leave currency unchecked: configuration errors, so fail loudly instead
    # of refusing (or honoring) every call.
    if clock_skew < timedelta(0):
        raise ValueError("clock_skew must be non-negative")
    if record_source is None and policy is None:
        raise ValueError("verify_envelope needs a record_source or a policy")
    if pinned_public_keys is None and key_record_view is None:
        raise ValueError("verify_envelope needs trusted issuer keys: pinned_public_keys or key_record_view")

    provenance = verify_provenance(
        envelope, pinned_public_keys=pinned_public_keys, key_record_view=key_record_view,
        now=now, clock_skew=clock_skew,
    )
    if not provenance["accepted"]:
        return provenance
    rc = envelope["request_context"]

    # ----- Currency and integrity -----
    # Any structural surprise reassert() trips over (e.g. a policy block that
    # is not a dict) fails closed.
    try:
        outcome = reassert(envelope, record_source=record_source, policy=policy)["outcome"]
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
    if not isinstance(call, dict):
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # Binding is exact: any field in the live call beyond the bound set is a
    # refusal, or a receipt holder could smuggle unbound data past the check.
    extra = set(call.keys()) - set(_CALL_KEYS) - set(_OPTIONAL_CALL_KEYS)
    if extra or not set(_CALL_KEYS) <= set(call.keys()):
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # principal: the receipt's must equal the one the target authenticated.
    # An unauthenticated caller never matches, whatever the receipt says.
    if not valid_principal(call["principal"]) or not valid_principal(rc["principal"]):
        return _reject(REF_VERIFY_PRINCIPAL_MISMATCH)
    if rc["principal"] != call["principal"]:
        return _reject(REF_VERIFY_PRINCIPAL_MISMATCH)
    # on_behalf_of: the issuer's assertion of whom the caller acts for. A
    # target that knows the delegation itself supplies it and it must match;
    # a target that does not know omits it. A live claim of delegation the
    # receipt does not record is a mismatch.
    if "on_behalf_of" in call:
        if not valid_principal(call["on_behalf_of"]) or rc.get("on_behalf_of") != call["on_behalf_of"]:
            return _reject(REF_VERIFY_PRINCIPAL_MISMATCH)

    # target_url: exact string equality, no URL normalization.
    if envelope["target_url"] != target_url:
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # tool: exact string equality.
    if not isinstance(rc["tool"], str) or rc["tool"] != call["tool"]:
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # args: the hash of the live arguments must equal the one the receipt
    # carries. Unserializable arguments cannot be bound and are refused.
    try:
        live_args_hash = args_sha256(call["args"])
    except (TypeError, ValueError):
        return _reject(REF_VERIFY_BINDING_MISMATCH)
    if rc["args_sha256"] != live_args_hash:
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    return _accept()
