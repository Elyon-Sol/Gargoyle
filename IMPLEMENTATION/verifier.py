"""
Target-side admissibility-envelope verifier for Elyon-Sol.

Built at VL-037 per docs/restructure/08_enforcement_design.md section 8
step 1 (the delivery-agnostic, target-side verifier). This is the first
G4 (non-bypassable enforcement) build increment. It wires nothing into
pep.py; delivery (attaching an envelope to a call so a target actually
receives it) is VL-038's domain (artifact 08 section 8 step 2). Verifier
first, delivery later, mirrors the CCS sequencing (VL-025 built
envelope.py with no caller; VL-029 wired pep.py to it).

==============================================================
What this module does
==============================================================

verify_envelope(envelope, interaction, target_url) decides whether a
target should honor an admissibility envelope for the interaction it is
about to act on. It returns {"accepted": bool, "reason": str} and does
two things, in order:

  1. Currency + integrity, via envelope.reassert(). The envelope's
     pinned state hashes (canon, evaluator, manifest) must still match
     live state, and decision_sha256 must verify. Any reassert() outcome
     other than REASSERTED rejects. This closes forgery / tamper
     (adversary A2) and detects state transitions (canon section 12.1 /
     12.4); reassert() Row 2 returns INVALIDATED on a decision_sha256
     mismatch (a fabricated or mutated envelope).
  2. Interaction binding. The envelope's request_context (AP, OP,
     context, expected_manifest_version, expected_manifest_sha256) and
     its target_url must match the live interaction and target_url. A
     genuine, current envelope for interaction X presented against a
     different interaction Y reassert()s REASSERTED (no state
     transition) but is rejected here. This closes same-state replay
     (adversary A3), which reassert() alone does NOT close because
     reassert() compares repository-state hashes and never compares
     request_context against a live interaction (artifact 08 sections
     4.2 and 7).

Canon basis: section 13 ("Eligibility does not persist across state
transitions without revalidation") is the revalidation that reassert()
performs; the binding check operationalizes section 13's coverage of
the exact interaction and the section 11.1 interaction identity
I = (A, S, C, t). No new canonical invariant is introduced: this is an
application of existing constructs (artifact 08 section 5).

==============================================================
What this module does NOT do (canon section 14)
==============================================================

The verifier is non-executing: it computes an accept / reject decision
and performs no action and no I/O beyond reassert()'s file reads. It
does not replace an identity system; it is identity-agnostic. It is
target-side code a target runs by its own policy; it is not the gate.

==============================================================
Deployment precondition: G5 (durable published hash source)
==============================================================

reassert() reads its comparison hashes from LOCAL disk
(CANON/canon.lock, IMPLEMENTATION/evaluator.py, the live manifest).
That is valid for this in-repo, co-located build and its tests. A real
target on a different host needs an authentic, current, PUBLISHED
source for those hashes; that durable source is gap G5 (artifact 08
section 6, Decision E1). G5 is NAMED here as the deployment
precondition and is NOT built in this module.

The A1 adversary (a caller that never routes through the gate) is
closeable only by a target-side policy that refuses un-attested calls,
not by this verifier (artifact 08 section 4.4). Every mechanism here is
therefore necessary-but-not-sufficient for full non-bypassability: it
makes routed calls verifiable and forge / replay resistant, while A1
remains a separate, target-policy sub-problem.

==============================================================
Normalization parity
==============================================================

Canon section 11.5 / 11.6 define AP and OP as sets, so the binding
check compares them as sets. The verifier normalizes BOTH sides with
the same rule the PEP applied (request_validator._normalize_set_field:
sorted(set(...))) before comparing: the live interaction's AP / OP and
the envelope's recorded AP / OP. In production build_envelope records
the already-PEP-normalized lists, so the envelope side is already
sorted/deduped; normalizing it again is a no-op there but keeps the
comparison correct for a target-side verifier handling envelopes it did
not construct, and a caller passing an unsorted or duplicated AP / OP
does not cause a false reject. context is compared by canonical_json
equality (reusing envelope.canonical_json) for consistency with the
envelope's hashing discipline; target_url and the manifest-pinning
fields are compared by string equality.

The context-equality choice is an [INFERENCE] (artifact 08 gap
candidate 1: artifact 08 does not pin equality semantics for the
free-form canon section 11.1 C). canonical_json equality is the chosen
default; for two dict values it is behaviorally equivalent to Python
value equality, and it stays consistent with the decision_sha256
canonicalization. A later spec edit may pin this explicitly.
"""

from typing import Any, Dict
from datetime import datetime, timedelta, timezone

from IMPLEMENTATION.envelope import (
    INVALIDATED,
    REASSERTED,
    RE_EVALUATE_REQUIRED,
    canonical_json,
    reassert,
)


# ---------------------------------------------------------------------------
# Reject reason vocabulary (REF_VERIFY_* layer; parallels
# request_validator.py's REF_SCHEMA_* convention). Closed set: one code
# per reassert() non-REASSERTED outcome, one presence code, one binding
# code. The reassert() outcome set is itself closed (REASSERTED,
# INVALIDATED, RE-EVALUATE-REQUIRED) per envelope.py.
# ---------------------------------------------------------------------------

REF_VERIFY_ENVELOPE_ABSENT = "REF_VERIFY_ENVELOPE_ABSENT"
REF_VERIFY_REASSERT_INVALIDATED = "REF_VERIFY_REASSERT_INVALIDATED"
REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED = "REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED"
REF_VERIFY_BINDING_MISMATCH = "REF_VERIFY_BINDING_MISMATCH"
REF_VERIFY_SIGNATURE_INVALID = "REF_VERIFY_SIGNATURE_INVALID"
REF_VERIFY_SIGNATURE_UNKNOWN_KEY = "REF_VERIFY_SIGNATURE_UNKNOWN_KEY"
REF_VERIFY_SIGNATURE_EXPIRED = "REF_VERIFY_SIGNATURE_EXPIRED"
# Executor-layer replay defense (VL-066): emitted by an enforcing target that
# de-dups decision_id over the freshness window. verify_envelope stays pure and
# does NOT emit this; anti-replay is the acting party's stateful concern.
REF_VERIFY_REPLAY = "REF_VERIFY_REPLAY"

# B-prime-2 key-record codes (VL-042). verifier.py is the canonical REF_VERIFY_*
# home (mirroring request_validator.py owning REF_SCHEMA_* even for codes other
# modules emit). RECORD_INVALID / RECORD_STALE are EMITTED by
# key_record_source.py (the reader) and imported there from here;
# UNKNOWN / REVOKED / OUT_OF_WINDOW are emitted by verify_envelope's trust-view
# lookup below.
REF_VERIFY_KEY_RECORD_INVALID = "REF_VERIFY_KEY_RECORD_INVALID"
REF_VERIFY_KEY_RECORD_STALE = "REF_VERIFY_KEY_RECORD_STALE"
REF_VERIFY_KEY_UNKNOWN = "REF_VERIFY_KEY_UNKNOWN"
REF_VERIFY_KEY_REVOKED = "REF_VERIFY_KEY_REVOKED"
REF_VERIFY_KEY_OUT_OF_WINDOW = "REF_VERIFY_KEY_OUT_OF_WINDOW"
# Role separation, the reverse of approver_trust's: a key whose SIGNED record
# role is anything but "issuer" (e.g. an R1 approver key) never signs an
# envelope. Role-less keys (pre-VL-119 records, the gate key) remain issuers.
REF_VERIFY_KEY_ROLE_NOT_ISSUER = "REF_VERIFY_KEY_ROLE_NOT_ISSUER"

# B-prime-3 root-record codes (VL-044). Same canonical home. ROOT_RECORD_INVALID /
# ROOT_RECORD_STALE are EMITTED by root_record_source.py (the root reader) and
# imported there from here; ROOT_RETIRED / ROOT_REVOKED are emitted by
# key_record_source.py's cross-record status gate. verify_envelope's logic is
# unchanged by VL-044 (constants only); the root status check lives at the reader
# layer (11_root_record_spec.md sections 1, 8).
REF_VERIFY_ROOT_RECORD_INVALID = "REF_VERIFY_ROOT_RECORD_INVALID"
REF_VERIFY_ROOT_RECORD_STALE = "REF_VERIFY_ROOT_RECORD_STALE"
REF_VERIFY_ROOT_RETIRED = "REF_VERIFY_ROOT_RETIRED"
REF_VERIFY_ROOT_REVOKED = "REF_VERIFY_ROOT_REVOKED"
# Per-root validity window (2026-10-07, VL-154 open item): the analog of
# KEY_OUT_OF_WINDOW one layer up, emitted by key_record_source.py's cross-record
# gate when the signing root's [not_before, not_after) window (skew-widened)
# does not cover `now` or the key record's issued_at.
REF_VERIFY_ROOT_OUT_OF_WINDOW = "REF_VERIFY_ROOT_OUT_OF_WINDOW"

# B-prime-1 signed published-record codes (VL-074, B1; A3b sub-case b). Same
# canonical home. PUBLISHED_RECORD_INVALID / PUBLISHED_RECORD_STALE are EMITTED
# by published_record_source.py (the signed published-hashes reader) and imported
# there from here. Build-then-wire: the byte-anchor reader published_source.py
# (B-prime-1 original) and the default reassert() / verify_envelope() path are
# byte-unchanged; record-freshness enforcement (now < not_after + monotonic
# serial) lives in the new signed reader, mirroring key_record_source.py.
REF_VERIFY_PUBLISHED_RECORD_INVALID = "REF_VERIFY_PUBLISHED_RECORD_INVALID"
REF_VERIFY_PUBLISHED_RECORD_STALE = "REF_VERIFY_PUBLISHED_RECORD_STALE"

# Accept reason (not a refusal code).
ACCEPT_REASSERTED_AND_BOUND = "REASSERTED_AND_BOUND"


# Top-level envelope keys the verifier requires before it can run
# reassert() and the binding check. Absence of any of these means the
# object is unusable as a decision artifact -> REF_VERIFY_ENVELOPE_ABSENT.
_REQUIRED_ENVELOPE_KEYS = (
    "canon",
    "evaluator",
    "evaluated_against",
    "request_context",
    "decision_sha256",
    "target_url",
)

# request_context sub-keys the binding check compares (the five fields
# build_envelope records from the normalized interaction).
_REQUEST_CONTEXT_KEYS = (
    "AP",
    "OP",
    "context",
    "expected_manifest_version",
    "expected_manifest_sha256",
)

# SES-7: interaction_type is an OPTIONAL bound field (typed-impact). Not
# required-present (flat manifests omit it), but when present it is bound - the
# envelope and the live interaction must agree, and it is allowed past the
# exact-binding check without opening the door to other unbound fields.
_OPTIONAL_REQUEST_CONTEXT_KEYS = ("interaction_type",)


def _normalize_set_field(value: Any) -> list:
    """
    Mirror request_validator._normalize_set_field: deduplicate (set
    semantics, canon section 11.5 / 11.6) and sort, so the binding check
    compares AP / OP under the same normalization the PEP applied before
    build_envelope recorded them.
    """
    return sorted(set(value))


def _reject(reason: str) -> Dict[str, Any]:
    return {"accepted": False, "reason": reason}


def _accept(reason: str = ACCEPT_REASSERTED_AND_BOUND) -> Dict[str, Any]:
    return {"accepted": True, "reason": reason}


def not_after_valid(not_after_raw, now=None, clock_skew=timedelta(0)):
    """
    Shared validity-window check for a signed `not_after` instant (VL-041
    semantics, factored out at VL-114 so the decision-freshness check in
    verify_envelope and the approval-grant freshness check in approval.py
    ([FIX H7]) use ONE implementation, not two).

    Returns True iff the instant is acceptable:
      - `None` (absent) -> True: no expiry was stamped (the issuer's choice;
        a caller may additionally require presence by policy - approval.py
        does, for grants).
      - a malformed or tz-NAIVE ISO-8601 string -> False (fail closed,
        canon section 9).
      - a tz-aware instant -> True iff now < not_after + clock_skew (strict;
        clock_skew default 0 reproduces the pre-VL-114 strict comparison).

    `now` is injectable for deterministic tests; it defaults to
    datetime.now(timezone.utc).
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
    """
    Decide whether a target should honor an admissibility envelope for
    the live interaction it is about to act on.

    Args:
        envelope: The admissibility envelope as produced by
            envelope.build_envelope() and delivered to the target. May
            be None or malformed if the caller declined to attest
            (adversary A1) or fabricated a non-envelope.
        interaction: The live interaction the target is about to act on,
            in the normalized shape request_validator.validate_request()
            returns (AP, OP, context, expected_manifest_version,
            expected_manifest_sha256). AP / OP need not be pre-sorted;
            the verifier normalizes them before comparison.
        target_url: The live target_url the interaction is addressed to.
        record_source: Optional fetched published record (VL-039
            cross-host); None uses local-disk currency (unchanged default).
        pinned_public_keys: Optional {key_id: public_key} map (VL-040).
            When supplied, the issuer signature is REQUIRED and verified
            fail-closed (REF_VERIFY_SIGNATURE_INVALID /
            REF_VERIFY_SIGNATURE_UNKNOWN_KEY) before reassert(). None
            (default) is the unsigned path, byte-behavior-unchanged.
        key_record_view: Optional validated B-prime-2 trust view (VL-042)
            from key_record_source.load_key_record_from_bytes, shape
            {key_id: {"public_key", "revoked", "not_before", "not_after"}}.
            When supplied it is the SOLE issuer-key trust source (record-
            exclusive, decision 3); pinned_public_keys is ignored. The issuer
            key_id must be present, not revoked, and in-window
            (REF_VERIFY_KEY_UNKNOWN / _REVOKED / _OUT_OF_WINDOW) before the
            signature is verified against the record-sourced key. Appended last
            to preserve positional-call compatibility.
        clock_skew: Optional non-negative tolerance (timedelta, default
            timedelta(0)) for cross-host clock divergence (VL-075, B2; spec
            15_clock_skew_tolerance_spec.md). Widens BOTH time windows this
            verifier enforces, symmetrically: the issuer-key validity window
            (step 1.5) becomes not_before - clock_skew <= now < not_after +
            clock_skew, and the decision not_after (step 1.5b) becomes
            now < not_after + clock_skew. Default 0 is byte-behavior-identical
            to the strict pre-VL-075 checks. A negative value would narrow the
            window (a config error) and raises ValueError. Appended last to
            preserve positional-call compatibility.

    Returns:
        {"accepted": bool, "reason": str}. On accept, reason is
        ACCEPT_REASSERTED_AND_BOUND. On reject, reason is one of the
        four REF_VERIFY_* codes.

    Steps (artifact 08 section 8 step 1):
        1. Structural presence guard. A non-dict, or a dict missing a
           required key, is unusable -> REF_VERIFY_ENVELOPE_ABSENT. This
           also guards reassert()'s key accesses so a malformed envelope
           rejects cleanly rather than raising.
        2. reassert() currency / integrity. INVALIDATED ->
           REF_VERIFY_REASSERT_INVALIDATED; RE-EVALUATE-REQUIRED ->
           REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED.
        3. Interaction binding. Any request_context or target_url
           mismatch -> REF_VERIFY_BINDING_MISMATCH.
        4. Accept.
    """
    # ----- Step 0: clock-skew config guard (VL-075) -----
    # A negative skew would narrow the honored window (stricter than the issuer
    # intended) - a configuration error, not an adversary path. Fail loud at the
    # boundary (parity with sign_envelope's naive-not_after refusal). Default
    # timedelta(0) leaves every time check byte-behavior-identical.
    if clock_skew < timedelta(0):
        raise ValueError("clock_skew must be non-negative")

    # ----- Step 1: structural presence guard -----
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

    # ----- Step 1.5: issuer signature (VL-040..042; signed or record path) -----
    # Runs when the target supplies pinned_public_keys OR a key_record_view
    # (the signature-required / record path; VL-042 added the record path).
    # With both None the unsigned path is byte-behavior-unchanged.
    # Fail-closed (canon section 9): a
    # missing / malformed / unverifiable signature, or an unknown key_id, is
    # a REFUSE, never a downgrade to the unsigned path. Checked BEFORE
    # reassert() so a forgery is rejected on provenance before any currency
    # work. Duck-typed: verifier.py does not import cryptography; the pinned
    # public key object supplies .verify(signature, message) (e.g. an
    # Ed25519PublicKey). Closes the VL-039 follow-up 2 forgery finding on the
    # signed path: an unkeyed decision_sha256 recompute is no longer
    # sufficient; the envelope must carry a signature from a pinned issuer.
    if pinned_public_keys is not None or key_record_view is not None:
        key_id = envelope.get("issuer_key_id")
        signature_hex = envelope.get("issuer_signature")
        if not isinstance(key_id, str) or not isinstance(signature_hex, str):
            return _reject(REF_VERIFY_SIGNATURE_INVALID)
        # VL-042: key_record_view is RECORD-EXCLUSIVE when present (decision 3);
        # the static map is not consulted. The record vouches for the KEY's
        # provenance (present / not revoked / in-window); the envelope must
        # STILL be signed by it (the signature check below).
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
            # VL-075: widen the validity window symmetrically by clock_skew
            # (default 0 -> the strict pre-VL-075 window).
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

        # ----- Step 1.5b: issuer-key validity window (VL-041; signed-path) -----
        # not_after, when present, is inside the signed region (verified just
        # above), so it is tamper-proof: an adversary cannot extend a captured
        # envelope's lifetime without breaking the signature. Absence means no
        # expiry (VL-040 byte-behavior; bounding validity is the issuer's
        # choice, a target may additionally require presence by policy - a
        # later knob). Fail-closed (canon section 9): a malformed or naive
        # not_after, or a current time at/after not_after, is a REFUSE. The
        # comparison is strict (valid iff now < not_after). `now` is injectable
        # for deterministic tests; it defaults to datetime.now(timezone.utc).
        # This is the time-bounded answer to the VL-040 follow-up 2 decisive
        # failure (compromised key): it bounds a leaked key's usefulness
        # without depending on detecting the leak.
        # VL-114: the decision-freshness check is now the shared not_after_valid()
        # primitive (below), so the approval-grant freshness check
        # (IMPLEMENTATION/approval.py, [FIX H7]) REUSES the exact same logic
        # rather than re-implementing it. Behavior is byte-identical to the
        # prior inline VL-041/VL-075 block: absent not_after = no expiry; a
        # malformed or tz-naive value, or now >= not_after + clock_skew, is a
        # REFUSE (REF_VERIFY_SIGNATURE_EXPIRED).
        if not not_after_valid(envelope.get("not_after"), now=now, clock_skew=clock_skew):
            return _reject(REF_VERIFY_SIGNATURE_EXPIRED)

    # ----- Step 2: currency + integrity via reassert() -----
    # Fail closed on any structural surprise reassert() trips over that
    # the guard above did not catch (e.g. canon present but not a dict).
    try:
        outcome = reassert(envelope, record_source=record_source)["outcome"]
    except Exception:
        return _reject(REF_VERIFY_ENVELOPE_ABSENT)

    if outcome == INVALIDATED:
        return _reject(REF_VERIFY_REASSERT_INVALIDATED)
    if outcome == RE_EVALUATE_REQUIRED:
        return _reject(REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED)
    if outcome != REASSERTED:
        # Defensive: reassert()'s outcome set is closed. An unrecognized
        # outcome fails closed rather than falling through to accept.
        return _reject(REF_VERIFY_REASSERT_INVALIDATED)

    # ----- Step 3: interaction binding -----
    if not isinstance(interaction, dict):
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # F1 fix: binding is EXACT - reject any live-interaction field beyond the
    # bound set (else a valid-token holder smuggles unbound body data past the check).
    if set(interaction.keys()) - set(_REQUEST_CONTEXT_KEYS) - set(_OPTIONAL_REQUEST_CONTEXT_KEYS):
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # target_url: plain string equality (the schema does no target_url
    # normalization; request_validator only checks absolute-URL syntax).
    if envelope["target_url"] != target_url:
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # AP / OP: symmetric normalized-set comparison. Canon section
    # 11.5 / 11.6 define AP and OP as sets, so the binding comparison is
    # set equality, not list-order equality. In production
    # build_envelope records the already-PEP-normalized lists (sorted +
    # deduped via request_validator._normalize_set_field), but
    # normalizing BOTH the envelope side and the live side keeps the
    # comparison correct regardless of an envelope's internal ordering -
    # which matters for a target-side verifier handling envelopes it did
    # not itself construct. A missing or non-list AP / OP on either side
    # is a binding failure, not an envelope-structure failure.
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

    # Manifest-pinning fields: string equality.
    if rc["expected_manifest_version"] != interaction.get("expected_manifest_version"):
        return _reject(REF_VERIFY_BINDING_MISMATCH)
    if rc["expected_manifest_sha256"] != interaction.get("expected_manifest_sha256"):
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # context: canonical_json equality [INFERENCE] (artifact 08 gap
    # candidate 1). A missing live context is a binding failure.
    if "context" not in interaction:
        return _reject(REF_VERIFY_BINDING_MISMATCH)
    if canonical_json(rc["context"]) != canonical_json(interaction["context"]):
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # SES-7: interaction_type binding. Both absent (flat) is fine; both present must
    # be equal; a one-sided declaration is a mismatch. Binds the load-bearing
    # eligibility input the gate used into what the target independently verifies.
    if rc.get("interaction_type") != interaction.get("interaction_type"):
        return _reject(REF_VERIFY_BINDING_MISMATCH)

    # ----- Step 4: accept -----
    return _accept()
