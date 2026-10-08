"""
Admissibility envelope construction and reassertion for Elyon-Sol.

Implements docs/restructure/05_admissibility_envelope_spec.md build-order
step 3. This file is the build half of G0 - the canonical CCS
(whitepaper section 12) implementation. The rename half of G0 closed at
VL-012 by renaming `ccs_valid()` to `manifest_integrity_valid()` and
reserving the name "CCS" for this implementation; this file claims that
reservation.

==============================================================
What this module does
==============================================================

Two functions:

- build_envelope(...) constructs a canonical envelope dict matching
  artifact 05's "Envelope structure" section. The envelope records the
  inputs and outputs of a single admissibility decision in a form that
  can be hashed (decision_sha256), persisted, and later re-checked
  against the live repository state.

- reassert(envelope) implements artifact 05's "Reassertion protocol"
  table. Given an envelope, it returns one of three string outcomes
  (REASSERTED, INVALIDATED, RE-EVALUATE-REQUIRED) per the table's five
  rows checked in table order. The function is pure with respect to
  the envelope (reads live file hashes; does not modify the input).

==============================================================
Integration boundary (one-sided per VL-025 opener risk-reduction note)
==============================================================

This module imports from evaluator.py only via manifest_sha256() (the
on-disk MANIFEST/manifest.json hash). It does NOT import the
evaluate() function or the condition functions (ac3_valid, t26_valid,
manifest_integrity_valid). The caller (VL-029's pep.py wiring) is
responsible for calling those condition functions and passing the
resulting booleans into build_envelope() as parameters. This keeps
the integration boundary one-sided and matches receipt.py's pattern
(caller passes decision and condition results in).

This module IS imported by pep.py: VL-029 wired build_envelope() onto
every ELIGIBLE decision, and VL-047 made sign_envelope() the gate's
default forward. It is NOT imported by evaluator.py - the one-sided
boundary above holds (envelope.py reads from evaluator.py, never the
reverse).

==============================================================
Canonicalization discipline
==============================================================

Canonical JSON serialization uses sort_keys=True, separators=(",",":"),
ensure_ascii=True. The ensure_ascii=True choice matches the VL-009
ASCII-safe standard repo-wide. This function is the ONE canonicalization
for the whole repository: replay/receipt.py's former local copy (which
used ensure_ascii=False; latent inconsistency surfaced at VL-012's
process findings, recorded at VL-025, dispositioned OPEN as SES-5 at
VL-141) now REUSES this function (SES-5 / VL-143), so envelope, grant,
published-record, and receipt canonicalization agree byte-for-byte.

decision_sha256 is computed over the envelope dict minus two fields:

  - decision_sha256 itself (cannot self-hash)
  - timestamp_utc (excluded per artifact 05's timestamp_utc field
    rationale: "excluded from decision_sha256 so the same decision is
    bit-identical regardless of issue time; preserves section 9
    reproducibility")

==============================================================
ccs field on first issuance (artifact 05 open question 1, locked by
VL-025 opener constraint (e))
==============================================================

On first issuance there is no S_t to compare against; only S_{t+1}.
Per artifact 05's first listed proposal and the VL-025 opener's lock
(constraint (e)), condition_results.ccs is recorded as None (Python's
representation of JSON null) on first issuance. The ccs field becomes
a true boolean only at reassertion: per post-VL-026 Edit 5's
forward-looking rule, reassert() in this module performs the
derivation as part of its return value (True on REASSERTED;
False on INVALIDATED or RE-EVALUATE-REQUIRED per canon section
12.4 "if any condition is violated: CCS = 0"). The envelope's
stored condition_results.ccs remains None per the post-VL-026
Edit 2 purity contract; the derivation is in reassert()'s return,
not in the input envelope.
The reassert-time ccs semantic was recorded as a gap candidate in
the VL-025 ledger entry; the spec edit landed at VL-026 (Open
question 1 resolution, Edit 5) and the implementation lands at
VL-029 per Decision A (this commit).

==============================================================
Spec citations
==============================================================

Every field in the returned envelope cites a specific passage of
artifact 05 or of CANON/canon.md. The citation map is recorded in
the VL-025 ledger entry under "Spec-citation map." The reassertion-
table mapping is recorded under "Reassertion-protocol mapping."
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from IMPLEMENTATION.evaluator import manifest_sha256


# ---------------------------------------------------------------------------
# File-path constants (module-scope per VL-025 opener risk-reduction note
# on disk-read pattern; matches manifest_integrity_valid's discipline)
# ---------------------------------------------------------------------------

CANON_LOCK_PATH = "CANON/canon.lock"
EVALUATOR_PATH = "IMPLEMENTATION/evaluator.py"


# ---------------------------------------------------------------------------
# Reassertion outcome constants (artifact 05 reassertion-protocol table;
# closed set per VL-025 opener constraint (g) set-exhaustiveness)
# ---------------------------------------------------------------------------

REASSERTED = "REASSERTED"
INVALIDATED = "INVALIDATED"
RE_EVALUATE_REQUIRED = "RE-EVALUATE-REQUIRED"

# Keys excluded from the decision_sha256 hash region (artifact 05; VL-040
# adds the issuer fields so a signed envelope's decision_sha256 is identical
# to the unsigned one and reassert() Row 2 verifies it unchanged). VL-041
# adds not_after for the same reason: not_after is issue-time-dependent (like
# timestamp_utc), so excluding it keeps decision_sha256 bit-identical
# regardless of issue time / validity window (canon section 9 reproducibility).
_HASH_EXCLUDED_KEYS = (
    "decision_sha256",
    "timestamp_utc",
    "issuer_key_id",
    "issuer_signature",
    "not_after",
    "decision_id",
)

# Keys excluded from the issuer-signature region (VL-040). The signature
# covers everything else, including decision_sha256 and issuer_key_id. VL-041:
# not_after is NOT excluded here - the signature MUST cover the validity window
# or an adversary could extend a captured signed envelope's lifetime. This is
# the deliberate asymmetry with timestamp_utc (excluded from BOTH regions
# because it carries no security weight; not_after is security-bearing).
_SIGNATURE_EXCLUDED_KEYS = ("issuer_signature", "timestamp_utc")


# ---------------------------------------------------------------------------
# Envelope version (artifact 05 structure block; literal "1.0")
# ---------------------------------------------------------------------------

ENVELOPE_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Canonical-JSON helper
# ---------------------------------------------------------------------------


def canonical_json(data: Any) -> str:
    """
    Canonical JSON serialization for envelope hashing.

    Per artifact 05's decision_sha256 field rationale: "canonical JSON
    (sorted keys, no whitespace)." The ensure_ascii=True choice matches
    the VL-009 ASCII-safe standard. This is the repo-wide canonicalization:
    replay/receipt.py reuses this function (SES-5 / VL-143). See module
    docstring "Canonicalization discipline".
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _sha256_text(value: str) -> str:
    """SHA-256 hex digest of a UTF-8 encoded string."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: str) -> str:
    """SHA-256 hex digest of a file's bytes."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _read_canon_lock(path: str = CANON_LOCK_PATH) -> str:
    """
    Read CANON/canon.lock and return its trimmed contents.

    Per VL-006, canon.lock contains the SHA-256 of CANON/canon.md.
    The lockfile is the source of truth for canon_sha256 in the
    envelope; trusting the lockfile rather than recomputing canon.md's
    hash on every build matches the VL-006 + VL-012 pattern (the
    lockfile is the pinning artifact).
    """
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def _evaluator_sha256(path: str = EVALUATOR_PATH) -> str:
    """
    SHA-256 of IMPLEMENTATION/evaluator.py.

    Pins the envelope to the exact evaluator code that produced the
    decision. A changed evaluator hash signals a section-12.4-class
    transition (decision logic moved) and triggers RE-EVALUATE-REQUIRED
    in reassert(). See artifact 05's "evaluator block" field rationale.
    """
    return _sha256_file(path)


# ---------------------------------------------------------------------------
# build_envelope()
# ---------------------------------------------------------------------------


def build_envelope(
    *,
    decision: str,
    target_url: str,
    normalized_interaction: Dict[str, Any],
    manifest: Dict[str, Any],
    ac3: bool,
    t26: bool,
    manifest_integrity: bool,
    timestamp_utc: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Construct an admissibility envelope per artifact 05.

    Args:
        decision: Either "ELIGIBLE" or "REFUSE" - the output of
            evaluator.evaluate() for the request that produced this
            envelope.
        target_url: The URL the decision was about. Recorded for
            audit; non-bypassable enforcement is G4's domain (deferred).
            Sourced from the request's top-level target_url field per
            SPEC/request_schema.md.
        normalized_interaction: The output of
            request_validator.validate_request() on schema acceptance.
            Provides AP, OP, context, expected_manifest_version,
            expected_manifest_sha256.
        manifest: The manifest dict the decision was evaluated against
            (the same dict passed to evaluator.evaluate()). Provides
            manifest.version. The on-disk hash is computed via
            manifest_sha256(); the manifest argument provides only
            the version field.
        ac3: AC^3 condition result (whitepaper section 11.7;
            decision variable u per section 12.2). Caller-supplied
            per VL-025 Option A integration; evaluator.evaluate()
            returns only the aggregate decision, not the individual
            condition results.
        t26: T^26 condition result (whitepaper section 11.8;
            decision variable c per section 12.2).
        manifest_integrity: Point-in-time manifest integrity check
            result (evaluator.manifest_integrity_valid() return).
            Distinct from the canonical CCS d-consistency, which is
            a transition invariant; this field is the point-in-time
            check renamed at VL-012 from the pre-rename ccs_valid.
        timestamp_utc: ISO-8601 UTC timestamp. If None, generated
            internally as datetime.now(timezone.utc).isoformat().
            Tests can pin a specific timestamp for determinism.
            Excluded from decision_sha256 per artifact 05.

    Returns:
        The envelope dict matching artifact 05's "Envelope structure"
        JSON example. The dict's key order is not significant for
        correctness (decision_sha256 is computed over the canonical
        sorted-keys serialization).

    The function is pure with respect to its arguments (no caller-
    visible side effects). It does read files on disk (canon.lock,
    manifest.json, evaluator.py) to populate the hash-pinning fields;
    this is the documented disk-read pattern from artifact 05's
    rationale.
    """
    if timestamp_utc is None:
        timestamp_utc = datetime.now(timezone.utc).isoformat()

    envelope: Dict[str, Any] = {
        "envelope_version": ENVELOPE_VERSION,
        "decision": decision,
        "target_url": target_url,
        "canon": {
            "version": "0.9.8.4",
            "canon_sha256": _read_canon_lock(),
        },
        "evaluated_against": {
            "manifest_version": manifest["version"],
            "manifest_sha256": manifest_sha256(),
        },
        "request_context": {
            "AP": list(normalized_interaction["AP"]),
            "OP": list(normalized_interaction["OP"]),
            "context": normalized_interaction["context"],
            "expected_manifest_version": normalized_interaction[
                "expected_manifest_version"
            ],
            "expected_manifest_sha256": normalized_interaction[
                "expected_manifest_sha256"
            ],
        },
        "evaluator": {
            "version": "0.9.8.4",
            "evaluator_sha256": _evaluator_sha256(),
        },
        "condition_results": {
            "ac3": ac3,
            "t26": t26,
            "manifest_integrity": manifest_integrity,
            "ccs": None,
        },
        "timestamp_utc": timestamp_utc,
    }

    # SES-7 fix: bind interaction_type when the caller declared one (typed-impact).
    # It is a load-bearing eligibility input (evaluator.resolve_required_sets), so it
    # belongs in the signed, hashed receipt. Omitted when absent -> the flat/default
    # path stays byte-identical (decision_sha256 unchanged for untyped calls).
    _it = normalized_interaction.get("interaction_type")
    if _it is not None:
        envelope["request_context"]["interaction_type"] = _it

    # Compute decision_sha256 last, over the envelope minus
    # decision_sha256 itself and minus timestamp_utc (per artifact 05).
    hashable = {k: v for k, v in envelope.items() if k not in _HASH_EXCLUDED_KEYS}
    envelope["decision_sha256"] = _sha256_text(canonical_json(hashable))

    return envelope


# ---------------------------------------------------------------------------
# reassert()
# ---------------------------------------------------------------------------


def reassert(envelope: Dict[str, Any], record_source: Optional[Dict[str, Any]] = None) -> str:
    """
    Re-check an envelope against live repository state.

    Implements artifact 05's "Reassertion protocol" table. The table's
    five rows are checked in table order; the first matching row's
    outcome is returned. Order matters because some conditions overlap
    (e.g., a tampered envelope might also have hash mismatches; per
    the table's row 2 ordering, tamper takes precedence over hash
    mismatch).

    Per VL-025 opener constraint (a) and confirmed contract: this
    function is pure with respect to the input envelope. It reads
    live file hashes (side effect: file I/O) but does not modify the
    envelope. The condition_results.ccs reassertion semantic (canon
    section 12.3 d-consistency derivation) is performed here per
    post-VL-026 Edit 5's forward-looking rule and VL-029's Decision A:
    reassert() returns a dict {"outcome": <str>, "ccs": <bool>} where
    ccs is True on REASSERTED (canon section 12.3 holds per row 5),
    False on INVALIDATED or RE-EVALUATE-REQUIRED (per canon section
    12.4 "if any condition is violated: CCS = 0"). The derivation
    is in the return value, not in the input envelope (purity contract
    per post-VL-026 Edit 2).

    Reassertion-protocol mapping (artifact 05 table rows -> branches):

      Row 1: canon_sha256 mismatch         -> INVALIDATED
      Row 2: decision_sha256 verification  -> INVALIDATED
      Row 3: evaluator_sha256 mismatch     -> RE-EVALUATE-REQUIRED
      Row 4: manifest_sha256 mismatch      -> RE-EVALUATE-REQUIRED
      Row 5: all hashes match + verified   -> REASSERTED

    VL-024 Implication 2 attention point: Row 3 (evaluator_sha256
    mismatch -> RE-EVALUATE-REQUIRED, canon basis section 12.4) is
    the load-bearing case for the evaluator-versioning continuity
    layer surfaced at VL-023 follow-up. The fail-closed posture
    flagged as inferred-rather-than-explicit at VL-023 follow-up
    (lines 5200-5210) dissolves on direct read of artifact 05's
    table: this branch returns RE-EVALUATE-REQUIRED, not silent
    fallthrough to REASSERTED.

    Args:
        envelope: A dict in the shape returned by build_envelope().

    Returns:
        A dict of shape {"outcome": <str>, "ccs": <bool>} where
        `outcome` is one of REASSERTED, INVALIDATED, RE_EVALUATE_REQUIRED
        and `ccs` is True only when outcome is REASSERTED (canon
        section 12.3 holds; d_{t+1} = u_{t+1} AND c_{t+1}), False
        otherwise (canon section 12.4: "if any condition is violated:
        CCS = 0"). Per VL-028 Decision A; implementation lands at
        VL-029.
    """
    # ----- Row 1: canon_sha256 mismatch -> INVALIDATED -----
    # Canon basis: canon is locked (GR-1); a hash mismatch means the
    # envelope predates a canon change, so the envelope's rules of
    # the game no longer apply.
    live_canon_sha256 = (
        _read_canon_lock() if record_source is None
        else record_source["canon_sha256"]
    )
    if envelope["canon"]["canon_sha256"] != live_canon_sha256:
        return {"outcome": INVALIDATED, "ccs": False}

    # ----- Row 2: decision_sha256 verification -> INVALIDATED -----
    # Canon basis: tampered or corrupt envelope. Re-canonicalize the
    # envelope minus decision_sha256 and timestamp_utc (same exclusions
    # as build_envelope's hash input), hash, compare against the
    # envelope's stored decision_sha256.
    stored_decision_sha256 = envelope.get("decision_sha256")
    if not isinstance(stored_decision_sha256, str):
        return {"outcome": INVALIDATED, "ccs": False}
    hashable = {
        k: v
        for k, v in envelope.items()
        if k not in _HASH_EXCLUDED_KEYS
    }
    computed_decision_sha256 = _sha256_text(canonical_json(hashable))
    if stored_decision_sha256 != computed_decision_sha256:
        return {"outcome": INVALIDATED, "ccs": False}

    # ----- Row 3: evaluator_sha256 mismatch -> RE-EVALUATE-REQUIRED -----
    # Canon basis: whitepaper section 12.4 - "decision logic transition."
    # See VL-024 Implication 2 attention point above.
    live_evaluator_sha256 = (
        _evaluator_sha256() if record_source is None
        else record_source["evaluator_sha256"]
    )
    if envelope["evaluator"]["evaluator_sha256"] != live_evaluator_sha256:
        return {"outcome": RE_EVALUATE_REQUIRED, "ccs": False}

    # ----- Row 4: manifest_sha256 mismatch -> RE-EVALUATE-REQUIRED -----
    # Canon basis: whitepaper section 7 / section 12.4 - "manifest version/
    # schema transition." manifest_sha256() hashes the on-disk
    # MANIFEST/manifest.json, the single pinned source of truth. The
    # manifest-source asymmetry once tracked here as G11 (surfaced VL-012)
    # was closed at VL-053: manifest_integrity_valid() now fails closed on
    # a passed manifest that diverges from that on-disk source. The on-disk
    # file remains what manifest_sha256() hashes, so Row 4 reads it as-is.
    live_manifest_sha256 = (
        manifest_sha256() if record_source is None
        else record_source["manifest_sha256"]
    )
    if envelope["evaluated_against"]["manifest_sha256"] != live_manifest_sha256:
        return {"outcome": RE_EVALUATE_REQUIRED, "ccs": False}

    # ----- Row 5: all hashes match + decision_sha256 verified -> REASSERTED -----
    # Canon basis: whitepaper section 12.3 - continuity holds across the
    # transition; d_{t+1} = d_t provably for the d that is decision-equal-
    # to-the-envelope's decision. Per artifact 05: "the only state in
    # which a past ELIGIBLE may be honored without re-evaluation."
    return {"outcome": REASSERTED, "ccs": True}


# ---------------------------------------------------------------------------
# sign_envelope() - VL-040 issuer signing (opt-in)
# ---------------------------------------------------------------------------


def sign_envelope(
    envelope: Dict[str, Any],
    signing_key: Any,
    key_id: str,
    not_after: Optional[datetime] = None,
    decision_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Sign an envelope with the gate's issuer key (VL-040; opt-in).

    Returns a NEW envelope dict with issuer_key_id and issuer_signature
    added; the input envelope is not modified (purity, matching reassert()).

    signing_key is any object exposing .sign(message: bytes) -> bytes (e.g.
    a cryptography Ed25519PrivateKey). envelope.py does NOT import
    cryptography: the signed path is opt-in and the unsigned path (and the
    existing suite) never requires the dependency; the caller supplies the
    key object.

    The signature covers canonical_json(envelope minus issuer_signature and
    timestamp_utc) - which includes decision_sha256 and issuer_key_id,
    binding both. issuer_key_id is excluded from decision_sha256's region
    (_HASH_EXCLUDED_KEYS) so decision_sha256 is identical signed-vs-unsigned;
    the issuer fields' integrity is the signature's job (artifact 05 'Issuer
    signature (opt-in)'). Authenticates the ISSUER of the decision artifact
    (canon section 8.2 PoE; section 11.9 integrity); introduces no new
    invariant and is not a reassert()/CCS concern (verification is
    verifier-layer).

    not_after (VL-041; opt-in within opt-in): an optional tz-aware datetime.
    When supplied, the envelope gains a not_after ISO-8601 field that bounds
    the validity window. not_after is INSIDE the signed region (covered by
    issuer_signature, so it is tamper-proof: an adversary cannot extend a
    captured envelope's lifetime) and OUTSIDE decision_sha256's region (in
    _HASH_EXCLUDED_KEYS, so a signed-with-expiry envelope's decision_sha256
    is byte-identical to the unsigned one and reassert() Row 2 is unchanged).
    When None, no not_after field is added and behavior is byte-identical to
    VL-040 (a signed envelope with no expiry is valid until canon/evaluator/
    manifest transition; bounding it is the issuer's choice, enforced
    target-side by verify_envelope). Expiry is the time-bounded answer to the
    VL-040 follow-up 2 decisive failure: it bounds a compromised key's
    usefulness WITHOUT depending on detecting the compromise.
    """
    signed = dict(envelope)
    signed["issuer_key_id"] = key_id
    if not_after is not None:
        if not_after.tzinfo is None:
            raise ValueError("not_after must be timezone-aware (UTC)")
        signed["not_after"] = not_after.isoformat()
    # decision_id (VL-066): a unique per-issuance id, signed (tamper-proof) and
    # excluded from decision_sha256 (in _HASH_EXCLUDED_KEYS, like not_after) so the
    # wire decision hash is unchanged. It is the key an executor de-dups on to deny
    # replay within the freshness window (exactly-once); absence = no replay id.
    if decision_id is not None:
        signed["decision_id"] = decision_id
    region = {k: v for k, v in signed.items() if k not in _SIGNATURE_EXCLUDED_KEYS}
    signature = signing_key.sign(canonical_json(region).encode("utf-8"))
    signed["issuer_signature"] = signature.hex()
    return signed
