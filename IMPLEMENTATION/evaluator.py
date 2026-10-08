import hashlib
import json

MANIFEST_PATH = "MANIFEST/manifest.json"


def load_manifest():
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def manifest_sha256(path=MANIFEST_PATH):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def safe_set(value):
    if not isinstance(value, list):
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return set(value)


def safe_manifest(manifest):
    if not isinstance(manifest, dict):
        return None

    AR = manifest.get("AR")
    R = manifest.get("R")
    version = manifest.get("version")

    if not isinstance(AR, list) or not all(isinstance(x, str) for x in AR):
        return None
    if not isinstance(R, list) or not all(isinstance(x, str) for x in R):
        return None
    if not isinstance(version, str):
        return None

    # Typed-impact extension (additive, backward-compatible). A manifest MAY
    # declare `interaction_types`: a map of type-name -> {AR, R, high_impact}.
    # When absent (the flat/default manifest), nothing below runs and behavior
    # is byte-identical. When present it is validated fail-closed: any
    # malformation returns None (evaluate -> REFUSE).
    #
    # Invariants enforced here (all fail-closed):
    #   (a) each type's AR/R are string lists whose union is a SUBSET of the
    #       top-level AR u R (the token vocabulary). Top-level AR/R therefore
    #       stays the union, so impact.safe_high_impact's [FIX H2] check
    #       (HIGH_IMPACT subset of AR u R) is unchanged and needs no edit.
    #   (b) each type carries an explicit boolean `high_impact`.
    #   (c) consistency: a type's high_impact flag matches whether its own
    #       tokens intersect the manifest's HIGH_IMPACT set. A mislabeled type
    #       (benign flag but a high-impact token, or vice-versa) is a manifest
    #       error -> None. Skipped only when HIGH_IMPACT is absent/malformed,
    #       which impact.safe_high_impact already fails closed on ([FIX H1]).
    types = manifest.get("interaction_types")
    if types is not None:
        if not isinstance(types, dict):
            return None
        vocab = set(AR) | set(R)
        hi_raw = manifest.get("HIGH_IMPACT")
        hi_set = safe_set(hi_raw) if isinstance(hi_raw, list) else None
        for name, spec in types.items():
            if not isinstance(name, str) or not isinstance(spec, dict):
                return None
            tAR = safe_set(spec.get("AR"))
            tR = safe_set(spec.get("R"))
            if tAR is None or tR is None:
                return None
            ttok = tAR | tR
            if not ttok <= vocab:
                return None  # (a) type token outside the manifest vocabulary
            flag = spec.get("high_impact")
            if not isinstance(flag, bool):
                return None  # (b) explicit boolean required
            if hi_set is not None:
                intersects = bool(ttok & hi_set)
                if intersects != flag:
                    return None  # (c) mislabeled type -> fail closed

    return manifest


def resolve_required_sets(manifest, ctx):
    """Return (AR, R) the caller must cover for eligibility, selected by the
    caller's declared `interaction_type`.

    Flat/default manifest (no `interaction_types`) OR a caller that declares no
    type -> the top-level AR/R (byte-identical to the pre-typed behavior). A
    declared type is resolved from the manifest's `interaction_types` map;
    an UNKNOWN or malformed type is fail-closed -> (None, None) -> REFUSE.
    Assumes `manifest` already passed safe_manifest (types well-formed)."""
    types = manifest.get("interaction_types")
    if not isinstance(types, dict):
        return manifest.get("AR"), manifest.get("R")
    itype = ctx.get("interaction_type") if isinstance(ctx, dict) else None
    if itype is None:
        # No declared type: default to the top-level (union) sets. This is the
        # conservative choice - the caller must then cover the full vocabulary,
        # which under a typed manifest makes it high-impact (fail toward oversight).
        return manifest.get("AR"), manifest.get("R")
    spec = types.get(itype)
    if not isinstance(spec, dict):
        return None, None  # unknown/malformed declared type -> fail closed
    return spec.get("AR"), spec.get("R")


def ac3_valid(ctx, AR):
    AP_set = safe_set(ctx.get("AP"))
    AR_set = safe_set(AR)

    if AP_set is None or AR_set is None:
        return False

    return AP_set >= AR_set


def t26_valid(ctx, R):
    OP_set = safe_set(ctx.get("OP"))
    R_set = safe_set(R)

    if OP_set is None or R_set is None:
        return False

    return OP_set >= R_set


def manifest_integrity_valid(ctx, manifest):
    """
    Point-in-time manifest integrity check.

    Verifies that the caller's pinned manifest version and SHA256 match the
    manifest currently loaded by the evaluator. Both expected_manifest_version
    and expected_manifest_sha256 are caller-asserted pinning tags - they
    express which manifest the caller expects to be evaluated against, not a
    property derived from any ground truth (canon, signed registry, etc.).
    The check is internal consistency between the caller's pins and the
    evaluator's loaded manifest; it is load-bearing because it gives the
    caller a mechanism to refuse evaluation against an unexpected manifest.

    This is NOT canonical CCS (whitepaper section 12). Canonical CCS is a
    temporal invariant over state transitions S_t -> S_{t+1}; this function
    is point-in-time. The name "CCS" is reserved for the canonical
    implementation (see docs/restructure/05_admissibility_envelope_spec.md;
    gap G0 in docs/restructure/04_current_vs_claimed.md; ledger VL-012).
    """
    # G11 fix (VL-053): the passed manifest is the source of truth for
    # the version and the AR/R sets ac3_valid/t26_valid read, but
    # manifest_sha256() below hashes the on-disk MANIFEST/manifest.json.
    # Before trusting that split-source check, require the passed manifest
    # to BE the on-disk source; a divergent manifest fails closed (canon
    # section 9) rather than yielding an integrity verdict whose version
    # came from the argument and whose sha came from a different file.
    # Closes the manifest-source asymmetry (G11, surfaced VL-012) WITHOUT
    # changing what manifest_sha256() hashes: the on-disk file remains the
    # single pinned source of truth (expected_manifest_sha256,
    # published_hashes.json, decision_sha256, reassert() Row 4).
    if manifest != load_manifest():
        return False

    expected_version = ctx.get("expected_manifest_version")
    actual_version = manifest.get("version")

    if not isinstance(expected_version, str) or not isinstance(actual_version, str):
        return False

    if expected_version != actual_version:
        return False

    expected_manifest_sha256 = ctx.get("expected_manifest_sha256")
    actual_manifest_sha256 = manifest_sha256()

    if (
        not isinstance(expected_manifest_sha256, str)
        or expected_manifest_sha256 != actual_manifest_sha256
    ):
        return False

    return True


# Refusal reason codes: a closed set naming WHICH condition caused a REFUSE.
# The G_ namespace (from G(I), canon section 13) is DISJOINT from the boundary/
# transport REF_* vocabulary emitted by pep.py / verifier.py / authz_sidecar.py
# (those layers never call evaluate()). These annotate an already-determined
# decision - they add no invariant and no gate (canon section 13/14). The first
# three name conjuncts of G(I); the last three name fail-closed preconditions and
# the catch-all, not invariants.
G_MANIFEST_MALFORMED = "G_MANIFEST_MALFORMED"              # safe_manifest -> None
G_REQUIRED_SETS_UNRESOLVED = "G_REQUIRED_SETS_UNRESOLVED"  # AR/R not derivable from M
G_AC3 = "G_AC3"                                            # AC^3 conjunct (section 11.7)
G_T26 = "G_T26"                                            # T^26 conjunct (section 11.8)
G_MANIFEST_INTEGRITY = "G_MANIFEST_INTEGRITY"             # realized continuity check (section 6/12)
G_INTERNAL = "G_INTERNAL"                                  # fail-closed catch-all (section 9)


def decide(ctx, manifest):
    """Single source of truth for the admissibility decision.

    Returns (state, reason): state is "ELIGIBLE" or "REFUSE"; reason is the G_
    code naming the FIRST failing condition on REFUSE, or None on ELIGIBLE.
    Short-circuit order preserved (canon section 6). evaluate() and
    refusal_reason() are thin projections of this function - one evaluation,
    two views - so a bare-state caller and a reason-aware caller never disagree.
    """
    try:
        manifest = safe_manifest(manifest)
        if manifest is None:
            return "REFUSE", G_MANIFEST_MALFORMED

        AR, R = resolve_required_sets(manifest, ctx)
        if AR is None or R is None:
            return "REFUSE", G_REQUIRED_SETS_UNRESOLVED

        if not ac3_valid(ctx, AR):
            return "REFUSE", G_AC3

        if not t26_valid(ctx, R):
            return "REFUSE", G_T26

        if not manifest_integrity_valid(ctx, manifest):
            return "REFUSE", G_MANIFEST_INTEGRITY

        return "ELIGIBLE", None

    except Exception:
        return "REFUSE", G_INTERNAL


def evaluate(ctx, manifest):
    """The admissibility decision as a bare terminal state ("ELIGIBLE" /
    "REFUSE"). Byte-behavior-IDENTICAL to every prior revision - a back-compat
    projection of decide()[0] so existing callers and tests are unaffected."""
    return decide(ctx, manifest)[0]


def refusal_reason(ctx, manifest):
    """The G_ refusal reason code for this interaction, or None if ELIGIBLE.
    Additive diagnostic surface: closes the evaluator-layer refusal-vocabulary
    gap pep.py documented (it withheld any code because none was specified).
    Does not change any admissibility decision."""
    return decide(ctx, manifest)[1]


if __name__ == "__main__":
    manifest = load_manifest()

    with open("TESTS/test_cases.json", "r", encoding="utf-8") as f:
        tests = json.load(f)

    for t in tests:
        result = evaluate(t, manifest)
        print(f"{t['name']}: {result} (expected: {t['expected']})")
