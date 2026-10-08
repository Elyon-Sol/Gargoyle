"""
Governance layer - impact classification (Feature 1, increment 1a).

docs/design/governance_layer_design.md sections 1.2 + 1.3, with the
adversarial-review fixes [FIX H1] (fail-closed on missing/malformed
HIGH_IMPACT) and [FIX H2] (selector tokens constrained to caller-forced
required tokens) folded in.

WHY ITS OWN MODULE (not evaluator.py, as the base design suggested).
`envelope.reassert()` pins `evaluator_sha256` = sha256(IMPLEMENTATION/
evaluator.py); any edit to that file - even adding a pure function - changes
the hash and reads, to every target verifying against a pinned published
record, as an evaluator-version TRANSITION (canon 12.4 -> RE_EVALUATE_REQUIRED),
rejecting otherwise-valid envelopes. Impact classification is orchestration-
layer logic that lives ABOVE G(I) (the same layer as the PENDING_APPROVAL
state); putting it here keeps the hash-pinned core predicate byte-identical and
keeps the G(I) boundary clean. It reuses evaluator.safe_set (no re-implement).

Build-then-wire: NO caller on the default pep.py path in this increment.
"""

from IMPLEMENTATION.evaluator import safe_set


def safe_high_impact(manifest):
    """
    Validate and return the manifest's HIGH_IMPACT selector set, or None
    (the fail-closed sentinel) on any malformation.

    [FIX H1] A MISSING key is malformation, not an empty set: a typo'd or
    absent HIGH_IMPACT must never silently disable oversight. Returns None
    for: non-dict manifest, missing key, non-list, or non-string elements.

    [FIX H2] Every HIGH_IMPACT token must be a member of the manifest's
    required sets (AR union R). A selector token OUTSIDE AR u R is a
    manifest error -> None, because eligibility only forces the caller to
    declare AR/R tokens (AP >= AR, OP >= R); a high-impact token the caller
    is not forced to declare could be omitted to escape classification.

    On success returns a set of tokens. An EXPLICIT empty list yields the
    empty set (the operator's conscious "nothing is high-impact"
    declaration) - distinct from a missing key, which is None.
    """
    if not isinstance(manifest, dict):
        return None
    hi = manifest.get("HIGH_IMPACT")
    if hi is None:
        return None  # [FIX H1] missing != empty
    hi_set = safe_set(hi)
    if hi_set is None:
        return None  # malformed (non-list or non-string elements)
    AR = safe_set(manifest.get("AR"))
    R = safe_set(manifest.get("R"))
    if AR is None or R is None:
        return None
    if not hi_set <= (AR | R):
        return None  # [FIX H2] token outside the caller-forced required sets
    return hi_set


def requires_approval(ctx, manifest):
    """
    True iff this interaction is high-impact per the SHA-pinned manifest and
    therefore requires an out-of-band human approval grant before forward.

    Pure and manifest-derived (the HIGH_IMPACT set comes only from the
    pinned manifest, never from caller input), and FAIL-CLOSED: any doubt
    returns True (require a human). A missing/malformed HIGH_IMPACT
    (safe_high_impact -> None), a malformed ctx, or any internal error
    returns True. Never `.get(..., [])`, which would fail OPEN. [FIX H1]

    Matching: high-impact iff the caller's declared authority/operation
    tokens (AP union OP) intersect HIGH_IMPACT. Because [FIX H2] constrains
    HIGH_IMPACT to AR u R and coverage forces AP >= AR and OP >= R, an
    ELIGIBLE caller necessarily declares every high-impact token, so it
    cannot self-declare low-impact by omission. Impact is therefore a
    property of the interaction TYPE (the manifest), not a caller-set flag.

    Build-then-wire: NO caller on the default pep.py path in this increment;
    wiring into pep.governed_call (design 1.3 / 1c) is a later increment.
    """
    try:
        hi = safe_high_impact(manifest)
        if hi is None:
            return True  # [FIX H1] fail closed on missing/malformed policy
        ap = safe_set(ctx.get("AP")) if isinstance(ctx, dict) else None
        op = safe_set(ctx.get("OP")) if isinstance(ctx, dict) else None
        if ap is None and op is None and len(hi) > 0:
            return True  # ctx unusable but policy declares high-impact -> fail closed
        declared = set()
        if ap is not None:
            declared |= ap
        if op is not None:
            declared |= op
        return len(hi & declared) > 0
    except Exception:
        return True  # fail closed on any internal error
