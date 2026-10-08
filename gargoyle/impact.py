"""High-impact classification for ManifestPolicy.

ManifestPolicy.decide() calls requires_approval() on an ELIGIBLE call to set
Decision.requires_approval. A manifest names its high-impact tokens in
HIGH_IMPACT; a call that declares any of them is held for a human-signed
grant before its receipt may be used. Both functions fail closed: when in
doubt, require a human.
"""

from gargoyle.policy import safe_set


def safe_high_impact(manifest):
    """The manifest's HIGH_IMPACT tokens as a set, or None if malformed.

    A missing key is malformed, not empty: a typo'd or absent HIGH_IMPACT
    must never silently disable oversight. An explicit empty list is the
    operator saying "nothing is high-impact" and yields the empty set.

    Every HIGH_IMPACT token must be in AR u R. Eligibility only forces a
    caller to declare AR and R tokens, so a high-impact token outside them
    could simply be omitted to escape classification; such a manifest is
    rejected (None).
    """
    if not isinstance(manifest, dict):
        return None
    hi = manifest.get("HIGH_IMPACT")
    if hi is None:
        return None  # missing is not empty
    hi_set = safe_set(hi)
    if hi_set is None:
        return None  # malformed (non-list or non-string elements)
    AR = safe_set(manifest.get("AR"))
    R = safe_set(manifest.get("R"))
    if AR is None or R is None:
        return None
    if not hi_set <= (AR | R):
        return None  # token a caller is not forced to declare
    return hi_set


def requires_approval(ctx, manifest):
    """True iff the call must be held for a human approval grant.

    High-impact means the call's declared tokens (AP u OP) intersect
    HIGH_IMPACT. Because HIGH_IMPACT is confined to AR u R and an ELIGIBLE
    call must cover AR and R, an eligible caller always declares every
    high-impact token it needs and cannot self-declare low impact by
    omission. Impact is a property of the manifest, never a caller flag.

    Fail closed: a missing or malformed HIGH_IMPACT, an unusable call, or
    any internal error returns True. Never `.get(..., [])`, which would
    fail open.
    """
    try:
        hi = safe_high_impact(manifest)
        if hi is None:
            return True  # missing or malformed HIGH_IMPACT
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
