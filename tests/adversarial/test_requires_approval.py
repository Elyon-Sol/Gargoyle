"""Impact classification: which eligible calls must be held for a human.

requires_approval() and safe_high_impact() are pure, derived only from the
manifest, and fail closed: a missing or malformed HIGH_IMPACT requires
approval, and every HIGH_IMPACT token must be one the caller is forced to
declare. Tests marked "regression guard" fail if the check they name is
removed.
"""

from gargoyle.impact import safe_high_impact, requires_approval
from gargoyle.policy import coverage_covered, authority_covered


# A well-formed high-impact manifest: every HIGH_IMPACT token is a required
# token (a subset of AR u R).
HI_MANIFEST = {
    "version": "1.0",
    "AR": ["auth_admin"],
    "R": ["op_transfer", "op_read"],
    "HIGH_IMPACT": ["op_transfer"],
}

ELIGIBLE_CTX = {"AP": ["auth_admin"], "OP": ["op_transfer", "op_read"]}


# --------------------------------------------------------------------------
# A missing or malformed HIGH_IMPACT fails closed, never as an empty set
# --------------------------------------------------------------------------

def test_missing_high_impact_requires_approval_REVERT_CATCHER():
    """Regression guard: a manifest with no HIGH_IMPACT key requires approval.
    Reading it as `.get("HIGH_IMPACT", [])` would make this False and switch
    oversight off silently."""
    manifest = {"version": "1.0", "AR": ["auth_admin"], "R": ["op_transfer"]}
    assert safe_high_impact(manifest) is None
    assert requires_approval(ELIGIBLE_CTX, manifest) is True


def test_malformed_high_impact_not_a_list_requires_approval():
    manifest = dict(HI_MANIFEST, HIGH_IMPACT="op_transfer")  # str, not list
    assert safe_high_impact(manifest) is None
    assert requires_approval(ELIGIBLE_CTX, manifest) is True


def test_malformed_high_impact_non_string_elements_requires_approval():
    manifest = dict(HI_MANIFEST, HIGH_IMPACT=["op_transfer", 7])
    assert safe_high_impact(manifest) is None
    assert requires_approval(ELIGIBLE_CTX, manifest) is True


def test_explicit_empty_high_impact_is_low_impact():
    """An explicit empty list is the operator's deliberate opt-out: nothing is
    held. A missing key, by contrast, fails closed."""
    manifest = dict(HI_MANIFEST, HIGH_IMPACT=[])
    assert safe_high_impact(manifest) == set()
    assert requires_approval(ELIGIBLE_CTX, manifest) is False


# --------------------------------------------------------------------------
# HIGH_IMPACT tokens must be ones the caller is forced to declare (in AR u R)
# --------------------------------------------------------------------------

def test_high_impact_token_outside_required_is_manifest_error_REVERT_CATCHER():
    """Regression guard: a HIGH_IMPACT token outside AR u R is a manifest
    error and fails closed. Without the subset check a caller could omit that
    token and be classified low-impact while still eligible."""
    manifest = dict(HI_MANIFEST, HIGH_IMPACT=["op_transfer", "op_not_required"])
    assert safe_high_impact(manifest) is None
    assert requires_approval(ELIGIBLE_CTX, manifest) is True


def test_h2_eligible_and_low_impact_by_omission_is_impossible_REVERT_CATCHER():
    """Regression guard: a HIGH_IMPACT token outside AR u R is the escape
    route, because the caller need not declare it and could be eligible yet
    classified low-impact. The subset check makes it a manifest error, so
    approval is required and "eligible and not held" is unreachable."""
    manifest = {
        "version": "1.0",
        "AR": ["auth_admin"],
        "R": ["op_read"],
        "HIGH_IMPACT": ["op_secret_export"],  # NOT in AR u R -> the escape token
    }
    R = manifest["R"]
    ctx = {"AP": ["auth_admin"], "OP": ["op_read"]}  # eligible, omits the token

    assert coverage_covered(ctx, R) is True
    assert authority_covered(ctx, manifest["AR"]) is True
    # The out-of-range selector fails closed, so approval is required. Without
    # the subset check requires_approval would be False while eligible.
    assert requires_approval(ctx, manifest) is True
    assert not (coverage_covered(ctx, R) and not requires_approval(ctx, manifest))


# --------------------------------------------------------------------------
# Malformed calls fail closed; classification comes from the manifest, not the caller
# --------------------------------------------------------------------------

def test_malformed_ctx_with_high_impact_fails_closed():
    assert requires_approval(None, HI_MANIFEST) is True
    assert requires_approval({"AP": "not-a-list", "OP": 3}, HI_MANIFEST) is True
    assert requires_approval({}, HI_MANIFEST) is True


def test_caller_cannot_self_declare_low_impact():
    """Classification comes from the manifest, not the caller. A caller that
    declares the high-impact token is high-impact whatever else it sends."""
    ctx = {"AP": ["auth_admin"], "OP": ["op_transfer", "op_read"], "impact": "low"}
    assert requires_approval(ctx, HI_MANIFEST) is True


def test_caller_cannot_self_declare_high_impact_when_policy_empty():
    """And the inverse: with an explicit-empty policy, a caller cannot make an
    action high-impact by labeling it."""
    manifest = dict(HI_MANIFEST, HIGH_IMPACT=[])
    ctx = {"AP": ["auth_admin"], "OP": ["op_transfer"], "impact": "high"}
    assert requires_approval(ctx, manifest) is False


def test_authority_token_high_impact_matches_AP():
    """A high-impact token drawn from AR matches the caller's AP."""
    manifest = {
        "version": "1.0",
        "AR": ["auth_root"],
        "R": ["op_read"],
        "HIGH_IMPACT": ["auth_root"],
    }
    assert safe_high_impact(manifest) == {"auth_root"}
    ctx = {"AP": ["auth_root"], "OP": ["op_read"]}
    assert authority_covered(ctx, manifest["AR"]) is True
    assert requires_approval(ctx, manifest) is True
