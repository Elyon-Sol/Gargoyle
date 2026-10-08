"""
Governance layer, Feature 1, increment 1a: impact classification.

Canon/spec basis: docs/design/governance_layer_design.md sections 1.2 + 1.8,
with the eight-finding review folded in. These tests pin the [FIX H1] and
[FIX H2] corrections for the pure, manifest-derived, fail-closed
requires_approval()/safe_high_impact() functions. The starred tests are the
revert-catchers: each is proven to go RED when its fix is reverted before it
is trusted (per SESSION_PROTOCOL / GR; recorded in the VL entry).

Build-then-wire: these functions have NO caller on the default pep.py path in
this increment; evaluate() and safe_manifest() are unchanged. The pep.py
approval branch (design 1.3 / 1c) is a later increment.
"""

from IMPLEMENTATION.impact import safe_high_impact, requires_approval
from IMPLEMENTATION.evaluator import t26_valid, ac3_valid


# A well-formed high-impact manifest: every HIGH_IMPACT token is a required
# token (subset of AR u R), per [FIX H2].
HI_MANIFEST = {
    "version": "1.0",
    "AR": ["auth_admin"],
    "R": ["op_transfer", "op_read"],
    "HIGH_IMPACT": ["op_transfer"],
}

ELIGIBLE_CTX = {"AP": ["auth_admin"], "OP": ["op_transfer", "op_read"]}


# --------------------------------------------------------------------------
# [FIX H1] missing / malformed HIGH_IMPACT must fail CLOSED, never empty-set
# --------------------------------------------------------------------------

def test_missing_high_impact_requires_approval_REVERT_CATCHER():
    """star: a manifest with NO HIGH_IMPACT key must require approval.

    The silent-disable catcher: a `.get("HIGH_IMPACT", [])` regression would
    make this False (oversight silently off). [FIX H1]
    """
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
    """An EXPLICIT empty list is the operator's conscious opt-out: low-impact,
    forwards as today. Distinct from a missing key (which fails closed)."""
    manifest = dict(HI_MANIFEST, HIGH_IMPACT=[])
    assert safe_high_impact(manifest) == set()
    assert requires_approval(ELIGIBLE_CTX, manifest) is False


# --------------------------------------------------------------------------
# [FIX H2] selector tokens must be caller-forced (in AR u R)
# --------------------------------------------------------------------------

def test_high_impact_token_outside_required_is_manifest_error_REVERT_CATCHER():
    """star: a HIGH_IMPACT token NOT in AR u R is a manifest error -> fail
    closed. Reverting the subset check would let a caller omit that token and
    be classified low-impact while still eligible. [FIX H2]
    """
    manifest = dict(HI_MANIFEST, HIGH_IMPACT=["op_transfer", "op_not_required"])
    assert safe_high_impact(manifest) is None
    assert requires_approval(ELIGIBLE_CTX, manifest) is True


def test_h2_eligible_and_low_impact_by_omission_is_impossible_REVERT_CATCHER():
    """star: the H2 guarantee. An out-of-band HIGH_IMPACT token (NOT in
    AR u R) is the escape vector: a caller need not declare it, so without
    [FIX H2] it could be coverage-eligible AND classified low-impact. With the
    fix the out-of-band selector is a manifest error -> fail closed -> approval
    required, so (t26_valid AND not requires_approval) is unreachable.
    Reverting the subset check makes requires_approval here return False -> RED.
    """
    manifest = {
        "version": "1.0",
        "AR": ["auth_admin"],
        "R": ["op_read"],
        "HIGH_IMPACT": ["op_secret_export"],  # NOT in AR u R -> the escape token
    }
    R = manifest["R"]
    ctx = {"AP": ["auth_admin"], "OP": ["op_read"]}  # eligible, omits the token

    assert t26_valid(ctx, R) is True
    assert ac3_valid(ctx, manifest["AR"]) is True
    # With [FIX H2]: out-of-band selector -> fail closed -> approval required.
    # Without it: requires_approval would be False (escape) while eligible.
    assert requires_approval(ctx, manifest) is True
    assert not (t26_valid(ctx, R) and not requires_approval(ctx, manifest))


# --------------------------------------------------------------------------
# fail-closed on malformed ctx; manifest-derived (caller cannot influence)
# --------------------------------------------------------------------------

def test_malformed_ctx_with_high_impact_fails_closed():
    assert requires_approval(None, HI_MANIFEST) is True
    assert requires_approval({"AP": "not-a-list", "OP": 3}, HI_MANIFEST) is True
    assert requires_approval({}, HI_MANIFEST) is True


def test_caller_cannot_self_declare_low_impact():
    """Classification comes from the pinned manifest, not the caller. A caller
    that declares the high-impact token is high-impact regardless of any extra
    fields it sends."""
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
    assert ac3_valid(ctx, manifest["AR"]) is True
    assert requires_approval(ctx, manifest) is True
