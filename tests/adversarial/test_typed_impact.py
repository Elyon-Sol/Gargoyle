"""
Typed interactions in the reference manifest policy.

A manifest may declare interaction_types, each with its own AR/R sets, so a
benign type is ELIGIBLE while declaring fewer tokens than a sensitive type.
That is what lets requires_approval tell them apart: some types go straight
through, some are held for a human. With a flat manifest every eligible
caller declares the full vocabulary, so any non-empty HIGH_IMPACT matches
every call.

A flat manifest (no interaction_types) behaves exactly as before. The
top-level AR/R stays the full token vocabulary, so the check that HIGH_IMPACT
is a subset of AR u R keeps its meaning. Tests whose names end in
REVERT_CATCHER fail if the per-type selection or a fail-closed guard is
removed.
"""

import json
import pytest

from gargoyle.policy import (
    REQUIRED_SETS_UNRESOLVED, ManifestPolicy, safe_manifest, resolve_required_sets,
    authority_covered, coverage_covered,
)
from gargoyle.impact import safe_high_impact, requires_approval


# A well-formed TYPED manifest. Top-level AR/R is the vocabulary (union); each
# type's sets are a subset. HIGH_IMPACT names the tokens only the sensitive
# type requires, so a benign caller never declares them.
TYPED = {
    "version": "1.1",
    "interaction_type": "default",
    "AR": ["identity", "role"],
    "R": ["session", "request"],
    "HIGH_IMPACT": ["role", "request"],
    "interaction_types": {
        "read": {"AR": ["identity"], "R": ["session"], "high_impact": False},
        "transfer": {"AR": ["identity", "role"], "R": ["session", "request"],
                     "high_impact": True},
    },
}

BENIGN_CTX = {"interaction_type": "read", "AP": ["identity"], "OP": ["session"]}
SENSITIVE_CTX = {"interaction_type": "transfer",
                 "AP": ["identity", "role"], "OP": ["session", "request"]}


# --------------------------------------------------------------------------
# safe_manifest: the typed shape is validated fail-closed; flat is unchanged
# --------------------------------------------------------------------------

def test_flat_manifest_unchanged():
    """A manifest with no interaction_types is returned as-is."""
    flat = {"version": "1.0", "AR": ["identity", "role"],
            "R": ["session", "request"], "HIGH_IMPACT": []}
    assert safe_manifest(flat) == flat


def test_typed_manifest_well_formed_accepted():
    assert safe_manifest(TYPED) == TYPED


def test_typed_types_not_a_dict_rejected():
    assert safe_manifest(dict(TYPED, interaction_types=["read"])) is None


def test_type_token_outside_vocabulary_rejected():
    """
    A type requiring a token outside the top-level AR u R vocabulary makes the
    manifest malformed. This keeps the top-level sets the true union, so the
    HIGH_IMPACT subset check stays meaningful.
    """
    bad = dict(TYPED, interaction_types={
        "read": {"AR": ["identity"], "R": ["session"], "high_impact": False},
        "transfer": {"AR": ["identity", "role"], "R": ["session", "wipe_all"],
                     "high_impact": True},  # wipe_all not in vocabulary
    })
    assert safe_manifest(bad) is None


def test_type_high_impact_flag_must_be_bool():
    bad = dict(TYPED, interaction_types={
        "read": {"AR": ["identity"], "R": ["session"], "high_impact": "no"},
    })
    assert safe_manifest(bad) is None


def test_mislabeled_type_consistency_rejected():
    """
    A type flagged benign whose tokens intersect HIGH_IMPACT, or the reverse, is
    a mislabel and fails closed, so a sensitive action cannot be dressed up as
    benign in the manifest.
    """
    # 'read' flagged benign but given a high-impact token ('role').
    mislabeled = dict(TYPED, interaction_types={
        "read": {"AR": ["identity", "role"], "R": ["session"], "high_impact": False},
        "transfer": {"AR": ["identity", "role"], "R": ["session", "request"],
                     "high_impact": True},
    })
    assert safe_manifest(mislabeled) is None


# --------------------------------------------------------------------------
# resolve_required_sets: per-type selection; fail-closed on unknown type
# --------------------------------------------------------------------------

def test_resolve_flat_returns_top_level():
    flat = {"version": "1.0", "AR": ["identity"], "R": ["session"]}
    assert resolve_required_sets(flat, BENIGN_CTX) == (["identity"], ["session"])


def test_resolve_selects_declared_type():
    assert resolve_required_sets(TYPED, BENIGN_CTX) == (["identity"], ["session"])
    assert resolve_required_sets(TYPED, SENSITIVE_CTX) == (
        ["identity", "role"], ["session", "request"])


def test_resolve_no_declared_type_defaults_to_union():
    """
    Under a typed manifest, a caller that declares no type gets the top-level
    (union) sets: the conservative choice, which leans toward human review.
    """
    assert resolve_required_sets(TYPED, {"AP": ["identity"], "OP": ["session"]}) == (
        ["identity", "role"], ["session", "request"])


def test_resolve_unknown_type_fails_closed():
    """An unknown declared type resolves to (None, None), which the policy refuses."""
    assert resolve_required_sets(TYPED, {"interaction_type": "delete"}) == (None, None)


# --------------------------------------------------------------------------
# A benign type is ELIGIBLE and low-impact, which a flat manifest cannot express
# --------------------------------------------------------------------------

def test_benign_type_would_be_refused_without_per_type_selection():
    """
    The per-type selection is what admits the benign caller: against the
    top-level R, OP={session} does not cover {session, request}.
    """
    assert coverage_covered(BENIGN_CTX, TYPED["R"]) is False           # union view: refused
    assert coverage_covered(BENIGN_CTX, ["session"]) is True           # per-type view: eligible


def _typed_policy(tmp_path):
    path = tmp_path / "typed.json"
    path.write_text(json.dumps(TYPED))
    policy = ManifestPolicy(str(path))
    return policy, policy.pin()["policy_sha256"]


def test_benign_eligible_and_low_impact(tmp_path):
    """A benign-type call is ELIGIBLE and not held: the state a flat manifest
    cannot express."""
    policy, sha = _typed_policy(tmp_path)
    ctx = dict(BENIGN_CTX, expected_manifest_version="1.1", expected_manifest_sha256=sha)
    d = policy.decide("https://t.example.com", ctx)
    assert d.outcome == "ELIGIBLE" and d.requires_approval is False
    assert requires_approval(ctx, TYPED) is False


def test_sensitive_eligible_and_high_impact_holds(tmp_path):
    """Same manifest, a sensitive type: ELIGIBLE and held for a human."""
    policy, sha = _typed_policy(tmp_path)
    ctx = dict(SENSITIVE_CTX, expected_manifest_version="1.1", expected_manifest_sha256=sha)
    d = policy.decide("https://t.example.com", ctx)
    assert d.outcome == "ELIGIBLE" and d.requires_approval is True
    assert requires_approval(ctx, TYPED) is True


def test_unknown_type_refused_end_to_end(tmp_path):
    policy, sha = _typed_policy(tmp_path)
    ctx = {"interaction_type": "delete", "AP": ["identity", "role"],
           "OP": ["session", "request"], "expected_manifest_version": "1.1",
           "expected_manifest_sha256": sha}
    d = policy.decide("https://t.example.com", ctx)
    assert (d.outcome, d.reason) == ("REFUSE", REQUIRED_SETS_UNRESOLVED)


# --------------------------------------------------------------------------
# The HIGH_IMPACT fail-closed rules still hold on a typed manifest
# --------------------------------------------------------------------------

def test_typed_missing_high_impact_still_fails_closed():
    """
    A typed manifest with no HIGH_IMPACT key still fails closed: every eligible
    caller requires approval. A missing key never silently disables review.
    """
    typed_no_hi = {k: v for k, v in TYPED.items() if k != "HIGH_IMPACT"}
    assert safe_high_impact(typed_no_hi) is None
    assert requires_approval(SENSITIVE_CTX, typed_no_hi) is True
    assert requires_approval(BENIGN_CTX, typed_no_hi) is True
