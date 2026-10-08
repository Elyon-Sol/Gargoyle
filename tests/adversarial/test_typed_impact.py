"""
Typed-impact support (step 8.1 of the full-path spec): the evaluator gains
per-interaction-type AR/R selection so a benign type can be ELIGIBLE while
declaring FEWER tokens than a sensitive type - which is what makes
requires_approval discriminate (some types forward, some hold). Before this,
impact was structurally all-or-nothing (flat AR/R; every eligible caller
declared AR u R, so any non-empty HIGH_IMPACT matched every mint).

Backward-compatibility law: a flat manifest (no `interaction_types`) is
byte-behaviour-identical to the pre-typed evaluator. impact.py is UNCHANGED -
top-level AR/R stays the token vocabulary, so safe_high_impact's [FIX H2]
subset check is unaffected. These are the proving tests; the starred ones are
revert-catchers (RED if the per-type selection or a fail-closed guard is
reverted).
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
    """A manifest with no interaction_types is returned as-is (byte-behaviour
    identical to the pre-typed evaluator)."""
    flat = {"version": "1.0", "AR": ["identity", "role"],
            "R": ["session", "request"], "HIGH_IMPACT": []}
    assert safe_manifest(flat) == flat


def test_typed_manifest_well_formed_accepted():
    assert safe_manifest(TYPED) == TYPED


def test_typed_types_not_a_dict_rejected():
    assert safe_manifest(dict(TYPED, interaction_types=["read"])) is None


def test_type_token_outside_vocabulary_rejected_REVERT_CATCHER():
    """star: a type requiring a token NOT in the top-level AR u R vocabulary is
    a manifest error -> None. Keeps top-level AR/R the true union so [FIX H2]
    (HIGH_IMPACT subset of AR u R) stays meaningful."""
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


def test_mislabeled_type_consistency_rejected_REVERT_CATCHER():
    """star: a type flagged benign whose tokens DO intersect HIGH_IMPACT (or
    vice-versa) is a mislabel -> fail closed. Prevents a sensitive action being
    dressed as benign in the manifest."""
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
    """A typed manifest with a caller that declares no type falls back to the
    top-level (union) sets - the conservative choice (fail toward oversight)."""
    assert resolve_required_sets(TYPED, {"AP": ["identity"], "OP": ["session"]}) == (
        ["identity", "role"], ["session", "request"])


def test_resolve_unknown_type_fails_closed_REVERT_CATCHER():
    """star: an unknown declared type resolves to (None, None) -> REFUSE."""
    assert resolve_required_sets(TYPED, {"interaction_type": "delete"}) == (None, None)


# --------------------------------------------------------------------------
# The headline: a benign type is ELIGIBLE *and* low-impact - impossible flat
# --------------------------------------------------------------------------

def test_benign_type_would_be_refused_without_per_type_selection():
    """Proves the mechanism matters: against the top-level (union) R, the benign
    read caller is NOT eligible (OP={session} does not cover {session,request}).
    Per-type selection is exactly what admits it."""
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
# [FIX H1]/[FIX H2] still hold on a typed manifest (impact.py unchanged)
# --------------------------------------------------------------------------

def test_typed_missing_high_impact_still_fails_closed():
    """[FIX H1] survives typing: a typed manifest with NO HIGH_IMPACT key still
    fails closed to approval-required for any eligible caller."""
    typed_no_hi = {k: v for k, v in TYPED.items() if k != "HIGH_IMPACT"}
    assert safe_high_impact(typed_no_hi) is None
    assert requires_approval(SENSITIVE_CTX, typed_no_hi) is True
    assert requires_approval(BENIGN_CTX, typed_no_hi) is True
