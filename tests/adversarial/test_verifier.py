"""
Tests for verifier.verify_envelope, the target-side receipt check.

The verifier combines two checks:
  - envelope.reassert() for integrity and currency (decision_sha256 verifies,
    and the receipt's policy pin matches the live pin), and
  - a binding check that the receipt's request_context and target_url match
    the call the target is about to execute, which reassert() does not do.

_rehash_decision_sha256 lets a test change a pinned field without tripping
the integrity check first, so the check under test is the one that fires.
Receipts use a fixed timestamp_utc; the manifest hash is computed live.
"""

import hashlib

from gargoyle.policy import ManifestPolicy
from gargoyle.envelope import (
    INVALIDATED,
    REASSERTED,
    RE_EVALUATE_REQUIRED,
    build_envelope,
    canonical_json,
)
from gargoyle.policy import load_manifest, manifest_sha256
from gargoyle.verifier import (
    ACCEPT_REASSERTED_AND_BOUND,
    REF_VERIFY_BINDING_MISMATCH,
    REF_VERIFY_ENVELOPE_ABSENT,
    REF_VERIFY_REASSERT_INVALIDATED,
    REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED,
    verify_envelope,
)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

TARGET_URL = "http://127.0.0.1:9000/target"


def _normalized_interaction(ap=None, op=None, context=None):
    """
    A call in normalized form: AP and OP default to the sets the reference
    manifest requires, already sorted; expected_manifest_sha256 is computed live.
    """
    return {
        "AP": ["identity", "role"] if ap is None else ap,
        "OP": ["session", "request"] if op is None else op,
        "context": {} if context is None else context,
        "expected_manifest_version": "1.0",
        "expected_manifest_sha256": manifest_sha256(),
    }


def _build_valid_envelope(interaction=None, target_url=TARGET_URL,
                          timestamp_utc="2026-05-21T00:00:00+00:00"):
    """Build a receipt under the current reference policy."""
    if interaction is None:
        interaction = _normalized_interaction()
    return build_envelope(
        policy_pin=ManifestPolicy().pin(),
        decision="ELIGIBLE",
        target_url=target_url,
        normalized_interaction=interaction,
        timestamp_utc=timestamp_utc,
    )


def _rehash_decision_sha256(envelope):
    """
    Recompute decision_sha256 after a test edits a field, so the integrity check
    passes and the check under test is the one that fires.
    """
    hashable = {
        k: v
        for k, v in envelope.items()
        if k not in ("decision_sha256", "timestamp_utc")
    }
    envelope["decision_sha256"] = hashlib.sha256(
        canonical_json(hashable).encode("utf-8")
    ).hexdigest()
    return envelope


# ---------------------------------------------------------------------------
# Accept path
# ---------------------------------------------------------------------------


def test_verify_accepts_valid_current_bound_envelope():
    """
    A receipt issued under the current policy, presented with the matching call
    and target_url, is accepted. REASSERTED plus a matching binding is the only
    way a past ELIGIBLE is honored without asking the policy again.
    """
    interaction = _normalized_interaction()
    env = _build_valid_envelope(interaction=interaction)
    result = verify_envelope(env, interaction, TARGET_URL)
    assert result["accepted"] is True
    assert result["reason"] == ACCEPT_REASSERTED_AND_BOUND


# ---------------------------------------------------------------------------
# Integrity and policy-pin rejects
# ---------------------------------------------------------------------------


def test_verify_rejects_forged_envelope_tamper():
    """
    Forgery by editing: changing request_context without re-hashing makes
    decision_sha256 stale, reassert() returns INVALIDATED, and the verifier
    refuses.
    """
    env = _build_valid_envelope()
    env["request_context"]["AP"] = ["identity", "role", "admin"]
    result = verify_envelope(env, _normalized_interaction(), TARGET_URL)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_REASSERT_INVALIDATED


def test_verify_rejects_policy_logic_change_re_evaluate():
    """A receipt issued under another policy_id (different decision logic)
    is not honored: reassert() returns RE-EVALUATE-REQUIRED and the verifier
    refuses with REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED. decision_sha256 is
    re-hashed so the integrity check does not fire first."""
    env = _build_valid_envelope()
    env["policy"]["policy_id"] = "some-other-policy/2"
    _rehash_decision_sha256(env)
    result = verify_envelope(env, _normalized_interaction(), TARGET_URL)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED


def test_verify_rejects_policy_config_change_re_evaluate():
    """A receipt issued under another policy_sha256 (the manifest changed)
    is not honored: RE-EVALUATE-REQUIRED."""
    env = _build_valid_envelope()
    env["policy"]["policy_sha256"] = "0" * 64
    _rehash_decision_sha256(env)
    result = verify_envelope(env, _normalized_interaction(), TARGET_URL)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED


# ---------------------------------------------------------------------------
# Presence rejects (no usable receipt)
# ---------------------------------------------------------------------------


def test_verify_rejects_absent_envelope():
    """
    A call arriving with no receipt is refused with REF_VERIFY_ENVELOPE_ABSENT:
    there is nothing to check.
    """
    result = verify_envelope(None, _normalized_interaction(), TARGET_URL)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_ENVELOPE_ABSENT


def test_verify_rejects_malformed_envelope_without_raising():
    """
    A dict missing required structure is refused cleanly with
    REF_VERIFY_ENVELOPE_ABSENT by the presence check, never by an exception from
    deeper key access. Both an empty dict and a partial one are covered.
    """
    result_empty = verify_envelope({}, _normalized_interaction(), TARGET_URL)
    assert result_empty["accepted"] is False
    assert result_empty["reason"] == REF_VERIFY_ENVELOPE_ABSENT

    # request_context present but missing its sub-keys.
    partial = {
        "policy": {},
        "request_context": {"AP": ["identity"]},
        "decision_sha256": "0" * 64,
        "target_url": TARGET_URL,
    }
    result_partial = verify_envelope(partial, _normalized_interaction(), TARGET_URL)
    assert result_partial["accepted"] is False
    assert result_partial["reason"] == REF_VERIFY_ENVELOPE_ABSENT


# ---------------------------------------------------------------------------
# Binding rejects (reuse for another call or target)
# ---------------------------------------------------------------------------


def test_verify_rejects_replay_binding_mismatch():
    """
    Reuse for a different call: a genuine, current receipt for call X reasserts
    fine, because reassert() only checks integrity and the policy pin. The
    binding check is what refuses it when presented with call Y (AP adds
    "admin"): REF_VERIFY_BINDING_MISMATCH.
    """
    interaction_x = _normalized_interaction(ap=["identity", "role"])
    env = _build_valid_envelope(interaction=interaction_x)
    interaction_y = _normalized_interaction(ap=["identity", "role", "admin"])
    result = verify_envelope(env, interaction_y, TARGET_URL)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_BINDING_MISMATCH


def test_verify_rejects_target_url_mismatch():
    """
    Rebinding to another target: a genuine receipt issued for one target_url,
    presented at another, fails the binding check.
    """
    interaction = _normalized_interaction()
    env = _build_valid_envelope(interaction=interaction, target_url=TARGET_URL)
    result = verify_envelope(env, interaction, "http://127.0.0.1:9000/other")
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_BINDING_MISMATCH


def test_verify_accepts_under_ap_op_normalization():
    """
    AP and OP are compared as sets: a call that presents the same tokens unsorted
    or with a duplicate is not falsely refused.
    """
    env_interaction = _normalized_interaction(
        ap=["identity", "role"], op=["request", "session"]
    )
    env = _build_valid_envelope(interaction=env_interaction)
    # Live interaction: same sets, unsorted, with a duplicate.
    live = _normalized_interaction(
        ap=["role", "identity", "role"], op=["session", "request"]
    )
    result = verify_envelope(env, live, TARGET_URL)
    assert result["accepted"] is True
    assert result["reason"] == ACCEPT_REASSERTED_AND_BOUND


def test_verify_context_binding():
    """
    context is part of what the receipt binds and is compared by canonical JSON:
    the same values in another key order are accepted, a different value is
    refused with REF_VERIFY_BINDING_MISMATCH.
    """
    ctx = {"purpose": "demo", "tier": 1}
    interaction = _normalized_interaction(context=ctx)
    env = _build_valid_envelope(interaction=interaction)

    # Same context value (different key insertion order) accepts.
    same_ctx_other_order = _normalized_interaction(context={"tier": 1, "purpose": "demo"})
    accepted = verify_envelope(env, same_ctx_other_order, TARGET_URL)
    assert accepted["accepted"] is True
    assert accepted["reason"] == ACCEPT_REASSERTED_AND_BOUND

    # Different context value rejects.
    different_ctx = _normalized_interaction(context={"purpose": "demo", "tier": 2})
    rejected = verify_envelope(env, different_ctx, TARGET_URL)
    assert rejected["accepted"] is False
    assert rejected["reason"] == REF_VERIFY_BINDING_MISMATCH
