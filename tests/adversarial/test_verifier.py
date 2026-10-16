"""
Tests for verifier.verify_envelope, the target-side receipt check.

The verifier combines two checks:
  - envelope.reassert(, policy=reference_policy()) for integrity and currency (decision_sha256 verifies,
    and the receipt's policy pin matches the live pin), and
  - a binding check that the receipt's request_context (principal, tool,
    args_sha256) and target_url match the call the target is about to
    execute, which reassert(, policy=reference_policy()) does not do.

_rehash_decision_sha256 lets a test change a pinned field without tripping
the integrity check first, so the check under test is the one that fires.
Receipts use a fixed timestamp_utc.
"""

import hashlib

from reference import reference_policy
from gargoyle.policy import ManifestPolicy
from gargoyle.envelope import (
    build_envelope,
    canonical_json,
)
from gargoyle.verifier import (
    ACCEPT_REASSERTED_AND_BOUND,
    REF_VERIFY_BINDING_MISMATCH,
    REF_VERIFY_ENVELOPE_ABSENT,
    REF_VERIFY_PRINCIPAL_MISMATCH,
    REF_VERIFY_REASSERT_INVALIDATED,
    REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED,
    verify_envelope,
)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

TARGET_URL = "http://127.0.0.1:9000/target"
PRINCIPAL = "agent-7"


def _call(tool="transfer", args=None, principal=PRINCIPAL):
    """A call as a target sees it: the tool and arguments it is about to run,
    and the principal it authenticated."""
    return {
        "tool": tool,
        "args": {"amount": 5, "to": "acct-9"} if args is None else args,
        "principal": principal,
    }


def _build_valid_envelope(call=None, target_url=TARGET_URL,
                          timestamp_utc="2026-05-21T00:00:00+00:00"):
    """Build a receipt under the current reference policy."""
    if call is None:
        call = _call()
    return build_envelope(
        policy_pin=reference_policy().pin(),
        decision="ELIGIBLE",
        target_url=target_url,
        call=call,
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


def test_verify_without_a_live_pin_is_a_configuration_error():
    """No record and no policy: the verifier cannot check currency, and it
    raises rather than quietly refuse or honor every receipt."""
    import pytest
    with pytest.raises(ValueError):
        verify_envelope(_build_valid_envelope(), _call(), TARGET_URL)


def test_verify_accepts_valid_current_bound_envelope():
    """
    A receipt issued under the current policy, presented with the matching call
    and target_url, is accepted. REASSERTED plus a matching binding is the only
    way a past ELIGIBLE is honored without asking the policy again.
    """
    call = _call()
    env = _build_valid_envelope(call=call)
    result = verify_envelope(env, call, TARGET_URL, policy=reference_policy())
    assert result["accepted"] is True
    assert result["reason"] == ACCEPT_REASSERTED_AND_BOUND


# ---------------------------------------------------------------------------
# Integrity and policy-pin rejects
# ---------------------------------------------------------------------------


def test_verify_rejects_forged_envelope_tamper():
    """
    Forgery by editing: changing request_context without re-hashing makes
    decision_sha256 stale, reassert(, policy=reference_policy()) returns INVALIDATED, and the verifier
    refuses.
    """
    env = _build_valid_envelope()
    env["request_context"]["tool"] = "delete_database"
    result = verify_envelope(env, _call(tool="delete_database"), TARGET_URL, policy=reference_policy())
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_REASSERT_INVALIDATED


def test_verify_rejects_policy_logic_change_re_evaluate():
    """A receipt issued under another policy_id (different decision logic)
    is not honored: reassert(, policy=reference_policy()) returns RE-EVALUATE-REQUIRED and the verifier
    refuses with REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED. decision_sha256 is
    re-hashed so the integrity check does not fire first."""
    env = _build_valid_envelope()
    env["policy"]["policy_id"] = "some-other-policy/2"
    _rehash_decision_sha256(env)
    result = verify_envelope(env, _call(), TARGET_URL, policy=reference_policy())
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED


def test_verify_rejects_policy_config_change_re_evaluate():
    """A receipt issued under another policy_sha256 (the manifest changed)
    is not honored: RE-EVALUATE-REQUIRED."""
    env = _build_valid_envelope()
    env["policy"]["policy_sha256"] = "0" * 64
    _rehash_decision_sha256(env)
    result = verify_envelope(env, _call(), TARGET_URL, policy=reference_policy())
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
    result = verify_envelope(None, _call(), TARGET_URL, policy=reference_policy())
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_ENVELOPE_ABSENT


def test_verify_rejects_malformed_envelope_without_raising():
    """
    A dict missing required structure is refused cleanly with
    REF_VERIFY_ENVELOPE_ABSENT by the presence check, never by an exception from
    deeper key access. Both an empty dict and a partial one are covered.
    """
    result_empty = verify_envelope({}, _call(), TARGET_URL, policy=reference_policy())
    assert result_empty["accepted"] is False
    assert result_empty["reason"] == REF_VERIFY_ENVELOPE_ABSENT

    # request_context present but missing its sub-keys (no principal).
    partial = {
        "policy": {},
        "request_context": {"tool": "transfer", "args_sha256": "0" * 64},
        "decision_sha256": "0" * 64,
        "target_url": TARGET_URL,
    }
    result_partial = verify_envelope(partial, _call(), TARGET_URL, policy=reference_policy())
    assert result_partial["accepted"] is False
    assert result_partial["reason"] == REF_VERIFY_ENVELOPE_ABSENT


# ---------------------------------------------------------------------------
# Binding rejects (reuse for another call, caller or target)
# ---------------------------------------------------------------------------


def test_verify_rejects_replay_binding_mismatch():
    """
    Reuse for a different call: a genuine, current receipt for call X reasserts
    fine, because reassert(, policy=reference_policy()) only checks integrity and the policy pin. The
    binding check is what refuses it when presented with call Y (a different
    amount): REF_VERIFY_BINDING_MISMATCH.
    """
    call_x = _call(args={"amount": 5, "to": "acct-9"})
    env = _build_valid_envelope(call=call_x)
    call_y = _call(args={"amount": 5000, "to": "acct-9"})
    result = verify_envelope(env, call_y, TARGET_URL, policy=reference_policy())
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_BINDING_MISMATCH


def test_verify_rejects_tool_mismatch():
    """A receipt for one tool presented with another, same arguments."""
    env = _build_valid_envelope(call=_call(tool="read_balance"))
    result = verify_envelope(env, _call(tool="transfer"), TARGET_URL, policy=reference_policy())
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_BINDING_MISMATCH


def test_verify_rejects_target_url_mismatch():
    """
    Rebinding to another target: a genuine receipt issued for one target_url,
    presented at another, fails the binding check.
    """
    call = _call()
    env = _build_valid_envelope(call=call, target_url=TARGET_URL)
    result = verify_envelope(env, call, "http://127.0.0.1:9000/other", policy=reference_policy())
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_BINDING_MISMATCH


def test_verify_rejects_extra_live_field():
    """
    Binding is exact: a field in the live call beyond tool/args/principal is
    unbound data, and the verifier refuses rather than ignore it.
    """
    call = _call()
    env = _build_valid_envelope(call=call)
    result = verify_envelope(env, {**call, "mode": "force"}, TARGET_URL, policy=reference_policy())
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_BINDING_MISMATCH


def test_verify_accepts_args_in_any_key_order():
    """
    args are bound by args_sha256 over canonical JSON, so the same arguments
    in another key order are not falsely refused, and a different value is.
    """
    env = _build_valid_envelope(call=_call(args={"amount": 5, "to": "acct-9"}))
    same_other_order = _call(args={"to": "acct-9", "amount": 5})
    accepted = verify_envelope(env, same_other_order, TARGET_URL, policy=reference_policy())
    assert accepted["accepted"] is True
    assert accepted["reason"] == ACCEPT_REASSERTED_AND_BOUND

    different = _call(args={"to": "acct-9", "amount": 6})
    rejected = verify_envelope(env, different, TARGET_URL, policy=reference_policy())
    assert rejected["accepted"] is False
    assert rejected["reason"] == REF_VERIFY_BINDING_MISMATCH


def test_verify_rejects_unserializable_live_args():
    """Arguments canonical_json cannot encode cannot be bound: refused."""
    env = _build_valid_envelope()
    result = verify_envelope(env, _call(args={"blob": b"\\x00"}), TARGET_URL, policy=reference_policy())
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_BINDING_MISMATCH


# ---------------------------------------------------------------------------
# Principal: the receipt is spendable only by whom it was issued to
# ---------------------------------------------------------------------------


def test_verify_rejects_principal_mismatch():
    """
    A receipt issued to agent-7, presented by a caller the target
    authenticated as agent-8, is refused with REF_VERIFY_PRINCIPAL_MISMATCH:
    same tool, same arguments, wrong holder.
    """
    env = _build_valid_envelope(call=_call(principal="agent-7"))
    result = verify_envelope(env, _call(principal="agent-8"), TARGET_URL, policy=reference_policy())
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_PRINCIPAL_MISMATCH


def test_verify_rejects_unauthenticated_caller():
    """
    A target that authenticated nobody (None, empty, or not a string) never
    matches a receipt, whatever principal the receipt names.
    """
    env = _build_valid_envelope()
    for nobody in (None, "", 7, ["agent-7"]):
        result = verify_envelope(env, _call(principal=nobody), TARGET_URL, policy=reference_policy())
        assert result["accepted"] is False, nobody
        assert result["reason"] == REF_VERIFY_PRINCIPAL_MISMATCH, nobody


def test_verify_rejects_receipt_naming_no_principal():
    """
    A receipt whose principal is empty, even with a correct hash, is not a
    bearer token: it matches nobody.
    """
    env = _build_valid_envelope()
    env["request_context"]["principal"] = ""
    _rehash_decision_sha256(env)
    result = verify_envelope(env, _call(principal=""), TARGET_URL, policy=reference_policy())
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_PRINCIPAL_MISMATCH


def test_verify_checks_who_before_what():
    """
    When both the principal and the call differ, the refusal names the
    principal: the wrong holder is the finding, not the arguments.
    """
    env = _build_valid_envelope(call=_call(tool="transfer", principal="agent-7"))
    result = verify_envelope(env, _call(tool="delete_database", principal="agent-8"), TARGET_URL, policy=reference_policy())
    assert result["reason"] == REF_VERIFY_PRINCIPAL_MISMATCH
