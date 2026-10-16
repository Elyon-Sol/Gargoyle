"""The decision interface and issue(): any object with pin() and decide()
is a policy; a receipt is issued only for ELIGIBLE, carries the pin, a
decision_id and an expiry, and a misbehaving policy is a refusal."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.envelope import RE_EVALUATE_REQUIRED, REASSERTED, reassert
from gargoyle.issuer import DEFAULT_TTL_SECONDS, ISSUE_POLICY_ERROR, ISSUE_UNBINDABLE_CALL, issue
from gargoyle.policy import ELIGIBLE, POLICY_INTERNAL, REFUSE, Decision, Policy, evaluate, refuse, valid_pin
from gargoyle.verifier import ACCEPT_REASSERTED_AND_BOUND, verify_envelope
from reference import reference_policy

TARGET = "https://target.example.com/act"


def call(**over):
    base = {"tool": "t", "args": {"k": 1}, "principal": "agent-7"}
    base.update(over)
    return base


class FixedPolicy:
    """A non-rules policy: whatever the integrator's engine says."""

    def __init__(self, decision, pin=None):
        self.decision = decision
        self._pin = pin or {"policy_id": "engine/1", "policy_sha256": "a" * 64}

    def pin(self):
        return self._pin

    def decide(self, target_url, interaction):
        if isinstance(self.decision, Exception):
            raise self.decision
        return self.decision


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def test_decision_and_pin_shapes():
    assert Decision(ELIGIBLE).eligible and not refuse("X").eligible
    assert refuse("X") == Decision(REFUSE, "X", False)
    assert valid_pin({"policy_id": "p", "policy_sha256": "a" * 64})
    for bad in (None, {}, {"policy_id": "x"}, {"policy_id": "", "policy_sha256": "a" * 64},
                {"policy_id": "x", "policy_sha256": "short"}):
        assert not valid_pin(bad)
    assert isinstance(reference_policy(), Policy) and isinstance(FixedPolicy(Decision(ELIGIBLE)), Policy)


def test_evaluate_needs_a_policy():
    assert evaluate(call(), reference_policy()) == ELIGIBLE
    assert evaluate(call(), FixedPolicy(refuse("NO"))) == REFUSE
    with pytest.raises(TypeError):
        evaluate(call())


def test_issue_eligible_receipt_verifies_end_to_end(key):
    now = datetime.now(timezone.utc)
    r = issue(reference_policy(), TARGET, call(), signing_key=key, key_id="k1", now=now)
    assert r.decision.eligible and r.envelope is not None
    env = r.envelope
    assert env["policy"] == reference_policy().pin()
    assert env["decision_id"]
    assert datetime.fromisoformat(env["not_after"]) == now + timedelta(seconds=DEFAULT_TTL_SECONDS)
    v = verify_envelope(env, call(), TARGET, pinned_public_keys={"k1": key.public_key()}, policy=reference_policy())
    assert (v["accepted"], v["reason"]) == (True, ACCEPT_REASSERTED_AND_BOUND)
    assert set(env["request_context"]) == {"tool", "args_sha256", "principal"}


def test_issue_gives_each_receipt_its_own_decision_id(key):
    ids = {issue(reference_policy(), TARGET, call(), signing_key=key, key_id="k1").envelope["decision_id"]
           for _ in range(5)}
    assert len(ids) == 5


def test_issue_refusal_carries_no_receipt(key):
    r = issue(FixedPolicy(refuse("OVER_LIMIT")), TARGET, call(), signing_key=key, key_id="k1")
    assert r.envelope is None and r.decision.reason == "OVER_LIMIT"


def test_issue_from_a_custom_policy_and_pin_change_invalidates(key):
    policy = FixedPolicy(Decision(ELIGIBLE))
    r = issue(policy, TARGET, call(), signing_key=key, key_id="k1")
    assert r.envelope["policy"] == {"policy_id": "engine/1", "policy_sha256": "a" * 64}
    assert reassert(r.envelope, policy=policy)["outcome"] == REASSERTED
    policy._pin = {"policy_id": "engine/1", "policy_sha256": "b" * 64}   # the engine's bundle changed
    assert reassert(r.envelope, policy=policy)["outcome"] == RE_EVALUATE_REQUIRED


@pytest.mark.parametrize("policy,reason", [
    (FixedPolicy(RuntimeError("engine down")), POLICY_INTERNAL),
    (FixedPolicy("ELIGIBLE"), ISSUE_POLICY_ERROR),                               # not a Decision
    (FixedPolicy(Decision(ELIGIBLE), pin={"policy_id": "x"}), ISSUE_POLICY_ERROR),  # malformed pin
])
def test_issue_fails_closed_on_a_misbehaving_policy(key, policy, reason):
    r = issue(policy, TARGET, call(), signing_key=key, key_id="k1")
    assert r.envelope is None and r.decision.outcome == REFUSE and r.decision.reason == reason


@pytest.mark.parametrize("unbindable", [
    {"tool": "t"},                                      # no args, no principal
    {"tool": "t", "args": {}},                          # no principal
    {"tool": "t", "args": {}, "principal": ""},         # nobody
    {"tool": "", "args": {}, "principal": "agent-7"},   # no tool
    {"tool": "t", "args": object(), "principal": "agent-7"},  # unserializable args
])
def test_issue_refuses_an_eligible_call_it_cannot_bind(key, unbindable):
    r = issue(FixedPolicy(Decision(ELIGIBLE)), TARGET, unbindable, signing_key=key, key_id="k1")
    assert r.envelope is None and r.decision.reason == ISSUE_UNBINDABLE_CALL


def test_issue_surfaces_requires_approval(key):
    r = issue(FixedPolicy(Decision(ELIGIBLE, requires_approval=True)), TARGET, call(), signing_key=key, key_id="k1")
    assert r.decision.requires_approval is True and r.envelope["requires_approval"] is True
    assert r.envelope["approval_request_id"]


@pytest.mark.parametrize("ttl", [0, -1, 1.5, True, None])
def test_issue_rejects_unbounded_or_bad_ttl(key, ttl):
    with pytest.raises(ValueError):
        issue(reference_policy(), TARGET, call(), signing_key=key, key_id="k1", ttl_seconds=ttl)


def test_issue_requires_a_key():
    with pytest.raises(ValueError):
        issue(reference_policy(), TARGET, call(), signing_key=None, key_id="k1")
