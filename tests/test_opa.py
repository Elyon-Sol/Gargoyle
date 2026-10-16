"""OpaPolicy: a real policy engine behind the Policy interface, pinned by
the exact module set OPA holds, failing closed on every doubt."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.consumer import Consumer, REF_TARGET_APPROVAL_REQUIRED
from gargoyle.envelope import reassert, REASSERTED, RE_EVALUATE_REQUIRED
from gargoyle.issuer import issue
from gargoyle.opa import (
    OPA_DENIED, OPA_UNAVAILABLE, OPA_UNDEFINED, OPA_UNRECOGNIZED_RESULT, OpaPolicy,
)
from gargoyle.policy import ELIGIBLE, POLICY_INTERNAL, REFUSE, Policy

TARGET = "https://tools.example/target"
CALL = {"tool": "transfer_funds", "args": {"amount": 250}, "principal": "spiffe://example.org/agents/payments"}


class _Resp:
    def __init__(self, status=200, body=None, raise_json=False):
        self.status_code = status; self._body = body; self._raise = raise_json

    def json(self):
        if self._raise:
            raise ValueError("not json")
        return self._body


class FakeOpa:
    """Stands in for requests.Session against a running OPA."""

    def __init__(self, result="undefined", modules=None, status=200, broken=False):
        self.result = result; self.modules = modules if modules is not None else [
            {"id": "gargoyle.rego", "raw": "package gargoyle\ndefault decision := false\n"}]
        self.status = status; self.broken = broken; self.posts = []

    def get(self, url, timeout=None):
        assert url.endswith("/v1/policies")
        return _Resp(self.status, {"result": self.modules})

    def post(self, url, json=None, timeout=None):
        self.posts.append((url, json))
        if self.broken:
            raise ConnectionError("opa down")
        if self.result == "undefined":
            return _Resp(self.status, {})
        if self.result == "garbage":
            return _Resp(self.status, None, raise_json=True)
        return _Resp(self.status, {"result": self.result})


def policy(**kw):
    return OpaPolicy("http://127.0.0.1:8181/", "gargoyle/decision", session=FakeOpa(**kw))


def test_satisfies_the_policy_protocol_and_posts_the_interaction_as_input():
    p = policy(result=True)
    assert isinstance(p, Policy)
    d = p.decide(TARGET, {**CALL, "ticket": "T-1"})
    assert d.outcome == ELIGIBLE and d.requires_approval is False
    url, body = p._session.posts[-1]
    assert url == "http://127.0.0.1:8181/v1/data/gargoyle/decision"
    assert body == {"input": {**CALL, "ticket": "T-1", "target_url": TARGET}}


@pytest.mark.parametrize("result,outcome,reason,hold", [
    (True, ELIGIBLE, None, False),
    ({"allow": True}, ELIGIBLE, None, False),
    ({"allow": True, "requires_approval": False}, ELIGIBLE, None, False),
    ({"allow": True, "requires_approval": True}, ELIGIBLE, None, True),
    ({"allow": True, "requires_approval": "yes"}, ELIGIBLE, None, True),      # not an explicit false: held
    (False, REFUSE, OPA_DENIED, False),
    ({"allow": False}, REFUSE, OPA_DENIED, False),
    ({"allow": False, "reason": "OVER_LIMIT"}, REFUSE, "OVER_LIMIT", False),
    ({"allow": "true"}, REFUSE, OPA_UNRECOGNIZED_RESULT, False),
    ("allow", REFUSE, OPA_UNRECOGNIZED_RESULT, False),
    (None, REFUSE, OPA_UNRECOGNIZED_RESULT, False),
    ("undefined", REFUSE, OPA_UNDEFINED, False),
    ("garbage", REFUSE, OPA_UNAVAILABLE, False),
])
def test_result_shapes(result, outcome, reason, hold):
    d = policy(result=result).decide(TARGET, CALL)
    assert (d.outcome, d.reason, d.requires_approval) == (outcome, reason, hold)


def test_unreachable_or_erroring_opa_refuses():
    assert policy(result=True, broken=True).decide(TARGET, CALL).reason == OPA_UNAVAILABLE
    assert policy(result=True, status=500).decide(TARGET, CALL).reason == OPA_UNAVAILABLE
    assert policy(result=True).decide(TARGET, ["not", "a", "mapping"]).reason == OPA_UNRECOGNIZED_RESULT


def test_pin_follows_the_module_set():
    p = policy(result=True)
    pin = p.pin()
    assert pin["policy_id"] == "opa:gargoyle/decision" and len(pin["policy_sha256"]) == 64
    assert OpaPolicy("http://x", "a/b", policy_id="payments/3", session=FakeOpa()).pin()["policy_id"] == "payments/3"
    p._session.modules[0]["raw"] += "\nallow := true\n"
    assert p.pin()["policy_sha256"] != pin["policy_sha256"]
    with pytest.raises(RuntimeError):
        policy(status=500).pin()
    with pytest.raises(ValueError):
        OpaPolicy("", "a/b")


def test_receipts_issued_under_opa_verify_and_die_when_the_policy_changes():
    key = Ed25519PrivateKey.generate()
    p = policy(result={"allow": True})
    r = issue(p, TARGET, CALL, signing_key=key, key_id="k1")
    assert r.envelope is not None and r.envelope["policy"] == p.pin()
    assert reassert(r.envelope, policy=p)["outcome"] == REASSERTED
    c = Consumer(target_id=TARGET, record=p.pin(), pinned_public_keys={"k1": key.public_key()})
    assert c.check(r.envelope, CALL).honored is True
    p._session.modules.append({"id": "extra.rego", "raw": "package extra\n"})
    assert reassert(r.envelope, policy=p)["outcome"] == RE_EVALUATE_REQUIRED

    held = issue(policy(result={"allow": True, "requires_approval": True}), TARGET, CALL,
                 signing_key=key, key_id="k1")
    assert held.decision.requires_approval and held.envelope["requires_approval"] is True
    c2 = Consumer(target_id=TARGET, record=held.envelope["policy"], pinned_public_keys={"k1": key.public_key()},
                  approver_public_keys={"a": key.public_key()})
    assert c2.check(held.envelope, CALL) == (False, REF_TARGET_APPROVAL_REQUIRED)

    denied = issue(policy(result={"allow": False, "reason": "OVER_LIMIT"}), TARGET, CALL, signing_key=key, key_id="k1")
    assert denied.envelope is None and denied.decision.reason == "OVER_LIMIT"
    down = issue(policy(result=True, broken=True), TARGET, CALL, signing_key=key, key_id="k1")
    assert down.envelope is None and down.decision.reason == OPA_UNAVAILABLE
    unpinnable = issue(policy(result=True, status=500), TARGET, CALL, signing_key=key, key_id="k1")
    assert unpinnable.envelope is None and unpinnable.decision.reason in (OPA_UNAVAILABLE, POLICY_INTERNAL)
