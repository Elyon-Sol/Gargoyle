"""gargoyle.consumer.Consumer: the one check every executor runs. Trust
material is required at construction, sources are consulted on every check
and fail closed, serial high-water marks refuse rollback, and single use is
enforced after verification."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.consumer import (
    REF_TARGET_ANCHOR_MISMATCH, REF_TARGET_NO_DECISION_ID, Consumer, HighWater, Verdict,
)
from gargoyle.envelope import build_envelope, sign_envelope
from gargoyle.issuer import issue
from gargoyle.policy import ELIGIBLE, Decision
from gargoyle.published_source import anchor_sha256
from gargoyle.verifier import (
    ACCEPT_REASSERTED_AND_BOUND, REF_VERIFY_BINDING_MISMATCH, REF_VERIFY_KEY_RECORD_INVALID,
    REF_VERIFY_KEY_RECORD_STALE, REF_VERIFY_PUBLISHED_RECORD_INVALID,
    REF_VERIFY_PUBLISHED_RECORD_STALE, REF_VERIFY_REPLAY, REF_VERIFY_SIGNATURE_INVALID,
    REF_VERIFY_SIGNATURE_UNKNOWN_KEY,
)
from reference import reference_pin, reference_record_bytes

TARGET = "https://target.example/act"
KID = "issuer-1"
priv = Ed25519PrivateKey.generate(); pub = priv.public_key()
PIN = {"policy_id": "engine/1", "policy_sha256": "a" * 64}
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)


class AllowAll:
    def pin(self):
        return PIN

    def decide(self, target_url, interaction):
        return Decision(ELIGIBLE)


def call(principal="agent-7"):
    return {"tool": "transfer", "args": {"amount": 5}, "principal": principal}


def receipt(decision_id=True):
    if decision_id:
        return issue(AllowAll(), TARGET, call(), signing_key=priv, key_id=KID, now=NOW).envelope
    env = build_envelope(decision="ELIGIBLE", target_url=TARGET, call=call(), policy_pin=PIN)
    return sign_envelope(env, priv, KID)


def consumer(**over):
    kw = dict(target_id=TARGET, pinned_public_keys={KID: pub}, record=PIN)
    kw.update(over)
    return Consumer(**kw)


# ---- construction: trust material is mandatory and unambiguous ----

def test_requires_exactly_one_pin_source():
    with pytest.raises(ValueError):
        Consumer(target_id=TARGET, pinned_public_keys={KID: pub})
    with pytest.raises(ValueError):
        Consumer(target_id=TARGET, pinned_public_keys={KID: pub}, record=PIN,
                 record_bytes=reference_record_bytes())


def test_requires_issuer_key_trust():
    """No keys at all: there is nothing to check provenance against."""
    with pytest.raises(ValueError):
        Consumer(target_id=TARGET, record=PIN)
    with pytest.raises(ValueError):
        Consumer(target_id=TARGET, record=PIN, key_record_view={}, key_record_source=lambda s: {})
    with pytest.raises(ValueError):
        consumer(clock_skew=timedelta(seconds=-1))


# ---- the honor path and the two rules that are not optional ----

def test_honors_once_then_refuses_replay():
    c = consumer()
    env = receipt()
    assert c.check(env, call(), now=NOW) == Verdict(True, ACCEPT_REASSERTED_AND_BOUND)
    assert c.check(env, call(), now=NOW) == Verdict(False, REF_VERIFY_REPLAY)


def test_unsigned_receipt_is_refused_even_with_an_empty_key_map():
    c = consumer(pinned_public_keys={})
    env = receipt()
    assert c.check(env, call(), now=NOW).reason == REF_VERIFY_SIGNATURE_UNKNOWN_KEY
    forged = {k: v for k, v in env.items() if k != "issuer_signature"}
    assert consumer().check(forged, call(), now=NOW).reason == REF_VERIFY_SIGNATURE_INVALID


def test_receipt_without_decision_id_is_refused():
    c = consumer()
    assert c.check(receipt(decision_id=False), call(), now=NOW) == (False, REF_TARGET_NO_DECISION_ID)
    assert c.check(None, call(), now=NOW).honored is False
    assert c.check(receipt(), {**call(), "extra": 1}, now=NOW) == (False, REF_VERIFY_BINDING_MISMATCH)


def test_replay_claim_outlives_not_after_by_the_skew():
    skew = timedelta(seconds=60)
    c = consumer(clock_skew=skew)
    env = receipt()                      # not_after = NOW + 300 s
    assert c.check(env, call(), now=NOW).honored is True
    inside_skew = NOW + timedelta(seconds=330)
    assert c.check(env, call(), now=inside_skew) == (False, REF_VERIFY_REPLAY)


# ---- anchored bytes ----

def test_record_bytes_are_anchored():
    raw = reference_record_bytes()
    ok = Consumer(target_id=TARGET, pinned_public_keys={KID: pub}, record_bytes=raw)
    assert ok._pinned_root == anchor_sha256(raw)
    bad = Consumer(target_id=TARGET, pinned_public_keys={KID: pub}, record_bytes=raw,
                   pinned_root="0" * 64)
    assert bad.check(receipt(), call(), now=NOW) == (False, REF_TARGET_ANCHOR_MISMATCH)
    # A receipt under another pin than the anchored record's is not current.
    assert ok.check(receipt(), call(), now=NOW).honored is False
    assert reference_pin() != PIN


# ---- a record source: consulted every check, serial threaded, fail closed ----

def test_record_source_threads_the_high_water_mark_and_refuses_rollback():
    seen = []
    state = {"serial": 10}

    def source(last_seen_serial):
        seen.append(last_seen_serial)
        if last_seen_serial is not None and state["serial"] < last_seen_serial:
            return {"record": None, "reason": REF_VERIFY_PUBLISHED_RECORD_STALE}
        return {"record": {**PIN, "serial": state["serial"]}, "reason": None}

    c = consumer(record=None, record_source=source)
    assert c.check(receipt(), call(), now=NOW).honored is True
    assert seen == [None] and c.high_water.record_serial == 10
    state["serial"] = 12
    assert c.check(receipt(), call(), now=NOW).honored is True
    assert seen[-1] == 10 and c.high_water.record_serial == 12
    state["serial"] = 11                                   # rolled back, still fresh
    assert c.check(receipt(), call(), now=NOW) == (False, REF_VERIFY_PUBLISHED_RECORD_STALE)
    assert seen[-1] == 12


@pytest.mark.parametrize("result,reason", [
    ({"record": None, "reason": None}, REF_TARGET_ANCHOR_MISMATCH),
    ({"record": None, "reason": "REF_VERIFY_PUBLISHED_RECORD_INVALID"}, REF_VERIFY_PUBLISHED_RECORD_INVALID),
    ("garbage", REF_TARGET_ANCHOR_MISMATCH),
    (RuntimeError("publisher down"), REF_VERIFY_PUBLISHED_RECORD_INVALID),
])
def test_record_source_failure_refuses(result, reason):
    def source(last_seen_serial):
        if isinstance(result, Exception):
            raise result
        return result
    c = consumer(record=None, record_source=source)
    assert c.check(receipt(), call(), now=NOW) == (False, reason)


# ---- a key record source: the only key trust when present ----

def _view(revoked=False):
    return {KID: {"public_key": pub, "revoked": revoked,
                  "not_before": NOW - timedelta(days=1), "not_after": NOW + timedelta(days=1),
                  "role": "issuer"}}


def test_key_record_source_replaces_the_static_pin_and_tracks_its_serial():
    seen = []

    def source(last_seen_serial):
        seen.append(last_seen_serial)
        return {"trust_view": _view(), "reason": None, "serial": 7}

    c = consumer(pinned_public_keys=None, key_record_source=source)
    assert c.check(receipt(), call(), now=NOW).honored is True
    assert seen == [None] and c.high_water.key_record_serial == 7

    def revoked(last_seen_serial):
        return {"trust_view": _view(revoked=True), "reason": None, "serial": 8}

    c = consumer(key_record_source=revoked)   # static pin present but ignored
    assert c.check(receipt(), call(), now=NOW).reason == "REF_VERIFY_KEY_REVOKED"


@pytest.mark.parametrize("result,reason", [
    ({"trust_view": None, "reason": REF_VERIFY_KEY_RECORD_STALE}, REF_VERIFY_KEY_RECORD_STALE),
    ({"trust_view": None, "reason": None}, REF_VERIFY_KEY_RECORD_INVALID),
    (None, REF_VERIFY_KEY_RECORD_INVALID),
    (RuntimeError("down"), REF_VERIFY_KEY_RECORD_INVALID),
])
def test_key_record_source_failure_never_falls_back_to_the_pin(result, reason):
    def source(last_seen_serial):
        if isinstance(result, Exception):
            raise result
        return result
    c = consumer(key_record_source=source)
    assert c.check(receipt(), call(), now=NOW) == (False, reason)


def test_shared_high_water_and_replay_cache_span_consumers():
    """Two consumers for the same target (the reference target builds one per
    request) share single use and the rollback floor through injected state."""
    hw = HighWater()
    hw.advance_record(5); hw.advance_record(3); hw.advance_record(True)
    assert hw.record_serial == 5
    a = consumer(high_water=hw)
    b = consumer(high_water=hw, replay_cache=a.replay_cache)
    env = receipt()
    assert a.check(env, call(), now=NOW).honored is True
    assert b.check(env, call(), now=NOW) == (False, REF_VERIFY_REPLAY)


# ---- flagged receipts: the human-held key is required at execution ----

from gargoyle.approval import (  # noqa: E402
    REF_APPROVAL_BINDING_MISMATCH, REF_APPROVAL_REPLAY, REF_APPROVAL_SOD, REF_APPROVAL_KEY_UNKNOWN,
    build_grant, sign_grant,
)
from gargoyle.consumer import REF_TARGET_APPROVAL_REQUIRED, REF_TARGET_NO_APPROVER_TRUST  # noqa: E402
from gargoyle.verifier import REF_VERIFY_SIGNATURE_INVALID as _SIG_INVALID  # noqa: E402

approver = Ed25519PrivateKey.generate(); AKID = "approver-alice"


class FlagAll(AllowAll):
    def decide(self, target_url, interaction):
        return Decision(ELIGIBLE, requires_approval=True)


def flagged():
    return issue(FlagAll(), TARGET, call(), signing_key=priv, key_id=KID, now=NOW).envelope


def grant_for(env, signer=approver, kid=AKID, grant_id="g-1", decision_sha256=None):
    g = build_grant(decision_sha256=decision_sha256 or env["decision_sha256"],
                    approval_request_id=env["approval_request_id"], grant_id=grant_id,
                    not_after=NOW + timedelta(minutes=10))
    return sign_grant(g, signer, kid)


def approving_consumer(**over):
    return consumer(approver_public_keys={AKID: approver.public_key()}, **over)


def test_flagged_receipt_is_issued_with_a_signed_hold():
    env = flagged()
    assert env["requires_approval"] is True and env["approval_request_id"]
    free = receipt()
    assert free["requires_approval"] is False and "approval_request_id" not in free


def test_flagged_receipt_needs_a_grant():
    c = approving_consumer()
    env = flagged()
    assert c.check(env, call(), now=NOW) == (False, REF_TARGET_APPROVAL_REQUIRED)
    assert c.check(env, call(), grant=grant_for(env), now=NOW).honored is True


def test_flagged_receipt_without_approver_trust_is_never_honored():
    c = consumer()                        # no approver keys at all
    env = flagged()
    assert c.check(env, call(), grant=grant_for(env), now=NOW) == (False, REF_TARGET_NO_APPROVER_TRUST)


def test_hold_cannot_be_stripped_from_a_flagged_receipt():
    """requires_approval is inside the signature: flipping it, or dropping
    the hold id, breaks provenance before the hold is even considered."""
    env = flagged()
    stripped = dict(env); stripped["requires_approval"] = False
    assert approving_consumer().check(stripped, call(), now=NOW) == (False, _SIG_INVALID)
    unnamed = dict(env); del unnamed["approval_request_id"]
    assert approving_consumer().check(unnamed, call(), grant=grant_for(env), now=NOW).reason == "REF_VERIFY_ENVELOPE_ABSENT"


def test_grant_must_name_this_decision_and_hold():
    c = approving_consumer()
    env = flagged()
    other = issue(FlagAll(), TARGET, call(principal="agent-8"), signing_key=priv, key_id=KID, now=NOW).envelope
    wrong_decision = grant_for(env, decision_sha256=other["decision_sha256"])
    assert c.check(env, call(), grant=wrong_decision, now=NOW) == (False, REF_APPROVAL_BINDING_MISMATCH)
    reissued = flagged()                  # same decision, another hold id
    assert c.check(reissued, call(), grant=grant_for(env), now=NOW).reason == "REF_APPROVAL_REQUEST_MISMATCH"


def test_issuer_cannot_approve_its_own_receipt():
    c = consumer(approver_public_keys={KID: pub, AKID: approver.public_key()})
    env = flagged()
    self_signed = grant_for(env, signer=priv, kid=KID)
    assert c.check(env, call(), grant=self_signed, now=NOW) == (False, REF_APPROVAL_SOD)
    stranger = Ed25519PrivateKey.generate()
    assert c.check(env, call(), grant=grant_for(env, signer=stranger, kid="nobody"), now=NOW) == (False, REF_APPROVAL_KEY_UNKNOWN)


def test_grant_is_single_use_and_a_refused_grant_leaves_the_receipt_unspent():
    c = approving_consumer()
    env1, env2 = flagged(), flagged()
    g = grant_for(env1)
    # A grant for env1 presented with env2 is refused, and env2 stays spendable.
    assert c.check(env2, call(), grant=g, now=NOW).honored is False
    assert c.check(env2, call(), grant=grant_for(env2, grant_id="g-2"), now=NOW).honored is True
    # The honored grant g-1 cannot release a third hold even if it matched.
    assert c.check(env1, call(), grant=g, now=NOW).honored is True
    env3 = flagged()
    g_replayed = grant_for(env3, grant_id="g-1")
    assert c.check(env3, call(), grant=g_replayed, now=NOW) == (False, REF_APPROVAL_REPLAY)


def test_approver_keys_come_from_the_key_record_when_one_is_in_use():
    """With a key record, only its approver-role keys can approve; a pinned
    approver map is ignored, and an issuer-role key in the record cannot."""
    view = {
        KID: {"public_key": pub, "revoked": False, "role": "issuer",
              "not_before": NOW - timedelta(days=1), "not_after": NOW + timedelta(days=1)},
        AKID: {"public_key": approver.public_key(), "revoked": False, "role": "approver",
               "not_before": NOW - timedelta(days=1), "not_after": NOW + timedelta(days=1)},
    }
    c = consumer(pinned_public_keys=None, key_record_view=view)
    env = flagged()
    assert c.check(env, call(), grant=grant_for(env), now=NOW).honored is True
    pinned_only = Ed25519PrivateKey.generate()
    c2 = consumer(pinned_public_keys=None, key_record_view=view,
                  approver_public_keys={"pinned": pinned_only.public_key()})
    env2 = flagged()
    assert c2.check(env2, call(), grant=grant_for(env2, signer=pinned_only, kid="pinned"), now=NOW) == (False, REF_APPROVAL_KEY_UNKNOWN)
    no_approver_role = {KID: view[KID]}
    c3 = consumer(pinned_public_keys=None, key_record_view=no_approver_role)
    assert c3.check(flagged(), call(), grant=grant_for(env), now=NOW) == (False, REF_TARGET_NO_APPROVER_TRUST)
