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
    """No keys at all would put verify_envelope on its unsigned path."""
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
