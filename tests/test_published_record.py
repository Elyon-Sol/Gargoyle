"""The signed published record: the live policy pin a remote consumer
fetches, trusted by the publisher's signature, with freshness and a serial
so a rolled-back record is refused."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.consumer import Consumer
from gargoyle.envelope import canonical_json
from gargoyle.issuer import issue
from gargoyle.policy import ELIGIBLE, Decision
from gargoyle.published_record_source import (
    PUBLISHED_RECORD_FORMAT, fetch_signed_record, load_signed_record_from_bytes,
)
from gargoyle.verifier import REF_VERIFY_PUBLISHED_RECORD_INVALID, REF_VERIFY_PUBLISHED_RECORD_STALE

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
publisher = Ed25519PrivateKey.generate(); PUB = {"pub-1": publisher.public_key()}
PIN = {"policy_id": "gargoyle.rules/1", "policy_sha256": "a" * 64}


def record(serial=1, not_after=None, pin=PIN, signer=publisher, kid="pub-1"):
    doc = {"format": PUBLISHED_RECORD_FORMAT, "version": 1, "publisher_key_id": kid, "serial": serial,
           "issued_at": NOW.isoformat(), "not_after": (not_after or NOW + timedelta(hours=1)).isoformat(), **pin}
    doc["publisher_signature"] = signer.sign(canonical_json(doc).encode()).hex()
    return json.dumps(doc).encode()


def test_valid_record_is_loaded_with_its_pin():
    res = load_signed_record_from_bytes(record(), PUB, now=NOW)
    assert res["reason"] is None and res["record"]["policy_sha256"] == "a" * 64 and res["record"]["serial"] == 1


@pytest.mark.parametrize("raw,reason", [
    (b"not json", REF_VERIFY_PUBLISHED_RECORD_INVALID),
    (record(kid="unknown"), REF_VERIFY_PUBLISHED_RECORD_INVALID),
    (record(signer=Ed25519PrivateKey.generate()), REF_VERIFY_PUBLISHED_RECORD_INVALID),
    (record(not_after=NOW - timedelta(seconds=1)), REF_VERIFY_PUBLISHED_RECORD_STALE),
])
def test_refusals(raw, reason):
    assert load_signed_record_from_bytes(raw, PUB, now=NOW)["reason"] == reason
    assert load_signed_record_from_bytes(record(), {}, now=NOW)["reason"] == REF_VERIFY_PUBLISHED_RECORD_INVALID


def test_rollback_is_stale_and_skew_widens_freshness():
    assert load_signed_record_from_bytes(record(serial=3), PUB, now=NOW, last_seen_serial=5)["reason"] == REF_VERIFY_PUBLISHED_RECORD_STALE
    assert load_signed_record_from_bytes(record(serial=5), PUB, now=NOW, last_seen_serial=5)["reason"] is None
    just_expired = record(not_after=NOW - timedelta(seconds=30))
    assert load_signed_record_from_bytes(just_expired, PUB, now=NOW)["reason"] == REF_VERIFY_PUBLISHED_RECORD_STALE
    assert load_signed_record_from_bytes(just_expired, PUB, now=NOW, clock_skew=timedelta(seconds=60))["reason"] is None
    with pytest.raises(ValueError):
        load_signed_record_from_bytes(record(), PUB, now=NOW, clock_skew=timedelta(seconds=-1))


def test_fetch_wraps_transport_failures():
    class R:
        def __init__(self, code, body): self.status_code, self.content = code, body
    import gargoyle.published_record_source as prs
    calls = []
    prs.requests.get = lambda url, timeout=None, verify=True: (calls.append((url, verify)), R(200, record()))[1]
    try:
        assert fetch_signed_record("https://pub.example/record", PUB, now=NOW)["reason"] is None
        assert calls[-1][1] is True
        prs.requests.get = lambda url, timeout=None, verify=True: R(503, b"")
        assert fetch_signed_record("https://pub.example/record", PUB, now=NOW)["reason"] == REF_VERIFY_PUBLISHED_RECORD_INVALID
        def boom(url, timeout=None, verify=True): raise ConnectionError("down")
        prs.requests.get = boom
        assert fetch_signed_record("https://pub.example/record", PUB, now=NOW)["reason"] == REF_VERIFY_PUBLISHED_RECORD_INVALID
    finally:
        import importlib; importlib.reload(prs)


def test_consumer_follows_a_signed_record_source_and_refuses_rollback():
    class AllowAll:
        def pin(self): return PIN
        def decide(self, t, i): return Decision(ELIGIBLE)
    issuer = Ed25519PrivateKey.generate()
    state = {"serial": 10}
    def source(last_seen):
        return load_signed_record_from_bytes(record(serial=state["serial"]), PUB, now=NOW, last_seen_serial=last_seen)
    c = Consumer(target_id="t", pinned_public_keys={"k1": issuer.public_key()}, record_source=source)
    env = issue(AllowAll(), "t", {"tool": "x", "args": {}, "principal": "p"}, signing_key=issuer, key_id="k1", now=NOW).envelope
    assert c.check(env, {"tool": "x", "args": {}, "principal": "p"}, now=NOW).honored is True
    state["serial"] = 9
    env2 = issue(AllowAll(), "t", {"tool": "x", "args": {}, "principal": "p"}, signing_key=issuer, key_id="k1", now=NOW).envelope
    assert c.check(env2, {"tool": "x", "args": {}, "principal": "p"}, now=NOW) == (False, REF_VERIFY_PUBLISHED_RECORD_STALE)
