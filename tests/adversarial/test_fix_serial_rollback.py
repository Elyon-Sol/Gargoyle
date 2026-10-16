"""
Rollback protection: the enforcing target passes its highest seen record
serial into the signed-record fetch, so an older (lower-serial) record that
is still inside its not_after window is refused instead of honored.
"""
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from reference import reference_policy
from gargoyle.policy import ManifestPolicy
from gargoyle.envelope import build_envelope, sign_envelope
from gargoyle.reference_target import build_reference_target_app
from gargoyle.replay_cache import InMemoryReplayCache
from gargoyle.verifier import REF_VERIFY_PUBLISHED_RECORD_STALE

TARGET = "https://target.example.com:9443/target"
KID = "gate-ed25519-001"
priv = Ed25519PrivateKey.generate()

def inter():
    return {"tool": "transfer", "args": {"amount": 5}, "principal": "agent-7"}

def signed_env(did):
    e = build_envelope(
        policy_pin=reference_policy().pin(),decision="ELIGIBLE", target_url=TARGET, call=inter(),
                       timestamp_utc="2026-07-11T00:00:00+00:00")
    return sign_envelope(e, priv, KID, decision_id=did)

_e0 = signed_env("d0")
PINS = dict(_e0["policy"])

def make():
    cfg = {"target_url": TARGET, "publisher_url": "http://pub", "pinned_root_sha256": "x",
           "pinned_public_keys": {KID: priv.public_key()}, "principal_header": "X-Peer",
           "pinned_publisher_keys": {"pub-1": object()},  # truthy -> signed mode
           "signed_record_url": "http://pub/signed"}
    st = {"serial": 200, "seen": []}
    def signed_fetch(url, keys, now=None, last_seen_serial=None):
        st["seen"].append(last_seen_serial)
        s = st["serial"]
        if last_seen_serial is not None and s < last_seen_serial:
            return {"record": None, "reason": REF_VERIFY_PUBLISHED_RECORD_STALE}
        return {"record": {"serial": s, **PINS}, "reason": None}
    app = build_reference_target_app(config_provider=lambda: cfg, signed_fetch=signed_fetch,
                                     replay_cache=InMemoryReplayCache())
    return TestClient(app), st

def post(c, env):
    return c.post("/target", json={"tool": "transfer", "args": {"amount": 5}},
                  headers={"X-Gargoyle-Envelope": json.dumps(env), "X-Peer": "agent-7"})

def test_rollback_refused():
    c, st = make()
    st["serial"] = 200
    assert post(c, signed_env("d1")).status_code == 200          # honored, high-water -> 200
    assert st["seen"][-1] is None                                # first fetch: no high-water yet
    st["serial"] = 100                                           # a rolled-back, still-fresh record
    r = post(c, signed_env("d2"))
    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == REF_VERIFY_PUBLISHED_RECORD_STALE
    assert st["seen"][-1] == 200                                 # the app THREADED the high-water mark

def test_monotonic_advance_ok():
    c, st = make()
    st["serial"] = 200; assert post(c, signed_env("a")).status_code == 200
    st["serial"] = 300; assert post(c, signed_env("b")).status_code == 200   # advance honored
    assert st["seen"][-1] == 200
    st["serial"] = 250                                           # below the new high-water 300
    r = post(c, signed_env("c"))
    assert r.status_code == 403 and r.json()["detail"]["reason"] == REF_VERIFY_PUBLISHED_RECORD_STALE
    assert st["seen"][-1] == 300
