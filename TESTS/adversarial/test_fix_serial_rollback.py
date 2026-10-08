"""SES-8 regression: the enforcing target threads a monotonic serial high-water
mark into the signed-record fetch, so a rolled-back (lower-serial) but still-fresh
record is refused instead of honored inside its not_after window."""
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from IMPLEMENTATION.envelope import build_envelope, sign_envelope
from IMPLEMENTATION.evaluator import load_manifest, manifest_sha256
from IMPLEMENTATION.reference_target import build_reference_target_app
from IMPLEMENTATION.replay_cache import InMemoryReplayCache
from IMPLEMENTATION.verifier import REF_VERIFY_PUBLISHED_RECORD_STALE

TARGET = "https://target.elyon-sol.io:9443/target"
KID = "gate-ed25519-001"
priv = Ed25519PrivateKey.generate()

def inter():
    return {"AP": ["identity","role"], "OP": ["session","request"], "context": {},
            "expected_manifest_version": "1.0", "expected_manifest_sha256": manifest_sha256()}

def signed_env(did):
    e = build_envelope(decision="ELIGIBLE", target_url=TARGET, normalized_interaction=inter(),
                       manifest=load_manifest(), ac3=True, t26=True, manifest_integrity=True,
                       timestamp_utc="2026-07-11T00:00:00+00:00")
    return sign_envelope(e, priv, KID, decision_id=did)

_e0 = signed_env("d0")
PINS = {"canon_sha256": _e0["canon"]["canon_sha256"],
        "evaluator_sha256": _e0["evaluator"]["evaluator_sha256"],
        "manifest_sha256": _e0["evaluated_against"]["manifest_sha256"]}

def make():
    cfg = {"target_url": TARGET, "publisher_url": "http://pub", "pinned_root_sha256": "x",
           "pinned_public_keys": {KID: priv.public_key()},
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
    return c.post("/target", json=inter(), headers={"X-Elyon-Sol-Envelope": json.dumps(env)})

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
