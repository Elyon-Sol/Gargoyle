"""
Binding and replay hardening: exact binding of the request body (extra fields
are refused), decision_id required on the signed path as the replay key, and
replay records kept for not_after plus the clock-skew allowance so a receipt
cannot be replayed inside the skew window.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.policy import ManifestPolicy
from gargoyle.envelope import build_envelope, sign_envelope
from gargoyle.verifier import verify_envelope, REF_VERIFY_BINDING_MISMATCH, REF_VERIFY_REPLAY
from gargoyle.reference_target import build_reference_target_app, REF_TARGET_NO_DECISION_ID
from gargoyle.replay_cache import InMemoryReplayCache

TARGET = "https://target.example.com:9443/target"
KID = "gate-ed25519-001"
priv = Ed25519PrivateKey.generate()

PRINCIPAL = "agent-7"

def inter():
    return {"tool": "transfer", "args": {"amount": 5}, "principal": PRINCIPAL}

def signed(decision_id="d1", not_after=None):
    e = build_envelope(
        policy_pin=ManifestPolicy().pin(),decision="ELIGIBLE", target_url=TARGET, call=inter(),
                       timestamp_utc="2026-07-09T00:00:00+00:00")
    return sign_envelope(e, priv, KID, not_after=not_after, decision_id=decision_id)

def record_for(env):
    return dict(env["policy"])

def client_for(env, cache=None):
    cfg = {"target_url": TARGET, "publisher_url": "http://pub", "pinned_root_sha256": "anchor",
           "pinned_public_keys": {KID: priv.public_key()}, "principal_header": "X-Peer"}
    rec = record_for(env)
    app = build_reference_target_app(config_provider=lambda: cfg, fetch=lambda url, anchor: rec,
                                     replay_cache=cache or InMemoryReplayCache())
    return TestClient(app)

def post(client, env, call):
    body = {"tool": call["tool"], "args": call["args"]}
    return client.post("/target", json=body,
                       headers={"X-Gargoyle-Envelope": json.dumps(env), "X-Peer": call["principal"]})

# ---- exact binding ----
def test_f1_extra_body_fields_rejected():
    env = signed()
    r = verify_envelope(env, {**inter(), "evil_cmd": "rm -rf /"}, TARGET,
                        pinned_public_keys={KID: priv.public_key()})
    assert r["accepted"] is False and r["reason"] == REF_VERIFY_BINDING_MISMATCH

def test_f1_exact_body_still_accepted():
    env = signed()
    r = verify_envelope(env, inter(), TARGET, pinned_public_keys={KID: priv.public_key()})
    assert r["accepted"] is True

# ---- decision_id required ----
def test_f2_no_decision_id_fails_closed():
    env = signed(decision_id=None)
    r = post(client_for(env), env, inter())
    assert r.status_code == 403 and r.json()["detail"]["reason"] == REF_TARGET_NO_DECISION_ID

def test_f2_control_decision_id_present_replay_caught():
    env = signed(decision_id="d1")
    c = client_for(env)
    assert post(c, env, inter()).status_code == 200
    r2 = post(c, env, inter())
    assert r2.status_code == 403 and r2.json()["detail"]["reason"] == REF_VERIFY_REPLAY

# ---- replay records outlive not_after by the skew allowance ----
def test_f3_retention_closes_skew_window():
    now0 = datetime(2026,7,9,12,0,0,tzinfo=timezone.utc)
    na = now0 + timedelta(seconds=10)
    skew = timedelta(seconds=60)
    c = InMemoryReplayCache()
    # reference_target now claims with exp = not_after + skew:
    assert c.check_and_claim("d", na + skew, now=now0) is True
    later = now0 + timedelta(seconds=20)          # past not_after, within skew
    assert c.check_and_claim("d", na + skew, now=later) is False   # still retained -> replay refused
