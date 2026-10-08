"""Regression tests for the red-team fixes F1 (exact binding), F2 (decision_id
backstop), F3 (skew-aware replay retention)."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from IMPLEMENTATION.envelope import build_envelope, sign_envelope
from IMPLEMENTATION.evaluator import load_manifest, manifest_sha256
from IMPLEMENTATION.verifier import verify_envelope, REF_VERIFY_BINDING_MISMATCH, REF_VERIFY_REPLAY
from IMPLEMENTATION.reference_target import build_reference_target_app, REF_TARGET_NO_DECISION_ID
from IMPLEMENTATION.replay_cache import InMemoryReplayCache

TARGET = "https://target.elyon-sol.io:9443/target"
KID = "gate-ed25519-001"
priv = Ed25519PrivateKey.generate()

def inter():
    return {"AP": ["identity","role"], "OP": ["session","request"], "context": {},
            "expected_manifest_version": "1.0", "expected_manifest_sha256": manifest_sha256()}

def signed(decision_id="d1", not_after=None):
    e = build_envelope(decision="ELIGIBLE", target_url=TARGET, normalized_interaction=inter(),
                       manifest=load_manifest(), ac3=True, t26=True, manifest_integrity=True,
                       timestamp_utc="2026-07-09T00:00:00+00:00")
    return sign_envelope(e, priv, KID, not_after=not_after, decision_id=decision_id)

def record_for(env):
    return {"canon_sha256": env["canon"]["canon_sha256"],
            "evaluator_sha256": env["evaluator"]["evaluator_sha256"],
            "manifest_sha256": env["evaluated_against"]["manifest_sha256"]}

def client_for(env, cache=None):
    cfg = {"target_url": TARGET, "publisher_url": "http://pub", "pinned_root_sha256": "anchor",
           "pinned_public_keys": {KID: priv.public_key()}}
    rec = record_for(env)
    app = build_reference_target_app(config_provider=lambda: cfg, fetch=lambda url, anchor: rec,
                                     replay_cache=cache or InMemoryReplayCache())
    return TestClient(app)

def post(client, env, body):
    return client.post("/target", json=body, headers={"X-Elyon-Sol-Envelope": json.dumps(env)})

# ---- F1: exact binding ----
def test_f1_extra_body_fields_rejected():
    env = signed()
    r = verify_envelope(env, {**inter(), "evil_cmd": "rm -rf /"}, TARGET,
                        pinned_public_keys={KID: priv.public_key()})
    assert r["accepted"] is False and r["reason"] == REF_VERIFY_BINDING_MISMATCH

def test_f1_exact_body_still_accepted():
    env = signed()
    r = verify_envelope(env, inter(), TARGET, pinned_public_keys={KID: priv.public_key()})
    assert r["accepted"] is True

# ---- F2: decision_id backstop ----
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

# ---- F3: skew-aware retention closes the replay window (retention principle) ----
def test_f3_retention_closes_skew_window():
    now0 = datetime(2026,7,9,12,0,0,tzinfo=timezone.utc)
    na = now0 + timedelta(seconds=10)
    skew = timedelta(seconds=60)
    c = InMemoryReplayCache()
    # reference_target now claims with exp = not_after + skew:
    assert c.check_and_claim("d", na + skew, now=now0) is True
    later = now0 + timedelta(seconds=20)          # past not_after, within skew
    assert c.check_and_claim("d", na + skew, now=later) is False   # still retained -> replay refused
