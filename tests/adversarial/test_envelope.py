"""Receipt construction, the policy-pin reassertion check, and canonical JSON."""

import json

import pytest

from gargoyle.envelope import (
    ENVELOPE_VERSION,
    INVALIDATED,
    RE_EVALUATE_REQUIRED,
    REASSERTED,
    build_envelope,
    canonical_json,
    decision_sha256_of,
    live_pin,
    reassert,
)
from gargoyle.policy import ManifestPolicy, manifest_sha256

TARGET = "http://127.0.0.1:9000/target"


def _interaction():
    return {
        "AP": ["identity", "role"],
        "OP": ["session", "request"],
        "context": {},
        "expected_manifest_version": "1.0",
        "expected_manifest_sha256": manifest_sha256(),
    }


def _env(timestamp_utc=None, pin=None):
    return build_envelope(
        decision="ELIGIBLE",
        target_url=TARGET,
        normalized_interaction=_interaction(),
        policy_pin=pin or ManifestPolicy().pin(),
        timestamp_utc=timestamp_utc,
    )


def _rehash(env):
    env["decision_sha256"] = decision_sha256_of(env)
    return env


# --- construction -----------------------------------------------------------

def test_receipt_top_level_and_request_context_keys():
    env = _env()
    assert set(env) == {"envelope_version", "decision", "target_url", "policy",
                        "request_context", "timestamp_utc", "decision_sha256"}
    assert env["envelope_version"] == ENVELOPE_VERSION
    assert env["policy"] == ManifestPolicy().pin()
    assert set(env["request_context"]) == {"AP", "OP", "context", "expected_manifest_version",
                                           "expected_manifest_sha256"}


def test_interaction_type_is_recorded_only_when_declared():
    assert "interaction_type" not in _env()["request_context"]
    env = build_envelope(decision="ELIGIBLE", target_url=TARGET,
                         normalized_interaction=dict(_interaction(), interaction_type="read"),
                         policy_pin=ManifestPolicy().pin())
    assert env["request_context"]["interaction_type"] == "read"


@pytest.mark.parametrize("pin", [None, {}, {"policy_id": "x"}, {"policy_id": "", "policy_sha256": "a" * 64},
                                 {"policy_id": "x", "policy_sha256": "short"}])
def test_build_rejects_malformed_pin(pin):
    with pytest.raises((ValueError, TypeError)):
        build_envelope(decision="ELIGIBLE", target_url=TARGET,
                       normalized_interaction=_interaction(), policy_pin=pin)


def test_decision_sha256_is_hex_and_deterministic():
    a = _env("2026-05-21T00:00:00+00:00")
    b = _env("2026-05-21T00:00:00+00:00")
    assert len(a["decision_sha256"]) == 64 and set(a["decision_sha256"]) <= set("0123456789abcdef")
    assert canonical_json(a) == canonical_json(b)


def test_decision_sha256_ignores_timestamp():
    a = _env("2026-05-21T00:00:00+00:00")
    b = _env("2026-05-22T12:34:56+00:00")
    assert a["timestamp_utc"] != b["timestamp_utc"]
    assert a["decision_sha256"] == b["decision_sha256"]


def test_decision_sha256_covers_the_policy_pin():
    a = _env()
    b = _env(pin={"policy_id": "gargoyle.manifest-subset/1", "policy_sha256": "0" * 64})
    assert a["decision_sha256"] != b["decision_sha256"]


# --- reassert ---------------------------------------------------------------

def test_reassert_current_receipt():
    assert reassert(_env()) == {"outcome": REASSERTED}


def test_reassert_tampered_receipt_is_invalidated():
    env = _env()
    env["request_context"]["AP"] = ["identity", "role", "admin"]
    assert reassert(env)["outcome"] == INVALIDATED


@pytest.mark.parametrize("value", [None, 42, "0" * 64])
def test_reassert_missing_or_wrong_hash_is_invalidated(value):
    env = _env()
    env["decision_sha256"] = value
    assert reassert(env)["outcome"] == INVALIDATED


@pytest.mark.parametrize("field,value", [("policy_id", "other/2"), ("policy_sha256", "0" * 64)])
def test_reassert_policy_change_requires_re_evaluation(field, value):
    env = _env()
    env["policy"][field] = value
    _rehash(env)
    assert reassert(env)["outcome"] == RE_EVALUATE_REQUIRED


def test_reassert_checks_integrity_before_the_pin():
    env = _env()
    env["policy"]["policy_sha256"] = "0" * 64      # policy changed AND not re-hashed
    assert reassert(env)["outcome"] == INVALIDATED


def test_reassert_against_a_record_ignores_the_local_policy():
    env = _env(pin={"policy_id": "engine/1", "policy_sha256": "a" * 64})
    record = {"policy_id": "engine/1", "policy_sha256": "a" * 64}
    assert reassert(env)["outcome"] == RE_EVALUATE_REQUIRED          # local manifest differs
    assert reassert(env, record_source=record)["outcome"] == REASSERTED


def test_reassert_does_not_mutate_its_input():
    env = _env()
    before = canonical_json(env)
    reassert(env)
    assert canonical_json(env) == before


def test_live_pin_prefers_record_then_policy_then_default():
    rec = {"policy_id": "r/1", "policy_sha256": "c" * 64, "extra": 1}

    class P:
        def pin(self):
            return {"policy_id": "p/1", "policy_sha256": "d" * 64}

    assert live_pin(rec, P()) == {"policy_id": "r/1", "policy_sha256": "c" * 64}
    assert live_pin(None, P()) == {"policy_id": "p/1", "policy_sha256": "d" * 64}
    assert live_pin() == ManifestPolicy().pin()


# --- canonical JSON ---------------------------------------------------------

def test_canonical_json_sorted_compact_ascii():
    assert canonical_json({"b": 2, "a": 1, "c": {"y": 20, "x": 10}}) == canonical_json(
        {"a": 1, "c": {"x": 10, "y": 20}, "b": 2})
    s = canonical_json({"b": 2, "a": {"k": "café"}})
    assert " " not in s and "\n" not in s
    assert "\\u00e9" in s and "é" not in s
    assert json.loads(s) == {"a": {"k": "café"}, "b": 2}
