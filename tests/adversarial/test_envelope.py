"""Receipt construction, the policy-pin reassertion check, and canonical JSON."""

import json

import pytest

from gargoyle.envelope import (
    ENVELOPE_VERSION,
    INVALIDATED,
    RE_EVALUATE_REQUIRED,
    REASSERTED,
    args_sha256,
    build_envelope,
    canonical_json,
    decision_sha256_of,
    live_pin,
    reassert,
)
from gargoyle.policy import ManifestPolicy

TARGET = "http://127.0.0.1:9000/target"


def _call(args=None, principal="agent-7"):
    return {"tool": "transfer", "args": {"amount": 5} if args is None else args,
            "principal": principal}


def _env(timestamp_utc=None, pin=None, call=None):
    return build_envelope(
        decision="ELIGIBLE",
        target_url=TARGET,
        call=call or _call(),
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
    assert set(env["request_context"]) == {"tool", "args_sha256", "principal"}


def test_args_bound_by_canonical_hash():
    """The receipt stores a hash of the arguments over canonical JSON, so key
    order does not matter and the receipt stays small whatever the args."""
    env = _env(call=_call(args={"b": 2, "a": {"y": 1, "x": [1, 2]}}))
    rc = env["request_context"]
    assert rc["args_sha256"] == args_sha256({"a": {"x": [1, 2], "y": 1}, "b": 2})
    assert "args" not in rc
    assert args_sha256(None) != args_sha256({}) != args_sha256([])


def test_policy_inputs_are_not_recorded():
    """Only tool, args and principal are bound; what the policy was shown
    beyond them (claims, manifest pins) is represented by the policy pin."""
    env = _env(call=dict(_call(), AP=["identity"], expected_manifest_version="1.0"))
    assert set(env["request_context"]) == {"tool", "args_sha256", "principal"}


@pytest.mark.parametrize("bad", [None, "", 7, ["transfer"]])
def test_build_rejects_malformed_tool(bad):
    with pytest.raises((ValueError, TypeError)):
        _env(call=dict(_call(), tool=bad))


def test_build_rejects_missing_bound_field():
    for key in ("tool", "args", "principal"):
        c = _call(); del c[key]
        with pytest.raises(KeyError):
            _env(call=c)
    with pytest.raises(TypeError):
        _env(call=["transfer"])


@pytest.mark.parametrize("pin", [None, {}, {"policy_id": "x"}, {"policy_id": "", "policy_sha256": "a" * 64},
                                 {"policy_id": "x", "policy_sha256": "short"}])
def test_build_rejects_malformed_pin(pin):
    with pytest.raises((ValueError, TypeError)):
        build_envelope(decision="ELIGIBLE", target_url=TARGET,
                       call=_call(), policy_pin=pin)


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


def test_decision_sha256_covers_tool_args_and_principal():
    base = _env()["decision_sha256"]
    assert _env(call=dict(_call(), tool="delete"))["decision_sha256"] != base
    assert _env(call=_call(args={"amount": 6}))["decision_sha256"] != base
    assert _env(call=_call(principal="agent-8"))["decision_sha256"] != base


# --- reassert ---------------------------------------------------------------

def test_reassert_current_receipt():
    assert reassert(_env()) == {"outcome": REASSERTED}


def test_reassert_tampered_receipt_is_invalidated():
    env = _env()
    env["request_context"]["tool"] = "delete_database"
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
    s = canonical_json({"b": 2, "a": {"k": "caf\u00e9"}})
    assert " " not in s and "\n" not in s
    assert "\\u00e9" in s and "\u00e9" not in s
    assert json.loads(s) == {"a": {"k": "caf\u00e9"}, "b": 2}
