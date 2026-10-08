"""
VL-041 canon/spec-derived tests for issuer-key validity windows (expiry).

Derivation: artifact 05 "Issuer signature (opt-in)" (the not_after field, the
signed-region placement, the decision_sha256 exclusion) + canon section 9
(fail-closed) + the VL-040 follow-up 2 verdict (expiry is the time-bounded
answer to the compromised-key decisive failure). reassert() runs pure via
record_source; `now` is injected for determinism. The signed path only:
expiry is meaningless without a verified signature.
"""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from IMPLEMENTATION.envelope import (
    canonical_json, _sha256_text, _HASH_EXCLUDED_KEYS, _SIGNATURE_EXCLUDED_KEYS,
    sign_envelope,
)
from IMPLEMENTATION.verifier import (
    verify_envelope, ACCEPT_REASSERTED_AND_BOUND,
    REF_VERIFY_SIGNATURE_EXPIRED, REF_VERIFY_SIGNATURE_INVALID,
)

C, E, M = "a" * 64, "b" * 64, "c" * 64
TARGET = "https://target.example/act"
NOW = datetime(2026, 6, 2, 12, 0, 0, tzinfo=timezone.utc)
REC = {"canon_sha256": C, "evaluator_sha256": E, "manifest_sha256": M}
INTER = {"AP": ["role", "identity"], "OP": ["request", "session"],
         "context": {"k": "v"}, "expected_manifest_version": "1.0",
         "expected_manifest_sha256": M}


def _env():
    env = {
        "envelope_version": "1.0", "decision": "ELIGIBLE", "target_url": TARGET,
        "canon": {"version": "0.9.8.4", "canon_sha256": C},
        "evaluated_against": {"manifest_version": "1.0", "manifest_sha256": M},
        "request_context": {"AP": ["identity", "role"], "OP": ["session", "request"],
                            "context": {"k": "v"}, "expected_manifest_version": "1.0",
                            "expected_manifest_sha256": M},
        "evaluator": {"version": "0.9.8.4", "evaluator_sha256": E},
        "condition_results": {"ac3": True, "t26": True, "manifest_integrity": True, "ccs": None},
        "timestamp_utc": "2026-06-02T00:00:00+00:00",
    }
    hashable = {k: v for k, v in env.items() if k not in _HASH_EXCLUDED_KEYS}
    env["decision_sha256"] = _sha256_text(canonical_json(hashable))
    return env


@pytest.fixture
def keys():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def _vfy(env, pub, **kw):
    return verify_envelope(env, INTER, TARGET, record_source=REC,
                           pinned_public_keys={"k1": pub}, **kw)


def test_not_after_in_signed_region_not_in_hash_region():
    # Checkpoint B decision encoded as a test (artifact 05).
    assert "not_after" in _HASH_EXCLUDED_KEYS
    assert "not_after" not in _SIGNATURE_EXCLUDED_KEYS


def test_signed_no_expiry_honored(keys):
    # VL-040 compat: absent not_after means no expiry.
    priv, pub = keys
    e = sign_envelope(_env(), priv, "k1")
    assert _vfy(e, pub, now=NOW)["reason"] == ACCEPT_REASSERTED_AND_BOUND


def test_future_window_honored(keys):
    priv, pub = keys
    e = sign_envelope(_env(), priv, "k1", not_after=NOW + timedelta(hours=1))
    assert _vfy(e, pub, now=NOW)["reason"] == ACCEPT_REASSERTED_AND_BOUND


def test_past_window_refused_expired(keys):
    priv, pub = keys
    e = sign_envelope(_env(), priv, "k1", not_after=NOW - timedelta(seconds=1))
    assert _vfy(e, pub, now=NOW)["reason"] == REF_VERIFY_SIGNATURE_EXPIRED


def test_boundary_now_equals_not_after_refused(keys):
    # Strict: valid iff now < not_after (canon section 9 fail-closed at the edge).
    priv, pub = keys
    e = sign_envelope(_env(), priv, "k1", not_after=NOW)
    assert _vfy(e, pub, now=NOW)["reason"] == REF_VERIFY_SIGNATURE_EXPIRED


def test_extend_not_after_breaks_signature(keys):
    # not_after is tamper-proof because it is inside the signed region.
    priv, pub = keys
    e = sign_envelope(_env(), priv, "k1", not_after=NOW + timedelta(hours=1))
    e = dict(e); e["not_after"] = (NOW + timedelta(days=3650)).isoformat()
    assert _vfy(e, pub, now=NOW)["reason"] == REF_VERIFY_SIGNATURE_INVALID


def test_decision_sha256_unchanged_by_not_after(keys):
    # VL-040 no-op property preserved.
    priv, pub = keys
    base = _env()["decision_sha256"]
    e_none = sign_envelope(_env(), priv, "k1")
    e_exp = sign_envelope(_env(), priv, "k1", not_after=NOW + timedelta(hours=1))
    assert e_none["decision_sha256"] == e_exp["decision_sha256"] == base


def test_malformed_not_after_fails_closed(keys):
    # A signed-but-garbage not_after is treated as expired (fail-closed).
    priv, pub = keys
    e = _env(); e["not_after"] = "not-a-timestamp"
    e = sign_envelope(e, priv, "k1")  # sign the garbage so the signature is valid
    assert _vfy(e, pub, now=NOW)["reason"] == REF_VERIFY_SIGNATURE_EXPIRED


def test_naive_not_after_fails_closed(keys):
    # A tz-naive not_after cannot be safely compared -> fail-closed.
    priv, pub = keys
    e = _env(); e["not_after"] = "2026-06-02T13:00:00"  # no tzinfo
    e = sign_envelope(e, priv, "k1")
    assert _vfy(e, pub, now=NOW)["reason"] == REF_VERIFY_SIGNATURE_EXPIRED


def test_sign_rejects_naive_not_after(keys):
    # The issuer side refuses to stamp a naive not_after.
    priv, _ = keys
    with pytest.raises(ValueError):
        sign_envelope(_env(), priv, "k1", not_after=datetime(2026, 6, 2, 13, 0, 0))


def test_expired_on_unsigned_path_not_checked(keys):
    # Expiry is a signed-path concern: with pinned_public_keys=None the
    # not_after field is not consulted (an unsigned not_after is forgeable;
    # only the signed path enforces it). Honored via reassert+binding.
    priv, _ = keys
    e = _env(); e["not_after"] = (NOW - timedelta(days=1)).isoformat()
    r = verify_envelope(e, INTER, TARGET, record_source=REC, now=NOW)
    assert r["reason"] == ACCEPT_REASSERTED_AND_BOUND
