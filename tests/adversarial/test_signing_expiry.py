"""
Receipt expiry (not_after) on the signed path.

not_after is inside the signed region, so it cannot be extended, and outside
decision_sha256, so it does not change the decision hash. Expiry bounds how
long a captured or leaked receipt is useful without anyone having to detect
the leak. It is only enforced when the signature is verified; an unsigned
not_after is forgeable. `now` is injected and reassert() uses record_source,
so the tests are deterministic.
"""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from reference import reference_policy
from gargoyle.envelope import (
    ENVELOPE_VERSION, args_sha256, canonical_json, _sha256_text, _HASH_EXCLUDED_KEYS, _SIGNATURE_EXCLUDED_KEYS,
    sign_envelope,
)
from gargoyle.verifier import (
    verify_envelope, ACCEPT_REASSERTED_AND_BOUND,
    REF_VERIFY_SIGNATURE_EXPIRED, REF_VERIFY_SIGNATURE_INVALID,
)

P, M = "b" * 64, "c" * 64
TARGET = "https://target.example/act"
NOW = datetime(2026, 6, 2, 12, 0, 0, tzinfo=timezone.utc)
REC = {"policy_id": "test-policy/1", "policy_sha256": P}
INTER = {"tool": "act", "args": {"k": "v"}, "principal": "agent-7"}


def _env():
    env = {
        "envelope_version": ENVELOPE_VERSION, "decision": "ELIGIBLE", "requires_approval": False,
        "target_url": TARGET,
        "policy": dict(REC),
        "request_context": {"tool": "act", "args_sha256": args_sha256({"k": "v"}),
                            "principal": "agent-7"},
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
    assert "not_after" in _HASH_EXCLUDED_KEYS
    assert "not_after" not in _SIGNATURE_EXCLUDED_KEYS


def test_signed_no_expiry_honored(keys):
    # sign_envelope without not_after produces a receipt with no expiry.
    # gargoyle.issuer.issue always sets one.
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
    # Strict: valid only while now < not_after; the boundary itself is expired.
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


def test_no_trusted_keys_is_a_configuration_error(keys):
    # There is no unsigned path on which an unsigned not_after could be
    # believed: a verifier without trusted keys raises.
    e = _env(); e["not_after"] = (NOW - timedelta(days=1)).isoformat()
    with pytest.raises(ValueError):
        verify_envelope(e, INTER, TARGET, record_source=REC, now=NOW)
