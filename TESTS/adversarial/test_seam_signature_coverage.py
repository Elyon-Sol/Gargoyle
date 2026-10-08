"""
Signature field-coverage property test (external-review hardening, 2026-07).

Reviewer seam: "an envelope field the signature doesn't actually cover." The
issuer signature covers canonical_json(envelope minus issuer_signature and
timestamp_utc). This proves, field by field, that mutating ANY signed leaf
causes signed-path verify_envelope to REJECT - and that the two deliberately
excluded fields behave exactly as specified (timestamp_utc mutable without
breaking; the signature bytes themselves break verification).
"""
import copy
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from IMPLEMENTATION.envelope import build_envelope, sign_envelope
from IMPLEMENTATION.evaluator import load_manifest, manifest_sha256
from IMPLEMENTATION.verifier import verify_envelope

TARGET_URL = "http://127.0.0.1:9000/target"
KEY_ID = "gate-ed25519-001"


def _interaction():
    return {
        "AP": ["identity", "role"],
        "OP": ["session", "request"],
        "context": {"k": "v"},
        "expected_manifest_version": "1.0",
        "expected_manifest_sha256": manifest_sha256(),
    }


def _signed(priv, not_after=None, decision_id=None):
    env = build_envelope(
        decision="ELIGIBLE",
        target_url=TARGET_URL,
        normalized_interaction=_interaction(),
        manifest=load_manifest(),
        ac3=True,
        t26=True,
        manifest_integrity=True,
        timestamp_utc="2026-07-09T00:00:00+00:00",
    )
    return sign_envelope(env, priv, KEY_ID, not_after=not_after, decision_id=decision_id)


def _leaf_paths(obj, prefix=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaf_paths(v, prefix + (k,))
    else:
        yield prefix


def _mutate(env, path):
    d = env
    for k in path[:-1]:
        d = d[k]
    cur = d[path[-1]]
    if isinstance(cur, bool):
        d[path[-1]] = not cur
    elif cur is None:
        d[path[-1]] = "MUTATED"
    elif isinstance(cur, str):
        d[path[-1]] = cur + "X"
    elif isinstance(cur, (int, float)):
        d[path[-1]] = cur + 1
    elif isinstance(cur, list):
        d[path[-1]] = cur + ["MUTATED"]
    else:
        d[path[-1]] = "MUTATED"


def test_every_signed_field_is_covered():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    base = _signed(
        priv,
        not_after=datetime.now(timezone.utc) + timedelta(hours=1),
        decision_id="dec-1",
    )

    # Sanity: the unmutated signed envelope verifies.
    ok = verify_envelope(
        copy.deepcopy(base), _interaction(), TARGET_URL,
        pinned_public_keys={KEY_ID: pub},
    )
    assert ok["accepted"] is True

    # timestamp_utc is excluded from the signed region BY DESIGN (carries no
    # security weight); mutating it must still ACCEPT. Every other leaf must
    # REJECT. issuer_signature has its own test below.
    EXCLUDED = {("timestamp_utc",)}
    failures = []
    for path in _leaf_paths(base):
        if path == ("issuer_signature",):
            continue
        env = copy.deepcopy(base)
        _mutate(env, path)
        r = verify_envelope(
            env, _interaction(), TARGET_URL,
            pinned_public_keys={KEY_ID: pub},
        )
        if path in EXCLUDED:
            if r["accepted"] is not True:
                failures.append((path, "expected ACCEPT (excluded field)", r))
        else:
            if r["accepted"] is not False:
                failures.append((path, "expected REJECT (signed field)", r))
    assert not failures, failures


def test_mutating_signature_bytes_rejects():
    priv = Ed25519PrivateKey.generate()
    base = _signed(priv)
    sig = bytearray(bytes.fromhex(base["issuer_signature"]))
    sig[0] ^= 0x01  # flip one bit
    base["issuer_signature"] = sig.hex()
    r = verify_envelope(
        base, _interaction(), TARGET_URL,
        pinned_public_keys={KEY_ID: priv.public_key()},
    )
    assert r["accepted"] is False


def test_timestamp_utc_is_the_only_mutable_signed_field():
    # Explicit companion to the property test: prove timestamp_utc alone can
    # change without breaking verification (it is excluded from both the
    # signature region and decision_sha256's region).
    priv = Ed25519PrivateKey.generate()
    base = _signed(priv)
    base["timestamp_utc"] = "1999-01-01T00:00:00+00:00"
    r = verify_envelope(
        base, _interaction(), TARGET_URL,
        pinned_public_keys={KEY_ID: priv.public_key()},
    )
    assert r["accepted"] is True
