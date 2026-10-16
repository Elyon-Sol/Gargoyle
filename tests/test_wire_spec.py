"""SPEC.md is authoritative for the wire format, and this test keeps it so:
every vector in its section 11 is recomputed from the seed labels with the
reference implementation, compared to tests/fixtures/wire_vectors.json, and
looked up verbatim in SPEC.md. A change to a hash or signature region shows
up here before it ships."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from gargoyle.approval import build_grant, sign_grant, verify_grant, ACCEPT_GRANT_VALID
from gargoyle.envelope import (
    ENVELOPE_VERSION, _HASH_EXCLUDED_KEYS, _SIGNATURE_EXCLUDED_KEYS,
    args_sha256, build_envelope, canonical_json, sign_envelope,
)
from gargoyle.verifier import ACCEPT_REASSERTED_AND_BOUND, verify_envelope

ROOT = Path(__file__).resolve().parent.parent
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
VECTORS = json.loads((ROOT / "tests" / "fixtures" / "wire_vectors.json").read_text(encoding="utf-8"))


def _key(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def _pub_hex(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _recompute():
    issuer = _key(VECTORS["issuer_seed_label"])
    approver = _key(VECTORS["approver_seed_label"])
    call = VECTORS["call"]
    env = build_envelope(decision="ELIGIBLE", target_url=VECTORS["unsigned"]["target_url"], call=call,
                         policy_pin=VECTORS["unsigned"]["policy"],
                         timestamp_utc=VECTORS["unsigned"]["timestamp_utc"])
    signed = sign_envelope(env, issuer, VECTORS["signed"]["issuer_key_id"],
                           not_after=datetime.fromisoformat(VECTORS["signed"]["not_after"]),
                           decision_id=VECTORS["signed"]["decision_id"])
    grant = sign_grant(build_grant(decision_sha256=env["decision_sha256"],
                                   approval_request_id=VECTORS["grant"]["approval_request_id"],
                                   grant_id=VECTORS["grant"]["grant_id"],
                                   not_after=datetime.fromisoformat(VECTORS["grant"]["not_after"])),
                       approver, VECTORS["grant"]["approver_key_id"])
    return issuer, approver, env, signed, grant


def test_vectors_recompute_from_the_seeds():
    issuer, approver, env, signed, grant = _recompute()
    assert _pub_hex(issuer) == VECTORS["issuer_public_key_hex"]
    assert _pub_hex(approver) == VECTORS["approver_public_key_hex"]
    assert args_sha256(VECTORS["call"]["args"]) == VECTORS["args_sha256"]
    assert env == VECTORS["unsigned"]
    assert signed == VECTORS["signed"]
    assert grant == VECTORS["grant"]


def test_vectors_verify_with_the_reference_implementation():
    issuer, approver, env, signed, grant = _recompute()
    now = datetime(2026, 10, 16, 12, 1, tzinfo=timezone.utc)
    r = verify_envelope(signed, VECTORS["call"], signed["target_url"],
                        record_source=signed["policy"],
                        pinned_public_keys={signed["issuer_key_id"]: issuer.public_key()}, now=now)
    assert r == {"accepted": True, "reason": ACCEPT_REASSERTED_AND_BOUND}
    g = verify_grant(grant, expected_decision_sha256=env["decision_sha256"],
                     expected_approval_request_id=grant["approval_request_id"],
                     approver_public_keys={grant["approver_key_id"]: approver.public_key()},
                     gate_key_id=signed["issuer_key_id"], now=now)
    assert g == {"accepted": True, "reason": ACCEPT_GRANT_VALID}


def test_regions_match_the_spec():
    """Sections 4 and 5: the excluded key sets, and the exact region bytes."""
    signed = VECTORS["signed"]
    assert set(_HASH_EXCLUDED_KEYS) == {"decision_sha256", "timestamp_utc", "issuer_key_id",
                                        "issuer_signature", "not_after", "decision_id"}
    assert set(_SIGNATURE_EXCLUDED_KEYS) == {"issuer_signature", "timestamp_utc"}
    hash_region = canonical_json({k: v for k, v in signed.items() if k not in _HASH_EXCLUDED_KEYS})
    signed_region = canonical_json({k: v for k, v in signed.items() if k not in _SIGNATURE_EXCLUDED_KEYS})
    assert hash_region == VECTORS["hash_region"]
    assert signed_region == VECTORS["signed_region"]
    assert hashlib.sha256(hash_region.encode()).hexdigest() == signed["decision_sha256"]
    assert set(signed["request_context"]) == {"tool", "args_sha256", "principal"}
    assert ENVELOPE_VERSION == "gargoyle/1"


def test_spec_quotes_the_vectors_verbatim():
    for value in (
        VECTORS["issuer_public_key_hex"], VECTORS["approver_public_key_hex"],
        VECTORS["args_sha256"], VECTORS["unsigned"]["decision_sha256"],
        VECTORS["signed"]["issuer_signature"], VECTORS["grant"]["approver_signature"],
        VECTORS["hash_region"], VECTORS["signed_region"],
        VECTORS["signed"]["decision_id"], VECTORS["signed"]["issuer_key_id"],
        VECTORS["grant"]["approver_key_id"], VECTORS["grant"]["grant_id"],
        ENVELOPE_VERSION,
    ):
        assert value in SPEC, value


def test_spec_names_every_refusal_code():
    """Every REF_* code the package can emit is documented."""
    import re
    import gargoyle.approval, gargoyle.reference_target, gargoyle.verifier
    codes = set()
    for mod in (gargoyle.verifier, gargoyle.approval, gargoyle.reference_target):
        codes |= {v for k, v in vars(mod).items() if k.startswith("REF_") and isinstance(v, str)}
    documented = set(re.findall(r"REF_[A-Z_]+", SPEC))
    assert codes <= documented, sorted(codes - documented)
