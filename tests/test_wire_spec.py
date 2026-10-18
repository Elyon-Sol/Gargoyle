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
from gargoyle.consumer import REF_TARGET_APPROVAL_REQUIRED, Consumer
from gargoyle.execution import ACCEPT_CHAIN_VERIFIED, build_execution_receipt, sign_execution_receipt, verify_chain
from gargoyle.jws import b64url_decode, decode_receipt, encode_receipt
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
                         timestamp_utc=VECTORS["unsigned"]["timestamp_utc"],
                         requires_approval=VECTORS["unsigned"]["requires_approval"])
    signed = sign_envelope(env, issuer, VECTORS["signed"]["issuer_key_id"],
                           not_after=datetime.fromisoformat(VECTORS["signed"]["not_after"]),
                           decision_id=VECTORS["signed"]["decision_id"],
                           approval_request_id=VECTORS["signed"]["approval_request_id"])
    grant = sign_grant(build_grant(decision_sha256=env["decision_sha256"],
                                   approval_request_id=VECTORS["grant"]["approval_request_id"],
                                   grant_id=VECTORS["grant"]["grant_id"],
                                   not_after=datetime.fromisoformat(VECTORS["grant"]["not_after"])),
                       approver, VECTORS["grant"]["approver_key_id"])
    return issuer, approver, env, signed, grant


def test_execution_vector_recomputes_and_the_chain_verifies():
    issuer, approver, env, signed, grant = _recompute()
    executor = _key(VECTORS["executor_seed_label"])
    assert _pub_hex(executor) == VECTORS["executor_public_key_hex"]
    execution = sign_execution_receipt(
        build_execution_receipt(envelope=signed, outputs=VECTORS["outputs"],
                                executed_at=datetime.fromisoformat(VECTORS["execution"]["executed_at"])),
        executor, VECTORS["execution"]["executor_key_id"])
    assert execution == VECTORS["execution"]
    region = canonical_json({k: v for k, v in execution.items() if k != "executor_signature"})
    assert region == VECTORS["execution_signed_region"]
    chain = verify_chain(signed, execution, issuer_public_keys={signed["issuer_key_id"]: issuer.public_key()},
                         executor_public_keys={execution["executor_key_id"]: executor.public_key()},
                         grant=grant, approver_public_keys={grant["approver_key_id"]: approver.public_key()},
                         outputs=VECTORS["outputs"], check_outputs=True)
    assert chain["accepted"] is True and chain["reason"] == ACCEPT_CHAIN_VERIFIED
    assert [s[0] for s in chain["steps"]] == ["authorization", "approval", "execution"]


def test_jws_vector_recomputes_and_decodes():
    issuer, approver, env, signed, grant = _recompute()
    assert encode_receipt(signed, issuer) == VECTORS["jws"]
    header, payload, _ = VECTORS["jws"].split(".")
    assert json.loads(b64url_decode(header)) == {"alg": "EdDSA", "kid": signed["issuer_key_id"], "typ": "JWT"}
    assert json.loads(b64url_decode(payload))["gargoyle"] == signed
    res = decode_receipt(VECTORS["jws"], {signed["issuer_key_id"]: issuer.public_key()},
                         audience=signed["target_url"], now=datetime(2026, 10, 16, 12, 1, tzinfo=timezone.utc))
    assert res["reason"] is None and res["envelope"] == signed


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
    # The flagged vector receipt is honored by a consumer only with its grant (section 8.1).
    consumer = Consumer(target_id=signed["target_url"], record=signed["policy"],
                        pinned_public_keys={signed["issuer_key_id"]: issuer.public_key()},
                        approver_public_keys={grant["approver_key_id"]: approver.public_key()})
    assert consumer.check(signed, VECTORS["call"], now=now) == (False, REF_TARGET_APPROVAL_REQUIRED)
    assert consumer.check(signed, VECTORS["call"], grant=grant, now=now).honored is True


def test_regions_match_the_spec():
    """Sections 4 and 5: the excluded key sets, and the exact region bytes."""
    signed = VECTORS["signed"]
    assert set(_HASH_EXCLUDED_KEYS) == {"decision_sha256", "timestamp_utc", "issuer_key_id",
                                        "issuer_signature", "not_after", "decision_id",
                                        "approval_request_id"}
    assert set(_SIGNATURE_EXCLUDED_KEYS) == {"issuer_signature", "timestamp_utc"}
    hash_region = canonical_json({k: v for k, v in signed.items() if k not in _HASH_EXCLUDED_KEYS})
    signed_region = canonical_json({k: v for k, v in signed.items() if k not in _SIGNATURE_EXCLUDED_KEYS})
    assert hash_region == VECTORS["hash_region"]
    assert signed_region == VECTORS["signed_region"]
    assert hashlib.sha256(hash_region.encode()).hexdigest() == signed["decision_sha256"]
    assert set(signed["request_context"]) == {"tool", "args_sha256", "principal", "on_behalf_of"}
    assert ENVELOPE_VERSION == "gargoyle/3"


def test_spec_quotes_the_vectors_verbatim():
    for value in (
        VECTORS["issuer_public_key_hex"], VECTORS["approver_public_key_hex"],
        VECTORS["args_sha256"], VECTORS["unsigned"]["decision_sha256"],
        VECTORS["signed"]["issuer_signature"], VECTORS["grant"]["approver_signature"],
        VECTORS["hash_region"], VECTORS["signed_region"],
        VECTORS["signed"]["decision_id"], VECTORS["signed"]["issuer_key_id"],
        VECTORS["grant"]["approver_key_id"], VECTORS["grant"]["grant_id"],
        VECTORS["signed"]["approval_request_id"],
        VECTORS["executor_public_key_hex"], VECTORS["execution"]["outputs_sha256"],
        VECTORS["execution"]["executor_signature"], VECTORS["execution_signed_region"],
        VECTORS["execution"]["executor_key_id"], "gargoyle-execution/1",
        VECTORS["call"]["on_behalf_of"], VECTORS["jws"].split(".")[0],
        ENVELOPE_VERSION,
    ):
        assert value in SPEC, value


def test_spec_names_every_refusal_code():
    """Every REF_* code the package can emit is documented."""
    import re
    import gargoyle.approval, gargoyle.consumer, gargoyle.execution, gargoyle.identity, gargoyle.jws, gargoyle.verifier
    codes = set()
    for mod in (gargoyle.verifier, gargoyle.approval, gargoyle.consumer, gargoyle.execution, gargoyle.jws, gargoyle.identity):
        codes |= {v for k, v in vars(mod).items() if k.startswith("REF_") and isinstance(v, str)}
    documented = set(re.findall(r"REF_[A-Z_]+", SPEC))
    assert codes <= documented, sorted(codes - documented)


def test_threshold_vector_recomputes_and_needs_both_grants():
    """Section 11.1: the approval terms are in the hash region; one grant is
    insufficient, two release the receipt, in the consumer and the chain."""
    from gargoyle.approval import REF_APPROVAL_INSUFFICIENT, verify_grants
    T = VECTORS["threshold"]
    issuer = _key(VECTORS["issuer_seed_label"]); alice = _key(VECTORS["approver_seed_label"])
    bob = _key(T["approver_2_seed_label"]); executor = _key(VECTORS["executor_seed_label"])
    assert _pub_hex(bob) == T["approver_2_public_key_hex"]
    env = build_envelope(decision="ELIGIBLE", target_url=VECTORS["unsigned"]["target_url"], call=VECTORS["call"],
                         policy_pin=VECTORS["unsigned"]["policy"], timestamp_utc=VECTORS["unsigned"]["timestamp_utc"],
                         requires_approval=True, approval=T["approval"])
    signed = sign_envelope(env, issuer, T["signed"]["issuer_key_id"], not_after=datetime.fromisoformat(T["signed"]["not_after"]),
                           decision_id=T["signed"]["decision_id"], approval_request_id=T["signed"]["approval_request_id"])
    assert env == T["unsigned"] and signed == T["signed"]
    assert canonical_json({k: v for k, v in signed.items() if k not in _HASH_EXCLUDED_KEYS}) == T["hash_region"]
    grants = [sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=g["approval_request_id"],
                                     grant_id=g["grant_id"], not_after=datetime.fromisoformat(g["not_after"])), key, g["approver_key_id"])
              for g, key in zip(T["grants"], (alice, bob))]
    assert grants == T["grants"]
    execution = sign_execution_receipt(build_execution_receipt(envelope=signed, outputs=VECTORS["outputs"],
                                                               executed_at=datetime.fromisoformat(T["execution"]["executed_at"])),
                                       executor, T["execution"]["executor_key_id"])
    assert execution == T["execution"]
    approvers = {"approver-alice": alice.public_key(), "approver-bob": bob.public_key()}
    now = datetime(2026, 10, 16, 12, 1, tzinfo=timezone.utc)
    assert verify_grants(grants[:1], envelope=signed, approver_public_keys=approvers, now=now)["reason"] == REF_APPROVAL_INSUFFICIENT
    assert verify_grants(grants, envelope=signed, approver_public_keys=approvers, now=now)["accepted"]
    consumer = Consumer(target_id=signed["target_url"], record=signed["policy"],
                        pinned_public_keys={signed["issuer_key_id"]: issuer.public_key()}, approver_public_keys=approvers)
    assert consumer.check(signed, VECTORS["call"], grant=grants[1], now=now).reason == REF_APPROVAL_INSUFFICIENT
    assert consumer.check(signed, VECTORS["call"], grant=grants, now=now).honored
    chain = verify_chain(signed, execution, grant=grants, issuer_public_keys={signed["issuer_key_id"]: issuer.public_key()},
                         executor_public_keys={execution["executor_key_id"]: executor.public_key()}, approver_public_keys=approvers)
    assert chain["reason"] == ACCEPT_CHAIN_VERIFIED
    for value in (T["approver_2_public_key_hex"], T["unsigned"]["decision_sha256"], T["signed"]["issuer_signature"],
                  T["grants"][0]["approver_signature"], T["grants"][1]["approver_signature"], T["execution"]["executor_signature"],
                  T["hash_region"], T["signed"]["decision_id"], T["signed"]["approval_request_id"]):
        assert value in SPEC, value[:40]
