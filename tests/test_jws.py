"""JWS compact serialization with EdDSA: the interoperable encoding of a
receipt, verifiable by any JWT library and by Gargoyle itself."""

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.consumer import Consumer
from gargoyle.issuer import issue
from gargoyle.jws import (
    REF_JWS_ALG_UNSUPPORTED, REF_JWS_AUDIENCE_MISMATCH, REF_JWS_EXPIRED, REF_JWS_KEY_UNKNOWN,
    REF_JWS_MALFORMED, REF_JWS_PAYLOAD_MISMATCH, REF_JWS_SIGNATURE_INVALID,
    b64url_decode, b64url_encode, decode, decode_receipt, encode, encode_receipt,
)
from gargoyle.policy import ELIGIBLE, Decision

TARGET = "https://tools.example/target"
PIN = {"policy_id": "engine/1", "policy_sha256": "a" * 64}
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
issuer = Ed25519PrivateKey.generate(); KEYS = {"issuer-1": issuer.public_key()}
CALL = {"tool": "transfer", "args": {"amount": 5}, "principal": "agent-7", "on_behalf_of": "user-42"}


class AllowAll:
    def pin(self): return PIN
    def decide(self, target_url, interaction): return Decision(ELIGIBLE)


def receipt():
    return issue(AllowAll(), TARGET, CALL, signing_key=issuer, key_id="issuer-1", now=NOW).envelope


def test_base64url_is_unpadded_and_strict():
    assert b64url_encode(b"\xfb\xff") == "-_8"
    assert b64url_decode("-_8") == b"\xfb\xff"
    with pytest.raises(ValueError):
        b64url_decode("not base64url!")


def test_encode_decode_round_trip_and_refusals():
    token = encode({"sub": "agent-7", "n": 1}, issuer, "issuer-1")
    h, p, s = token.split(".")
    assert json.loads(b64url_decode(h)) == {"alg": "EdDSA", "kid": "issuer-1", "typ": "JWT"}
    res = decode(token, KEYS)
    assert res["reason"] is None and res["payload"] == {"n": 1, "sub": "agent-7"}
    assert decode("a.b", KEYS)["reason"] == REF_JWS_MALFORMED
    assert decode(token, {})["reason"] == REF_JWS_KEY_UNKNOWN
    other = Ed25519PrivateKey.generate()
    assert decode(token, {"issuer-1": other.public_key()})["reason"] == REF_JWS_SIGNATURE_INVALID
    forged_payload = h + "." + b64url_encode(b'{"sub":"agent-8"}') + "." + s
    assert decode(forged_payload, KEYS)["reason"] == REF_JWS_SIGNATURE_INVALID
    none_alg = b64url_encode(b'{"alg":"none","kid":"issuer-1"}') + "." + p + "."
    assert decode(none_alg, KEYS)["reason"] == REF_JWS_ALG_UNSUPPORTED
    hs256 = b64url_encode(b'{"alg":"HS256","kid":"issuer-1"}') + "." + p + "." + s
    assert decode(hs256, KEYS)["reason"] == REF_JWS_ALG_UNSUPPORTED


def test_receipt_as_jws_carries_registered_claims_and_the_receipt():
    env = receipt()
    token = encode_receipt(env, issuer)
    payload = json.loads(b64url_decode(token.split(".")[1]))
    assert payload["iss"] == "issuer-1" and payload["jti"] == env["decision_id"] and payload["aud"] == TARGET
    assert payload["exp"] == int(datetime.fromisoformat(env["not_after"]).timestamp())
    assert payload["gargoyle"] == env                      # canonical signature intact inside
    res = decode_receipt(token, KEYS, audience=TARGET, now=NOW)
    assert res["reason"] is None and res["envelope"] == env
    # The decoded receipt is then checked like any other.
    consumer = Consumer(target_id=TARGET, record=PIN, pinned_public_keys=KEYS)
    assert consumer.check(res["envelope"], CALL, now=NOW).honored is True


def test_receipt_jws_refusals():
    env = receipt(); token = encode_receipt(env, issuer)
    h, p, s = token.split(".")
    assert decode_receipt(token, KEYS, now=NOW + timedelta(minutes=10))["reason"] == REF_JWS_EXPIRED
    assert decode_receipt(token, KEYS, audience="https://other", now=NOW)["reason"] == REF_JWS_AUDIENCE_MISMATCH
    assert decode_receipt(token, {}, now=NOW)["reason"] == REF_JWS_KEY_UNKNOWN
    # Registered claims that disagree with the wrapped receipt are a forgery
    # attempt, caught even when the issuer signed both (a buggy issuer).
    payload = json.loads(b64url_decode(p))
    for bad in ({**payload, "jti": "other"}, {**payload, "aud": "https://other"},
                {**payload, "exp": payload["exp"] + 1}, {**payload, "gargoyle": {**env, "issuer_key_id": "x"}}):
        t = encode(bad, issuer, "issuer-1")
        assert decode_receipt(t, KEYS, now=NOW)["reason"] == REF_JWS_PAYLOAD_MISMATCH
    assert decode_receipt(encode({"iss": "issuer-1"}, issuer, "issuer-1"), KEYS, now=NOW)["reason"] == REF_JWS_MALFORMED
    with pytest.raises(ValueError):
        encode_receipt({k: v for k, v in env.items() if k != "decision_id"}, issuer)


def test_a_standard_jwt_verification_accepts_the_outer_signature():
    """What a JWT library does: verify EdDSA over ASCII(b64(header).b64(payload))."""
    token = encode_receipt(receipt(), issuer)
    h, p, s = token.split(".")
    issuer.public_key().verify(b64url_decode(s), (h + "." + p).encode("ascii"))
    assert base64.urlsafe_b64decode(h + "==").startswith(b"{")
