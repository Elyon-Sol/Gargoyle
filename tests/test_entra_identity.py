"""Enterprise identity: tokens signed with RS256 or ES256 by a provider's
JWKS keys (Entra ID), the UPN as the principal, groups and app roles as
claims a rules file can match by department."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.identity import entra_keys, principal_from_token
from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import (
    IDENTITY_ALGS, REF_JWS_ALG_UNSUPPORTED, REF_JWS_SIGNATURE_INVALID, b64url_decode, b64url_encode, decode,
    decode_receipt, keys_from_jwks,
)
from gargoyle.rules import RulesPolicy

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
EXP = int((NOW + timedelta(minutes=10)).timestamp())
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ec_key = ec.generate_private_key(ec.SECP256R1())


def _token(header, payload, sign):
    h = b64url_encode(json.dumps(header).encode()); p = b64url_encode(json.dumps(payload).encode())
    return h + "." + p + "." + b64url_encode(sign((h + "." + p).encode("ascii")))


def rs256(payload, kid="entra-k1"):
    return _token({"alg": "RS256", "typ": "JWT", "kid": kid}, payload,
                  lambda m: rsa_key.sign(m, padding.PKCS1v15(), hashes.SHA256()))


def es256(payload, kid="okta-k1"):
    def sign(m):
        r, s = utils.decode_dss_signature(ec_key.sign(m, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return _token({"alg": "ES256", "typ": "JWT", "kid": kid}, payload, sign)


def jwks():
    pub = rsa_key.public_key().public_numbers(); ecpub = ec_key.public_key().public_numbers()
    ed = Ed25519PrivateKey.generate().public_key()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return {"keys": [
        {"kty": "RSA", "kid": "entra-k1", "use": "sig",
         "n": b64url_encode(pub.n.to_bytes(256, "big")), "e": b64url_encode(pub.e.to_bytes(3, "big"))},
        {"kty": "EC", "kid": "okta-k1", "crv": "P-256",
         "x": b64url_encode(ecpub.x.to_bytes(32, "big")), "y": b64url_encode(ecpub.y.to_bytes(32, "big"))},
        {"kty": "OKP", "kid": "ed-k1", "crv": "Ed25519", "x": b64url_encode(ed.public_bytes(Encoding.Raw, PublicFormat.Raw))},
        {"kty": "RSA", "use": "sig", "n": "AQAB", "e": "AQAB"},          # no kid: skipped
        {"kty": "oct", "kid": "hmac", "k": "secret"},                     # unsupported: skipped
    ]}


ENTRA_CLAIMS = {"aud": "api://gargoyle-issuer", "iss": "https://login.microsoftonline.com/tenant/v2.0",
                "sub": "pairwise-opaque-id", "oid": "11111111-2222-3333-4444-555555555555",
                "preferred_username": "j.doe@acme.example", "name": "J. Doe",
                "groups": ["finance-group-guid"], "roles": ["Finance", "Approver"], "exp": EXP}


def test_jwks_loads_rsa_ec_and_okp_keys_and_skips_the_rest():
    keys = keys_from_jwks(jwks())
    assert set(keys) == {"entra-k1", "okta-k1", "ed-k1"}
    assert keys_from_jwks({"keys": "nope"}) == {} and keys_from_jwks(None) == {}


def test_rs256_and_es256_identity_tokens_verify_and_map_entra_claims():
    keys = keys_from_jwks(jwks())
    who = principal_from_token(rs256(ENTRA_CLAIMS), keys, audience="api://gargoyle-issuer", now=NOW)
    assert who["reason"] is None
    assert who["principal"] == "j.doe@acme.example"            # the UPN, not the opaque sub
    assert who["on_behalf_of"] is None
    assert who["groups"] == ["finance-group-guid"] and who["roles"] == ["Finance", "Approver"]
    assert who["oid"] == "11111111-2222-3333-4444-555555555555"
    who = principal_from_token(es256({**ENTRA_CLAIMS, "preferred_username": None, "upn": "j.doe@acme.example"}), keys, now=NOW)
    assert who["principal"] == "j.doe@acme.example"


def test_algorithm_is_fixed_by_the_key_not_the_header():
    keys = keys_from_jwks(jwks())
    # A token claiming RS256 but signed under the EC kid, and vice versa, is refused on alg.
    h = b64url_encode(json.dumps({"alg": "RS256", "kid": "okta-k1"}).encode()); p = b64url_encode(json.dumps(ENTRA_CLAIMS).encode())
    forged = h + "." + p + "." + b64url_encode(b"\x00" * 256)
    assert decode(forged, keys, allowed_algs=IDENTITY_ALGS)["reason"] == REF_JWS_ALG_UNSUPPORTED
    assert decode(es256(ENTRA_CLAIMS, kid="entra-k1"), keys, allowed_algs=IDENTITY_ALGS)["reason"] == REF_JWS_ALG_UNSUPPORTED
    # Receipts never accept RS256/ES256, whatever keys are present.
    assert decode(rs256(ENTRA_CLAIMS), keys)["reason"] == REF_JWS_ALG_UNSUPPORTED
    assert decode_receipt(rs256(ENTRA_CLAIMS), keys, now=NOW)["reason"] == REF_JWS_ALG_UNSUPPORTED
    # A wrong signature under the right key is refused on the signature.
    t = rs256(ENTRA_CLAIMS); h, p, s = t.split(".")
    assert decode(h + "." + p + "." + b64url_encode(b64url_decode(s)[::-1]), keys, allowed_algs=IDENTITY_ALGS)["reason"] == REF_JWS_SIGNATURE_INVALID
    bad_es = es256(ENTRA_CLAIMS); h, p, s = bad_es.split(".")
    assert decode(h + "." + p + "." + b64url_encode(b"\x01" * 63), keys, allowed_algs=IDENTITY_ALGS)["reason"] == REF_JWS_SIGNATURE_INVALID


def test_entra_keys_fetches_the_tenant_jwks():
    class Http:
        def get(self, url, timeout=None):
            assert url == "https://login.microsoftonline.com/acme.example/discovery/v2.0/keys"
            class R:
                status_code = 200
                def json(self_inner): return jwks()
            return R()
    assert "entra-k1" in entra_keys("acme.example", http=Http())

    class Down:
        def get(self, url, timeout=None):
            class R: status_code = 503
            return R()
    with pytest.raises(RuntimeError):
        entra_keys("acme.example", http=Down())


def test_departments_by_group_or_role_in_the_rules_file(tmp_path):
    rules = {"version": "acme", "default": "deny", "rules": [
        {"tools": ["read_*", "list_*", "query"], "args": {"sql": "SELECT*"}, "action": "allow"},
        {"tools": ["read_*", "list_*"], "action": "allow"},
        {"tools": ["send_mail"], "roles": ["Sales", "Finance"], "action": "hold"},
        {"tools": ["query"], "groups": ["finance-*"], "action": "hold"},
        {"tools": ["create_shipment"], "roles": ["Shipping"], "action": "allow"},
        {"tools": ["change_firewall_rule"], "roles": ["Admin"], "action": "hold"},
    ]}
    p = tmp_path / "rules.json"; p.write_text(json.dumps(rules))
    policy = RulesPolicy(str(p))
    issuer = Ed25519PrivateKey.generate()
    app = build_issuer_app(policy=policy, signing_key=issuer, key_id="issuer-1",
                           idp_public_keys=keys_from_jwks(jwks()), audience="api://gargoyle-issuer", now=lambda: NOW)
    c = TestClient(app)

    def ask(claims, tool, args=None):
        r = c.post("/issue", json={"target_url": "mcp://x", "tool": tool, "args": args or {}},
                   headers={"Authorization": "Bearer " + rs256(claims)})
        body = r.json()
        return ("hold" if body["envelope"]["requires_approval"] else "allow") if body.get("issued") else body["reason"]

    finance = ENTRA_CLAIMS
    shipping = {**ENTRA_CLAIMS, "preferred_username": "s.lee@acme.example", "groups": ["ship-guid"], "roles": ["Shipping"]}
    admin = {**ENTRA_CLAIMS, "preferred_username": "it@acme.example", "groups": [], "roles": ["Admin"]}
    assert ask(finance, "list_mail") == "allow"
    assert ask(finance, "send_mail") == "hold"
    assert ask(shipping, "send_mail") == "RULE_DENIED"               # not sales or finance
    assert ask(finance, "query", {"sql": "UPDATE invoices SET paid=1"}) == "hold"
    assert ask(shipping, "query", {"sql": "UPDATE invoices SET paid=1"}) == "RULE_DENIED"
    assert ask(shipping, "query", {"sql": "SELECT * FROM shipments"}) == "allow"
    assert ask(shipping, "create_shipment") == "allow" and ask(finance, "create_shipment") == "RULE_DENIED"
    assert ask(admin, "change_firewall_rule") == "hold" and ask(finance, "change_firewall_rule") == "RULE_DENIED"
    # Groups and roles are policy inputs only: the receipt binds the call and the UPN.
    r = c.post("/issue", json={"target_url": "mcp://x", "tool": "list_mail", "args": {}},
               headers={"Authorization": "Bearer " + rs256(finance)}).json()["envelope"]
    assert r["request_context"] == {"tool": "list_mail", "args_sha256": r["request_context"]["args_sha256"],
                                    "principal": "j.doe@acme.example"}
