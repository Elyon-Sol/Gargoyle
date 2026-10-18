"""Approvers who sign in with Entra: a browser-held key enrolled under the
token's UPN, published by the issuer, trusted by the middleware and the
audit, and usable in threshold rules by name."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from gargoyle.approval import build_grant, sign_grant
from gargoyle.approvers import ApproverRegistry, may_enroll
from gargoyle.consumer import Consumer
from gargoyle.issuer_service import REF_ISSUER_NOT_AN_APPROVER, build_issuer_app
from gargoyle.jws import encode
from gargoyle.policy import ELIGIBLE, Decision

issuer, idp = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}
TARGET = "mcp://fs"
pub_hex = lambda k: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


class Hold:
    def __init__(self, required=1, approvers=None): self.d = Decision(ELIGIBLE, None, True, required, approvers)
    def pin(self): return PIN
    def decide(self, target_url, interaction): return self.d


def token(upn, roles=(), groups=()):
    claims = {"preferred_username": upn, "sub": "oid-" + upn, "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}
    if roles: claims["roles"] = list(roles)
    if groups: claims["groups"] = list(groups)
    return encode(claims, idp, "idp-1")


def test_registry_persists_one_key_per_upn(tmp_path):
    path = tmp_path / "approvers.json"
    reg = ApproverRegistry(str(path))
    k1, k2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    r = reg.enroll("dana@contoso.com", pub_hex(k1))
    assert r["replaced"] is False and "dana@contoso.com" in reg
    assert reg.enroll("dana@contoso.com", pub_hex(k2))["replaced"] is True
    again = ApproverRegistry(str(path))                    # survives a restart
    assert again.public_hex() == {"dana@contoso.com": pub_hex(k2)}
    assert set(again.keys()) == {"dana@contoso.com"}
    assert again.remove("dana@contoso.com") and not again.remove("dana@contoso.com")
    with pytest.raises(ValueError):
        reg.enroll("x@y", "zz")
    assert may_enroll({"roles": ["Approver"]}) and not may_enroll({"roles": ["Reader"]})
    assert may_enroll({"groups": ["g-1"]}, groups=["g-1"]) and not may_enroll({"groups": ["g-2"]}, groups=["g-1"])


def _app(tmp_path, policy=None, groups=None):
    reg = ApproverRegistry(str(tmp_path / "approvers.json"))
    app = build_issuer_app(policy=policy or Hold(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           approver_registry=reg, approver_groups=groups,
                           console_entra={"tenant": "t", "client_id": "c", "scope": "api://a/access"})
    return TestClient(app), reg


def test_enrollment_needs_the_role_and_binds_the_tokens_upn(tmp_path):
    c, reg = _app(tmp_path)
    key = Ed25519PrivateKey.generate()
    h = lambda t: {"Authorization": "Bearer " + t}
    r = c.post("/approvers/enroll", json={"public_key_hex": pub_hex(key)}, headers=h(token("eve@contoso.com")))
    assert r.status_code == 403 and r.json()["detail"]["reason"] == REF_ISSUER_NOT_AN_APPROVER
    r = c.post("/approvers/enroll", json={"public_key_hex": pub_hex(key)}, headers=h(token("dana@contoso.com", roles=["Approver"])))
    assert r.json() == {"enrolled": True, "key_id": "dana@contoso.com", "replaced": False}
    assert c.get("/approvers").json() == {"approvers": {"dana@contoso.com": pub_hex(key)}}        # public
    me = c.get("/me", headers=h(token("dana@contoso.com", roles=["Approver"]))).json()
    assert me == {"principal": "dana@contoso.com", "may_approve": True, "enrolled_public_key_hex": pub_hex(key)}
    assert c.get("/me", headers=h(token("eve@contoso.com"))).json()["may_approve"] is False
    assert c.get("/approve-config").json() == {"entra": {"tenant": "t", "client_id": "c", "scope": "api://a/access"}}
    assert c.post("/approvers/enroll", json={"public_key_hex": "nope"}, headers=h(token("dana@contoso.com", roles=["Approver"]))).status_code == 400
    # A group qualifies too.
    c2, _ = _app(tmp_path / "g", groups=["grp-approvers"])
    assert c2.post("/approvers/enroll", json={"public_key_hex": pub_hex(key)}, headers=h(token("sam@contoso.com", groups=["grp-approvers"]))).json()["enrolled"]


def test_an_enrolled_approver_releases_a_hold_and_the_middleware_trusts_the_published_key(tmp_path):
    c, reg = _app(tmp_path, policy=Hold(2, ("dana@contoso.com", "lee@contoso.com")))
    dana, lee = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    h = lambda t: {"Authorization": "Bearer " + t}
    for upn, key in (("dana@contoso.com", dana), ("lee@contoso.com", lee)):
        assert c.post("/approvers/enroll", json={"public_key_hex": pub_hex(key)}, headers=h(token(upn, roles=["Approver"]))).json()["enrolled"]
    agent = token("agent@contoso.com")
    env = c.post("/issue", json={"target_url": TARGET, "tool": "transfer_funds", "args": {"amount": 5}}, headers=h(agent)).json()["envelope"]
    assert env["approval"] == {"required": 2, "approvers": ["dana@contoso.com", "lee@contoso.com"]}
    arid = env["approval_request_id"]
    g = lambda key, upn: sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=arid, grant_id="g-" + upn,
                                                not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), key, upn)
    assert c.post("/grants", json=g(dana, "dana@contoso.com"), headers=h(agent)).json()["accepted"]
    assert c.post("/grants", json=g(lee, "lee@contoso.com"), headers=h(agent)).json()["complete"] is True
    grants = c.get("/grants/" + arid, headers=h(agent)).json()["grants"]
    assert [x["approver_key_id"] for x in grants] == ["dana@contoso.com", "lee@contoso.com"]

    # The middleware's consumer has no static approver keys; it learns them from the issuer.
    from gargoyle.mcp_server import IssuerClient
    class Shim:
        def post(self, url, json=None, headers=None, timeout=None): return c.post(url.replace("http://i", ""), json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return c.get(url.replace("http://i", ""), headers=headers)
    ic = IssuerClient("http://i", agent, http=Shim())
    assert set(ic.approver_keys()) == {"dana@contoso.com", "lee@contoso.com"}
    consumer = Consumer(target_id=TARGET, pinned_public_keys={"issuer-1": issuer.public_key()}, record=PIN,
                        approver_key_source=ic.approver_keys)
    assert consumer.check(env, {"tool": "transfer_funds", "args": {"amount": 5}, "principal": "agent@contoso.com"}, grant=grants).honored
    # The audit command merges approvers.json from the deploy folder.
    assert json.loads((tmp_path / "approvers.json").read_text())["approvers"]["lee@contoso.com"]["public_key_hex"] == pub_hex(lee)
