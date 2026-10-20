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


def test_enrollment_keeps_the_directory_ids_beside_the_upn(tmp_path):
    reg = ApproverRegistry(str(tmp_path / "a.json"))
    key = Ed25519PrivateKey.generate()
    reg.enroll("dana@contoso.com", pub_hex(key), oid="11111111-2222-3333-4444-555555555555", tid="0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9")
    import json
    entry = json.loads((tmp_path / "a.json").read_text())["approvers"]["dana@contoso.com"]
    assert entry["oid"] == "11111111-2222-3333-4444-555555555555" and entry["tid"] == "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"


def test_a_revoked_approver_is_refused_at_once_and_still_verifies_in_the_past(tmp_path):
    """Revocation moves the key out of trust for new grants (issuer and
    middleware) and into the revoked list, where an audit of earlier
    evidence still finds it. An approver may revoke only their own key here;
    the operator revokes anyone on the host."""
    from gargoyle.approval import REF_APPROVAL_KEY_UNKNOWN
    from gargoyle.issuer_service import REF_ISSUER_FORBIDDEN
    from gargoyle.mcp_server import IssuerClient
    c, reg = _app(tmp_path, policy=Hold(1, ("dana@contoso.com",)))
    dana = Ed25519PrivateKey.generate()
    h = lambda t: {"Authorization": "Bearer " + t}
    assert c.post("/approvers/enroll", json={"public_key_hex": pub_hex(dana)}, headers=h(token("dana@contoso.com", roles=["Approver"]))).json()["enrolled"]
    agent = token("agent@contoso.com")
    env = c.post("/issue", json={"target_url": TARGET, "tool": "transfer_funds", "args": {"amount": 5}}, headers=h(agent)).json()["envelope"]
    g = sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"], grant_id="g-1",
                               not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), dana, "dana@contoso.com")
    # Someone else cannot revoke Dana; Dana can.
    r = c.post("/approvers/revoke", json={"upn": "dana@contoso.com"}, headers=h(token("lee@contoso.com", roles=["Approver"])))
    assert r.status_code == 403 and r.json()["detail"]["reason"] == REF_ISSUER_FORBIDDEN
    assert c.post("/approvers/revoke", json={"upn": "dana@contoso.com"}, headers=h(token("dana@contoso.com", roles=["Approver"]))).json() == {"revoked": True}
    assert c.post("/approvers/revoke", json={"upn": "dana@contoso.com"}, headers=h(token("dana@contoso.com", roles=["Approver"]))).json() == {"revoked": False}
    assert c.get("/approvers").json()["approvers"] == {}
    assert c.post("/grants", json=g, headers=h(agent)).json()["reason"] in (REF_APPROVAL_KEY_UNKNOWN, "REF_ISSUER_NO_APPROVER_TRUST")

    class Shim:
        def post(self, url, json=None, headers=None, timeout=None): return c.post(url.replace("http://i", ""), json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return c.get(url.replace("http://i", ""), headers=headers)
    assert IssuerClient("http://i", agent, http=Shim()).approver_keys() == {}
    doc = json.loads((tmp_path / "approvers.json").read_text())
    assert "dana@contoso.com" not in doc["approvers"] and doc["revoked"]["dana@contoso.com"]["public_key_hex"] == pub_hex(dana)
    assert doc["revoked"]["dana@contoso.com"]["revoked_by"] == "dana@contoso.com"
    # Enrolling again is a fresh key, and the revoked record goes.
    dana2 = Ed25519PrivateKey.generate()
    assert c.post("/approvers/enroll", json={"public_key_hex": pub_hex(dana2)}, headers=h(token("dana@contoso.com", roles=["Approver"]))).json()["enrolled"]
    assert reg.revoked_hex() == {} and reg.public_hex() == {"dana@contoso.com": pub_hex(dana2)}


def test_the_registry_picks_up_a_file_another_process_wrote(tmp_path):
    """`gargoyle approvers revoke` edits the file on the issuer's host; the
    running service sees the change without a restart."""
    import os, time
    path = tmp_path / "a.json"
    live = ApproverRegistry(str(path))
    key = Ed25519PrivateKey.generate()
    live.enroll("dana@contoso.com", pub_hex(key))
    operator = ApproverRegistry(str(path))                 # another process
    assert operator.revoke("dana@contoso.com", revoked_by="operator:root")
    os.utime(path, (time.time() + 2, time.time() + 2))     # make the change visible even on a coarse filesystem clock
    assert "dana@contoso.com" not in live and live.public_hex() == {} and live.revoked_hex() == {"dana@contoso.com": pub_hex(key)}


def test_an_operators_revocation_on_the_host_reaches_the_witness(tmp_path):
    """`gargoyle approvers revoke` edits the file; the service witnesses the
    revocation (who, when) the first time it reads the file afterwards, and
    only once. Its own revocations are witnessed as they happen, not again."""
    import os
    events = []
    reg = ApproverRegistry(str(tmp_path / "approvers.json"))
    app = build_issuer_app(policy=Hold(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           approver_registry=reg, log_events=events.append)
    c = TestClient(app)
    h = lambda t: {"Authorization": "Bearer " + t}
    for who in ("dana@contoso.com", "lee@contoso.com"):
        assert c.post("/approvers/enroll", json={"public_key_hex": pub_hex(Ed25519PrivateKey.generate())}, headers=h(token(who, roles=["Approver"]))).json()["enrolled"]
    # The operator, in another process.
    other = ApproverRegistry(str(tmp_path / "approvers.json"))
    assert other.revoke("dana@contoso.com", revoked_by="operator:root")
    st = os.stat(tmp_path / "approvers.json"); os.utime(tmp_path / "approvers.json", (st.st_atime, st.st_mtime + 2))
    assert c.get("/approvers").json()["approvers"].keys() == {"lee@contoso.com"}
    c.get("/approvers")
    revoked = [e for e in events if e["event"] == "revoked"]
    assert len(revoked) == 1 and revoked[0]["approver"] == "dana@contoso.com" and revoked[0]["by"] == "operator:root" and revoked[0]["revoked_at"]
    # Lee revokes their own key through the service: one entry, by Lee.
    assert c.post("/approvers/revoke", json={"upn": "lee@contoso.com"}, headers=h(token("lee@contoso.com", roles=["Approver"]))).json() == {"revoked": True}
    c.get("/approvers")
    revoked = [e for e in events if e["event"] == "revoked"]
    assert [(e["approver"], e["by"]) for e in revoked] == [("dana@contoso.com", "operator:root"), ("lee@contoso.com", "lee@contoso.com")]
