"""The issuing service: identity in, receipts out, holds and grants in between."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.approval import REF_APPROVAL_SOD, build_grant, sign_grant
from gargoyle.consumer import Consumer
from gargoyle.issuer_service import (
    REF_ISSUER_BAD_REQUEST, REF_ISSUER_NO_APPROVER_TRUST, REF_ISSUER_UNAUTHENTICATED, REF_ISSUER_UNKNOWN_HOLD,
    build_issuer_app,
)
from gargoyle.jws import REF_JWS_EXPIRED, encode
from gargoyle.policy import ELIGIBLE, Decision, refuse

TARGET = "mcp://fs.example"
PIN = {"policy_id": "opa:gargoyle/decision", "policy_sha256": "a" * 64}
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
issuer = Ed25519PrivateKey.generate(); idp = Ed25519PrivateKey.generate(); approver = Ed25519PrivateKey.generate()


class ToolPolicy:
    """Reads are free, writes are held, deletes are refused: what the example's Rego says."""
    def pin(self): return PIN
    def decide(self, target_url, interaction):
        tool = interaction.get("tool")
        if tool in ("read_file", "list_directory"):
            return Decision(ELIGIBLE)
        if tool in ("write_file", "move_file"):
            return Decision(ELIGIBLE, requires_approval=True)
        return refuse("TOOL_NOT_ALLOWED")


def token(sub="spiffe://example.org/agents/coder", exp=None, **claims):
    return encode({"sub": sub, "exp": int(((exp or NOW + timedelta(minutes=5))).timestamp()), **claims}, idp, "idp-1")


@pytest.fixture
def client():
    clock = {"now": NOW}
    app = build_issuer_app(policy=ToolPolicy(), signing_key=issuer, key_id="issuer-1",
                           idp_public_keys={"idp-1": idp.public_key()},
                           approver_public_keys={"approver-alice": approver.public_key()},
                           audience="gargoyle-issuer", now=lambda: clock["now"])
    c = TestClient(app); c.clock = clock
    return c


def auth(tok=None):
    return {"Authorization": "Bearer " + (tok or token(aud="gargoyle-issuer"))}


def test_issue_requires_a_trusted_identity_token(client):
    body = {"target_url": TARGET, "tool": "read_file", "args": {"path": "a.txt"}}
    assert client.post("/issue", json=body).status_code == 401
    assert client.post("/issue", json=body, headers={"Authorization": "Bearer nope"}).json()["detail"]["reason"] != None
    r = client.post("/issue", json=body, headers=auth(token(aud="other")))
    assert r.status_code == 401
    r = client.post("/issue", json=body, headers=auth(token(aud="gargoyle-issuer", exp=NOW - timedelta(seconds=1))))
    assert r.json()["detail"]["reason"] == REF_JWS_EXPIRED
    assert client.post("/issue", json={"tool": "x"}, headers=auth()).json()["detail"]["reason"] == REF_ISSUER_BAD_REQUEST


def test_free_call_is_issued_for_the_token_subject(client):
    r = client.post("/issue", json={"target_url": TARGET, "tool": "read_file", "args": {"path": "a.txt"}}, headers=auth())
    body = r.json()
    assert body["issued"] is True
    env = body["envelope"]
    assert env["request_context"]["principal"] == "spiffe://example.org/agents/coder"
    assert "on_behalf_of" not in env["request_context"] and env["requires_approval"] is False
    consumer = Consumer(target_id=TARGET, record=PIN, pinned_public_keys={"issuer-1": issuer.public_key()})
    assert consumer.check(env, {"tool": "read_file", "args": {"path": "a.txt"},
                                "principal": "spiffe://example.org/agents/coder"}, now=NOW).honored is True
    delegated = token(sub="user-42", aud="gargoyle-issuer", act={"sub": "spiffe://example.org/agents/coder"})
    env = client.post("/issue", json={"target_url": TARGET, "tool": "read_file", "args": {}}, headers=auth(delegated)).json()["envelope"]
    assert env["request_context"] == {"tool": "read_file", "args_sha256": env["request_context"]["args_sha256"],
                                      "principal": "spiffe://example.org/agents/coder", "on_behalf_of": "user-42"}


def test_refused_call_carries_the_policy_reason(client):
    r = client.post("/issue", json={"target_url": TARGET, "tool": "delete_file", "args": {}}, headers=auth())
    assert r.json() == {"issued": False, "reason": "TOOL_NOT_ALLOWED"}
    assert client.get("/pending", headers=auth()).json() == {"pending": []}


def test_flagged_call_is_held_until_a_valid_grant_is_posted(client):
    env = client.post("/issue", json={"target_url": TARGET, "tool": "write_file", "args": {"path": "a.txt", "content": "x"}},
                      headers=auth()).json()["envelope"]
    arid = env["approval_request_id"]
    assert env["requires_approval"] is True
    listed = client.get("/pending", headers=auth()).json()["pending"]
    assert [h["envelope"]["approval_request_id"] for h in listed] == [arid]
    assert listed[0]["args"] == {"path": "a.txt", "content": "x"}      # the reviewer sees the arguments
    assert client.get("/grants/" + arid, headers=auth()).json() == {"pending": True, "grant": None, "grants": [], "collected": 0,
                                                                   "required": 1, "declined": False}

    def grant_by(key, kid, **over):
        g = build_grant(decision_sha256=over.get("decision_sha256", env["decision_sha256"]),
                        approval_request_id=over.get("arid", arid), grant_id=over.get("grant_id", "g-1"),
                        not_after=NOW + timedelta(minutes=10))
        return sign_grant(g, key, kid)

    assert client.post("/grants", json=grant_by(approver, "approver-alice", arid="nope"), headers=auth()).json()["reason"] == REF_ISSUER_UNKNOWN_HOLD
    assert client.post("/grants", json=grant_by(issuer, "issuer-1"), headers=auth()).json()["reason"] == REF_APPROVAL_SOD
    assert client.post("/grants", json=grant_by(Ed25519PrivateKey.generate(), "approver-alice"), headers=auth()).json()["accepted"] is False
    ok = client.post("/grants", json=grant_by(approver, "approver-alice"), headers=auth()).json()
    assert ok["accepted"] is True
    got = client.get("/grants/" + arid, headers=auth()).json()
    assert got["pending"] is True and got["grant"]["grant_id"] == "g-1"
    assert client.get("/pending", headers=auth()).json() == {"pending": []}      # granted: no longer listed
    # The executor honors receipt + grant exactly as if the client had brought both.
    consumer = Consumer(target_id=TARGET, record=PIN, pinned_public_keys={"issuer-1": issuer.public_key()},
                        approver_public_keys={"approver-alice": approver.public_key()})
    call = {"tool": "write_file", "args": {"path": "a.txt", "content": "x"}, "principal": "spiffe://example.org/agents/coder"}
    assert consumer.check(env, call, grant=got["grant"], now=NOW).honored is True


def test_expired_holds_are_dropped_and_no_approver_trust_refuses():
    app = build_issuer_app(policy=ToolPolicy(), signing_key=issuer, key_id="issuer-1",
                           idp_public_keys={"idp-1": idp.public_key()}, now=lambda: NOW)
    c = TestClient(app)
    env = c.post("/issue", json={"target_url": TARGET, "tool": "write_file", "args": {}}, headers=auth(token())).json()["envelope"]
    g = sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                               grant_id="g", not_after=NOW + timedelta(minutes=1)), approver, "approver-alice")
    assert c.post("/grants", json=g, headers=auth(token())).json()["reason"] == REF_ISSUER_NO_APPROVER_TRUST
    clock = {"now": NOW}
    app2 = build_issuer_app(policy=ToolPolicy(), signing_key=issuer, key_id="issuer-1",
                            idp_public_keys={"idp-1": idp.public_key()}, now=lambda: clock["now"], ttl_seconds=60)
    c2 = TestClient(app2)
    c2.post("/issue", json={"target_url": TARGET, "tool": "write_file", "args": {}}, headers=auth(token()))
    assert len(c2.get("/pending", headers=auth(token())).json()["pending"]) == 1
    clock["now"] = NOW + timedelta(seconds=61)
    assert c2.get("/pending", headers=auth(token(exp=NOW + timedelta(hours=1)))).json()["pending"] == []


def test_decline_drops_the_hold_and_is_reported(client):
    from gargoyle.issuer_service import REF_ISSUER_UNKNOWN_HOLD
    env = client.post("/issue", json={"target_url": TARGET, "tool": "write_file", "args": {"path": "a.txt"}},
                      headers=auth()).json()["envelope"]
    arid = env["approval_request_id"]
    assert client.post("/decline", json={"approval_request_id": "nope"}, headers=auth()).json()["reason"] == REF_ISSUER_UNKNOWN_HOLD
    assert client.post("/decline", json={"approval_request_id": arid}, headers=auth()).json() == {"declined": True, "reason": None}
    assert client.get("/grants/" + arid, headers=auth()).json() == {"pending": False, "grant": None, "grants": [], "collected": 0,
                                                                   "required": None, "declined": True}
    assert client.get("/pending", headers=auth()).json()["pending"] == []
    # A grant for a declined hold is refused: the hold is gone.
    g = sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=arid, grant_id="g",
                               not_after=NOW + timedelta(minutes=1)), approver, "approver-alice")
    assert client.post("/grants", json=g, headers=auth()).json()["reason"] == REF_ISSUER_UNKNOWN_HOLD
    assert client.post("/decline", json="junk", headers=auth()).json()["declined"] is False


def test_the_approval_console_is_served(client):
    page = client.get("/approve")
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    assert "Gargoyle approvals" in page.text and 'src' not in page.text.split("<script")[0]
    js = client.get("/approve.js")
    assert js.status_code == 200 and "export async function signGrant" in js.text
    # The console needs no token to load; every data call it makes does.
    assert client.get("/pending").status_code == 401


def test_record_and_keys_are_public(client):
    assert client.get("/record").json() == PIN
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    assert client.get("/keys").json() == {"issuer-1": issuer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}
