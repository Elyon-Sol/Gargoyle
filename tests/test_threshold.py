"""Threshold approvals (roadmap step 4): a flagged receipt may say how many
distinct approvers must sign and which keys count. The terms are hashed and
signed in the receipt; the consumer, the chain verifier and the issuing
service all enforce them from the receipt alone."""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.approval import (ACCEPT_GRANTS_SUFFICIENT, REF_APPROVAL_APPROVER_NOT_ELIGIBLE,
                               REF_APPROVAL_DUPLICATE_APPROVER, REF_APPROVAL_INSUFFICIENT, REF_APPROVAL_KEY_UNKNOWN,
                               REF_APPROVAL_REPLAY, build_grant, sign_grant, verify_grants)
from gargoyle.consumer import REF_TARGET_APPROVAL_REQUIRED, Consumer
from gargoyle.envelope import approval_terms, build_envelope, valid_approval
from gargoyle.execution import ACCEPT_CHAIN_VERIFIED, build_execution_receipt, sign_execution_receipt, verify_chain
from gargoyle.issuer import issue
from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import encode
from gargoyle.policy import ELIGIBLE, Decision
from gargoyle.rules import RULES_MALFORMED, decide_rules, validate_rules
from gargoyle.verifier import REF_VERIFY_ENVELOPE_ABSENT, verify_envelope

TARGET = "mcp://fs"
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}
NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
CALL = {"tool": "transfer_funds", "args": {"amount": 5}, "principal": "agent-7"}
issuer = Ed25519PrivateKey.generate(); executor = Ed25519PrivateKey.generate()
alice, bob, carol = (Ed25519PrivateKey.generate() for _ in range(3))
ISSUER_KEYS = {"issuer-1": issuer.public_key()}
APPROVERS = {"alice": alice.public_key(), "bob": bob.public_key(), "carol": carol.public_key()}


class Hold:
    def __init__(self, required=2, approvers=None): self.d = Decision(ELIGIBLE, None, True, required, approvers)
    def pin(self): return PIN
    def decide(self, target_url, interaction): return self.d


def receipt(required=2, approvers=None):
    return issue(Hold(required, approvers), TARGET, CALL, signing_key=issuer, key_id="issuer-1", now=NOW).envelope


def grant(env, key, kid, gid=None):
    return sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                  grant_id=gid or ("g-" + kid), not_after=NOW + timedelta(minutes=10)), key, kid)


# ---- the receipt ----

def test_the_terms_are_in_the_receipt_hashed_and_signed():
    env = receipt(2, ("alice", "bob"))
    assert env["approval"] == {"required": 2, "approvers": ["alice", "bob"]}
    assert approval_terms(env) == {"required": 2, "approvers": ["alice", "bob"], "plannable": True}
    plain = receipt(1)
    assert "approval" not in plain and approval_terms(plain) == {"required": 1, "approvers": None, "plannable": True}
    ok = verify_envelope(env, CALL, TARGET, record_source=PIN, pinned_public_keys=ISSUER_KEYS, now=NOW)
    assert ok["accepted"]
    # Lowering the threshold breaks the signature; a malformed or misplaced member is unusable.
    tampered = dict(env, approval={"required": 1, "approvers": ["alice", "bob"]})
    assert not verify_envelope(tampered, CALL, TARGET, record_source=PIN, pinned_public_keys=ISSUER_KEYS, now=NOW)["accepted"]
    for bad in ({"required": 0}, {"required": True}, {"required": 2, "approvers": ["alice"]}, {"required": 1, "approvers": []},
                {"required": 1, "approvers": ["a", "a"]}, {"required": 1, "extra": 1}, {"approvers": ["a"]}):
        assert not valid_approval(bad), bad
        broken = dict(env, approval=bad)
        assert verify_envelope(broken, CALL, TARGET, record_source=PIN, pinned_public_keys=ISSUER_KEYS, now=NOW)["reason"] == REF_VERIFY_ENVELOPE_ABSENT
    free = build_envelope(decision=ELIGIBLE, target_url=TARGET, call=CALL, policy_pin=PIN)
    assert verify_envelope(dict(free, approval={"required": 1}), CALL, TARGET, record_source=PIN,
                           pinned_public_keys=ISSUER_KEYS, now=NOW)["reason"] == REF_VERIFY_ENVELOPE_ABSENT
    with pytest.raises(ValueError):
        build_envelope(decision=ELIGIBLE, target_url=TARGET, call=CALL, policy_pin=PIN, approval={"required": 2})


def test_decision_approval_member():
    assert Decision(ELIGIBLE).approval is None
    assert Decision(ELIGIBLE, None, True).approval is None
    assert Decision(ELIGIBLE, None, True, 2).approval == {"required": 2}
    assert Decision(ELIGIBLE, None, True, 1, ("b", "a")).approval == {"required": 1, "approvers": ["a", "b"]}


# ---- the grant set ----

def test_verify_grants_counts_distinct_eligible_approvers():
    env = receipt(2, ("alice", "bob"))
    ga, gb, gc = grant(env, alice, "alice"), grant(env, bob, "bob"), grant(env, carol, "carol")
    kw = dict(envelope=env, approver_public_keys=APPROVERS, now=NOW)
    assert verify_grants([ga, gb], **kw)["reason"] == ACCEPT_GRANTS_SUFFICIENT
    assert verify_grants([ga], **kw)["reason"] == REF_APPROVAL_INSUFFICIENT
    assert verify_grants(ga, **kw)["reason"] == REF_APPROVAL_INSUFFICIENT
    assert verify_grants([], **kw)["reason"] == REF_APPROVAL_INSUFFICIENT
    assert verify_grants(None, **kw)["reason"] == REF_APPROVAL_INSUFFICIENT
    assert verify_grants([ga, grant(env, alice, "alice", "g-2")], **kw)["reason"] == REF_APPROVAL_DUPLICATE_APPROVER
    assert verify_grants([ga, gc], **kw)["reason"] == REF_APPROVAL_APPROVER_NOT_ELIGIBLE
    assert verify_grants([ga, grant(env, Ed25519PrivateKey.generate(), "mallory")], **kw)["reason"] == REF_APPROVAL_KEY_UNKNOWN
    # No approver list: any two trusted keys.
    env2 = receipt(2)
    assert verify_grants([grant(env2, alice, "alice"), grant(env2, carol, "carol")],
                         envelope=env2, approver_public_keys=APPROVERS, now=NOW)["accepted"]
    # The default terms: one grant, as before.
    env1 = receipt(1)
    assert verify_grants(grant(env1, bob, "bob"), envelope=env1, approver_public_keys=APPROVERS, now=NOW)["accepted"]


def test_consumer_requires_the_set_and_claims_every_grant():
    env = receipt(2, ("alice", "bob"))
    ga, gb = grant(env, alice, "alice"), grant(env, bob, "bob")
    c = Consumer(target_id=TARGET, pinned_public_keys=ISSUER_KEYS, record=PIN, approver_public_keys=APPROVERS)
    assert c.check(env, CALL, now=NOW).reason == REF_TARGET_APPROVAL_REQUIRED
    assert c.check(env, CALL, grant=ga, now=NOW).reason == REF_APPROVAL_INSUFFICIENT
    assert c.check(env, CALL, grant=[ga, gb], now=NOW).honored
    # Both grant ids are spent; a second receipt for the same decision cannot reuse either.
    env_again = receipt(2, ("alice", "bob"))
    assert c.check(env_again, CALL, grant=[grant(env_again, alice, "alice", "g-a2"), grant(env_again, bob, "bob", "g-b2")], now=NOW).honored
    assert c.check(receipt(2, ("alice", "bob")), CALL, grant=[ga, gb], now=NOW).reason != REF_APPROVAL_REPLAY  # binding fails first
    # Reusing one spent grant beside a fresh one is replay.
    env3 = receipt(2, ("alice", "bob"))
    c3 = Consumer(target_id=TARGET, pinned_public_keys=ISSUER_KEYS, record=PIN, approver_public_keys=APPROVERS)
    first = [grant(env3, alice, "alice", "g-a3"), grant(env3, bob, "bob", "g-b3")]
    assert c3.check(env3, CALL, grant=first, now=NOW).honored
    env4 = receipt(2, ("alice", "bob"))
    reused = [grant(env4, alice, "alice", "g-a3"), grant(env4, bob, "bob", "g-b4")]
    assert c3.check(env4, CALL, grant=reused, now=NOW).reason == REF_APPROVAL_REPLAY


def test_chain_verifies_a_threshold_release_offline():
    env = receipt(2, ("alice", "bob"))
    grants = [grant(env, alice, "alice"), grant(env, bob, "bob")]
    ex = sign_execution_receipt(build_execution_receipt(envelope=env, outputs={"ok": 1}, executed_at=NOW + timedelta(seconds=5)),
                                executor, "executor-1")
    kw = dict(issuer_public_keys=ISSUER_KEYS, executor_public_keys={"executor-1": executor.public_key()}, approver_public_keys=APPROVERS)
    assert verify_chain(env, ex, grant=grants, **kw)["reason"] == ACCEPT_CHAIN_VERIFIED
    assert verify_chain(env, ex, grant=grants[:1], **kw)["reason"] == REF_APPROVAL_INSUFFICIENT
    assert dict(verify_chain(env, ex, grant=grants[:1], **kw)["steps"])["approval"] == REF_APPROVAL_INSUFFICIENT


# ---- rules ----

def test_rules_express_the_threshold():
    doc = {"version": "v", "default": "deny", "rules": [
        {"tools": ["transfer_*"], "action": "hold", "approvals": 2, "approvers": ["alice", "bob", "carol"]},
        {"tools": ["write_*"], "action": "hold"},
    ]}
    assert validate_rules(doc) is None
    d = decide_rules(doc, {"tool": "transfer_funds", "args": {}, "principal": "p"})
    assert d.requires_approval and d.approvals_required == 2 and d.approvers == ("alice", "bob", "carol")
    assert d.approval == {"required": 2, "approvers": ["alice", "bob", "carol"]}
    assert decide_rules(doc, {"tool": "write_file", "args": {}, "principal": "p"}).approval is None
    for bad in ({"tools": ["t"], "action": "hold", "approvals": 0}, {"tools": ["t"], "action": "hold", "approvals": True},
                {"tools": ["t"], "action": "hold", "approvals": 2, "approvers": ["a"]},
                {"tools": ["t"], "action": "hold", "approvers": ["a", "a"]}, {"tools": ["t"], "action": "allow", "approvals": 2}):
        assert validate_rules({"version": "v", "rules": [bad]}) is not None, bad


# ---- the issuing service collects the set ----

def _token(idp, sub="agent-7"):
    return encode({"sub": sub, "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")


def test_issuer_service_holds_until_enough_distinct_eligible_approvers_sign():
    idp = Ed25519PrivateKey.generate()
    app = build_issuer_app(policy=Hold(2, ("alice", "bob")), signing_key=issuer, key_id="issuer-1",
                           idp_public_keys={"idp-1": idp.public_key()}, approver_public_keys=APPROVERS)
    c = TestClient(app); h = {"Authorization": "Bearer " + _token(idp)}
    env = c.post("/issue", json={"target_url": TARGET, "tool": "transfer_funds", "args": {"amount": 5}}, headers=h).json()["envelope"]
    arid = env["approval_request_id"]
    listed = c.get("/pending", headers=h).json()["pending"][0]
    assert (listed["collected"], listed["required"], listed["approvers"]) == (0, 2, [])
    live_now = datetime.now(timezone.utc) + timedelta(minutes=10)
    g = lambda key, kid: sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=arid,
                                                grant_id="g-" + kid, not_after=live_now), key, kid)
    r = c.post("/grants", json=g(alice, "alice"), headers=h).json()
    assert r["accepted"] and (r["collected"], r["required"], r["complete"]) == (1, 2, False)
    assert c.get("/grants/" + arid, headers=h).json()["grants"] == []            # not released yet
    listed = c.get("/pending", headers=h).json()["pending"][0]
    assert (listed["collected"], listed["approvers"]) == (1, ["alice"])          # still shown, with progress
    assert c.post("/grants", json=g(alice, "alice"), headers=h).json()["reason"] == REF_APPROVAL_DUPLICATE_APPROVER
    assert c.post("/grants", json=g(carol, "carol"), headers=h).json()["reason"] == REF_APPROVAL_APPROVER_NOT_ELIGIBLE
    r = c.post("/grants", json=g(bob, "bob"), headers=h).json()
    assert r["accepted"] and r["complete"] is True
    got = c.get("/grants/" + arid, headers=h).json()
    assert got["grant"] is None and [x["approver_key_id"] for x in got["grants"]] == ["alice", "bob"]
    assert c.get("/pending", headers=h).json()["pending"] == []


def test_middleware_waits_for_the_whole_set_and_runs_once(tmp_path):
    from gargoyle.mcp_server import IssuerClient, ServerState, _gate
    idp = Ed25519PrivateKey.generate()
    app = build_issuer_app(policy=Hold(2), signing_key=issuer, key_id="issuer-1",
                           idp_public_keys={"idp-1": idp.public_key()}, approver_public_keys=APPROVERS)
    c = TestClient(app); h = {"Authorization": "Bearer " + _token(idp)}

    class Shim:
        def post(self, url, json=None, headers=None, timeout=None): return c.post(url.replace("http://i", ""), json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return c.get(url.replace("http://i", ""), headers=headers)

    signed = []
    def two_humans(seconds):
        for item in c.get("/pending", headers=h).json()["pending"]:
            env = item["envelope"]
            for key, kid in ((alice, "alice"), (bob, "bob")):
                if kid not in signed:
                    gr = sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                                grant_id="g-" + kid, not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), key, kid)
                    c.post("/grants", json=gr, headers=h); signed.append(kid)
                    return                                                      # one signature per poll
    state = ServerState({"pinned_public_keys": ISSUER_KEYS, "record": PIN, "target_id": TARGET, "principal": "agent-7",
                         "approver_public_keys": APPROVERS},
                        issuer_client=IssuerClient("http://i", _token(idp), http=Shim(), approval_timeout=30, poll_seconds=0.01,
                                                   sleep=two_humans))
    gate = _gate(state, {"name": "transfer_funds", "arguments": {"amount": 5}})
    assert gate["executed"], gate["reason"]
    assert isinstance(gate["grant"], list) and [g["approver_key_id"] for g in gate["grant"]] == ["alice", "bob"]
    assert signed == ["alice", "bob"]


def test_init_creates_several_approvers(tmp_path, monkeypatch, capsys):
    from gargoyle.cli import main, _read_env
    out = tmp_path / "d"
    assert main(["init", str(tmp_path / "p"), "--out", str(out), "--approvers", "2"]) == 0
    keys = json.loads((out / "public-keys.json").read_text())
    assert set(keys["approver"]) == {"approver-1", "approver-2"}
    env = _read_env(out / "issuer.env")
    assert env["GARGOYLE_APPROVER_KEY_ID"] == "approver-1,approver-2"
    assert env["GARGOYLE_APPROVER_PUBLIC_KEY_HEX"] == keys["approver"]["approver-1"] + "," + keys["approver"]["approver-2"]
    assert (out / "approver-2.env").exists() and json.loads((out / "approver-web-2.json").read_text())["key_id"] == "approver-2"
    # Both sides parse the lists: the issuer accepts approver-2's grant on a held write.
    from gargoyle.issuer_service import app_from_env
    monkeypatch.setattr(os, "environ", dict(os.environ, **env))
    c = TestClient(app_from_env())
    menv0 = _read_env(out / "middleware.env")
    h = {"Authorization": "Bearer " + menv0["GARGOYLE_MCP_CLIENT_TOKEN"]}
    held = c.post("/issue", json={"target_url": menv0["GARGOYLE_MCP_TARGET_ID"], "tool": "write_file",
                                  "args": {"path": "x", "content": "y"}}, headers=h).json()["envelope"]
    a2 = _read_env(out / "approver-2.env")
    k2 = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(a2["GARGOYLE_APPROVER_KEY_HEX"]))
    gr = sign_grant(build_grant(decision_sha256=held["decision_sha256"], approval_request_id=held["approval_request_id"],
                                grant_id="g-2", not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), k2, "approver-2")
    assert c.post("/grants", json=gr, headers=h).json()["accepted"] is True
    menv = _read_env(out / "middleware.env")
    (out / "record.json").write_text(json.dumps(PIN))
    menv["GARGOYLE_MCP_RECORD_PATH"] = str(out / "record.json")
    monkeypatch.setattr(os, "environ", dict(os.environ, **menv))
    from gargoyle.mcp_server import config_from_env
    assert set(config_from_env()["approver_public_keys"]) == {"approver-1", "approver-2"}
