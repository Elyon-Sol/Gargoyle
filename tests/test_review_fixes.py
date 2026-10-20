"""Fixes from the second outside review (2026-10-20): caller claims stay apart
from the bound fields (finding 3), evidence on every path after the claim
(5), single use that survives the process and is checked after the fact (4),
identity keys refreshed on an unknown kid (9). The plan path (1) is in
test_plans.py and approver trust (2) in test_approvers.py."""

import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.cli import _audit_summary
from gargoyle.evidence import (ACCEPT_ENTRY_VERIFIED, HONORED, REF_EVIDENCE_REPLAY, REFUSED, TOOL_ERROR, UPSTREAM_ERROR,
                               UPSTREAM_UNAVAILABLE, read_log, verify_log)
from gargoyle.execution import ACCEPT_CHAIN_VERIFIED
from gargoyle.issuer import issue
from gargoyle.approval import build_grant, sign_grant
from gargoyle.issuer_service import REF_ISSUER_HOLD_EXPIRED, REF_ISSUER_SELF_APPROVAL, build_issuer_app
from gargoyle.jws import REF_JWS_KEY_UNKNOWN, encode
from gargoyle.mcp_server import ENVELOPE_META_KEY, EXECUTED_META_KEY, REASON_META_KEY, ServerState, call_for, handle_message
from gargoyle.policy import ELIGIBLE, Decision
from gargoyle.reconcile import reconcile
from gargoyle.replay_cache import InMemoryReplayCache, SqliteReplayCache
from gargoyle.verifier import REF_VERIFY_REPLAY

issuer, idp, idp2, executor = (Ed25519PrivateKey.generate() for _ in range(4))
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}
TARGET = "mcp://fs"
PRINCIPAL = "agent@contoso.com"
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


class Allow:
    def __init__(self): self.seen = []
    def pin(self): return PIN
    def decide(self, target_url, interaction):
        self.seen.append(interaction); return Decision(ELIGIBLE)


def bearer(key, kid, **claims):
    exp = int((NOW + timedelta(hours=1)).timestamp())
    return {"Authorization": "Bearer " + encode({"sub": PRINCIPAL, "exp": exp, **claims}, key, kid)}


def test_caller_claims_never_set_the_bound_fields():
    pol = Allow()
    c = TestClient(build_issuer_app(policy=pol, signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()}, now=lambda: NOW))
    claims = {"principal": "cfo@contoso.com", "on_behalf_of": "cfo@contoso.com", "roles": ["Approver"], "groups": ["finance"],
              "state_sha256": "b" * 64, "tool": "delete_file", "ticket": "INC-1"}
    r = c.post("/issue", json={"target_url": TARGET, "tool": "write_file", "args": {"path": "x"}, "claims": claims}, headers=bearer(idp, "idp-1")).json()
    rc = r["envelope"]["request_context"]
    assert rc["principal"] == PRINCIPAL and rc.get("on_behalf_of") is None and "state_sha256" not in rc and rc["tool"] == "write_file"
    seen = pol.seen[-1]
    assert seen["principal"] == PRINCIPAL and seen["roles"] == [] and seen["groups"] == [] and seen["tool"] == "write_file"
    assert "on_behalf_of" not in seen and "state_sha256" not in seen
    assert seen["claims"] == claims                       # a policy may still read them, apart, as the caller's word


def test_identity_keys_refresh_at_most_once_a_minute_on_an_unknown_kid():
    clock = [NOW]
    fetched = []
    def refresh():
        fetched.append(clock[0]); return {"idp-2": idp2.public_key()}
    c = TestClient(build_issuer_app(policy=Allow(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                                    now=lambda: clock[0], idp_key_refresh=refresh))
    body = {"target_url": TARGET, "tool": "read_file", "args": {}}
    rolled, unknown = bearer(idp2, "idp-2"), bearer(Ed25519PrivateKey.generate(), "idp-3")
    assert c.post("/issue", json=body, headers=rolled).json()["issued"] and len(fetched) == 1      # a key rolled after startup
    assert c.post("/issue", json=body, headers=rolled).json()["issued"] and len(fetched) == 1      # known from now on
    r = c.post("/issue", json=body, headers=unknown)
    assert r.status_code == 401 and r.json()["detail"]["reason"] == REF_JWS_KEY_UNKNOWN and len(fetched) == 1   # within the minute: no refetch
    clock[0] += timedelta(seconds=61)
    assert c.post("/issue", json=body, headers=unknown).status_code == 401 and len(fetched) == 2


class Upstream:
    """A scripted upstream: each reply in turn, an exception where one is scripted."""
    def __init__(self, *replies): self.replies = list(replies); self.sent = []
    def send(self, msg):
        self.sent.append(msg)
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return {"jsonrpc": "2.0", "id": msg.get("id"), **r}


OK = {"result": {"content": [{"type": "text", "text": "done"}], "isError": False}}
TOOL_FAILED = {"result": {"content": [{"type": "text", "text": "disk full"}], "isError": True}}
RPC_ERROR = {"error": {"code": -32000, "message": "internal"}}


def _config():
    return {"pinned_public_keys": {"k1": issuer.public_key()}, "record": PIN, "target_id": TARGET, "principal": PRINCIPAL,
            "executor_signing_key": executor, "executor_key_id": "executor-1"}


def _receipt(args):
    return issue(Allow(), TARGET, call_for("write_file", args, PRINCIPAL), signing_key=issuer, key_id="k1").envelope


def _call(env, args, msg_id):
    return {"jsonrpc": "2.0", "id": msg_id, "method": "tools/call", "params": {"name": "write_file", "arguments": args, "_meta": {ENVELOPE_META_KEY: env}}}


def _gate(tmp_path, *replies, replay_cache=None):
    state = ServerState(_config(), replay_cache=replay_cache, upstream=Upstream(*replies), audit_log=str(tmp_path / "audit.jsonl"))
    state.initialized = True
    return state


TRUST = dict(issuer_public_keys={"k1": issuer.public_key()}, executor_public_keys={"executor-1": executor.public_key()})


def test_every_path_after_the_claim_leaves_evidence(tmp_path, capsys):
    """Second review, finding 5: a tool error, a JSON-RPC error and an
    unreachable upstream all spend the receipt, so all are entries, with a
    verdict that says the work was not done."""
    state = _gate(tmp_path, TOOL_FAILED, RPC_ERROR, RuntimeError("gone"), OK)
    envs = [_receipt({"path": "f%d" % i}) for i in range(4)]
    r1 = handle_message(state, _call(envs[0], {"path": "f0"}, 1))
    assert r1["result"]["isError"] is True and r1["result"]["_meta"][EXECUTED_META_KEY] is True
    r2 = handle_message(state, _call(envs[1], {"path": "f1"}, 2))
    assert r2["error"]["code"] == -32000
    r3 = handle_message(state, _call(envs[2], {"path": "f2"}, 3))
    assert "upstream unavailable" in r3["error"]["message"]
    r4 = handle_message(state, _call(envs[3], {"path": "f3"}, 4))
    assert r4["result"]["isError"] is False
    log = read_log(str(tmp_path / "audit.jsonl"))
    assert [e["kind"] for e in log] == [HONORED] * 4
    assert [e["reason"] for e in log] == [TOOL_ERROR, UPSTREAM_ERROR, UPSTREAM_UNAVAILABLE, "REASSERTED_AND_BOUND"]
    assert log[1]["execution"]["outputs_sha256"] and log[2]["execution"]["outputs_sha256"]      # the error is what was attested
    report = verify_log(log, **TRUST)
    assert report["accepted"] and [e["verdict"] for e in report["entries"]][:3] == [TOOL_ERROR, UPSTREAM_ERROR, UPSTREAM_UNAVAILABLE]
    _audit_summary(report["entries"], log)
    out = capsys.readouterr().out
    assert "failed" in out and "%-24s %7d %7d %7d" % ("write_file", 1, 3, 0) in out
    # The spent receipts are spent: a retry of the failed one is a replay.
    again = handle_message(state, _call(envs[0], {"path": "f0"}, 5))
    assert again["result"]["_meta"][REASON_META_KEY] == REF_VERIFY_REPLAY


def test_sqlite_replay_cache_claims_once_prunes_and_persists(tmp_path):
    path = str(tmp_path / "r.sqlite")
    c = SqliteReplayCache(path)
    assert c.check_and_claim("d1", NOW + timedelta(minutes=5), now=NOW)
    assert not c.check_and_claim("d1", NOW + timedelta(minutes=5), now=NOW)
    assert not SqliteReplayCache(path).check_and_claim("d1", NOW + timedelta(minutes=5), now=NOW)   # another process, same file
    assert c.check_and_claim("forever", None, now=NOW)
    assert c.check_and_claim("d1", None, now=NOW + timedelta(minutes=6))                            # expired: pruned, free again
    assert not SqliteReplayCache(path).check_and_claim("forever", None, now=NOW + timedelta(days=400))


def test_single_use_survives_a_restart_and_a_replay_shows_in_the_audit(tmp_path):
    """Second review, finding 4: the claims live beside the log, so a restarted
    gate refuses a receipt it honored; a gate that lost its cache is caught by
    verification and reconciliation."""
    env, args = _receipt({"path": "f"}), {"path": "f"}
    s1 = _gate(tmp_path, OK)
    assert handle_message(s1, _call(env, args, 1))["result"]["isError"] is False
    assert (tmp_path / "audit.replay.sqlite").exists()
    s2 = _gate(tmp_path, OK)                                                   # a restart
    r = handle_message(s2, _call(env, args, 2))
    assert r["result"]["isError"] is True and r["result"]["_meta"][REASON_META_KEY] == REF_VERIFY_REPLAY
    s3 = _gate(tmp_path, OK, replay_cache=InMemoryReplayCache())               # a gate whose cache is gone
    assert handle_message(s3, _call(env, args, 3))["result"]["isError"] is False
    log = read_log(str(tmp_path / "audit.jsonl"))
    report = verify_log(log, **TRUST)
    assert [e["kind"] for e in log] == [HONORED, REFUSED, HONORED]
    assert not report["accepted"] and report["reason"] == REF_EVIDENCE_REPLAY
    assert [e["reason"] for e in report["entries"]] == [ACCEPT_CHAIN_VERIFIED, ACCEPT_ENTRY_VERIFIED, REF_EVIDENCE_REPLAY]
    found = reconcile(log, [])["findings"]
    assert {"finding": "REPLAYED_RECEIPT", "seq": 3, "decision_id": env["decision_id"], "tool": "write_file", "first_seq": 1} in found


class Hold:
    def pin(self): return PIN
    def decide(self, target_url, interaction): return Decision(ELIGIBLE, None, True)


approver = Ed25519PrivateKey.generate()


def _held(clock, **kw):
    app = build_issuer_app(policy=Hold(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           approver_public_keys={"approver-1": approver.public_key(), PRINCIPAL: approver.public_key(),
                                                 "boss@contoso.com": approver.public_key()},
                           now=lambda: clock[0], ttl_seconds=600, **kw)
    return TestClient(app)


def _grant(env, kid, gid="g-1"):
    return sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"], grant_id=gid,
                                  not_after=NOW + timedelta(hours=2)), approver, kid)


def test_an_expired_hold_cannot_be_released(tmp_path):
    """Second review, finding 10: the executor would refuse the expired
    receipt anyway; the issuer must not tell the approver it ran."""
    clock = [NOW]
    c = _held(clock)
    h = bearer(idp, "idp-1")
    env = c.post("/issue", json={"target_url": TARGET, "tool": "write_file", "args": {"path": "x"}}, headers=h).json()["envelope"]
    plan = c.post("/plans", json={"target_url": TARGET, "steps": [{"tool": "write_file", "args": {"path": "y"}}]}, headers=h).json()["plan"]
    clock[0] = datetime.fromisoformat(env["not_after"]) + timedelta(seconds=1)
    r = c.post("/grants", json=_grant(env, "approver-1"), headers=h).json()
    assert r == {"accepted": False, "reason": REF_ISSUER_HOLD_EXPIRED}
    assert c.post("/grants", json=_grant(env, "approver-1"), headers=h).json()["reason"] == "REF_ISSUER_UNKNOWN_HOLD"   # dropped at once
    assert c.get("/grants/" + env["approval_request_id"], headers=h).json()["pending"] is False
    clock[0] = datetime.fromisoformat(plan["not_after"]) + timedelta(seconds=1)
    h = bearer(idp, "idp-1", exp=int((clock[0] + timedelta(hours=1)).timestamp()))       # the token outlives the plan
    g = sign_grant(build_grant(decision_sha256=plan["plan_sha256"], approval_request_id=plan["approval_request_id"], grant_id="g-p",
                               not_after=clock[0] + timedelta(hours=1)), approver, "approver-1")
    assert c.post("/grants", json=g, headers=h).json()["reason"] == REF_ISSUER_HOLD_EXPIRED
    assert c.get("/pending", headers=bearer(idp, "idp-1", roles=["Approver"], exp=int((clock[0] + timedelta(hours=1)).timestamp()))).json()["pending"] == []


def test_the_requester_may_not_release_their_own_call(tmp_path):
    """Second review, finding 8: the approver key id may be neither the
    hold's principal nor the party it acts for, unless the operator allows it."""
    clock = [NOW]
    c = _held(clock)
    h = bearer(idp, "idp-1")
    env = c.post("/issue", json={"target_url": TARGET, "tool": "write_file", "args": {"path": "x"}}, headers=h).json()["envelope"]
    assert c.post("/grants", json=_grant(env, PRINCIPAL), headers=h).json() == {"accepted": False, "reason": REF_ISSUER_SELF_APPROVAL}
    assert c.post("/grants", json=_grant(env, "approver-1"), headers=h).json()["accepted"]
    # Acting on behalf of someone: that someone may not release it either.
    delegated = bearer(idp, "idp-1", act={"sub": PRINCIPAL}, sub="boss@contoso.com")
    env2 = c.post("/issue", json={"target_url": TARGET, "tool": "write_file", "args": {"path": "x"}}, headers=delegated).json()["envelope"]
    assert env2["request_context"]["on_behalf_of"] == "boss@contoso.com"
    assert c.post("/grants", json=_grant(env2, "boss@contoso.com"), headers=h).json()["reason"] == REF_ISSUER_SELF_APPROVAL
    assert c.post("/grants", json=_grant(env2, PRINCIPAL), headers=h).json()["reason"] == REF_ISSUER_SELF_APPROVAL
    # The operator's switch.
    c2 = _held(clock, allow_self_approval=True)
    env3 = c2.post("/issue", json={"target_url": TARGET, "tool": "write_file", "args": {"path": "x"}}, headers=h).json()["envelope"]
    assert c2.post("/grants", json=_grant(env3, PRINCIPAL), headers=h).json()["accepted"]
