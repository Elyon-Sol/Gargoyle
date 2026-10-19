"""Scoped grants: one approval for a bounded plan, each step bound and
single-use, the policy deciding what may be planned at all, the evidence
naming the plan and step behind every released call."""

import json
import sys
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.approval import build_grant, sign_grant
from gargoyle.consumer import Consumer
from gargoyle.envelope import args_sha256
from gargoyle.evidence import read_log, verify_log
from gargoyle.execution import ACCEPT_CHAIN_VERIFIED, build_execution_receipt, sign_execution_receipt, verify_chain
from gargoyle.issuer import issue
from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import encode
from gargoyle.mcp_server import EXECUTED_META_KEY, PLAN_TOOL, REASON_META_KEY, IssuerClient, ServerState, StdioUpstream, handle_message
from gargoyle.plans import (ACCEPT_PLAN_RELEASE, REF_PLAN_BINDING_MISMATCH, REF_PLAN_EXPIRED, REF_PLAN_GRANTS,
                            REF_PLAN_NO_MATCHING_STEP, REF_PLAN_SIGNATURE_INVALID, REF_PLAN_STEP_CONSUMED,
                            REF_PLAN_STEP_NOT_PLANNABLE, REF_PLAN_STEP_REFUSED, build_plan, match_step, sign_plan,
                            verify_plan, verify_plan_release)
from gargoyle.policy import ELIGIBLE, Decision, refuse
from gargoyle.rules import RulesPolicy

issuer, executor, approver, idp = (Ed25519PrivateKey.generate() for _ in range(4))
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}
TARGET = "mcp://fs"
PRINCIPAL = "agent@contoso.com"
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
ISSUER_KEYS = {"issuer-1": issuer.public_key()}
APPROVERS = {"approver-1": approver.public_key()}


class Hold:
    def pin(self): return PIN
    def decide(self, target_url, interaction): return Decision(ELIGIBLE, None, True)


def grant_for(plan, key=approver, kid="approver-1", gid="g-1"):
    return sign_grant(build_grant(decision_sha256=plan["plan_sha256"], approval_request_id=plan["approval_request_id"],
                                  grant_id=gid, not_after=NOW + timedelta(minutes=30)), key, kid)


def test_plan_objects_sign_verify_and_match():
    plan = sign_plan(build_plan(plan_id="p-1", approval_request_id="r-1", target_url=TARGET, principal=PRINCIPAL, policy_pin=PIN,
                                steps=[{"tool": "write_file", "match": {"path": "C:\\\\proj\\\\*.md"}},
                                       {"tool": "write_file", "args_sha256": args_sha256({"path": "C:\\\\proj\\\\todo.md", "content": "x"})}],
                                not_after=NOW + timedelta(minutes=30), note="close out the week"), issuer, "issuer-1")
    assert verify_plan(plan, issuer_public_keys=ISSUER_KEYS, now=NOW)["accepted"]
    assert verify_plan(dict(plan, note="changed"), issuer_public_keys=ISSUER_KEYS, now=NOW)["reason"] == REF_PLAN_SIGNATURE_INVALID
    assert verify_plan(plan, issuer_public_keys=ISSUER_KEYS, now=NOW + timedelta(hours=1))["reason"] == REF_PLAN_EXPIRED
    assert match_step(plan, "write_file", {"path": "C:\\\\proj\\\\notes.md", "content": "a"}) == 0
    assert match_step(plan, "write_file", {"path": "C:\\\\proj\\\\notes.md", "content": "a"}, consumed={0}) is None
    assert match_step(plan, "write_file", {"path": "C:\\\\proj\\\\todo.md", "content": "x"}, consumed={0}) == 1
    assert match_step(plan, "write_file", {"path": "C:\\\\other\\\\x.md", "content": "a"}) is None
    assert match_step(plan, "delete_file", {"path": "C:\\\\proj\\\\notes.md"}) is None
    with pytest.raises(ValueError):
        build_plan(plan_id="p", approval_request_id="r", target_url=TARGET, principal=PRINCIPAL, policy_pin=PIN,
                   steps=[{"tool": "x"}], not_after=NOW)


def test_release_is_verified_and_each_step_claimed_once():
    plan = sign_plan(build_plan(plan_id="p-1", approval_request_id="r-1", target_url=TARGET, principal=PRINCIPAL, policy_pin=PIN,
                                steps=[{"tool": "write_file", "match": {"path": "C:\\\\proj\\\\*"}}] * 2,
                                not_after=NOW + timedelta(minutes=30)), issuer, "issuer-1")
    g = grant_for(plan)
    call = {"tool": "write_file", "args": {"path": "C:\\\\proj\\\\a.md", "content": "1"}, "principal": PRINCIPAL}
    env = issue(Hold(), TARGET, call, signing_key=issuer, key_id="issuer-1", now=NOW).envelope
    rel = {"plan": plan, "grants": [g], "step": 0, "args": call["args"]}
    kw = dict(issuer_public_keys=ISSUER_KEYS, approver_public_keys=APPROVERS, now=NOW)
    assert verify_plan_release(rel, env, call, **kw)["reason"] == ACCEPT_PLAN_RELEASE
    assert verify_plan_release(dict(rel, grants=[]), env, call, **kw)["reason"] == REF_PLAN_GRANTS
    assert verify_plan_release(dict(rel, step=5), env, call, **kw)["reason"] == REF_PLAN_NO_MATCHING_STEP
    other = issue(Hold(), TARGET, dict(call, principal="eve@contoso.com"), signing_key=issuer, key_id="issuer-1", now=NOW).envelope
    assert verify_plan_release(rel, other, dict(call, principal="eve@contoso.com"), **kw)["reason"] == REF_PLAN_BINDING_MISMATCH
    off = issue(Hold(), TARGET, dict(call, args={"path": "C:\\\\other\\\\a.md"}), signing_key=issuer, key_id="issuer-1", now=NOW).envelope
    assert verify_plan_release(rel, off, dict(call, args={"path": "C:\\\\other\\\\a.md"}), **kw)["reason"] == REF_PLAN_NO_MATCHING_STEP

    c = Consumer(target_id=TARGET, pinned_public_keys=ISSUER_KEYS, record=PIN, approver_public_keys=APPROVERS)
    assert c.check(env, call, plan_release=rel, now=NOW).honored
    env2 = issue(Hold(), TARGET, call, signing_key=issuer, key_id="issuer-1", now=NOW).envelope
    assert c.check(env2, call, plan_release=rel, now=NOW).reason == REF_PLAN_STEP_CONSUMED       # step 0 spent
    assert c.check(env2, call, plan_release=dict(rel, step=1), now=NOW).honored                   # step 1 free
    # The offline chain accepts a plan release and re-matches the recorded arguments.
    ex = sign_execution_receipt(build_execution_receipt(envelope=env, outputs={}, executed_at=NOW + timedelta(seconds=5)), executor, "executor-1")
    chain = verify_chain(env, ex, grant=rel, issuer_public_keys=ISSUER_KEYS, executor_public_keys={"executor-1": executor.public_key()}, approver_public_keys=APPROVERS)
    assert chain["reason"] == ACCEPT_CHAIN_VERIFIED and dict(chain["steps"])["approval"] == ACCEPT_PLAN_RELEASE
    assert not verify_chain(env, ex, grant=dict(rel, args={"path": "C:\\\\other\\\\a.md", "content": "1"}), issuer_public_keys=ISSUER_KEYS,
                            executor_public_keys={"executor-1": executor.public_key()}, approver_public_keys=APPROVERS)["accepted"]


def _rules(tmp_path):
    doc = {"version": "t", "default": "deny", "rules": [
        {"tools": ["list_*", "read_*", "get_*"], "action": "allow"},
        {"tools": ["write_file"], "args": {"path": "*proj*"}, "action": "hold"},
        {"tools": ["send_mail"], "action": "hold", "plan": False},
        {"tools": ["delete_*"], "action": "deny", "reason": "DESTRUCTIVE_TOOL"},
    ]}
    p = tmp_path / "rules.json"; p.write_text(json.dumps(doc)); return RulesPolicy(str(p))


def token():
    return encode({"sub": PRINCIPAL, "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")


def test_issuer_judges_every_step_and_holds_the_plan(tmp_path):
    app = build_issuer_app(policy=_rules(tmp_path), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           approver_public_keys=APPROVERS)
    c = TestClient(app); h = {"Authorization": "Bearer " + token()}
    r = c.post("/plans", json={"target_url": TARGET, "note": "week close", "steps": [
        {"tool": "write_file", "match": {"path": "C:\\\\proj\\\\*.md"}}, {"tool": "write_file", "args": {"path": "C:\\\\proj\\\\todo.md", "content": "x"}}]}, headers=h).json()
    assert r["issued"] and r["held"] and r["plan"]["principal"] == PRINCIPAL and len(r["plan"]["steps"]) == 2
    assert r["plan"]["steps"][1] == {"tool": "write_file", "args_sha256": args_sha256({"path": "C:\\\\proj\\\\todo.md", "content": "x"})}
    arid = r["plan"]["approval_request_id"]
    listed = c.get("/pending", headers=h).json()["pending"]
    assert listed[0]["plan"]["plan_id"] == r["plan"]["plan_id"] and listed[0]["required"] == 1
    # A step the rules refuse, or keep individual, or a pattern too broad for the rule: no plan.
    assert c.post("/plans", json={"target_url": TARGET, "steps": [{"tool": "delete_file", "match": {"path": "*"}}]}, headers=h).json()["reason"] == REF_PLAN_STEP_REFUSED
    assert c.post("/plans", json={"target_url": TARGET, "steps": [{"tool": "send_mail", "match": {"to": "*"}}]}, headers=h).json()["reason"] == REF_PLAN_STEP_NOT_PLANNABLE
    assert c.post("/plans", json={"target_url": TARGET, "steps": [{"tool": "write_file", "match": {"path": "*"}}]}, headers=h).json()["reason"] == REF_PLAN_STEP_REFUSED
    # Reads need no approval: a plan of reads is issued and not held.
    free = c.post("/plans", json={"target_url": TARGET, "steps": [{"tool": "read_file", "match": {"path": "*"}}]}, headers=h).json()
    assert free["issued"] and free["held"] is False
    # The approver signs the plan's hash; the hold completes.
    g = sign_grant(build_grant(decision_sha256=r["plan"]["plan_sha256"], approval_request_id=arid, grant_id="g-p",
                               not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), approver, "approver-1")
    assert c.post("/grants", json=g, headers=h).json()["complete"] is True
    assert c.get("/grants/" + arid, headers=h).json()["grant"]["grant_id"] == "g-p"
    assert c.get("/pending", headers=h).json()["pending"] == []


def test_middleware_runs_a_planned_task_with_one_card(tmp_path):
    """Three held writes, one card: the plan. Then a write outside the plan
    gets its own card, and a fourth matching write finds no step left."""
    root = tmp_path / "proj"; root.mkdir()
    for n in ("a.md", "b.md", "c.md"): (root / n).write_text("old\\n", encoding="utf-8")
    app = build_issuer_app(policy=_rules(tmp_path), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           approver_public_keys=APPROVERS)
    c = TestClient(app); h = {"Authorization": "Bearer " + token()}; cards = []

    class Shim:
        def post(self, url, json=None, headers=None, timeout=None): return c.post(url.replace("http://i", ""), json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return c.get(url.replace("http://i", ""), headers=headers)

    def human(seconds):
        for hold in c.get("/pending", headers=h).json()["pending"]:
            cards.append(hold)
            arid = hold["plan"]["approval_request_id"] if "plan" in hold else hold["envelope"]["approval_request_id"]
            dsha = hold["plan"]["plan_sha256"] if "plan" in hold else hold["envelope"]["decision_sha256"]
            g = sign_grant(build_grant(decision_sha256=dsha, approval_request_id=arid, grant_id="g-" + arid,
                                       not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), approver, "approver-1")
            c.post("/grants", json=g, headers=h)

    up = StdioUpstream([sys.executable, "-I", "-m", "gargoyle.fs_server", str(root)])
    try:
        state = ServerState({"pinned_public_keys": ISSUER_KEYS, "record": _rules(tmp_path).pin(), "target_id": TARGET, "principal": PRINCIPAL,
                             "approver_public_keys": APPROVERS, "executor_signing_key": executor, "executor_key_id": "executor-1"},
                            upstream=up, issuer_client=IssuerClient("http://i", token(), http=Shim(), approval_timeout=30, poll_seconds=0.01, sleep=human),
                            audit_log=str(tmp_path / "audit.jsonl"))
        handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        handle_message(state, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = handle_message(state, {"jsonrpc": "2.0", "id": 0, "method": "tools/list", "params": {}})["result"]["tools"]
        assert any(t["name"] == PLAN_TOOL for t in tools)
        call = lambda n, name, args: handle_message(state, {"jsonrpc": "2.0", "id": n, "method": "tools/call", "params": {"name": name, "arguments": args}})["result"]
        steps = [{"tool": "write_file", "match": {"path": str(root) + "*"}}] * 3
        r = call(2, PLAN_TOOL, {"steps": steps, "note": "rewrite three notes"})
        assert r["_meta"][REASON_META_KEY] == "PLAN_APPROVED" and len(cards) == 1 and "plan" in cards[0]
        for n, name in enumerate(("a.md", "b.md", "c.md"), 3):
            r = call(n, "write_file", {"path": str(root / name), "content": "new\\n"})
            assert r["_meta"][EXECUTED_META_KEY] is True, r
        assert len(cards) == 1 and all((root / n).read_text(encoding="utf-8") == "new\\n" for n in ("a.md", "b.md", "c.md"))
        # A fourth matching write: no step left, so it gets its own card.
        r = call(6, "write_file", {"path": str(root / "a.md"), "content": "newer\\n"})
        assert r["_meta"][EXECUTED_META_KEY] is True and len(cards) == 2 and "envelope" in cards[1]
        # Evidence: three rows released by the plan, each naming the step; the fourth by its own grant.
        v = verify_log(read_log(str(tmp_path / "audit.jsonl")), issuer_public_keys=ISSUER_KEYS,
                       executor_public_keys={"executor-1": executor.public_key()}, approver_public_keys=APPROVERS)
        assert v["accepted"]
        writes = [e for e in v["entries"] if e["tool"] == "write_file"]
        assert [e["plan"]["step"] if e["plan"] else None for e in writes] == [0, 1, 2, None]
        assert all(e["released_by"] == ["approver-1"] for e in writes)
    finally:
        up.close()
