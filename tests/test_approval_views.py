"""Approval views by role: one signed object, three renderings. The issuer
describes every hold in plain words (gargoyle.holdtext), a rule routes a
hold to a directory role (`approver_roles`), the issuer refuses a grant
from a token without the role and attests the role on one that has it,
and the executor honors a role-routed receipt only with that attestation."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from gargoyle.approval import (ACCEPT_GRANTS_SUFFICIENT, REF_APPROVAL_ROLE_NOT_ELIGIBLE, REF_APPROVAL_ROLE_UNATTESTED,
                               attest_roles, build_grant, sign_grant, verify_grants, verify_role_attestation)
from gargoyle.approvers import ApproverRegistry, may_enroll
from gargoyle.consumer import Consumer
from gargoyle.envelope import approval_terms, build_envelope, sign_envelope, valid_approval
from gargoyle.holdtext import describe_hold, describe_plan, line_delta, split_path
from gargoyle.issuer_service import REF_ISSUER_BAD_REQUEST, build_issuer_app
from gargoyle.jws import encode
from gargoyle.policy import ELIGIBLE, Decision
from gargoyle.rules import RulesPolicy, decide_rules, decide_rules_pattern, validate_rules

issuer, idp = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}
TARGET = "mcp://fs"
NOW = datetime(2026, 10, 31, 9, 0, tzinfo=timezone.utc)
pub_hex = lambda k: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


# ---- the sentence ----

def test_filesystem_templates_read_as_one_sentence():
    old = "alpha\nbeta\ngamma\n"
    st = {"ref": "/srv/clients/acme/plan.md", "sha256": "b" * 64, "size": len(old), "text": old}
    d = describe_hold("write_file", {"path": "/srv/clients/acme/plan.md", "content": "alpha\nbeta two\ngamma\ndelta\n"}, st)
    assert d == {"sentence": "Replace the contents of plan.md in /srv/clients/acme (17 bytes -> 27 bytes; +2/-1 lines)",
                 "readable": True, "irreversible": False, "verb": "replace"}
    new = describe_hold("write_file", {"path": "C:\\gargoyle-share\\hello.txt", "content": "hi"}, {"ref": "C:\\gargoyle-share\\hello.txt", "sha256": None, "size": None})
    assert new["sentence"] == "Create hello.txt (2 bytes) in C:\\gargoyle-share" and new["readable"]
    assert describe_hold("edit_file", {"path": "/a/b.txt", "edits": [{"oldText": "x", "newText": "y"}]}, {"ref": "/a/b.txt", "sha256": "c" * 64, "size": 2048})["sentence"] \
        == "Change 1 passage in b.txt in /a (2.0 KB now)"
    assert describe_hold("create_directory", {"path": "/srv/clients/acme/2026"}, None)["sentence"] == "Create folder 2026 in /srv/clients/acme"
    assert describe_hold("move_file", {"source": "/a/x.txt", "destination": "/a/y.txt"}, None)["sentence"] == "Rename x.txt to y.txt in /a"
    assert describe_hold("move_file", {"source": "/a/x.txt", "destination": "/b/x.txt"}, None)["sentence"] == "Move x.txt from /a to /b"
    rm = describe_hold("delete_file", {"path": "/a/x.txt"}, {"ref": "/a/x.txt", "sha256": "d" * 64, "size": 10})
    assert rm["sentence"] == "Delete x.txt (10 bytes) from /a" and rm["irreversible"] and rm["readable"]
    assert describe_hold("read_file", {"path": "/a/x.txt"}, None)["sentence"] == "Read x.txt in /a"
    mail = describe_hold("send_mail", {"to": ["cfo@acme.example"], "subject": "Q3 invoices", "attachments": [1, 2]}, None)
    assert mail["sentence"] == "Send an email to cfo@acme.example with subject 'Q3 invoices' (2 attachments)" and mail["irreversible"]
    # The adapter's own summary wins; an unknown tool is for the technical view only.
    own = describe_hold("send_mail", {"x": 1}, {"ref": "mail", "sha256": None, "size": None, "summary": "Send 1 mail to 3 people", "irreversible": True})
    assert own["sentence"] == "Send 1 mail to 3 people" and own["irreversible"]
    unknown = describe_hold("transfer_funds", {"amount": 5, "to": "x"}, None)
    assert unknown["readable"] is False and unknown["sentence"] == "transfer_funds with 2 arguments"
    assert describe_hold(None, None, None)["readable"] is False
    assert split_path("C:\\x\\y.txt") == ("C:\\x", "y.txt") and split_path("/y.txt") == ("/", "y.txt") and split_path("y.txt") == ("", "y.txt")
    assert line_delta("a\nb\n", "a\nc\nd\n") == (2, 1)


def test_plan_summary_counts_the_steps():
    plan = {"note": "Reorganise Q3", "steps": [{"tool": "move_file", "match": {"source": "/q3/*"}}] * 6 + [{"tool": "write_file", "args_sha256": "e" * 64}] * 2}
    d = describe_plan(plan)
    assert d["sentence"] == "Plan of 8 steps: Reorganise Q3 (6 move_file, 2 write_file)" and d["readable"]
    assert describe_plan({"steps": "no"})["readable"] is False


# ---- the terms ----

def test_rules_route_a_hold_to_a_role():
    doc = {"version": "v", "default": "deny", "rules": [
        {"tools": ["write_file"], "args": {"path": "/srv/clients/*"}, "action": "hold", "approver_roles": ["Approver.Business", "Approver"]},
        {"tools": ["delete_*"], "action": "hold"},
    ]}
    assert validate_rules(doc) is None
    d = decide_rules(doc, {"tool": "write_file", "args": {"path": "/srv/clients/acme/a.md"}, "principal": "p"})
    assert d.requires_approval and d.approver_roles == ("Approver.Business", "Approver")
    assert d.approval == {"required": 1, "roles": ["Approver", "Approver.Business"]}
    assert decide_rules(doc, {"tool": "delete_file", "args": {}, "principal": "p"}).approval is None
    for bad in ({"tools": ["t"], "action": "hold", "approver_roles": []}, {"tools": ["t"], "action": "hold", "approver_roles": ["a", "a"]},
                {"tools": ["t"], "action": "hold", "approver_roles": "a"}, {"tools": ["t"], "action": "allow", "approver_roles": ["a"]}):
        assert validate_rules({"version": "v", "rules": [bad]}) is not None, bad
    # A pattern that reaches two role-routed rules: the intersection; disjoint roles make the step non-plannable.
    doc2 = {"version": "v", "default": "deny", "rules": [
        {"tools": ["write_file"], "args": {"path": "/srv/clients/acme/*"}, "action": "hold", "approver_roles": ["Approver.Business"]},
        {"tools": ["write_file"], "args": {"path": "/srv/clients/*"}, "action": "hold", "approver_roles": ["Approver.Business", "Approver.Deputy"]},
    ]}
    p = decide_rules_pattern(doc2, {"tool": "write_file", "args": {"path": "/srv/clients/*"}, "principal": "p"})
    assert p.approver_roles == ("Approver.Business",) and p.plannable
    doc2["rules"][0]["approver_roles"] = ["Approver.Deputy"]
    doc2["rules"][1]["approver_roles"] = ["Approver.Business"]
    assert decide_rules_pattern(doc2, {"tool": "write_file", "args": {"path": "/srv/clients/*"}, "principal": "p"}).plannable is False


def test_the_roles_are_in_the_receipt_and_validated():
    assert valid_approval({"required": 1, "roles": ["Approver.Business"]})
    for bad in ({"required": 1, "roles": []}, {"required": 1, "roles": ["a", "a"]}, {"required": 1, "roles": [""]}, {"required": 1, "roles": "a"}):
        assert not valid_approval(bad), bad
    env = build_envelope(decision=ELIGIBLE, target_url=TARGET, call={"tool": "write_file", "args": {}, "principal": "p"}, policy_pin=PIN,
                         requires_approval=True, approval={"required": 1, "roles": ["Approver.Deputy", "Approver.Business"]})
    assert env["approval"] == {"required": 1, "roles": ["Approver.Business", "Approver.Deputy"]}
    assert approval_terms(env)["roles"] == ["Approver.Business", "Approver.Deputy"]
    assert Decision(ELIGIBLE, None, True, approver_roles=("B", "A")).approval == {"required": 1, "roles": ["A", "B"]}


def test_sub_roles_of_the_approver_role_count_as_approvers():
    assert may_enroll({"roles": ["Approver.Business"]}) and may_enroll({"roles": ["Approver.Deputy"]}, role="Approver")
    assert not may_enroll({"roles": ["Approvers"]}) and not may_enroll({"roles": ["Reader.Approver"]})


# ---- the grant set: attested roles ----

def _receipt(roles):
    env = build_envelope(decision=ELIGIBLE, target_url=TARGET, call={"tool": "write_file", "args": {"path": "/x"}, "principal": "agent"},
                         policy_pin=PIN, requires_approval=True, approval={"required": 1, "roles": roles} if roles else None)
    return sign_envelope(env, issuer, "issuer-1", not_after=NOW + timedelta(minutes=5), decision_id="d-7", approval_request_id="r-7")


def _grant(env, key, kid, gid="g-1"):
    return sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"], grant_id=gid,
                                  not_after=NOW + timedelta(minutes=5)), key, kid)


def test_executor_requires_the_issuers_role_attestation():
    dana = Ed25519PrivateKey.generate()
    keys = {"dana@contoso.com": dana.public_key()}
    env = _receipt(["Approver.Business"])
    plain = _grant(env, dana, "dana@contoso.com")
    issuer_keys = {"issuer-1": issuer.public_key()}
    kw = dict(envelope=env, approver_public_keys=keys, now=NOW, issuer_public_keys=issuer_keys)
    # A grant the client brought without the issuer's attestation is refused; so is one the executor cannot verify.
    assert verify_grants(plain, **kw)["reason"] == REF_APPROVAL_ROLE_UNATTESTED
    att = dict(plain, role_attestation=attest_roles(plain, ["Approver.Business"], issuer, "issuer-1"))
    assert verify_grants(att, **kw)["reason"] == ACCEPT_GRANTS_SUFFICIENT
    assert verify_grants(att, envelope=env, approver_public_keys=keys, now=NOW)["reason"] == REF_APPROVAL_ROLE_UNATTESTED
    # The approver's signature is untouched by the attestation; the wrong role, a moved attestation,
    # a forged signer or a tampered role list are refused.
    wrong = dict(plain, role_attestation=attest_roles(plain, ["Approver.Deputy"], issuer, "issuer-1"))
    assert verify_grants(wrong, **kw)["reason"] == REF_APPROVAL_ROLE_NOT_ELIGIBLE
    other = _grant(env, dana, "dana@contoso.com", "g-2")
    moved = dict(other, role_attestation=att["role_attestation"])
    assert verify_grants(moved, **kw)["reason"] == REF_APPROVAL_ROLE_UNATTESTED
    forged = dict(plain, role_attestation=attest_roles(plain, ["Approver.Business"], Ed25519PrivateKey.generate(), "issuer-1"))
    assert verify_grants(forged, **kw)["reason"] == REF_APPROVAL_ROLE_UNATTESTED
    tampered = dict(att, role_attestation=dict(att["role_attestation"], roles=["Approver.Business", "Approver.Deputy"]))
    assert verify_grants(tampered, **kw)["reason"] == REF_APPROVAL_ROLE_UNATTESTED
    assert verify_role_attestation(att, required_roles=["Approver.Business"], issuer_public_keys=issuer_keys, gate_key_id="issuer-2")["reason"] == REF_APPROVAL_ROLE_UNATTESTED
    # A receipt without roles never needs one; one with an attestation on it is simply accepted.
    free = _receipt(None)
    assert verify_grants(_grant(free, dana, "dana@contoso.com"), envelope=free, approver_public_keys=keys, now=NOW)["accepted"]
    # The consumer passes its pinned issuer keys through.
    c = Consumer(target_id=TARGET, pinned_public_keys=issuer_keys, record=PIN, approver_public_keys=keys)
    call = {"tool": "write_file", "args": {"path": "/x"}, "principal": "agent"}
    assert c.check(env, call, grant=plain, now=NOW).reason == REF_APPROVAL_ROLE_UNATTESTED
    assert c.check(env, call, grant=att, now=NOW).honored


# ---- the issuing service ----

class Rules:
    def __init__(self, path): self.p = RulesPolicy(path)
    def pin(self): return self.p.pin()
    def decide(self, t, i): return self.p.decide(t, i)
    def decide_pattern(self, t, i): return self.p.decide_pattern(t, i)


def _token(upn, roles=()):
    claims = {"preferred_username": upn, "sub": "oid-" + upn, "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}
    if roles:
        claims["roles"] = list(roles)
    return encode(claims, idp, "idp-1")


@pytest.fixture
def site(tmp_path):
    import json
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"version": "v", "default": "deny", "rules": [
        {"tools": ["read_*"], "action": "allow"},
        {"tools": ["write_file"], "args": {"path": "/srv/clients/*"}, "action": "hold", "approver_roles": ["Approver.Business"]},
        {"tools": ["delete_file"], "action": "hold", "plan": False},
        {"tools": ["write_file"], "action": "hold"},
    ]}))
    from gargoyle.witness import WitnessLog
    witness = WitnessLog(str(tmp_path / "witness.jsonl"), issuer, "issuer-1")
    reg = ApproverRegistry(str(tmp_path / "approvers.json"))
    app = build_issuer_app(policy=Rules(str(rules)), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           approver_registry=reg, witness=witness, console_entra={"tenant": "t", "client_id": "c", "scope": "s"})
    c = TestClient(app)
    keys = {}
    for upn, roles in (("eng@contoso.com", ["Approver"]), ("owner@contoso.com", ["Approver.Business"]), ("deputy@contoso.com", ["Approver.Deputy"])):
        k = Ed25519PrivateKey.generate(); keys[upn] = k
        r = c.post("/approvers/enroll", json={"public_key_hex": pub_hex(k)}, headers={"Authorization": "Bearer " + _token(upn, roles)})
        assert r.status_code == 200, r.text
    c.keys = keys
    c.h = lambda upn, roles: {"Authorization": "Bearer " + _token(upn, roles)}
    return c


def _sign(c, env, upn, gid=None):
    return sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                  grant_id=gid or ("g-" + upn), not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), c.keys[upn], upn)


def test_issuer_routes_the_hold_refuses_the_wrong_role_and_attests_the_right_one(site):
    c = site
    agent = c.h("agent@contoso.com", [])
    body = {"target_url": TARGET, "tool": "write_file", "args": {"path": "/srv/clients/acme/plan.md", "content": "new\n"},
            "state": {"ref": "/srv/clients/acme/plan.md", "sha256": "f" * 64, "size": 4}}
    env = c.post("/issue", json=body, headers=agent).json()["envelope"]
    assert env["approval"] == {"required": 1, "roles": ["Approver.Business"]}
    # /pending: the sentence, and who is eligible, computed by the issuer.
    for upn, roles, eligible in (("eng@contoso.com", ["Approver"], False), ("owner@contoso.com", ["Approver.Business"], True),
                                 ("deputy@contoso.com", ["Approver.Deputy"], False)):
        item = c.get("/pending", headers=c.h(upn, roles)).json()["pending"][0]
        assert item["eligible"] is eligible, upn
        assert item["summary"]["sentence"] == "Replace the contents of plan.md in /srv/clients/acme (4 bytes -> 4 bytes)" and item["summary"]["readable"]
    # The engineer's grant is refused: the hold is routed to the business role.
    r = c.post("/grants", json=_sign(c, env, "eng@contoso.com"), headers=c.h("eng@contoso.com", ["Approver"])).json()
    assert r == {"accepted": False, "reason": REF_APPROVAL_ROLE_NOT_ELIGIBLE}
    # The owner's token carries the role: accepted, and the stored grant carries the issuer's attestation.
    r = c.post("/grants", json=_sign(c, env, "owner@contoso.com"), headers=c.h("owner@contoso.com", ["Approver.Business"])).json()
    assert r["accepted"] and r["complete"]
    got = c.get("/grants/" + env["approval_request_id"], headers=agent).json()["grant"]
    assert got["role_attestation"]["roles"] == ["Approver.Business"] and got["role_attestation"]["issuer_key_id"] == "issuer-1"
    # The executor honors it with its pinned issuer key, and only with the attestation.
    consumer = Consumer(target_id=TARGET, pinned_public_keys={"issuer-1": issuer.public_key()}, record=env["policy"],
                        approver_public_keys={"owner@contoso.com": c.keys["owner@contoso.com"].public_key()})
    from gargoyle.state import state_sha256
    call = {"tool": "write_file", "args": body["args"], "principal": "agent@contoso.com", "state_sha256": state_sha256(body["state"])}
    stripped = {k: v for k, v in got.items() if k != "role_attestation"}
    assert consumer.check(env, call, grant=stripped).reason == REF_APPROVAL_ROLE_UNATTESTED
    assert consumer.check(env, call, grant=got).honored
    # The witness names the role the release was made under.
    granted = [e for e in c.app.state.witness.entries if e["event"] == "granted"]
    assert granted[-1]["roles"] == ["Approver.Business"]
    refused = [e for e in c.app.state.witness.entries if e["event"] == "grant_refused"]
    assert refused[-1]["reason"] == REF_APPROVAL_ROLE_NOT_ELIGIBLE


def test_a_hold_without_roles_is_for_any_approver_and_the_week_is_counted(site):
    c = site
    agent = c.h("agent@contoso.com", [])
    env = c.post("/issue", json={"target_url": TARGET, "tool": "write_file", "args": {"path": "/tmp/x", "content": ""}}, headers=agent).json()["envelope"]
    assert "approval" not in env
    item = c.get("/pending", headers=c.h("owner@contoso.com", ["Approver.Business"])).json()["pending"][0]
    assert item["eligible"] is True and item["summary"]["sentence"] == "Write x (0 bytes) in /tmp"
    r = c.post("/grants", json=_sign(c, env, "deputy@contoso.com"), headers=c.h("deputy@contoso.com", ["Approver.Deputy"])).json()
    assert r["accepted"]
    assert "role_attestation" not in c.get("/grants/" + env["approval_request_id"], headers=agent).json()["grant"]
    me = c.get("/me", headers=c.h("deputy@contoso.com", ["Approver.Deputy"])).json()
    assert me["roles"] == ["Approver.Deputy"] and me["approver_role"] == "Approver"
    assert me["released_7d"] == 1 and me["released_by_tool_7d"] == {"write_file": 1}
    assert c.get("/me", headers=c.h("owner@contoso.com", ["Approver.Business"])).json()["released_7d"] == 0
    week = c.get("/health").json()["week"]
    assert week["held_7d"] == 1 and week["released_7d"] == 1 and week["released_by_role_7d"] == {"*": 1}
    assert isinstance(week["median_release_seconds"], float)


def test_decline_carries_an_optional_reason_into_the_witness(site):
    c = site
    env = c.post("/issue", json={"target_url": TARGET, "tool": "write_file", "args": {"path": "/tmp/y", "content": ""}}, headers=c.h("agent@contoso.com", [])).json()["envelope"]
    arid = env["approval_request_id"]
    r = c.post("/decline", json={"approval_request_id": arid, "reason": 5}, headers=c.h("owner@contoso.com", ["Approver.Business"]))
    assert r.status_code == 400 and r.json()["detail"]["reason"] == REF_ISSUER_BAD_REQUEST
    r = c.post("/decline", json={"approval_request_id": arid, "reason": "not this week"}, headers=c.h("owner@contoso.com", ["Approver.Business"])).json()
    assert r["declined"] is True
    assert [e for e in c.app.state.witness.entries if e["event"] == "declined"][-1]["why"] == "not this week"


def test_plans_carry_the_routing_and_are_released_only_by_the_role(site):
    c = site
    agent = c.h("agent@contoso.com", [])
    r = c.post("/plans", json={"target_url": TARGET, "note": "Acme Q3 updates",
                               "steps": [{"tool": "write_file", "match": {"path": "/srv/clients/acme/*"}}]}, headers=agent).json()
    assert r["issued"] and r["held"] and r["plan"]["approval"] == {"required": 1, "roles": ["Approver.Business"]}
    plan = r["plan"]
    item = c.get("/pending", headers=c.h("owner@contoso.com", ["Approver.Business"])).json()["pending"][0]
    assert item["summary"]["sentence"] == "Plan of 1 step: Acme Q3 updates (1 write_file)" and item["eligible"]
    assert c.get("/pending", headers=c.h("eng@contoso.com", ["Approver"])).json()["pending"][0]["eligible"] is False
    g = lambda upn: sign_grant(build_grant(decision_sha256=plan["plan_sha256"], approval_request_id=plan["approval_request_id"], grant_id="pg-" + upn,
                                           not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), c.keys[upn], upn)
    assert c.post("/grants", json=g("eng@contoso.com"), headers=c.h("eng@contoso.com", ["Approver"])).json()["reason"] == REF_APPROVAL_ROLE_NOT_ELIGIBLE
    assert c.post("/grants", json=g("owner@contoso.com"), headers=c.h("owner@contoso.com", ["Approver.Business"])).json()["accepted"]
    released = c.get("/grants/" + plan["approval_request_id"], headers=agent).json()["grant"]
    assert released["role_attestation"]["roles"] == ["Approver.Business"]
    # A plan whose steps are routed to disjoint roles cannot be one approval.
    r = c.post("/plans", json={"target_url": TARGET, "note": "mixed",
                               "steps": [{"tool": "write_file", "match": {"path": "/srv/clients/acme/*"}},
                                         {"tool": "delete_file", "match": {"path": "/srv/clients/acme/*"}}]}, headers=agent).json()
    assert r["issued"] is False          # delete_file is non-plannable here; the routing check comes after
    # The executor: the plan release needs the attestation too.
    from gargoyle.plans import verify_plan_release
    env = c.post("/issue", json={"target_url": TARGET, "tool": "write_file", "args": {"path": "/srv/clients/acme/a.md", "content": "x"},
                                 "plan_id": plan["plan_id"]}, headers=agent).json()["envelope"]
    call = {"tool": "write_file", "args": {"path": "/srv/clients/acme/a.md", "content": "x"}, "principal": "agent@contoso.com"}
    keys = {"owner@contoso.com": c.keys["owner@contoso.com"].public_key()}
    ok = verify_plan_release({"plan": plan, "grants": [released], "step": 0}, env, call, issuer_public_keys={"issuer-1": issuer.public_key()}, approver_public_keys=keys)
    assert ok["accepted"], ok
    stripped = {k: v for k, v in released.items() if k != "role_attestation"}
    bad = verify_plan_release({"plan": plan, "grants": [stripped], "step": 0}, env, call, issuer_public_keys={"issuer-1": issuer.public_key()}, approver_public_keys=keys)
    assert bad["reason"] == REF_APPROVAL_ROLE_UNATTESTED
