"""RulesPolicy: a JSON file instead of a policy engine. First match wins,
globs on tool, principal, delegation and string arguments; a malformed
file or any error is a refusal; editing the file moves the pin."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.envelope import RE_EVALUATE_REQUIRED, reassert
from gargoyle.issuer import issue
from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import encode
from gargoyle.policy import ELIGIBLE, Policy, REFUSE
from gargoyle.rules import RULE_DENIED, RULES_MALFORMED, RULES_POLICY_ID, RulesPolicy, decide_rules, validate_rules

RULES = {
    "version": "clients-2026-10",
    "default": "deny",
    "rules": [
        {"tools": ["read_*", "list_*"], "action": "allow"},
        {"tools": ["write_file"], "args": {"path": "/srv/clients/*"}, "action": "hold"},
        {"tools": ["write_file"], "action": "deny", "reason": "OUTSIDE_CLIENT_TREE"},
        {"tools": ["deploy_*"], "principals": ["spiffe://example.org/agents/*"],
         "on_behalf_of": ["user-*"], "action": "hold"},
        {"tools": ["delete_*"], "action": "deny", "reason": "DESTRUCTIVE_TOOL"},
    ],
}


def call(tool, args=None, principal="spiffe://example.org/agents/coder", **extra):
    return {"tool": tool, "args": args if args is not None else {}, "principal": principal, **extra}


@pytest.fixture
def policy(tmp_path):
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(RULES))
    return RulesPolicy(str(p)), p


def test_first_match_wins_and_default_denies(policy):
    pol, _ = policy
    assert isinstance(pol, Policy)
    d = pol.decide("t", call("read_file"));            assert (d.outcome, d.requires_approval) == (ELIGIBLE, False)
    d = pol.decide("t", call("write_file", {"path": "/srv/clients/acme/a.txt"}))
    assert (d.outcome, d.requires_approval) == (ELIGIBLE, True)
    d = pol.decide("t", call("write_file", {"path": "/etc/passwd"}));   assert (d.outcome, d.reason) == (REFUSE, "OUTSIDE_CLIENT_TREE")
    d = pol.decide("t", call("write_file", {"path": 7}));               assert d.reason == "OUTSIDE_CLIENT_TREE"
    d = pol.decide("t", call("deploy_prod", on_behalf_of="user-42"));   assert d.requires_approval is True
    d = pol.decide("t", call("deploy_prod"));                           assert d.reason == RULE_DENIED   # no delegation: rule skipped
    d = pol.decide("t", call("deploy_prod", principal="stranger", on_behalf_of="user-1")); assert d.reason == RULE_DENIED
    d = pol.decide("t", call("delete_everything"));                     assert d.reason == "DESTRUCTIVE_TOOL"
    d = pol.decide("t", call("unknown_tool"));                          assert d.reason == RULE_DENIED
    assert pol.decide("t", ["not", "a", "mapping"]).reason == RULES_MALFORMED


def test_default_can_hold_or_allow():
    doc = {"version": "1", "default": "hold", "rules": []}
    assert decide_rules(doc, call("anything")).requires_approval is True
    doc["default"] = "allow"
    assert decide_rules(doc, call("anything")).requires_approval is False


@pytest.mark.parametrize("bad", [
    [], {"rules": []}, {"version": "", "rules": []}, {"version": "1", "rules": {}},
    {"version": "1", "default": "maybe", "rules": []},
    {"version": "1", "rules": [{"action": "allow"}]},
    {"version": "1", "rules": [{"tools": [], "action": "allow"}]},
    {"version": "1", "rules": [{"tools": ["x"], "action": "permit"}]},
    {"version": "1", "rules": [{"tools": ["x"], "action": "allow", "principals": "me"}]},
    {"version": "1", "rules": [{"tools": ["x"], "action": "allow", "args": {"path": 1}}]},
    {"version": "1", "rules": [{"tools": ["x"], "action": "deny", "reason": ""}]},
])
def test_malformed_documents_are_refused(tmp_path, bad):
    assert validate_rules(bad) is not None
    p = tmp_path / "rules.json"; p.write_text(json.dumps(bad))
    assert RulesPolicy(str(p)).decide("t", call("x")).reason == RULES_MALFORMED
    p.write_text("not json")
    assert RulesPolicy(str(p)).decide("t", call("x")).outcome == REFUSE
    assert RulesPolicy(str(tmp_path / "missing.json")).decide("t", call("x")).outcome == REFUSE
    with pytest.raises(ValueError):
        RulesPolicy("")


def test_editing_the_file_moves_the_pin_and_kills_outstanding_receipts(policy):
    pol, p = policy
    key = Ed25519PrivateKey.generate()
    pin = pol.pin()
    assert pin["policy_id"] == RULES_POLICY_ID and len(pin["policy_sha256"]) == 64
    r = issue(pol, "t", call("read_file"), signing_key=key, key_id="k1")
    assert r.envelope is not None and reassert(r.envelope, policy=pol)["outcome"] == "REASSERTED"
    doc = dict(RULES); doc["rules"] = [{"tools": ["read_*"], "action": "hold"}] + RULES["rules"]
    p.write_text(json.dumps(doc))
    assert pol.pin()["policy_sha256"] != pin["policy_sha256"]
    assert reassert(r.envelope, policy=pol)["outcome"] == RE_EVALUATE_REQUIRED
    assert issue(pol, "t", call("read_file"), signing_key=key, key_id="k1").decision.requires_approval is True


def test_issuer_service_runs_on_a_rules_file(policy):
    pol, _ = policy
    issuer = Ed25519PrivateKey.generate(); idp = Ed25519PrivateKey.generate()
    app = build_issuer_app(policy=pol, signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()})
    c = TestClient(app)
    tok = encode({"sub": "spiffe://example.org/agents/coder", "exp": 4102444800}, idp, "idp-1")
    h = {"Authorization": "Bearer " + tok}
    assert c.post("/issue", json={"target_url": "t", "tool": "list_dir", "args": {}}, headers=h).json()["issued"] is True
    held = c.post("/issue", json={"target_url": "t", "tool": "write_file", "args": {"path": "/srv/clients/x"}}, headers=h).json()
    assert held["envelope"]["requires_approval"] is True
    assert c.post("/issue", json={"target_url": "t", "tool": "delete_db", "args": {}}, headers=h).json() == {"issued": False, "reason": "DESTRUCTIVE_TOOL"}
    assert c.get("/record").json() == pol.pin()


def test_app_from_env_prefers_rules_over_opa(monkeypatch, policy):
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
    from gargoyle.issuer_service import app_from_env
    _, p = policy
    issuer = Ed25519PrivateKey.generate(); idp = Ed25519PrivateKey.generate()
    monkeypatch.setenv("GARGOYLE_ISSUER_KEY_ID", "issuer-1")
    monkeypatch.setenv("GARGOYLE_ISSUER_KEY_HEX", issuer.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    monkeypatch.setenv("GARGOYLE_IDP_KEY_ID", "idp-1")
    monkeypatch.setenv("GARGOYLE_IDP_PUBLIC_KEY_HEX", idp.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    for v in ("GARGOYLE_RULES_PATH", "GARGOYLE_OPA_URL", "GARGOYLE_OPA_DECISION_PATH"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(RuntimeError):
        app_from_env()
    monkeypatch.setenv("GARGOYLE_RULES_PATH", str(p))
    assert TestClient(app_from_env()).get("/record").json()["policy_id"] == RULES_POLICY_ID
