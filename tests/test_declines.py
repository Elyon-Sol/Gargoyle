"""A decline carries the approver's words to the model; the same file asked
for again and again stops reaching the approver; and the model is told which
yes it got, so an observed call is never reported as approved."""

import io
import json

from fastapi.testclient import TestClient

from gargoyle.issuer_service import REF_ISSUER_DECLINED_RECENTLY, build_issuer_app
from gargoyle.mcp_server import REF_TARGET_APPROVAL_DECLINED, _gate, outcome_text
from gargoyle.witness import WitnessLog
from tests.test_mcp_self_issue import PRINCIPAL, ToolPolicy, approver, call, idp, issuer, middleware, token

APPROVER = "approver-alice"


def app(**kw):
    return build_issuer_app(policy=ToolPolicy(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                            approver_public_keys={APPROVER: approver.public_key()}, **kw)


def pending_ids(client):
    return [h["envelope"]["approval_request_id"] for h in client.get("/pending", headers={"Authorization": "Bearer " + token()}).json()["pending"]]


def decline_all(client, why=None, who=APPROVER):
    for arid in pending_ids(client):
        body = {"approval_request_id": arid}
        if why:
            body["reason"] = why
        assert client.post("/decline", json=body, headers={"Authorization": "Bearer " + token(who)}).json()["declined"]


def test_the_approvers_reason_reaches_the_gate_and_the_model():
    client = TestClient(app())
    state = middleware(client, sleep=lambda s: decline_all(client, "routed is for Sean, the business approver; put drafts in the top folder"))
    g = _gate(state, call("write_file", {"path": "routed/plan.md", "content": "x"}))
    assert (g["executed"], g["reason"]) == (False, REF_TARGET_APPROVAL_DECLINED)
    assert g["why"] == "routed is for Sean, the business approver; put drafts in the top folder"
    assert outcome_text(g, "write_file") == ("refused: REF_TARGET_APPROVAL_DECLINED (the approver said: routed is for Sean, "
                                             "the business approver; put drafts in the top folder)")
    # /grants says it too, and only when there are words to say.
    arid = g["envelope"]["approval_request_id"]
    r = client.get("/grants/" + arid, headers={"Authorization": "Bearer " + token()}).json()
    assert r["declined"] is True and r["why"].startswith("routed is for Sean")
    state2 = middleware(client, sleep=lambda s: decline_all(client))
    g2 = _gate(state2, call("write_file", {"path": "other.md", "content": "x"}))
    assert g2["reason"] == REF_TARGET_APPROVAL_DECLINED and "why" not in g2
    assert outcome_text(g2, "write_file") == "refused: REF_TARGET_APPROVAL_DECLINED"


def test_the_same_file_declined_twice_is_not_asked_a_third_time():
    client = TestClient(app(witness=WitnessLog(None, issuer, "issuer-1")))
    state = middleware(client, sleep=lambda s: decline_all(client, "not this file"))
    for _ in range(2):
        g = _gate(state, call("write_file", {"path": r"C:\share\routed\plan.md", "content": "x"}))
        assert g["reason"] == REF_TARGET_APPROVAL_DECLINED
    # Third time: the issuer answers from memory; no card, no wait, the last words relayed.
    polls = {"n": 0}
    state.issuer_client._sleep = lambda s: polls.__setitem__("n", polls["n"] + 1)
    g = _gate(state, call("write_file", {"path": "c:/share/routed/PLAN.md", "content": "y"}))   # same file, other spelling
    assert (g["executed"], g["reason"], g["why"]) == (False, REF_ISSUER_DECLINED_RECENTLY, "not this file")
    assert polls["n"] == 0 and pending_ids(client) == []
    assert outcome_text(g, "write_file") == "refused: REF_ISSUER_DECLINED_RECENTLY (the approver said: not this file)"
    refused = [e for e in client.app.state.witness.entries if e["event"] == "refused"]
    assert refused[-1]["reason"] == REF_ISSUER_DECLINED_RECENTLY and refused[-1]["declines"] == 2 and refused[-1]["why"] == "not this file"
    # Another file by the same principal is a fresh question.
    state.issuer_client._sleep = lambda s: decline_all(client)
    assert _gate(state, call("write_file", {"path": r"C:\share\notes.md", "content": "x"}))["reason"] == REF_TARGET_APPROVAL_DECLINED


def test_the_cooldown_ignores_the_gates_own_withdrawals_and_can_be_turned_off():
    client = TestClient(app())
    # The gate withdrawing its own hold (the principal declining) is not a decision about the file.
    state = middleware(client, sleep=lambda s: decline_all(client, "timed out", who=PRINCIPAL))
    for _ in range(3):
        assert _gate(state, call("write_file", {"path": "a.md", "content": "x"}))["reason"] == REF_TARGET_APPROVAL_DECLINED
    # Disabled: three human declines, still a fourth card.
    client = TestClient(app(decline_limit=0))
    state = middleware(client, sleep=lambda s: decline_all(client, "no"))
    for _ in range(4):
        assert _gate(state, call("write_file", {"path": "a.md", "content": "x"}))["reason"] == REF_TARGET_APPROVAL_DECLINED
    # A call that names no path is never remembered.
    client = TestClient(app())
    state = middleware(client, sleep=lambda s: decline_all(client, "no"))
    for _ in range(3):
        assert _gate(state, call("write_file", {"content": "x"}))["reason"] == REF_TARGET_APPROVAL_DECLINED


def test_the_model_is_told_which_yes_it_got():
    client = TestClient(app())
    state = middleware(client)
    g = _gate(state, call("read_file", {"path": "a.txt"}))
    assert g["executed"] and outcome_text(g, "read_file") == "executed read_file (allowed by rule and recorded; no approver saw it)"
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    from gargoyle.approver_cli import approve_at_issuer
    from tests.test_mcp_self_issue import Shim
    approver_hex = approver.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    state = middleware(client, sleep=lambda s: approve_at_issuer("http://issuer", token(APPROVER), key_hex=approver_hex,
                                                                 key_id=APPROVER, yes=True, http=Shim(client)))
    g = _gate(state, call("write_file", {"path": "a.txt", "content": "x"}))
    assert g["executed"] and g["grant"] is not None
    assert outcome_text(g, "write_file") == "executed write_file (released by an approver)"


def test_the_hook_says_the_same_in_its_note(tmp_path, monkeypatch):
    from tests.test_claude_hook import PRE, deployment, event
    from gargoyle.claude_hook import decide
    out, project, env, state, client = deployment(tmp_path, monkeypatch, observe=True)
    r = decide(event(PRE, "Read", {"file_path": str(project / "x")}), state())
    assert r["hookSpecificOutput"]["additionalContext"].endswith("; allowed by rule and recorded; no approver saw it")
