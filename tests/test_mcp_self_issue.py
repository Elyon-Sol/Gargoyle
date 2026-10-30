"""Self-issue mode: an unmodified MCP client sends a bare tools/call; the
middleware obtains the receipt from the issuing service, waits for the
human's grant when the call is flagged, and still verifies everything
against its own pinned keys."""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.approver_cli import approve_at_issuer
from gargoyle.consumer import REF_TARGET_APPROVAL_REQUIRED
from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import encode
from gargoyle.mcp_server import (
    EXECUTION_META_KEY, REASON_META_KEY, REF_TARGET_APPROVAL_TIMEOUT, REF_TARGET_ISSUER_UNAVAILABLE,
    IssuerClient, ServerState, StdioUpstream, handle_message, gate_tool_call,
)
from gargoyle.policy import ELIGIBLE, Decision, refuse
from gargoyle.verifier import REF_VERIFY_PRINCIPAL_MISMATCH
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

TARGET = "mcp://fs.example"
PRINCIPAL = "spiffe://example.org/agents/coder"
PIN = {"policy_id": "opa:gargoyle/decision", "policy_sha256": "a" * 64}
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
issuer = Ed25519PrivateKey.generate(); idp = Ed25519PrivateKey.generate()
approver = Ed25519PrivateKey.generate(); executor = Ed25519PrivateKey.generate()


class ToolPolicy:
    def pin(self): return PIN
    def decide(self, target_url, interaction):
        tool = interaction.get("tool")
        if tool in ("read_file", "list_directory", "echo"):
            return Decision(ELIGIBLE)
        if tool in ("write_file",):
            return Decision(ELIGIBLE, requires_approval=True)
        return refuse("TOOL_NOT_ALLOWED")


def token(sub=PRINCIPAL):
    return encode({"sub": sub, "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")


class Shim:
    """requests-like transport over a TestClient."""
    def __init__(self, client): self.c = client
    def post(self, url, json=None, headers=None, timeout=None): return self.c.post(url.replace("http://issuer", ""), json=json, headers=headers)
    def get(self, url, headers=None, timeout=None): return self.c.get(url.replace("http://issuer", ""), headers=headers)


def issuer_app():
    return build_issuer_app(policy=ToolPolicy(), signing_key=issuer, key_id="issuer-1",
                            idp_public_keys={"idp-1": idp.public_key()},
                            approver_public_keys={"approver-alice": approver.public_key()})


def middleware(client, token_sub=PRINCIPAL, sleep=None, approval_timeout=5.0, attest=False):
    config = {"pinned_public_keys": {"issuer-1": issuer.public_key()}, "record": PIN,
              "target_id": TARGET, "principal": PRINCIPAL,
              "approver_public_keys": {"approver-alice": approver.public_key()}}
    if attest:
        config.update(executor_signing_key=executor, executor_key_id="executor-1")
    ic = IssuerClient("http://issuer", token(token_sub), http=Shim(client), approval_timeout=approval_timeout,
                      poll_seconds=0.01, sleep=sleep or (lambda s: None))
    return ServerState(config, issuer_client=ic, state_root="/gargoyle-test-root")


def call(name, args):
    return {"name": name, "arguments": args}


def test_bare_call_is_issued_and_executed_once():
    client = TestClient(issuer_app())
    state = middleware(client)
    assert gate_tool_call(state, call("read_file", {"path": "a.txt"})) == (True, "REASSERTED_AND_BOUND")
    assert gate_tool_call(state, call("read_file", {"path": "a.txt"})) == (True, "REASSERTED_AND_BOUND")  # a fresh receipt each time
    assert len(state.executed) == 2
    assert gate_tool_call(state, call("delete_file", {})) == (False, "TOOL_NOT_ALLOWED")
    assert len(state.executed) == 2


def test_issuer_unavailable_or_wrong_subject_refuses():
    class Down:
        def post(self, *a, **k): raise ConnectionError("down")
        def get(self, *a, **k): raise ConnectionError("down")
    state = middleware(TestClient(issuer_app()))
    state.issuer_client._http = Down()
    assert gate_tool_call(state, call("read_file", {})) == (False, REF_TARGET_ISSUER_UNAVAILABLE)
    # A client token for someone else yields a receipt this server will not spend.
    state = middleware(TestClient(issuer_app()), token_sub="spiffe://example.org/agents/other")
    assert gate_tool_call(state, call("read_file", {})) == (False, REF_VERIFY_PRINCIPAL_MISMATCH)
    assert state.executed == []


def test_flagged_call_waits_for_the_human_then_runs_once():
    client = TestClient(issuer_app())
    approver_hex = approver.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    polls = {"n": 0}

    def human_approves_on_second_poll(seconds):
        polls["n"] += 1
        if polls["n"] == 2:
            rc = approve_at_issuer("http://issuer", token("approver-alice"), key_hex=approver_hex,
                                   key_id="approver-alice", yes=True, http=Shim(client))
            assert rc == 0

    state = middleware(client, sleep=human_approves_on_second_poll, attest=True)
    state.initialized = True
    reply = handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": call("write_file", {"path": "a.txt", "content": "hello"})})
    assert reply["result"]["isError"] is False, reply
    assert polls["n"] >= 2
    # The upstream ran the resolved call: the relative path became the root's.
    assert state.executed == [{"tool": "write_file", "args": {"path": "/gargoyle-test-root/a.txt", "content": "hello"}}]
    assert reply["result"]["_meta"][EXECUTION_META_KEY]["request_context"]["tool"] == "write_file"
    # The client never saw the receipt or the grant: the honored result carries them,
    # so the caller holds the whole chain and can audit it offline.
    from gargoyle.execution import verify_chain
    from gargoyle.mcp_server import RECEIPT_META_KEY, USED_GRANT_META_KEY
    meta = reply["result"]["_meta"]
    chain = verify_chain(meta[RECEIPT_META_KEY], meta[EXECUTION_META_KEY],
                         issuer_public_keys={"issuer-1": issuer.public_key()},
                         executor_public_keys={"executor-1": executor.public_key()},
                         grant=meta[USED_GRANT_META_KEY], approver_public_keys={"approver-alice": approver.public_key()})
    assert chain["accepted"] is True, chain
    assert client.get("/pending", headers={"Authorization": "Bearer " + token()}).json()["pending"] == []


def test_flagged_call_times_out_without_a_grant():
    client = TestClient(issuer_app())
    state = middleware(client, approval_timeout=0.0)
    assert gate_tool_call(state, call("write_file", {"path": "a.txt", "content": "x"})) == (False, REF_TARGET_APPROVAL_TIMEOUT)
    assert state.executed == []
    # The gate declines the hold it gave up on, so no approver releases a call
    # nobody is waiting for; a retry by the client opens a fresh hold.
    assert client.get("/pending", headers={"Authorization": "Bearer " + token()}).json()["pending"] == []


def test_declined_hold_stops_the_wait_at_once():
    from gargoyle.mcp_server import REF_TARGET_APPROVAL_DECLINED
    client = TestClient(issuer_app())
    polls = {"n": 0}

    def human_declines_on_first_poll(seconds):
        polls["n"] += 1
        pending = client.get("/pending", headers={"Authorization": "Bearer " + token()}).json()["pending"]
        for h in pending:
            client.post("/decline", json={"approval_request_id": h["envelope"]["approval_request_id"]},
                        headers={"Authorization": "Bearer " + token("approver-alice")})

    state = middleware(client, sleep=human_declines_on_first_poll, approval_timeout=60)
    assert gate_tool_call(state, call("write_file", {"path": "a.txt", "content": "x"})) == (False, REF_TARGET_APPROVAL_DECLINED)
    assert polls["n"] == 1 and state.executed == []


def test_a_receipt_the_client_brings_is_not_reissued():
    """Self-issue only fills a gap: a call that carries its own receipt is
    checked as such, and a flagged one still needs the grant in _meta."""
    from gargoyle.issuer import issue
    from gargoyle.mcp_server import ENVELOPE_META_KEY
    client = TestClient(issuer_app())
    state = middleware(client, approval_timeout=0.0)
    env = issue(ToolPolicy(), TARGET, {"tool": "write_file", "args": {}, "principal": PRINCIPAL},
                signing_key=issuer, key_id="issuer-1").envelope
    params = {**call("write_file", {}), "_meta": {ENVELOPE_META_KEY: env}}
    assert gate_tool_call(state, params) == (False, REF_TARGET_APPROVAL_REQUIRED)


def test_end_to_end_through_the_echo_upstream():
    fixture = str(Path(__file__).parent / "fixtures" / "echo_mcp_server.py")
    client = TestClient(issuer_app())
    up = StdioUpstream([sys.executable, "-I", fixture])
    try:
        state = middleware(client)
        state.upstream = up
        handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        handle_message(state, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        reply = handle_message(state, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": call("echo", {"x": 1})})
        assert reply["result"]["content"][0]["text"] == 'echo:{"x": 1}'
        assert reply["result"]["_meta"][REASON_META_KEY] == "REASSERTED_AND_BOUND"
        refused = handle_message(state, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": call("delete_file", {})})
        assert refused["result"]["isError"] is True and refused["result"]["_meta"][REASON_META_KEY] == "TOOL_NOT_ALLOWED"
        assert up.send({"jsonrpc": "2.0", "id": "f", "method": "fixture/calls"})["result"]["calls"] == [call("echo", {"x": 1})]
    finally:
        up.close()


def test_every_decision_lands_in_the_evidence_log(tmp_path):
    """Honored, refused by policy, and declined by the human: three decisions,
    three chained entries, the declined one still carrying the flagged receipt
    the human did not release. The whole file verifies offline."""
    from gargoyle.evidence import ACCEPT_ENTRY_VERIFIED, HONORED, REFUSED, read_log, verify_log
    from gargoyle.execution import ACCEPT_CHAIN_VERIFIED
    from gargoyle.mcp_server import EXECUTED_META_KEY, REF_TARGET_APPROVAL_DECLINED
    client = TestClient(issuer_app())

    def human_declines(seconds):
        for h in client.get("/pending", headers={"Authorization": "Bearer " + token()}).json()["pending"]:
            client.post("/decline", json={"approval_request_id": h["envelope"]["approval_request_id"]},
                        headers={"Authorization": "Bearer " + token("approver-alice")})

    state = middleware(client, sleep=human_declines, approval_timeout=60, attest=True)
    from gargoyle.evidence import EvidenceLog
    state.evidence = EvidenceLog(str(tmp_path / "e.jsonl"))
    handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "ChatGPT", "version": "2.1"}}})
    handle_message(state, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    ok = handle_message(state, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": call("read_file", {"path": "a"})})
    no = handle_message(state, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": call("delete_file", {"path": "a"})})
    declined = handle_message(state, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                      "params": call("write_file", {"path": "a", "content": "x"})})
    assert ok["result"]["_meta"][EXECUTED_META_KEY] is True
    assert no["result"]["_meta"][REASON_META_KEY] == "TOOL_NOT_ALLOWED"
    assert declined["result"]["_meta"][REASON_META_KEY] == REF_TARGET_APPROVAL_DECLINED

    entries = read_log(str(tmp_path / "e.jsonl"))
    assert [e["kind"] for e in entries] == [HONORED, REFUSED, REFUSED]
    assert {e["client"] for e in entries} == {"ChatGPT 2.1"}               # which assistant asked, every entry
    assert [e["seq"] for e in entries] == [1, 2, 3] and entries[2]["prev_sha256"] == entries[1]["entry_sha256"]
    assert entries[1]["receipt"] is None                               # policy said no: nothing was issued
    assert entries[2]["receipt"]["requires_approval"] is True          # the human said no: the hold is on record
    assert entries[2]["grant"] is None and entries[2]["execution"] is None
    v = verify_log(entries, issuer_public_keys={"issuer-1": issuer.public_key()},
                   executor_public_keys={"executor-1": executor.public_key()},
                   approver_public_keys={"approver-alice": approver.public_key()})
    assert v["accepted"] and (v["honored"], v["refused"]) == (1, 2)
    assert [r["reason"] for r in v["entries"]] == [ACCEPT_CHAIN_VERIFIED, ACCEPT_ENTRY_VERIFIED, ACCEPT_ENTRY_VERIFIED]


def test_the_gate_hands_the_model_standing_instructions(monkeypatch):
    """The initialize answer carries instructions in both modes, so the user
    never has to name the server; an operator may override the text."""
    from gargoyle.mcp_server import gate_instructions
    client = TestClient(issuer_app())
    state = middleware(client)
    r = handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    text = r["result"]["instructions"]
    assert TARGET in text and "do not use any other tool" in text and "gargoyle_plan" in text and "never needs to name this server" in text
    # Through a real upstream, the upstream's own instructions follow the gate's.
    fixture = str(Path(__file__).parent / "fixtures" / "echo_mcp_server.py")
    up = StdioUpstream([sys.executable, "-I", fixture])
    try:
        state = middleware(client); state.upstream = up
        r = handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert r["result"]["instructions"].startswith("Every operation on " + TARGET)
    finally:
        up.close()
    monkeypatch.setenv("GARGOYLE_MCP_INSTRUCTIONS", "House rule: files only.")
    state = middleware(client)
    assert handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})["result"]["instructions"] == "House rule: files only."
    assert gate_instructions("t", "Upstream says hi").endswith("Upstream says hi")
