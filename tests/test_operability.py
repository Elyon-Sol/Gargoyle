"""Operability items from the second review: one evidence log shared by
two gate processes, init that keeps keys, tokens minted alone, the gate's
own files out of the model's reach, holds declined when the gate stops
waiting."""

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from gargoyle.evidence import ACCEPT_EVIDENCE_VERIFIED, HONORED, REFUSED, EvidenceLog, read_log, verify_log
from gargoyle.issuer import issue
from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import encode
from gargoyle.mcp_server import (ENVELOPE_META_KEY, EXECUTED_META_KEY, REASON_META_KEY, REF_TARGET_APPROVAL_TIMEOUT,
                                 REF_TARGET_GATE_FILES, IssuerClient, ServerState, call_for, handle_message)
from gargoyle.policy import ELIGIBLE, Decision

issuer, idp = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}
TARGET = "mcp://fs"
PRINCIPAL = "agent@contoso.com"


class Allow:
    def pin(self): return PIN
    def decide(self, target_url, interaction): return Decision(ELIGIBLE)


class Hold:
    def pin(self): return PIN
    def decide(self, target_url, interaction): return Decision(ELIGIBLE, None, True)


def _config():
    return {"pinned_public_keys": {"k1": issuer.public_key()}, "record": PIN, "target_id": TARGET, "principal": PRINCIPAL}


def _call(tool, args, msg_id, env=None):
    params = {"name": tool, "arguments": args}
    if env is not None:
        params["_meta"] = {ENVELOPE_META_KEY: env}
    return {"jsonrpc": "2.0", "id": msg_id, "method": "tools/call", "params": params}


def test_two_writers_on_one_log_keep_one_chain(tmp_path):
    log = tmp_path / "audit.jsonl"
    a, b = EvidenceLog(str(log)), EvidenceLog(str(log))          # two gate processes, one file
    a.append(REFUSED, "write_file", {"path": "1"}, "p", "R1")
    b.append(REFUSED, "write_file", {"path": "2"}, "p", "R2")       # b never saw a's write before now
    a.append(REFUSED, "write_file", {"path": "3"}, "p", "R3")
    b.append(REFUSED, "write_file", {"path": "4"}, "p", "R4")
    entries = read_log(str(log))
    assert [e["seq"] for e in entries] == [1, 2, 3, 4]
    assert all(entries[i]["prev_sha256"] == entries[i - 1]["entry_sha256"] for i in range(1, 4))
    assert verify_log(entries, issuer_public_keys={}, executor_public_keys={})["reason"] == ACCEPT_EVIDENCE_VERIFIED
    assert (tmp_path / "audit.jsonl.lock").exists()


def test_the_gates_own_folder_is_never_a_target(tmp_path):
    gate = tmp_path / "gate"; gate.mkdir()
    state = ServerState(_config(), audit_log=str(gate / "audit.jsonl")); state.initialized = True
    inside = {"path": str(gate / "middleware.env")}
    outside = {"path": str(tmp_path / "proj" / "a.md")}
    r = handle_message(state, _call("read_file", inside, 1, issue(Allow(), TARGET, call_for("read_file", inside, PRINCIPAL), signing_key=issuer, key_id="k1").envelope))
    assert r["result"]["isError"] is True and r["result"]["_meta"][REASON_META_KEY] == REF_TARGET_GATE_FILES
    mixed_case = {"path": str(gate).upper() + "/snapshots/x"}
    assert handle_message(state, _call("read_file", mixed_case, 2))["result"]["_meta"][REASON_META_KEY] == REF_TARGET_GATE_FILES
    listed = {"paths": [str(tmp_path / "proj" / "a.md"), str(gate / "audit.jsonl")]}
    assert handle_message(state, _call("read_multiple_files", listed, 3))["result"]["_meta"][REASON_META_KEY] == REF_TARGET_GATE_FILES
    ok = handle_message(state, _call("read_file", outside, 4, issue(Allow(), TARGET, call_for("read_file", outside, PRINCIPAL), signing_key=issuer, key_id="k1").envelope))
    assert ok["result"]["_meta"][EXECUTED_META_KEY] is True
    assert [e["reason"] for e in read_log(str(gate / "audit.jsonl"))][:3] == [REF_TARGET_GATE_FILES] * 3


def test_a_hold_the_gate_stopped_waiting_for_is_declined(tmp_path):
    c = TestClient(build_issuer_app(policy=Hold(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()}))
    token = encode({"sub": PRINCIPAL, "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")
    approver = encode({"sub": "dana@contoso.com", "roles": ["Approver"], "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")

    class Shim:
        def post(self, url, json=None, headers=None, timeout=None): return c.post(url.replace("http://i", ""), json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return c.get(url.replace("http://i", ""), headers=headers)

    ic = IssuerClient("http://i", token, http=Shim(), approval_timeout=0, sleep=lambda s: None)
    state = ServerState(dict(_config(), pinned_public_keys={"issuer-1": issuer.public_key()}), issuer_client=ic); state.initialized = True
    r = handle_message(state, _call("write_file", {"path": "x", "content": "y"}, 1))
    assert r["result"]["_meta"][REASON_META_KEY] == REF_TARGET_APPROVAL_TIMEOUT
    assert c.get("/pending", headers={"Authorization": "Bearer " + approver}).json()["pending"] == []     # the card is gone


def test_init_keeps_an_existing_deployment_and_tokens_renews_only_tokens(tmp_path, capsys):
    from gargoyle.cli import main
    from gargoyle.jws import decode
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    out, sandbox = tmp_path / "deploy", tmp_path / "proj"; sandbox.mkdir()
    assert main(["init", str(sandbox), "--out", str(out), "--approvers", "2"]) == 0
    before = {p.name: p.read_text() for p in out.iterdir()}
    # A second init refuses and changes nothing.
    assert main(["init", str(sandbox), "--out", str(out)]) == 2
    assert "already holds a deployment" in capsys.readouterr().err
    assert {p.name: p.read_text() for p in out.iterdir()} == before
    # --observe on an existing deployment switches the rules only.
    assert main(["init", str(sandbox), "--out", str(out), "--observe"]) == 0
    after = {p.name: p.read_text() for p in out.iterdir()}
    assert json.loads(after["rules.json"])["default"] == "allow" and {k: v for k, v in after.items() if k != "rules.json"} == {k: v for k, v in before.items() if k != "rules.json"}
    # tokens: new client and approver tokens under the same identity key; keys untouched.
    assert main(["tokens", "--out", str(out), "--token-days", "7"]) == 0
    renewed = {p.name: p.read_text() for p in out.iterdir()}
    assert renewed["issuer.env"] == after["issuer.env"] and renewed["public-keys.json"] == after["public-keys.json"]
    old_env, new_env = dict(l.split("=", 1) for l in after["middleware.env"].splitlines()), dict(l.split("=", 1) for l in renewed["middleware.env"].splitlines())
    assert new_env["GARGOYLE_MCP_CLIENT_TOKEN"] != old_env["GARGOYLE_MCP_CLIENT_TOKEN"]
    assert {k: v for k, v in new_env.items() if k != "GARGOYLE_MCP_CLIENT_TOKEN"} == {k: v for k, v in old_env.items() if k != "GARGOYLE_MCP_CLIENT_TOKEN"}
    idp_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(json.loads(renewed["public-keys.json"])["identity_provider"]["idp-1"]))
    claims = decode(new_env["GARGOYLE_MCP_CLIENT_TOKEN"], {"idp-1": idp_pub})["payload"]
    assert claims["aud"] == "gargoyle-issuer" and claims["exp"] - int(datetime.now(timezone.utc).timestamp()) > 6 * 86400
    web2 = json.loads(renewed["approver-web-2.json"])
    assert web2["token"] != json.loads(after["approver-web-2.json"])["token"] and decode(web2["token"], {"idp-1": idp_pub})["payload"]["roles"] == ["Approver"]
    assert json.loads(renewed["mcp-config.json"])["mcpServers"]["filesystem-gargoyle"]["env"]["GARGOYLE_MCP_CLIENT_TOKEN"] == new_env["GARGOYLE_MCP_CLIENT_TOKEN"]
    # A fresh set of keys only on request.
    assert main(["init", str(sandbox), "--out", str(out), "--force"]) == 0
    assert {p.name: p.read_text() for p in out.iterdir()}["issuer.env"] != after["issuer.env"]
