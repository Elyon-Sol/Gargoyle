"""The issuer's witness log and reconciliation: client evidence checked
against an independent, issuer-signed record; a gated folder checked
against the evidence."""

import json
import sys
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.approval import build_grant, sign_grant
from gargoyle.evidence import HONORED, EvidenceLog, read_log, verify_log
from gargoyle.execution import build_execution_receipt, sign_execution_receipt
from gargoyle.issuer import issue
from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import encode
from gargoyle.mcp_server import EXECUTED_META_KEY, IssuerClient, ServerState, StdioUpstream, handle_message
from gargoyle.policy import ELIGIBLE, Decision
from gargoyle.reconcile import check_tree, reconcile
from gargoyle.witness import (ACCEPT_WITNESS_VERIFIED, REF_WITNESS_HASH_MISMATCH, REF_WITNESS_SIGNATURE_INVALID, WitnessLog,
                              read_witness, verify_witness)

issuer, executor, approver, idp = (Ed25519PrivateKey.generate() for _ in range(4))
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}
TARGET = "mcp://fs"
PRINCIPAL = "agent@contoso.com"
ISSUER_KEYS = {"issuer-1": issuer.public_key()}


class FsPolicy:
    def pin(self): return PIN
    def decide(self, target_url, interaction):
        return Decision(ELIGIBLE, None, True) if interaction.get("tool") == "write_file" else Decision(ELIGIBLE)


def token():
    return encode({"sub": PRINCIPAL, "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")


def test_witness_entries_are_signed_and_chained(tmp_path):
    w = WitnessLog(str(tmp_path / "w.jsonl"), issuer, "issuer-1")
    w.record("issued", decision_id="d-1", principal=PRINCIPAL, tool="read_file")
    w.record("granted", approval_request_id="r-1", approver="dana")
    again = WitnessLog(str(tmp_path / "w.jsonl"), issuer, "issuer-1")      # continues the chain after a restart
    again.record("declined", approval_request_id="r-2")
    entries = read_witness(str(tmp_path / "w.jsonl"))
    v = verify_witness(entries, issuer_public_keys=ISSUER_KEYS)
    assert v["accepted"] and v["count"] == 3 and [e["seq"] for e in entries] == [1, 2, 3]
    forged = dict(entries[1], approver="mallory")
    assert verify_witness([entries[0], forged, entries[2]], issuer_public_keys=ISSUER_KEYS)["entries"][1]["reason"] == REF_WITNESS_HASH_MISMATCH
    from gargoyle.witness import entry_sha256
    forged["entry_sha256"] = entry_sha256(forged)              # rehashed, but the issuer did not sign it
    assert verify_witness([entries[0], forged], issuer_public_keys=ISSUER_KEYS)["entries"][1]["reason"] == REF_WITNESS_SIGNATURE_INVALID
    assert not verify_witness(entries, issuer_public_keys={"other": executor.public_key()})["accepted"]


def _rig(tmp_path, root):
    w = WitnessLog(str(tmp_path / "witness.jsonl"), issuer, "issuer-1")
    app = build_issuer_app(policy=FsPolicy(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           approver_public_keys={"approver-1": approver.public_key()}, witness=w)
    c = TestClient(app); h = {"Authorization": "Bearer " + token()}

    class Shim:
        def post(self, url, json=None, headers=None, timeout=None): return c.post(url.replace("http://i", ""), json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return c.get(url.replace("http://i", ""), headers=headers)

    def human(seconds):
        for hold in c.get("/pending", headers=h).json()["pending"]:
            env = hold["envelope"]
            g = sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                       grant_id="g-" + env["approval_request_id"], not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), approver, "approver-1")
            c.post("/grants", json=g, headers=h)

    up = StdioUpstream([sys.executable, "-I", "-m", "gargoyle.fs_server", str(root)])
    state = ServerState({"pinned_public_keys": ISSUER_KEYS, "record": PIN, "target_id": TARGET, "principal": PRINCIPAL,
                         "approver_public_keys": {"approver-1": approver.public_key()}, "executor_signing_key": executor, "executor_key_id": "executor-1"},
                        upstream=up, issuer_client=IssuerClient("http://i", token(), http=Shim(), approval_timeout=30, poll_seconds=0.01, sleep=human),
                        audit_log=str(tmp_path / "audit.jsonl"))
    handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    handle_message(state, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    return state, up, c, h, w


def call(state, n, name, args):
    return handle_message(state, {"jsonrpc": "2.0", "id": n, "method": "tools/call", "params": {"name": name, "arguments": args}})["result"]


def test_honest_evidence_reconciles_and_tampering_is_found(tmp_path):
    root = tmp_path / "root"; root.mkdir(); (root / "n.md").write_text("one\n", encoding="utf-8"); (root / "other.md").write_text("x", encoding="utf-8")
    state, up, c, h, w = _rig(tmp_path, root)
    try:
        assert call(state, 2, "read_file", {"path": str(root / "n.md")})["_meta"][EXECUTED_META_KEY]
        assert call(state, 3, "write_file", {"path": str(root / "n.md"), "content": "two\n"})["_meta"][EXECUTED_META_KEY]
    finally:
        up.close()
    evidence = read_log(str(tmp_path / "audit.jsonl")); witness = read_witness(str(tmp_path / "witness.jsonl"))
    assert [e["event"] for e in witness] == ["issued", "issued", "granted"]
    assert evidence[1]["ref"] == str(root / "n.md") and evidence[1]["evidence_version"] == "gargoyle-evidence/4"
    assert verify_log(evidence, issuer_public_keys=ISSUER_KEYS, executor_public_keys={"executor-1": executor.public_key()},
                      approver_public_keys={"approver-1": approver.public_key()})["accepted"]
    r = reconcile(evidence, witness, principal=PRINCIPAL)
    assert r["accepted"] and r["issued"] == 2 and r["evidence_with_receipt"] == 2
    # The witness is served to an authenticated caller too.
    assert len(c.get("/witness", headers=h).json()["entries"]) == 3

    # 1. A forged honored entry for a decision the issuer never issued: the user holds the executor key, so it verifies alone.
    now = datetime.now(timezone.utc)
    fake_call = {"tool": "write_file", "args": {"path": str(root / "other.md"), "content": "pwned"}, "principal": PRINCIPAL}
    rogue_issuer = Ed25519PrivateKey.generate()
    fake_env = issue(FsPolicy(), TARGET, fake_call, signing_key=rogue_issuer, key_id="issuer-1", now=now).envelope
    forged = {"kind": HONORED, "receipt": fake_env, "grant": None, "execution": None, "seq": 99, "at": now.isoformat(), "tool": "write_file"}
    r = reconcile(evidence + [forged], witness, principal=PRINCIPAL)
    assert [f["finding"] for f in r["findings"]] == ["UNWITNESSED_RECEIPT"]
    # 2. A held call honored with no grant the issuer saw: drop the witness's grant line.
    r = reconcile(evidence, [x for x in witness if x["event"] != "granted"], principal=PRINCIPAL)
    assert [f["finding"] for f in r["findings"]] == ["UNWITNESSED_RELEASE"]
    # 3. A receipt the issuer issued but the client never recorded: drop the client's read entry.
    r = reconcile([e for e in evidence if e["tool"] != "read_file"], witness, principal=PRINCIPAL)
    assert [f["finding"] for f in r["findings"]] == ["MISSING_EVIDENCE"] and r["findings"][0]["tool"] == "read_file"

    # The tree: as the gate left it, then edited behind its back, then deleted.
    t = check_tree(evidence, str(root))
    assert t["accepted"] and t["checked"] == 1 and t["untouched"] == 1
    (root / "n.md").write_text("edited in notepad\n", encoding="utf-8")
    t = check_tree(evidence, str(root))
    assert [f["finding"] for f in t["findings"]] == ["CHANGED_OUTSIDE_GATE"] and t["findings"][0]["path"] == str(root / "n.md")
    (root / "n.md").unlink()
    assert check_tree(evidence, str(root))["findings"][0].get("missing") is True


def test_audit_command_reports_reconciliation_and_tree(tmp_path, capsys):
    root = tmp_path / "root"; root.mkdir(); (root / "n.md").write_text("one\n", encoding="utf-8")
    state, up, c, h, w = _rig(tmp_path, root)
    try:
        assert call(state, 2, "write_file", {"path": str(root / "n.md"), "content": "two\n"})["_meta"][EXECUTED_META_KEY]
    finally:
        up.close()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    hexpub = lambda k: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    out = tmp_path / "deploy"; out.mkdir()
    (out / "public-keys.json").write_text(json.dumps({"issuer": {"issuer-1": hexpub(issuer)}, "executor": {"executor-1": hexpub(executor)},
                                                      "approver": {"approver-1": hexpub(approver)}}))
    from gargoyle.cli import main
    assert main(["audit", "--log", str(tmp_path / "audit.jsonl"), "--out", str(out), "--witness", str(tmp_path / "witness.jsonl"),
                 "--check-tree", str(root)]) == 0
    text = capsys.readouterr().out
    assert "witness: 2 entries, WITNESS_VERIFIED" in text and "0 finding(s)" in text and "1 gated file(s) checked" in text
    (root / "n.md").write_text("tampered", encoding="utf-8")
    assert main(["audit", "--log", str(tmp_path / "audit.jsonl"), "--out", str(out), "--check-tree", str(root)]) == 1
    assert "CHANGED_OUTSIDE_GATE" in capsys.readouterr().out


def test_audit_names_a_missing_witness_or_folder_plainly(tmp_path, capsys):
    from gargoyle.cli import main
    log = tmp_path / "audit.jsonl"; log.write_text("")
    out = tmp_path / "deploy"; out.mkdir()
    (out / "public-keys.json").write_text(json.dumps({"issuer": {}, "executor": {}, "approver": {}}))
    assert main(["audit", "--log", str(log), "--out", str(out), "--witness", str(tmp_path / "nope.jsonl")]) == 2
    assert "witness file not found" in capsys.readouterr().err
    assert main(["audit", "--log", str(log), "--out", str(out), "--check-tree", str(tmp_path / "nodir")]) == 2
    assert "not a directory" in capsys.readouterr().err
    # The issuer creates the witness file at start, before any decision.
    w = WitnessLog(str(tmp_path / "fresh" / "witness.jsonl"), issuer, "issuer-1")
    assert (tmp_path / "fresh" / "witness.jsonl").exists() and w.entries == []
