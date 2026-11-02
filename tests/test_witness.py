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
    assert v["accepted"] and v["count"] == 5 and [e["event"] for e in entries] == ["started", "issued", "granted", "started", "declined"]
    assert entries[3]["resumed"] is True and entries[0]["resumed"] is False
    forged = dict(entries[2], approver="mallory")
    assert verify_witness(entries[:2] + [forged] + entries[3:], issuer_public_keys=ISSUER_KEYS)["entries"][2]["reason"] == REF_WITNESS_HASH_MISMATCH
    from gargoyle.witness import entry_sha256
    forged["entry_sha256"] = entry_sha256(forged)              # rehashed, but the issuer did not sign it
    assert verify_witness(entries[:2] + [forged], issuer_public_keys=ISSUER_KEYS)["entries"][2]["reason"] == REF_WITNESS_SIGNATURE_INVALID
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
    root = tmp_path / "root"; root.mkdir(); (root / "n.md").write_text("one\n", encoding="utf-8", newline="\n"); (root / "other.md").write_text("x", encoding="utf-8")
    state, up, c, h, w = _rig(tmp_path, root)
    try:
        assert call(state, 2, "read_file", {"path": str(root / "n.md")})["_meta"][EXECUTED_META_KEY]
        assert call(state, 3, "write_file", {"path": str(root / "n.md"), "content": "two\n"})["_meta"][EXECUTED_META_KEY]
    finally:
        up.close()
    evidence = read_log(str(tmp_path / "audit.jsonl")); witness = read_witness(str(tmp_path / "witness.jsonl"))
    assert [e["event"] for e in witness] == ["started", "issued", "issued", "granted"]
    assert evidence[1]["ref"] == str(root / "n.md") and evidence[1]["evidence_version"] == "gargoyle-evidence/4"
    assert verify_log(evidence, issuer_public_keys=ISSUER_KEYS, executor_public_keys={"executor-1": executor.public_key()},
                      approver_public_keys={"approver-1": approver.public_key()})["accepted"]
    r = reconcile(evidence, witness, principal=PRINCIPAL)
    assert r["accepted"] and r["issued"] == 2 and r["evidence_with_receipt"] == 2
    # The witness names every user's decisions, so it is served to approvers and to nobody else.
    from gargoyle.issuer_service import REF_ISSUER_FORBIDDEN
    assert c.get("/witness", headers=h).status_code == 403 and c.get("/witness", headers=h).json()["detail"]["reason"] == REF_ISSUER_FORBIDDEN
    approver_h = {"Authorization": "Bearer " + encode({"sub": "approver-1", "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")}
    assert len(c.get("/witness", headers=approver_h).json()["entries"]) == 4
    # A console that polls asks for the lines past the last one it saw, and
    # may cap a first page; the chain's tail comes back either way.
    page = c.get("/witness?after=2", headers=approver_h).json()
    assert [e["seq"] for e in page["entries"]] == [3, 4] and page["seq"] == 4
    page = c.get("/witness?limit=1", headers=approver_h).json()
    assert [e["seq"] for e in page["entries"]] == [4] and page["seq"] == 4
    assert c.get("/witness?after=4", headers=approver_h).json() == {"entries": [], "seq": 4}
    # Evidence from before the witness began is information, not a finding.
    old = dict(evidence[0], at="2026-01-01T00:00:00+00:00", receipt=dict(evidence[0]["receipt"], decision_id="before-the-witness"))
    r = reconcile(evidence + [old], witness, principal=PRINCIPAL)      # beside the real rows, not in place of one
    assert r["accepted"] and [f["finding"] for f in r["findings"]] == ["PREDATES_WITNESS"] and r["horizon"]

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
    # An issuance older than the log's first entry is one this log could never have recorded:
    # information with a count, not a failure (a fresh install, a rotated log).
    ancient = dict([w for w in witness if w["event"] == "issued"][0], decision_id="d-ancient",
                   at=(datetime.fromisoformat(evidence[0]["at"]) - timedelta(days=2)).isoformat())
    r = reconcile(evidence, witness + [ancient], principal=PRINCIPAL)
    assert r["accepted"] and [f["finding"] for f in r["findings"]] == ["PREDATES_EVIDENCE"] and r["log_start"] == evidence[0]["at"]
    later = dict(ancient, decision_id="d-later", at=(datetime.fromisoformat(evidence[0]["at"]) + timedelta(seconds=1)).isoformat())
    r = reconcile(evidence, witness + [later], principal=PRINCIPAL)
    assert not r["accepted"] and [f["finding"] for f in r["findings"]] == ["MISSING_EVIDENCE"]

    # The tree: as the gate left it, then edited behind its back, then deleted.
    t = check_tree(evidence, str(root))
    assert t["accepted"] and t["checked"] == 1 and t["untouched"] == 1
    (root / "n.md").write_text("edited in notepad\n", encoding="utf-8", newline="\n")
    t = check_tree(evidence, str(root))
    assert [f["finding"] for f in t["findings"]] == ["CHANGED_OUTSIDE_GATE"] and t["findings"][0]["path"] == str(root / "n.md")
    (root / "n.md").unlink()
    assert check_tree(evidence, str(root))["findings"][0].get("missing") is True


def test_audit_command_reports_reconciliation_and_tree(tmp_path, capsys):
    root = tmp_path / "root"; root.mkdir(); (root / "n.md").write_text("one\n", encoding="utf-8", newline="\n")
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
    assert "witness: 3 entries, WITNESS_VERIFIED" in text and "0 finding(s)" in text and "1 gated file(s) checked" in text
    (root / "n.md").write_text("tampered", encoding="utf-8")
    assert main(["audit", "--log", str(tmp_path / "audit.jsonl"), "--out", str(out), "--check-tree", str(root)]) == 1
    assert "CHANGED_OUTSIDE_GATE" in capsys.readouterr().out


def test_relative_path_write_binds_the_real_file(tmp_path, capsys):
    """2026-10-30 in the field: a client sent "hello.txt"; the gate bound an
    absent file beside itself, the upstream overwrote the real one, and the
    tree check called it a change outside the gate. With the root known,
    the receipt, the snapshot and the tree check all name the real file."""
    root = tmp_path / "root"; root.mkdir(); (root / "hello.txt").write_text("one\n", encoding="utf-8", newline="\n")
    state, up, c, h, w = _rig(tmp_path, root)
    state.state_root = str(root)
    try:
        r = call(state, 2, "write_file", {"path": "hello.txt", "content": "one\ntwo\n"})
        assert r["_meta"][EXECUTED_META_KEY]
    finally:
        up.close()
    assert (root / "hello.txt").read_text(encoding="utf-8") == "one\ntwo\n"
    e = read_log(str(tmp_path / "audit.jsonl"))[0]
    assert e["ref"] == str(root / "hello.txt")
    assert e["execution"]["pre_state_sha256"] != e["execution"]["post_state_sha256"]
    from gargoyle.reconcile import check_tree
    t = check_tree(read_log(str(tmp_path / "audit.jsonl")), str(root))
    assert t["checked"] == 1 and t["findings"] == []


def test_audit_names_a_missing_witness_or_folder_plainly(tmp_path, capsys):
    from gargoyle.cli import main
    log = tmp_path / "audit.jsonl"; log.write_text("")
    out = tmp_path / "deploy"; out.mkdir()
    (out / "public-keys.json").write_text(json.dumps({"issuer": {}, "executor": {}, "approver": {}}))
    assert main(["audit", "--log", str(log), "--out", str(out), "--witness", str(tmp_path / "nope.jsonl")]) == 2
    assert "witness file not found" in capsys.readouterr().err
    assert main(["audit", "--log", str(log), "--out", str(out), "--check-tree", str(tmp_path / "nodir")]) == 2
    assert "not a directory" in capsys.readouterr().err
    # --witness (or --check-tree, --summary) without --log is a usage error, not a crash.
    assert main(["audit", "--out", str(out), "--witness", str(tmp_path / "nope.jsonl")]) == 2
    assert "pass --log" in capsys.readouterr().err
    assert main(["audit", "--out", str(out), "--check-tree", str(tmp_path)]) == 2
    assert "pass --log" in capsys.readouterr().err
    assert main(["audit", "--out", str(out)]) == 2
    assert "nothing to verify" in capsys.readouterr().err
    # The issuer creates the witness file at start, before any decision.
    w = WitnessLog(str(tmp_path / "fresh" / "witness.jsonl"), issuer, "issuer-1")
    assert (tmp_path / "fresh" / "witness.jsonl").exists() and [e["event"] for e in w.entries] == ["started"]


def test_reconciliation_is_scoped_to_the_evidence_logs_target(tmp_path):
    """One issuer can serve several gates. The witness names the target of
    each issued receipt, and an audit of one gate's log does not report the
    other gates' receipts as missing evidence."""
    root = tmp_path / "root"; root.mkdir(); (root / "n.md").write_text("one\n", encoding="utf-8", newline="\n")
    state, up, c, h, w = _rig(tmp_path, root)
    try:
        assert call(state, 2, "read_file", {"path": str(root / "n.md")})["_meta"][EXECUTED_META_KEY]
    finally:
        up.close()
    evidence = read_log(str(tmp_path / "audit.jsonl")); witness = read_witness(str(tmp_path / "witness.jsonl"))
    issued = [e for e in witness if e["event"] == "issued"]
    assert issued and all(e["target_url"] == TARGET for e in issued)
    assert verify_witness(witness, issuer_public_keys=ISSUER_KEYS)["accepted"]     # the new field is under the signature
    other_gate = dict(issued[0], decision_id="another-gates-decision", target_url="mcp://filesystem/C:/elsewhere")
    legacy = dict(issued[0], decision_id="old-issuer-no-target"); legacy.pop("target_url")
    r = reconcile(evidence, witness + [other_gate], principal=PRINCIPAL, target_url=TARGET)
    assert r["accepted"] and r["findings"] == [] and r["issued_elsewhere"] == 1
    r = reconcile(evidence, witness + [other_gate], principal=PRINCIPAL)                 # unscoped: still reported
    assert [f["finding"] for f in r["findings"]] == ["MISSING_EVIDENCE"]
    r = reconcile(evidence, witness + [legacy], principal=PRINCIPAL, target_url=TARGET)   # no target on record: reported
    assert [f["finding"] for f in r["findings"]] == ["MISSING_EVIDENCE"] and r["issued_elsewhere"] == 0


def test_audit_finds_its_keys_beside_the_log_and_can_take_approver_keys_from_the_issuer(tmp_path, capsys, monkeypatch):
    """A workstation's keys sit beside audit.jsonl; a wrong --out is not a
    traceback. A grant signed by a key the local approvers copy does not list
    fails with a note that says so; --issuer fetches the issuer's full list."""
    root = tmp_path / "root"; root.mkdir(); (root / "n.md").write_text("one\n", encoding="utf-8", newline="\n")
    state, up, c, h, w = _rig(tmp_path, root)
    try:
        assert call(state, 2, "write_file", {"path": str(root / "n.md"), "content": "two\n"})["_meta"][EXECUTED_META_KEY]
    finally:
        up.close()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    hexpub = lambda k: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    from gargoyle.cli import main
    log = str(tmp_path / "audit.jsonl")
    # No keys anywhere: a usage error, not a traceback.
    monkeypatch.chdir(tmp_path)
    assert main(["audit", "--log", log]) == 2
    assert "public-keys.json not found" in capsys.readouterr().err
    # Keys beside the log, --out left at its default: found.
    (tmp_path / "public-keys.json").write_text(json.dumps({"issuer": {"issuer-1": hexpub(issuer)}, "executor": {"executor-1": hexpub(executor)},
                                                            "approver": {"approver-1": hexpub(approver)}}))
    assert main(["audit", "--log", log]) == 0
    # The local copy does not know the approver's key: the release fails, and the note says what to do.
    (tmp_path / "public-keys.json").write_text(json.dumps({"issuer": {"issuer-1": hexpub(issuer)}, "executor": {"executor-1": hexpub(executor)},
                                                            "approver": {}}))
    assert main(["audit", "--log", log]) == 1
    text = capsys.readouterr().out
    assert "REF_APPROVAL_KEY_UNKNOWN" in text and "not known here: approver-1" in text and "--issuer URL" in text
    # The copy knows the approver under an older key (the Windows run of 2026-11-02): named as stale, same remedy.
    (tmp_path / "public-keys.json").write_text(json.dumps({"issuer": {"issuer-1": hexpub(issuer)}, "executor": {"executor-1": hexpub(executor)},
                                                            "approver": {"approver-1": hexpub(Ed25519PrivateKey.generate())}}))
    assert main(["audit", "--log", log]) == 1
    text = capsys.readouterr().out
    assert "REF_APPROVAL_SIGNATURE_INVALID" in text and "listed key does not verify the grant: approver-1" in text
    # --issuer: the issuer's list (current key plus history) stands in for the copy.
    import gargoyle.cli as cli
    monkeypatch.setattr(cli, "_issuer_trust", lambda url: ({"issuer-1": hexpub(issuer)}, {"approver-1": [hexpub(Ed25519PrivateKey.generate()), hexpub(approver)]}))
    assert main(["audit", "--log", log, "--issuer", "https://issuer.test"]) == 0
    assert "0 failed" in capsys.readouterr().out
