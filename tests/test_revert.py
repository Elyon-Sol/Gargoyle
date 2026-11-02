"""Undo: an approved write leaves a snapshot; gargoyle_revert composes the
write that restores it and sends it through the gate, held and state-bound.
Run against the real filesystem server as the upstream."""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.approval import build_grant, sign_grant
from gargoyle.evidence import read_log, verify_log
from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import encode
from gargoyle.mcp_server import EXECUTED_META_KEY, REASON_META_KEY, IssuerClient, ServerState, StdioUpstream, handle_message
from gargoyle.policy import ELIGIBLE, Decision, refuse
from gargoyle.revert import (REF_REVERT_NOT_ATTESTED, REF_REVERT_NEEDS_DELETE, REF_REVERT_STATE_CHANGED, REF_REVERT_UNKNOWN, REVERT_TOOL,
                             SnapshotStore, plan_revert)
from gargoyle.adapters import FilesystemAdapter
from gargoyle.state import describe, filesystem_probe, state_sha256

issuer, executor, approver, idp = (Ed25519PrivateKey.generate() for _ in range(4))
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}
TARGET = "mcp://fs"
PRINCIPAL = "agent-7"


class FsPolicy:
    def pin(self): return PIN
    def decide(self, target_url, interaction):
        t = interaction.get("tool")
        if t in ("write_file", "move_file", "create_directory"): return Decision(ELIGIBLE, None, True)
        if t == "delete_file": return refuse("DESTRUCTIVE_TOOL")
        return Decision(ELIGIBLE)


def token():
    return encode({"sub": PRINCIPAL, "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")


def test_snapshot_store_and_plan(tmp_path):
    store = SnapshotStore(str(tmp_path / "snap"))
    f = tmp_path / "n.md"; f.write_bytes(b"one\n")
    desc = describe(str(f), b"one\n")
    meta = store.put("d-1", desc, b"one\n", "write_file", {"path": str(f), "content": "two\n"})
    assert meta["pre_state_sha256"] == state_sha256(desc) and meta["existed"] and meta["post_state_sha256"] is None
    assert plan_revert(store, "d-1", FilesystemAdapter())["reason"] == REF_REVERT_NOT_ATTESTED   # not finished yet
    f.write_bytes(b"two\n"); store.record_post("d-1", state_sha256(describe(str(f), b"two\n")))
    plan = plan_revert(store, "last", FilesystemAdapter())
    assert plan["reverts"] == "d-1" and plan["params"] == {"name": "write_file", "arguments": {"path": str(f), "content": "one\n"}}
    f.write_bytes(b"three\n")
    assert plan_revert(store, "d-1", FilesystemAdapter())["reason"] == REF_REVERT_STATE_CHANGED
    assert plan_revert(store, "nope", FilesystemAdapter())["reason"] == REF_REVERT_UNKNOWN
    store.put("d-2", describe(str(tmp_path / "new.md"), None), None, "write_file", {"path": str(tmp_path / "new.md"), "content": "x"}); store.record_post("d-2", "b" * 64)
    assert plan_revert(store, "d-2", FilesystemAdapter())["reason"] == REF_REVERT_NEEDS_DELETE


def _rig(tmp_path, root):
    app = build_issuer_app(policy=FsPolicy(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           approver_public_keys={"approver-1": approver.public_key()})
    c = TestClient(app); h = {"Authorization": "Bearer " + token()}
    cards = []

    class Shim:
        def post(self, url, json=None, headers=None, timeout=None): return c.post(url.replace("http://i", ""), json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return c.get(url.replace("http://i", ""), headers=headers)

    def human(seconds):
        for hold in c.get("/pending", headers=h).json()["pending"]:
            cards.append(hold)
            env = hold["envelope"]
            g = sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                       grant_id="g-" + env["approval_request_id"], not_after=datetime.now(timezone.utc) + timedelta(minutes=5)),
                           approver, "approver-1")
            c.post("/grants", json=g, headers=h)

    up = StdioUpstream([sys.executable, "-I", "-m", "gargoyle.fs_server", str(root)])
    state = ServerState({"pinned_public_keys": {"issuer-1": issuer.public_key()}, "record": PIN, "target_id": TARGET, "principal": PRINCIPAL,
                         "approver_public_keys": {"approver-1": approver.public_key()},
                         "executor_signing_key": executor, "executor_key_id": "executor-1"},
                        upstream=up, issuer_client=IssuerClient("http://i", token(), http=Shim(), approval_timeout=30, poll_seconds=0.01, sleep=human),
                        audit_log=str(tmp_path / "audit.jsonl"))
    handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    handle_message(state, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    return state, up, cards


def call(state, n, name, args):
    return handle_message(state, {"jsonrpc": "2.0", "id": n, "method": "tools/call", "params": {"name": name, "arguments": args}})


def test_revert_restores_an_approved_write_through_the_gate(tmp_path):
    root = tmp_path / "root"; root.mkdir()
    target = root / "notes.md"; target.write_text("one\n", encoding="utf-8", newline="\n")
    state, up, cards = _rig(tmp_path, root)
    try:
        tools = handle_message(state, {"jsonrpc": "2.0", "id": 0, "method": "tools/list", "params": {}})["result"]["tools"]
        assert any(t["name"] == REVERT_TOOL for t in tools) and any(t["name"] == "write_file" for t in tools)

        r = call(state, 2, "write_file", {"path": str(target), "content": "two\n"})
        assert r["result"]["_meta"][EXECUTED_META_KEY] is True and target.read_text(encoding="utf-8") == "two\n"
        assert cards[-1]["state"]["text"] == "one\n"
        snaps = list((tmp_path / "snapshots").glob("*.json")); assert len(snaps) == 1
        assert json.loads(snaps[0].read_text())["post_state_sha256"] == state_sha256(describe(str(target), b"two\n"))

        # Undo: held, shown as the restore, approved, executed, file back to "one".
        r = call(state, 3, REVERT_TOOL, {"decision_id": "last"})
        assert r["result"]["_meta"][EXECUTED_META_KEY] is True, r["result"]
        assert target.read_text(encoding="utf-8") == "one\n"
        assert cards[-1]["envelope"]["request_context"]["tool"] == "write_file" and cards[-1]["args"]["content"] == "one\n"
        assert cards[-1]["state"]["text"] == "two\n"                     # the approver saw the current state
        ex = r["result"]["_meta"]["gargoyle/execution"]
        assert ex["pre_state_sha256"] == state_sha256(describe(str(target), b"two\n"))
        assert ex["post_state_sha256"] == state_sha256(describe(str(target), b"one\n"))

        # The audit recognises the revert from the hashes alone.
        v = verify_log(read_log(str(tmp_path / "audit.jsonl")), issuer_public_keys={"issuer-1": issuer.public_key()},
                       executor_public_keys={"executor-1": executor.public_key()}, approver_public_keys={"approver-1": approver.public_key()})
        assert v["accepted"]
        writes = [e for e in v["entries"] if e["tool"] == "write_file"]
        assert writes[0]["reverts"] is None and writes[1]["reverts"] == writes[0]["seq"]

        # Nothing newer to revert: the revert itself finished, so "last" now points at it (a redo).
        r = call(state, 4, REVERT_TOOL, {"decision_id": "last"})
        assert r["result"]["_meta"][EXECUTED_META_KEY] is True and target.read_text(encoding="utf-8") == "two\n"

        # Changed since: refused before any card.
        n_cards = len(cards)
        target.write_text("someone edited this\n", encoding="utf-8", newline="\n")
        r = call(state, 5, REVERT_TOOL, {"decision_id": "last"})
        assert r["result"]["isError"] and r["result"]["_meta"][REASON_META_KEY] == REF_REVERT_STATE_CHANGED and len(cards) == n_cards

        # A create cannot be undone by a write.
        new = root / "fresh.md"
        assert call(state, 6, "write_file", {"path": str(new), "content": "x"})["result"]["_meta"][EXECUTED_META_KEY]
        r = call(state, 7, REVERT_TOOL, {"decision_id": "last"})
        assert r["result"]["_meta"][REASON_META_KEY] == REF_REVERT_NEEDS_DELETE and new.exists()

        # Both refusals are in the trail: the assistant asked to undo, and why it could not.
        log = read_log(str(tmp_path / "audit.jsonl"))
        refused = [(e["tool"], e["reason"]) for e in log if e["kind"] == "refused"]
        assert refused == [(REVERT_TOOL, REF_REVERT_STATE_CHANGED), (REVERT_TOOL, REF_REVERT_NEEDS_DELETE)]
        assert log[-1]["receipt"] is None and log[-1]["principal"]
        v = verify_log(log, issuer_public_keys={"issuer-1": issuer.public_key()},
                       executor_public_keys={"executor-1": executor.public_key()}, approver_public_keys={"approver-1": approver.public_key()})
        assert v["accepted"] and v["refused"] == 2
    finally:
        up.close()
