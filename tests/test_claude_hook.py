"""The gate as a Claude Code hook: a PreToolUse event is decided against
the issuer under middleware.env, a held Write waits for the approver, the
PostToolUse event attests the run, and the evidence log verifies."""

import io
import json
import os
from pathlib import Path

from fastapi.testclient import TestClient

from gargoyle.claude_hook import (PERMISSION_DENIED, POST, POST_FAILURE, PRE, REAP_SECONDS, REF_HOOK_NOT_RUN,
                                  ClaudeCodeAdapter, PendingReceipts, _pending_for, _state_from_env, decide, run_hook)
from gargoyle.cli import main
from gargoyle.evidence import read_log, verify_log
from gargoyle.issuer_service import app_from_env


def _read_env(path):
    return {k: v for k, v in (l.split("=", 1) for l in Path(path).read_text().splitlines() if "=" in l)}


class Shim:
    def __init__(self, client): self.c = client
    def post(self, url, json=None, headers=None, timeout=None): return self.c.post(url.split("8080", 1)[1], json=json, headers=headers)
    def get(self, url, headers=None, timeout=None): return self.c.get(url.split("8080", 1)[1], headers=headers)


def deployment(tmp_path, monkeypatch, observe=False):
    """`gargoyle init --client claude-code`, the issuer on it, and a hook
    state built from middleware.env with the test issuer as transport."""
    out = tmp_path / "deploy"; project = tmp_path / "project"; project.mkdir()
    argv = ["init", str(project), "--out", str(out), "--client", "claude-code"]
    assert main(argv + (["--observe"] if observe else [])) == 0
    assert not (out / "mcp-config.json").exists()
    settings = json.loads((out / "claude-settings.json").read_text())
    assert set(settings["hooks"]) == {"PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionDenied"}
    cmd = settings["hooks"]["PreToolUse"][0]["hooks"][0]
    assert "-m gargoyle hook --env" in cmd["command"] and cmd["timeout"] == 330
    monkeypatch.setattr(os, "environ", dict(os.environ, **_read_env(out / "issuer.env")))
    client = TestClient(app_from_env())
    (out / "record.json").write_text(json.dumps({k: client.get("/record").json()[k] for k in ("policy_id", "policy_sha256")}) + "\n")
    env = _read_env(out / "middleware.env")
    env.pop("GARGOYLE_MCP_RECORD_URL")          # the file stands in for the live record here
    assert env["GARGOYLE_MCP_TARGET_ID"] == "claude-code://" + str(project)
    approver_env = _read_env(out / "approver.env")

    def approve_now(seconds):
        from gargoyle.approver_cli import approve_at_issuer
        approve_at_issuer("http://127.0.0.1:8080", approver_env["GARGOYLE_APPROVER_TOKEN"],
                          key_hex=approver_env["GARGOYLE_APPROVER_KEY_HEX"], key_id="approver-1", yes=True, http=Shim(client))

    def state():
        return _state_from_env(env, http=Shim(client), sleep=approve_now)
    return out, project, env, state, client


def event(kind, tool, tool_input, tool_use_id="toolu_1", **more):
    return {"hook_event_name": kind, "session_id": "sess-1", "cwd": "/tmp", "tool_name": tool,
            "tool_input": tool_input, "tool_use_id": tool_use_id, **more}


def test_read_passes_held_write_waits_for_the_approver_and_the_log_verifies(tmp_path, monkeypatch):
    out, project, env, state, client = deployment(tmp_path, monkeypatch)
    target = project / "notes.md"; target.write_text("before\n")

    # A read is allowed by the rules; by default the gate adds context and
    # leaves Claude Code's own permission prompt in place.
    r = decide(event(PRE, "Read", {"file_path": str(target)}, "toolu_r"), state())
    assert "permissionDecision" not in r["hookSpecificOutput"]
    assert r["hookSpecificOutput"]["additionalContext"].startswith("gargoyle: REASSERTED_AND_BOUND, receipt ")
    r = decide(event(PRE, "Read", {"file_path": str(target)}, "toolu_r2"), state(), final=True)
    assert r["hookSpecificOutput"]["permissionDecision"] == "allow"
    for tid in ("toolu_r", "toolu_r2"):
        decide(event(POST, "Read", {"file_path": str(target)}, tid, tool_response={"type": "text", "file": {"content": "before\n"}}), state())

    # A Write is held; the approver releases it; the hook answers allow and
    # keeps the honored receipt for the PostToolUse step.
    r = decide(event(PRE, "Write", {"file_path": str(target), "content": "after\n"}, "toolu_w"), state(), final=True)
    assert r["hookSpecificOutput"]["permissionDecision"] == "allow", r
    pending = _pending_for(state())
    assert "toolu_w" in pending._read() and pending._read()["toolu_w"]["grant"] is not None
    target.write_text("after\n")                                   # Claude Code runs the tool
    r = decide(event(POST, "Write", {"file_path": str(target), "content": "after\n"}, "toolu_w",
                     tool_response={"filePath": str(target), "type": "update"}), state())
    assert r["hookSpecificOutput"]["additionalContext"].startswith("gargoyle: execution receipt for decision ")
    assert pending._read() == {}

    # The gate's own files are off limits whatever the rules say.
    r = decide(event(PRE, "Write", {"file_path": str(out / "middleware.env"), "content": "x"}, "toolu_g"), state())
    assert r["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "REF_TARGET_GATE_FILES" in r["hookSpecificOutput"]["permissionDecisionReason"]

    # The evidence log: the honored entries carry execution receipts over
    # the tool's actual output and the held one its grant; the whole log verifies.
    assert main(["audit", "--log", env["GARGOYLE_MCP_AUDIT_LOG"], "--out", str(out)]) == 0
    entries = read_log(env["GARGOYLE_MCP_AUDIT_LOG"])
    kinds = [(e["kind"], e["tool"], e["reason"]) for e in entries]
    assert kinds[0] == ("honored", "Read", "REASSERTED_AND_BOUND")
    assert kinds[2] == ("honored", "Write", "REASSERTED_AND_BOUND") and entries[2]["grant"] is not None
    assert entries[2]["execution"]["pre_state_sha256"] != entries[2]["execution"]["post_state_sha256"]
    assert kinds[3] == ("refused", "Write", "REF_TARGET_GATE_FILES")
    assert all(e["client"] == "claude-code session sess-1" for e in entries)
    keys = json.loads((out / "public-keys.json").read_text())
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pk = lambda d: {k: Ed25519PublicKey.from_public_bytes(bytes.fromhex(v)) for k, v in d.items()}
    assert verify_log(entries, issuer_public_keys=pk(keys["issuer"]), executor_public_keys=pk(keys["executor"]),
                      approver_public_keys=pk(keys["approver"]))["accepted"] is True


def test_declined_and_never_run_calls_are_recorded_as_refused(tmp_path, monkeypatch):
    out, project, env, state, client = deployment(tmp_path, monkeypatch)
    target = project / "a.txt"
    # Claude Code's own prompt refused a call the gate allowed.
    decide(event(PRE, "Write", {"file_path": str(target), "content": "x"}, "toolu_1"), state())
    decide(event(PERMISSION_DENIED, "Write", {"file_path": str(target), "content": "x"}, "toolu_1"), state())
    # A tool that ran and failed still ran: honored, attested over the error.
    decide(event(PRE, "Bash", {"command": "false"}, "toolu_2"), state())
    decide(event(POST_FAILURE, "Bash", {"command": "false"}, "toolu_2", error="exit 1"), state())
    # One nobody came back for, older than the reap window.
    s = state()
    decide(event(PRE, "Edit", {"file_path": str(target), "old_string": "a", "new_string": "b"}, "toolu_3"), s, now=1000.0)
    decide(event(PRE, "Read", {"file_path": str(target)}, "toolu_4"), state(), now=1000.0 + REAP_SECONDS + 1)
    entries = read_log(env["GARGOYLE_MCP_AUDIT_LOG"])
    assert [(e["kind"], e["tool"], e["reason"]) for e in entries] == [
        ("refused", "Write", REF_HOOK_NOT_RUN), ("honored", "Bash", "REASSERTED_AND_BOUND"), ("refused", "Edit", REF_HOOK_NOT_RUN)]
    assert entries[0]["receipt"] is not None and entries[0]["grant"] is not None
    assert main(["audit", "--log", env["GARGOYLE_MCP_AUDIT_LOG"], "--out", str(out)]) == 0


def test_observe_mode_holds_nothing_and_records_everything(tmp_path, monkeypatch):
    out, project, env, state, client = deployment(tmp_path, monkeypatch, observe=True)
    r = decide(event(PRE, "Bash", {"command": "rm -rf /"}, "toolu_1"), state())
    assert "permissionDecision" not in r["hookSpecificOutput"]
    assert _pending_for(state())._read()["toolu_1"]["grant"] is None


def test_run_hook_reads_the_event_and_denies_when_the_issuer_is_unreachable(tmp_path, monkeypatch):
    out, project, env, state, client = deployment(tmp_path, monkeypatch)
    stdin = io.StringIO(json.dumps(event(PRE, "Bash", {"command": "ls"})))
    stdout = io.StringIO()
    # No shim here: the issuer URL in middleware.env has nothing behind it.
    assert run_hook(["--env", str(out / "middleware.env")], stdin, stdout, environ={}) == 0
    out_json = json.loads(stdout.getvalue())
    assert out_json["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "REF_TARGET_ISSUER_UNAVAILABLE" in out_json["hookSpecificOutput"]["permissionDecisionReason"]
    entries = read_log(env["GARGOYLE_MCP_AUDIT_LOG"])
    assert [(e["kind"], e["reason"]) for e in entries] == [("refused", "REF_TARGET_ISSUER_UNAVAILABLE")]
    # A hook that cannot even build its state denies rather than letting the call through.
    stdout = io.StringIO()
    assert run_hook(["--env", str(tmp_path / "missing.env")], io.StringIO("{}"), stdout, environ={}) == 0
    assert json.loads(stdout.getvalue())["hookSpecificOutput"]["permissionDecision"] == "deny"
    stdout = io.StringIO()
    assert run_hook([], io.StringIO("not json"), stdout, environ={}) == 0
    assert json.loads(stdout.getvalue())["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_adapter_probes_claude_code_file_tools_only(tmp_path):
    f = tmp_path / "x.py"; f.write_bytes(b"print(1)\n")
    a = ClaudeCodeAdapter()
    desc, data = a.probe("Edit", {"file_path": str(f), "old_string": "1", "new_string": "2"})
    assert desc["ref"] == str(f) and data == b"print(1)\n"
    desc, data = a.probe("Write", {"file_path": str(tmp_path / "new.txt"), "content": ""})
    assert desc["sha256"] is None and data is None
    assert a.probe("Bash", {"command": "cat " + str(f)}) is None
    assert a.probe("Read", {"file_path": str(f)}) is None
    assert a.restore({"ref": str(f)}, b"old", b"new")["params"] == {"name": "Write", "arguments": {"file_path": str(f), "content": "old"}}


def test_pending_store_is_bounded_and_survives_garbage(tmp_path):
    p = PendingReceipts(str(tmp_path / "audit.hook-pending.json"))
    p.path.write_text("garbage")
    assert p.pop("x") is None
    gate = {"envelope": {"decision_id": "d"}, "grant": None, "self_issued": True, "reason": "ok", "ref": None}
    for i in range(205):
        p.put("t%d" % i, gate, {"name": "Read", "arguments": {}}, now=float(i))
    assert len(p._read()) == 200 and "t4" not in p._read() and "t204" in p._read()
    assert len(p.reap(now=1000.0, max_age=800.0)) == 195
    assert p.pop("t204")["params"]["name"] == "Read" and p.pop("t204") is None


def test_post_event_input_differs_from_pre_and_the_entry_still_matches_the_receipt(tmp_path, monkeypatch):
    # Claude Code presents some tools' input differently in PostToolUse than
    # in PreToolUse (seen live with Artifact). The receipt bound what the gate
    # saw; the honored entry must hash those arguments or the audit reports
    # REF_EVIDENCE_RECEIPT_MISSING for a call that was gated correctly.
    out, project, env, state, client = deployment(tmp_path, monkeypatch)
    decide(event(PRE, "Bash", {"command": "true"}, "toolu_1"), state())
    decide(event(POST, "Bash", {"command": "true", "description": "added afterwards"}, "toolu_1", tool_response={"stdout": ""}), state())
    entries = read_log(env["GARGOYLE_MCP_AUDIT_LOG"])
    assert [(e["kind"], e["tool"]) for e in entries] == [("honored", "Bash")]
    assert entries[0]["args_sha256"] == entries[0]["receipt"]["request_context"]["args_sha256"]
    assert main(["audit", "--log", env["GARGOYLE_MCP_AUDIT_LOG"], "--out", str(out)]) == 0


def test_reaped_entry_written_after_the_receipt_expired_still_verifies(tmp_path, monkeypatch):
    # An honored receipt nobody came back for is reaped REAP_SECONDS later,
    # long after its TTL. The refused entry carries it as provenance of what
    # was gated; it is checked as of issuance, not as of the entry.
    import datetime as dt
    from gargoyle import evidence as ev
    out, project, env, state, client = deployment(tmp_path, monkeypatch)
    decide(event(PRE, "Bash", {"command": "true"}, "toolu_1"), state(), now=1000.0)
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=REAP_SECONDS + 1)

    class Clock(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return later if tz is not None else later.replace(tzinfo=None)
    monkeypatch.setattr(ev, "datetime", Clock)
    decide(event(PRE, "Read", {"file_path": str(project / "a.txt")}, "toolu_2"), state(), now=1000.0 + REAP_SECONDS + 1)
    monkeypatch.undo()
    entries = read_log(env["GARGOYLE_MCP_AUDIT_LOG"])
    reaped = [e for e in entries if e["reason"] == REF_HOOK_NOT_RUN]
    assert len(reaped) == 1 and reaped[0]["at"] > reaped[0]["receipt"]["not_after"]
    # The audit exits 1 when any entry fails verification.
    assert main(["audit", "--log", env["GARGOYLE_MCP_AUDIT_LOG"], "--out", str(out)]) == 0


def test_pending_store_survives_concurrent_hooks(tmp_path):
    # Parallel tool calls run their Pre and Post hooks as separate processes
    # at once. Without the lock a put can overwrite a concurrent pop (the
    # honored receipt comes back and is reaped as never run) or a concurrent
    # put (a call that ran leaves no evidence row).
    import threading
    p = PendingReceipts(str(tmp_path / "audit.hook-pending.json"))
    gate = {"envelope": {"decision_id": "d"}, "grant": None, "self_issued": True, "reason": "ok", "ref": None}
    ids = ["t%d" % i for i in range(120)]
    threads = [threading.Thread(target=p.put, args=(i, gate, {"name": "Bash", "arguments": {}}, 1.0)) for i in ids]
    for t in threads: t.start()
    for t in threads: t.join()
    assert sorted(p._read()) == sorted(ids)
    popped = []
    threads = [threading.Thread(target=lambda i=i: popped.append(p.pop(i))) for i in ids]
    for t in threads: t.start()
    for t in threads: t.join()
    assert len(popped) == 120 and all(g is not None for g in popped) and p._read() == {}
