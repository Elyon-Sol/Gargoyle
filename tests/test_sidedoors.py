"""Discovery mode: the gate finds every other way into the files it
protects, records them beside the evidence log and in the issuer's
witness, and never refuses on them."""

import io
import json
import os
import shutil
from pathlib import Path

import pytest

from gargoyle import sidedoors as sd
from gargoyle.witness import describe
from gargoyle.issuer_service import build_issuer_app
from gargoyle.witness import WitnessLog
from tests.test_approvers import Hold, idp, issuer, token
from fastapi.testclient import TestClient
from tests.test_claude_hook import PRE, deployment, event

POSIX = os.name != "nt"


def home_with(tmp_path, **files):
    """A fake home with the given client files ("desktop", "code", "settings", "managed_mcp", "managed_settings")."""
    home, managed = tmp_path / "home", tmp_path / "managed"
    for d in (home, managed):
        shutil.rmtree(d, ignore_errors=True); d.mkdir()
    where = {"desktop": home / ".config/Claude/claude_desktop_config.json", "code": home / ".claude.json",
             "settings": home / ".claude/settings.json", "managed_mcp": managed / "managed-mcp.json",
             "managed_settings": managed / "managed-settings.json"}
    for k, doc in files.items():
        where[k].parent.mkdir(parents=True, exist_ok=True)
        where[k].write_text(json.dumps(doc))
    return home, managed


def discover(root, home, managed, **kw):
    paths = sd.client_config_paths(home, "Linux", {})
    paths["managed_dir"] = [managed]
    orig = sd.client_config_paths
    sd.client_config_paths = lambda *a, **k: paths
    try:
        return sd.discover(str(root), home=str(home), system="Linux", env={}, smb_conf=str(home / "no-smb.conf"), **kw)
    finally:
        sd.client_config_paths = orig


def kinds(findings):
    return sorted(f["kind"] for f in findings)


def test_a_second_server_on_the_same_folder_is_a_side_door_and_the_gate_itself_is_not(tmp_path):
    root = tmp_path / "share"; root.mkdir()
    home, managed = home_with(tmp_path, desktop={"mcpServers": {
        "gated": {"command": "python", "args": ["-m", "gargoyle.mcp_server", "--env", "/x/middleware.env", "--", "npx", "server-filesystem", str(root)]},
        "raw": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", str(root / "sub")]},
        "parent": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", str(tmp_path)]},
        "elsewhere": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", str(tmp_path / "other")]},
        "anywhere": {"command": "mcp-server-filesystem"}}},
        managed_settings={"permissions": {"deny": ["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"]}})
    f = discover(root, home, managed)
    ungated = [x for x in f if x["kind"] == sd.UNGATED_MCP_SERVER]
    names = sorted(x["detail"].split("'")[1] for x in ungated)
    assert names == ["anywhere", "parent", "raw"]
    assert all("gate" in x["remedy"] for x in ungated)
    assert sd.CLIENT_TOOLS_UNGATED not in kinds(f)         # the managed deny closes Claude Code's own tools


def test_claude_codes_own_tools_are_a_side_door_until_a_hook_or_a_managed_deny_closes_them(tmp_path):
    root = tmp_path / "share"; root.mkdir()
    home, managed = home_with(tmp_path)
    f = discover(root, home, managed)
    assert kinds(f) == [sd.CLIENT_TOOLS_UNGATED]
    assert "Write, Edit, MultiEdit, NotebookEdit, Bash" in f[0]["detail"]
    hook = {"hooks": {"PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "python -m gargoyle hook --env x"}]}]}}
    home, managed = home_with(tmp_path, settings=hook)
    assert kinds(discover(root, home, managed)) == [sd.CLIENT_SHELL_PASSTHROUGH, sd.HOOK_REMOVABLE]   # the user can edit it away
    home, managed = home_with(tmp_path, settings=hook, managed_settings=dict(hook, allowManagedHooksOnly=True))
    f = discover(root, home, managed)
    assert kinds(f) == [sd.CLIENT_SHELL_PASSTHROUGH]            # the standing note: no setting closes `!`
    assert "no hook fires" in f[0]["detail"] and "user agreement" in f[0]["remedy"]
    home, managed = home_with(tmp_path, managed_settings={"permissions": {"deny": ["Write", "Edit", "MultiEdit", "NotebookEdit"]}})
    f = discover(root, home, managed)
    assert kinds(f) == [sd.CLIENT_SHELL_PASSTHROUGH, sd.CLIENT_TOOLS_UNGATED] and f[0]["detail"].endswith("Bash run with no gargoyle hook")


def test_project_configs_and_a_non_exclusive_managed_file_are_named(tmp_path):
    root = tmp_path / "share"; root.mkdir()
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"extra": {"command": "npx", "args": ["x"]}}}))
    home, managed = home_with(tmp_path,
                              code={"projects": {str(root): {"mcpServers": {"proj": {"command": "npx", "args": ["server-filesystem", str(root)]}}}}},
                              managed_mcp={"mcpServers": {"gate": {"command": "python", "args": ["-m", "gargoyle.mcp_server"]}}},
                              managed_settings={"permissions": {"deny": ["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"]}})
    f = discover(root, home, managed)
    assert kinds(f) == [sd.CLIENT_SHELL_PASSTHROUGH, sd.MANAGED_NOT_EXCLUSIVE, sd.PROJECT_MCP_CONFIG, sd.UNGATED_MCP_SERVER]
    proj = next(x for x in f if x["kind"] == sd.PROJECT_MCP_CONFIG)
    assert proj["path"] == str(root / ".mcp.json") and "1 ungated server(s): extra" in proj["detail"]
    assert "(project %s)" % root in next(x for x in f if x["kind"] == sd.UNGATED_MCP_SERVER)["detail"]
    home, managed = home_with(tmp_path, managed_mcp={"mcpServers": {}}, managed_settings={"allowManagedMcpServersOnly": True,
                              "permissions": {"deny": ["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"]}})
    (root / ".mcp.json").unlink()
    assert kinds(discover(root, home, managed)) == [sd.CLIENT_SHELL_PASSTHROUGH]     # Claude Code is installed here; `!` stays


def test_a_script_written_through_the_gate_is_a_side_door_even_when_the_rules_allowed_it(tmp_path):
    root = tmp_path / "share"; root.mkdir()
    home, managed = home_with(tmp_path, managed_settings={"permissions": {"deny": ["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"]}})
    ev = [{"kind": "honored", "tool": "write_file", "ref": str(root / "gate-info.ps1"), "at": "2026-10-31T22:20:19+00:00",
           "principal": "claude@hearthcorp.com", "reason": "REASSERTED_AND_BOUND", "receipt": {"requires_approval": False}, "grant": None},
          {"kind": "honored", "tool": "write_file", "ref": str(root / "notes.md"), "at": "2026-10-31T22:21:00+00:00", "principal": "claude@hearthcorp.com"},
          {"kind": "refused", "tool": "write_file", "ref": str(root / "evil.bat"), "at": "2026-10-31T22:22:00+00:00", "principal": "claude@hearthcorp.com"},
          {"kind": "honored", "tool": "Write", "ref": str(root / "run.sh"), "at": "2026-10-31T22:23:00+00:00", "principal": "sysops@hearthcorp.com",
           "receipt": {"requires_approval": True}, "grant": {"g": 1}}]
    f = [x for x in discover(root, home, managed, evidence=ev) if x["kind"] == sd.EXECUTABLE_WRITTEN]
    assert sorted(x["path"] for x in f) == [str(root / "gate-info.ps1"), str(root / "run.sh")]
    ps1 = next(x for x in f if x["path"].endswith(".ps1"))
    assert ps1["detail"] == "ps1 file written through the gate at 2026-10-31T22:20:19 by claude@hearthcorp.com (allowed by rule; no approver saw it)"
    assert "released by an approver" in next(x for x in f if x["path"].endswith(".sh"))["detail"]
    assert '"action": "hold"' in ps1["remedy"]


@pytest.mark.skipif(not POSIX, reason="POSIX modes, symlinks and smb.conf")
def test_the_tree_itself_world_writable_folders_symlinks_out_and_shares(tmp_path):
    root = tmp_path / "share"; root.mkdir()
    (root / "open").mkdir(); os.chmod(root / "open", 0o777)
    (root / "inside").mkdir()
    os.symlink(tmp_path / "secret.txt", root / "inside" / "link.txt")
    os.symlink(root / "open", root / "inside" / "same-tree")
    home, managed = home_with(tmp_path, managed_settings={"permissions": {"deny": ["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"]}})
    smb = tmp_path / "smb.conf"
    smb.write_text("[global]\n  workgroup = X\n[clients]\n  path = %s\n  read only = no\n[other]\n  path = /srv/other\n" % root)
    paths = sd.client_config_paths(home, "Linux", {}); paths["managed_dir"] = [managed]
    orig = sd.client_config_paths; sd.client_config_paths = lambda *a, **k: paths
    try:
        f = sd.discover(str(root), home=str(home), system="Linux", env={}, smb_conf=str(smb))
    finally:
        sd.client_config_paths = orig
    by = {x["kind"]: x for x in f}
    assert kinds(f) == [sd.CLIENT_SHELL_PASSTHROUGH, sd.SMB_SHARE, sd.SYMLINK_OUT, sd.WORLD_WRITABLE]   # managed settings present: Claude Code is here
    assert by[sd.SYMLINK_OUT]["path"] == str(root / "inside" / "link.txt")   # the in-tree link is fine
    assert by[sd.WORLD_WRITABLE]["path"] == str(root / "open")
    assert by[sd.SMB_SHARE]["detail"] == "share 'clients' exports %s" % root


def test_windows_shares_come_from_powershell_through_the_injected_runner():
    class R:
        stdout = json.dumps([{"Name": "Clients", "Path": r"C:\gargoyle-share"}, {"Name": "ADMIN$", "Path": r"C:\Windows"}])
    calls = []
    def run(argv, **kw):
        calls.append(argv); return R()
    shares = sd._shares("Windows", "/nonexistent", run)
    assert shares == [{"name": "Clients", "path": r"C:\gargoyle-share"}]        # administrative shares are not reported
    assert calls[0][0] == "powershell" and "Get-SmbShare" in calls[0][-1]
    assert sd._touches(r"C:\gargoyle-share", r"c:/gargoyle-share/routed") and not sd._touches(r"C:\Windows", r"C:\gargoyle-share")
    def boom(argv, **kw): raise OSError("no powershell")
    assert sd._shares("Windows", "/nonexistent", boom) == []


def test_the_report_keeps_first_seen_and_decides_when_the_next_look_is_due(tmp_path):
    log = tmp_path / "audit.jsonl"
    f1 = [sd._finding(sd.SMB_SHARE, "/srv/x", "share", "remove")]
    t0 = 1_700_000_000
    out = sd.write_report(f1, str(log), root="/srv/x", now=t0)
    assert sd.report_path(str(log)) == tmp_path / "audit.sidedoors.json"
    assert out["findings"][0]["first_seen"] == out["at"] == "2023-11-14T22:13:20Z"
    later = sd.write_report(f1 + [sd._finding(sd.WORLD_WRITABLE, "/srv/x", "open", "chmod")], str(log), root="/srv/x", now=t0 + 3600 * 30)
    assert later["findings"][0]["first_seen"] == "2023-11-14T22:13:20Z"          # carried over
    assert later["findings"][1]["first_seen"] == later["at"] != "2023-11-14T22:13:20Z"
    assert sd.report_age_seconds(str(log), now=t0 + 3600 * 31) == 3600.0
    assert sd.due(str(log), {}, now=t0 + 3600 * 31) is False
    assert sd.due(str(log), {}, now=t0 + 3600 * 55) is True
    assert sd.due(str(log), {sd.ENV_DISCOVERY_HOURS: "1"}, now=t0 + 3600 * 31.5) is True
    assert sd.due(str(log), {sd.ENV_DISCOVERY_HOURS: "0"}, now=t0 + 3600 * 999) is False     # disabled
    assert sd.due(str(tmp_path / "fresh.jsonl"), {}) is True and sd.due(None, {}) is False
    assert sd.discovery_hours({sd.ENV_DISCOVERY_HOURS: "junk"}) == 24.0


def test_the_issuer_witnesses_a_report_and_the_console_reads_it(tmp_path):
    c = TestClient(build_issuer_app(policy=Hold(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                                    witness=WitnessLog(str(tmp_path / "witness.jsonl"), issuer, "issuer-1")))
    h = {"Authorization": "Bearer " + token("claude@hearthcorp.com")}
    body = {"target_url": "mcp://filesystem/C:/gargoyle-share", "findings": [
        {"kind": sd.UNGATED_MCP_SERVER, "path": r"C:\Users\assist\AppData\Roaming\Claude\claude_desktop_config.json", "detail": "x" * 500},
        {"kind": sd.SMB_SHARE, "path": r"C:\gargoyle-share", "detail": "share 'Clients'"}]}
    r = c.post("/sidedoors", json=body, headers=h)
    assert r.status_code == 200 and r.json() == {"recorded": True, "count": 2}
    entry = next(e for e in c.app.state.witness.entries if e["event"] == "sidedoors")
    assert entry["principal"] == "claude@hearthcorp.com" and entry["count"] == 2
    assert entry["kinds"] == {sd.SMB_SHARE: 1, sd.UNGATED_MCP_SERVER: 1}
    assert len(entry["findings"][0]["detail"]) == 200                    # bounded: the witness is not a dump
    d = describe(entry)
    assert d["outcome"] == "2 side doors found (1 SMB_SHARE, 1 UNGATED_MCP_SERVER)" and d["who"] == "claude@hearthcorp.com"
    assert describe({"event": "sidedoors", "count": 0})["outcome"] == "no side doors found"
    assert c.post("/sidedoors", json={"target_url": "x", "findings": [{"kind": 1}]}, headers=h).status_code == 400
    assert c.post("/sidedoors", json={"target_url": "x", "findings": [{}] * 101}, headers=h).status_code == 400
    assert c.post("/sidedoors", json=body).status_code == 401
    # The console's describeEntry says the same.
    src = Path(sd.__file__).with_name("static") / "approve.html"
    assert 'case "sidedoors"' in src.read_text(encoding="utf-8")


def test_the_hook_takes_the_daily_look_after_its_decision_and_the_gate_records_it(tmp_path, monkeypatch):
    monkeypatch.setenv("GARGOYLE_WITNESS_PATH", str(tmp_path / "witness.jsonl"))
    out, project, env, state, client = deployment(tmp_path, monkeypatch, observe=True)
    log = Path(env["GARGOYLE_MCP_AUDIT_LOG"])
    side = sd.report_path(str(log))
    # The hook's look uses this host's real client files; point discovery at the tmp home so the test is about the flow.
    monkeypatch.setattr(sd, "client_config_paths", lambda home, system, e=None: {"desktop": [], "code_user": [], "code_settings": [], "managed_dir": []})
    env = dict(env, GARGOYLE_MCP_STATE_ROOT=str(project), REQUESTS_CA_BUNDLE="")
    st = state()
    st.state_root = str(project)
    assert sd.due(str(log), env)
    found = sd.run_for_state(st, env=env, stderr=io.StringIO())
    assert found is not None and sd.CLIENT_TOOLS_UNGATED in kinds(found)
    assert side.exists() and json.loads(side.read_text())["root"] == str(project)
    w = [e for e in client.app.state.witness.entries if e["event"] == "sidedoors"]
    assert len(w) == 1 and w[0]["target_url"] == env["GARGOYLE_MCP_TARGET_ID"] and w[0]["count"] == len(found)
    # Not due again: nothing runs, nothing is witnessed twice.
    assert sd.run_for_state(st, env=env, stderr=io.StringIO()) is None
    assert len([e for e in client.app.state.witness.entries if e["event"] == "sidedoors"]) == 1
    # Disabled by the operator: never due, even with no report.
    side.unlink()
    assert sd.run_for_state(st, env=dict(env, GARGOYLE_MCP_DISCOVERY_HOURS="0"), stderr=io.StringIO()) is None
    # A gated file changed behind the gate is a finding too.
    r = __import__("gargoyle.claude_hook", fromlist=["decide"]).decide(event(PRE, "Write", {"file_path": str(project / "a.txt"), "content": "one"}), st)
    (project / "a.txt").write_text("one")
    from gargoyle.claude_hook import POST
    __import__("gargoyle.claude_hook", fromlist=["decide"]).decide(event(POST, "Write", {"file_path": str(project / "a.txt"), "content": "one"},
                                                                         tool_response={"ok": True}), st)
    (project / "a.txt").write_text("someone else")
    found = sd.run_for_state(st, force=True, env=env, stderr=io.StringIO())
    changed = [f for f in found if f["kind"] == sd.UNATTRIBUTED_CHANGE]
    assert len(changed) == 1 and changed[0]["path"].endswith("a.txt")
    # Discovery never raises into the hook: a broken state is a line on stderr.
    err = io.StringIO()
    class Broken:
        evidence = st.evidence
        state_root = 12345
    no_root = {k: v for k, v in env.items() if k != "GARGOYLE_MCP_STATE_ROOT"}
    assert sd.run_for_state(Broken(), force=True, env=no_root, stderr=err) is None and "side-door discovery failed" in err.getvalue()


def test_the_cli_lists_side_doors_and_exits_nonzero_when_there_are_any(tmp_path, monkeypatch, capsys):
    from gargoyle.cli import main
    root = tmp_path / "share"; root.mkdir()
    (root / ".mcp.json").write_text("{}")
    monkeypatch.setattr(sd, "client_config_paths", lambda home, system, e=None: {"desktop": [], "code_user": [], "code_settings": [], "managed_dir": []})
    assert main(["sidedoors", "--root", str(root), "--json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["root"] == str(root) and set(doc["kinds"]) == {sd.PROJECT_MCP_CONFIG, sd.CLIENT_TOOLS_UNGATED}
    assert main(["sidedoors", "--root", str(root)]) == 1
    text = capsys.readouterr().out
    assert text.startswith("side doors into %s: 2" % root) and "fix:" in text
    assert main(["sidedoors"]) == 2
