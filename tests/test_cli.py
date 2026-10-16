"""`gargoyle init` produces a working deployment: the issuer runs on the
rules file, the middleware config is complete, and the audit command
verifies a chain with the written public keys."""

import json
from pathlib import Path

from fastapi.testclient import TestClient

from gargoyle.cli import main
from gargoyle.issuer_service import app_from_env
from gargoyle.mcp_server import config_from_env, ServerState, IssuerClient, gate_tool_call
import os


def _read_env(path):
    return {k: v for k, v in (l.split("=", 1) for l in Path(path).read_text().splitlines() if "=" in l)}


def test_init_then_issue_hold_approve_execute_audit(tmp_path, monkeypatch, capsys):
    out = tmp_path / "deploy"; sandbox = tmp_path / "sandbox"; sandbox.mkdir()
    assert main(["init", str(sandbox), "--out", str(out)]) == 0
    for name in ("rules.json", "issuer.env", "middleware.env", "approver.env", "mcp-config.json", "public-keys.json"):
        assert (out / name).exists(), name
    assert oct((out / "approver.env").stat().st_mode & 0o777) == "0o600"
    cfg = json.loads((out / "mcp-config.json").read_text())["mcpServers"]["filesystem-gargoyle"]
    assert cfg["args"][:3] == ["-m", "gargoyle.mcp_server", "--"] and str(sandbox) in cfg["args"][-1]

    # The issuer, as `gargoyle issuer` would run it (minus uvicorn).
    monkeypatch.setattr(os, "environ", dict(os.environ, **_read_env(out / "issuer.env")))
    app = app_from_env()
    client = TestClient(app)
    (out / "record.json").write_text(json.dumps(client.get("/record").json()) + "\n")

    # The middleware, from middleware.env, in self-issue mode against that issuer.
    monkeypatch.setattr(os, "environ", dict(os.environ, **_read_env(out / "middleware.env")))
    config = config_from_env(); assert config is not None

    class Shim:
        def post(self, url, json=None, headers=None, timeout=None): return client.post(url.split("8080", 1)[1], json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return client.get(url.split("8080", 1)[1], headers=headers)
    approver_env = _read_env(out / "approver.env")

    def approve_now(seconds):
        from gargoyle.approver_cli import approve_at_issuer
        approve_at_issuer("http://127.0.0.1:8080", approver_env["GARGOYLE_APPROVER_TOKEN"],
                          key_hex=approver_env["GARGOYLE_APPROVER_KEY_HEX"], key_id="approver-1", yes=True, http=Shim())
    ic = IssuerClient("http://127.0.0.1:8080", os.environ["GARGOYLE_MCP_CLIENT_TOKEN"], http=Shim(),
                      approval_timeout=5, poll_seconds=0.01, sleep=approve_now)
    state = ServerState(config, issuer_client=ic)
    assert gate_tool_call(state, {"name": "list_directory", "arguments": {"path": str(sandbox)}})[0] is True
    assert gate_tool_call(state, {"name": "delete_file", "arguments": {}}) == (False, "DESTRUCTIVE_TOOL")
    from gargoyle.mcp_server import _gate, EXECUTION_META_KEY, RECEIPT_META_KEY, USED_GRANT_META_KEY, _audit_meta
    gate = _gate(state, {"name": "write_file", "arguments": {"path": str(sandbox / "a.txt"), "content": "x"}})
    assert gate["executed"] is True and gate["grant"] is not None
    meta = _audit_meta(state, gate, {"ok": True})
    for name, key in (("receipt", RECEIPT_META_KEY), ("execution", EXECUTION_META_KEY), ("grant", USED_GRANT_META_KEY)):
        (tmp_path / (name + ".json")).write_text(json.dumps(meta[key]))
    assert main(["audit", str(tmp_path / "receipt.json"), str(tmp_path / "execution.json"), str(tmp_path / "grant.json"),
                 "--out", str(out)]) == 0
    assert "chain: CHAIN_VERIFIED" in capsys.readouterr().out


def test_init_for_a_windows_client_and_audit_log_verification(tmp_path, monkeypatch, capsys):
    """Keys generated on the Linux issuer host, config written for a Windows
    client: paths kept as typed, the client's python in the MCP entry, the
    issuer reached at its TLS URL. The middleware's audit log is then
    verified entry by entry."""
    out = tmp_path / "deploy"
    assert main(["init", r"C:\Users\jdoe\project", "--out", str(out), "--issuer-url", "https://gargoyle.lan",
                 "--client-python", r"C:\Python314\python.exe", "--client-config-dir", r"C:\gargoyle"]) == 0
    env = _read_env(out / "middleware.env")
    assert env["GARGOYLE_MCP_TARGET_ID"] == r"mcp://filesystem/C:\Users\jdoe\project"
    assert env["GARGOYLE_MCP_RECORD_PATH"] == r"C:\gargoyle\record.json"
    assert env["GARGOYLE_MCP_AUDIT_LOG"] == r"C:\gargoyle\audit.jsonl"
    assert env["GARGOYLE_MCP_ISSUER_URL"] == "https://gargoyle.lan"
    cfg = json.loads((out / "mcp-config.json").read_text())["mcpServers"]["filesystem-gargoyle"]
    assert cfg["command"] == r"C:\Python314\python.exe" and cfg["args"][-1] == r"C:\Users\jdoe\project"
    web = json.loads((out / "approver-web.json").read_text())
    assert web["issuer_url"] == "https://gargoyle.lan" and set(web["jwk"]) == {"kty", "crv", "d", "x"}

    # An audit log as the middleware writes it, verified with the written public keys.
    from gargoyle.mcp_server import ServerState, _audit_meta, _gate, IssuerClient
    monkeypatch.setattr(os, "environ", dict(os.environ, **_read_env(out / "issuer.env")))
    app = app_from_env(); client = TestClient(app)
    (out / "record.json").write_text(json.dumps(client.get("/record").json()) + "\n")
    env["GARGOYLE_MCP_RECORD_PATH"] = str(out / "record.json")
    monkeypatch.setattr(os, "environ", dict(os.environ, **env))
    from gargoyle.mcp_server import config_from_env
    config = config_from_env(); assert config is not None
    class Shim:
        def post(self, url, json=None, headers=None, timeout=None): return client.post(url.replace("https://gargoyle.lan", ""), json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return client.get(url.replace("https://gargoyle.lan", ""), headers=headers)
    log = tmp_path / "audit.jsonl"
    state = ServerState(config, issuer_client=IssuerClient("https://gargoyle.lan", env["GARGOYLE_MCP_CLIENT_TOKEN"], http=Shim()),
                        audit_log=str(log))
    for i in range(3):
        gate = _gate(state, {"name": "list_directory", "arguments": {"path": "C:\\\\x%d" % i}})
        assert gate["executed"]
        _audit_meta(state, gate, {"ok": i})
    assert len(log.read_text().splitlines()) == 3
    assert main(["audit", "--log", str(log), "--out", str(out)]) == 0
    out_text = capsys.readouterr().out
    assert "3 entries, 0 failed" in out_text and out_text.count(" ok ") == 3
    # A tampered entry is caught.
    lines = log.read_text().splitlines(); e = json.loads(lines[1]); e["execution"]["outputs_sha256"] = "0" * 64
    lines[1] = json.dumps(e); log.write_text("\n".join(lines) + "\n")
    assert main(["audit", "--log", str(log), "--out", str(out)]) == 1
    assert "1 failed" in capsys.readouterr().out
