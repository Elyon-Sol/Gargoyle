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
