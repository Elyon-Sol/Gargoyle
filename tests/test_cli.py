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
    if os.name == "posix":
        assert oct((out / "approver.env").stat().st_mode & 0o777) == "0o600"
    cfg = json.loads((out / "mcp-config.json").read_text())["mcpServers"]["filesystem-gargoyle"]
    assert cfg["args"][:3] == ["-m", "gargoyle.mcp_server", "--"] and str(sandbox) in cfg["args"][-1]

    # The issuer, as `gargoyle issuer` would run it (minus uvicorn).
    monkeypatch.setattr(os, "environ", dict(os.environ, **_read_env(out / "issuer.env")))
    app = app_from_env()
    client = TestClient(app)
    (out / "record.json").write_text(json.dumps({k: client.get("/record").json()[k] for k in ("policy_id", "policy_sha256")}) + "\n")

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
    call_args = {"path": str(sandbox / "a.txt"), "content": "x"}
    gate = _gate(state, {"name": "write_file", "arguments": call_args})
    assert gate["executed"] is True and gate["grant"] is not None
    meta = _audit_meta(state, gate, {"ok": True}, {"name": "write_file", "arguments": call_args})
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
    (out / "record.json").write_text(json.dumps({k: client.get("/record").json()[k] for k in ("policy_id", "policy_sha256")}) + "\n")
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
    from gargoyle.mcp_server import _record
    from gargoyle.evidence import REFUSED
    for i in range(3):
        params = {"name": "list_directory", "arguments": {"path": "C:\\\\x%d" % i}}
        gate = _gate(state, params)
        assert gate["executed"]
        _audit_meta(state, gate, {"ok": i}, params)
    # A refusal is evidence too: the delete the rules forbid.
    params = {"name": "delete_file", "arguments": {"path": "C:\\\\x"}}
    gate = _gate(state, params); assert not gate["executed"]
    _record(state, REFUSED, gate, params)
    assert len(log.read_text().splitlines()) == 4
    assert main(["audit", "--log", str(log), "--out", str(out), "--summary"]) == 0
    out_text = capsys.readouterr().out
    assert "summary:" in out_text and "principal" in out_text and "clients:" in out_text
    assert "4 entries (3 honored, 1 refused), 0 failed; chain EVIDENCE_VERIFIED" in out_text
    assert out_text.count(" ok ") == 4 and "refused  delete_file" in out_text
    assert "ENTRY_VERIFIED (DESTRUCTIVE_TOOL)" in out_text
    # A tampered entry is caught, and the hash-chain names it: editing the
    # execution receipt inside entry 2 changes its hash.
    lines = log.read_text().splitlines(); e = json.loads(lines[1]); e["execution"]["outputs_sha256"] = "0" * 64
    lines[1] = json.dumps(e); log.write_text("\n".join(lines) + "\n")
    assert main(["audit", "--log", str(log), "--out", str(out)]) == 1
    out_text = capsys.readouterr().out
    assert "1 failed" in out_text and "REF_EVIDENCE_HASH_MISMATCH" in out_text


def test_approvers_list_and_revoke_on_the_issuer_host(tmp_path, capsys):
    from gargoyle.approvers import ApproverRegistry
    out = tmp_path / "deploy"; out.mkdir()
    reg = ApproverRegistry(str(out / "approvers.json"))
    reg.enroll("dana@contoso.com", "ab" * 32, oid="11111111-2222-3333-4444-555555555555")
    assert main(["approvers", "list", "--out", str(out)]) == 0
    assert "dana@contoso.com" in capsys.readouterr().out
    assert main(["approvers", "revoke", "nobody@contoso.com", "--out", str(out)]) == 1
    assert main(["approvers", "revoke", "dana@contoso.com", "--out", str(out)]) == 0
    assert "revoked dana@contoso.com" in capsys.readouterr().out
    doc = json.loads((out / "approvers.json").read_text())
    assert doc["approvers"] == {} and doc["revoked"]["dana@contoso.com"]["revoked_by"].startswith("operator:")
    assert main(["approvers", "list", "--out", str(out)]) == 0
    assert "revoked: dana@contoso.com" in capsys.readouterr().out


def test_the_package_runs_as_a_module():
    """`python -m gargoyle --help` works where gargoyle.exe is not on PATH."""
    import subprocess, sys
    r = subprocess.run([sys.executable, "-m", "gargoyle", "--help"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and "audit" in r.stdout


def test_init_observe_allows_everything_and_records_it(tmp_path, capsys):
    """Observe mode: the rules file allows every call, so the gate holds
    nothing and refuses nothing while every call still gets a receipt and an
    evidence entry. The default rules are not touched once someone edited them."""
    from gargoyle.cli import DEFAULT_RULES, OBSERVE_RULES
    from gargoyle.rules import RulesPolicy
    out = tmp_path / "deploy"
    assert main(["init", str(tmp_path / "project"), "--out", str(out), "--observe"]) == 0
    assert "observe mode" in capsys.readouterr().out
    assert json.loads((out / "rules.json").read_text()) == OBSERVE_RULES
    policy = RulesPolicy(str(out / "rules.json"))
    for tool in ("read_file", "write_file", "delete_file", "anything_else"):
        d = policy.decide("mcp://x", {"tool": tool, "args": {}, "principal": "p"})
        assert d.eligible and not d.requires_approval
    assert policy.pin()["policy_sha256"] != RulesPolicy.__module__ and policy.pin()["policy_id"]
    # A hand-edited rules file is left alone by a later --observe.
    custom = {**DEFAULT_RULES, "rules": DEFAULT_RULES["rules"][:1]}
    (out / "rules.json").write_text(json.dumps(custom))
    assert main(["init", str(tmp_path / "project"), "--out", str(out), "--observe"]) == 0
    assert json.loads((out / "rules.json").read_text()) == custom
    assert "left as it is" in capsys.readouterr().err
    # A broken rules file is refused, not overwritten and not a traceback.
    (out / "rules.json").write_text("{not json")
    assert main(["init", str(tmp_path / "project"), "--out", str(out), "--observe"]) == 2
    assert (out / "rules.json").read_text() == "{not json"



def test_witness_command_renders_the_issuers_log(tmp_path, capsys):
    """`gargoyle witness` prints the witness file as a table an operator
    reads on the issuer's host: when, event, who, tool, outcome. It is the
    rendering the console's Activity table gives, with no sign-in."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from gargoyle.witness import WitnessLog, describe
    w = WitnessLog(str(tmp_path / "witness.jsonl"), Ed25519PrivateKey.generate(), "issuer-1")
    w.record("issued", principal="ann@contoso.com", tool="read_file", held=False, decision_id="d-1", args_sha256="a" * 64)
    w.record("issued", principal="ann@contoso.com", tool="write_file", held=True, decision_id="d-2", approval_request_id="r-2", args_sha256="b" * 64)
    w.record("granted", approval_request_id="r-2", approver="dana@contoso.com", collected=1, required=1)
    w.record("refused", principal="bob@contoso.com", tool="delete_file", reason="REF_POLICY_DENIED")
    assert main(["witness", str(tmp_path / "witness.jsonl")]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].split()[0] == "at" and out[0].split()[2] == "event"      # the zone is this machine's
    assert main(["witness", str(tmp_path / "witness.jsonl"), "--utc"]) == 0
    utc = capsys.readouterr().out.splitlines()
    assert utc[0].split()[:3] == ["at", "(UTC)", "event"]
    assert "witness began" in out[1]
    assert "ann@contoso.com" in out[2] and "read_file" in out[2] and out[2].rstrip().endswith("allowed")
    assert "write_file" in out[3] and "held for approval" in out[3]
    assert "dana@contoso.com" in out[4] and "released" in out[4]
    assert "bob@contoso.com" in out[5] and "refused: REF_POLICY_DENIED" in out[5]
    assert main(["witness", str(tmp_path / "witness.jsonl"), "--tail", "1"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 2
    assert main(["witness", str(tmp_path / "missing.jsonl")]) == 2
    assert "does not exist" in capsys.readouterr().err
    assert describe("not a dict")["event"] == "malformed" and describe({"event": "something_new"})["outcome"] == "something_new"
