"""Remote middleware mode: the same gate behind a Streamable HTTP endpoint,
one capability URL per person, one shared upstream, shared single use."""

import json
import sys
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from gargoyle.approval import build_grant, sign_grant
from gargoyle.issuer_service import build_issuer_app
from gargoyle.mcp_server import EXECUTED_META_KEY, REASON_META_KEY, StdioUpstream
from gargoyle.policy import ELIGIBLE, Decision, refuse
from gargoyle.remote import SESSION_HEADER, HttpUpstream, TokenMap, build_remote_app, mint_identity_token
from gargoyle.revert import REVERT_TOOL

issuer, executor, approver, idp = (Ed25519PrivateKey.generate() for _ in range(4))
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}
TARGET = "mcp://fs"


class FsPolicy:
    def pin(self): return PIN
    def decide(self, target_url, interaction):
        t = interaction.get("tool")
        if t == "write_file": return Decision(ELIGIBLE, None, True)
        if t == "delete_file": return refuse("DESTRUCTIVE_TOOL")
        return Decision(ELIGIBLE)


def _issuer():
    app = build_issuer_app(policy=FsPolicy(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           approver_public_keys={"approver-1": approver.public_key()}, audience="gargoyle-issuer")
    c = TestClient(app)

    class Shim:
        def post(self, url, json=None, headers=None, timeout=None): return c.post(url.replace("http://i", ""), json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return c.get(url.replace("http://i", ""), headers=headers)

    def human(seconds):
        tok = mint_identity_token("approver-1", idp, "idp-1", "gargoyle-issuer")       # the approver key id: an approver sees every hold
        h = {"Authorization": "Bearer " + tok}
        for hold in c.get("/pending", headers=h).json()["pending"]:
            env = hold["envelope"]
            g = sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                       grant_id="g-" + env["approval_request_id"], not_after=datetime.now(timezone.utc) + timedelta(minutes=5)),
                           approver, "approver-1")
            c.post("/grants", json=g, headers=h)
    return c, Shim(), human


CONFIG = {"pinned_public_keys": {"issuer-1": issuer.public_key()}, "record": PIN, "target_id": TARGET,
          "approver_public_keys": {"approver-1": approver.public_key()}, "executor_signing_key": executor, "executor_key_id": "executor-1"}


def rpc(client, token, msg, sid=None):
    h = {"Content-Type": "application/json"}
    if sid: h[SESSION_HEADER] = sid
    return client.post("/mcp/" + token, content=json.dumps(msg), headers=h)


def test_remote_gate_over_stdio_upstream(tmp_path):
    root = tmp_path / "root"; root.mkdir(); (root / "n.md").write_text("one\n", encoding="utf-8")
    _, shim, human = _issuer()
    tokens = TokenMap(str(tmp_path / "remote-tokens.json"))
    alice = tokens.mint("alice@contoso.com", mint_identity_token("alice@contoso.com", idp, "idp-1", "gargoyle-issuer"))
    assert TokenMap(str(tmp_path / "remote-tokens.json")).lookup(alice)["principal"] == "alice@contoso.com"
    up = StdioUpstream([sys.executable, "-I", "-m", "gargoyle.fs_server", str(root)])
    try:
        app = build_remote_app(CONFIG, tokens, upstream=up, issuer_url="http://i", issuer_http=shim, audit_log=str(tmp_path / "audit.jsonl"),
                               state_probe="filesystem", approval_timeout=30, poll_seconds=0.01, sleep=human)
        c = TestClient(app)
        # Unknown capability: nothing.
        assert rpc(c, "nope", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).status_code == 401
        # Initialize: a session id comes back, the upstream's capabilities with it.
        r = rpc(c, alice, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
        assert r.status_code == 200 and r.headers[SESSION_HEADER]
        sid = r.headers[SESSION_HEADER]
        assert r.json()["result"]["serverInfo"]["name"].startswith("gargoyle+")
        assert "do not use any other tool" in r.json()["result"]["instructions"]
        assert rpc(c, alice, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid).status_code == 202
        # Tools: the upstream's plus undo.
        tools = rpc(c, alice, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, sid).json()["result"]["tools"]
        assert {"read_file", "write_file", REVERT_TOOL} <= {t["name"] for t in tools}
        # A free read runs; a held write is approved by the human and runs; the receipt names alice.
        r = rpc(c, alice, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": str(root / "n.md")}}}, sid).json()
        assert r["result"]["_meta"][EXECUTED_META_KEY] is True and r["result"]["content"][0]["text"] == "one\n"
        r = rpc(c, alice, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "write_file", "arguments": {"path": str(root / "n.md"), "content": "two\n"}}}, sid).json()
        assert r["result"]["_meta"][EXECUTED_META_KEY] is True and (root / "n.md").read_text(encoding="utf-8") == "two\n"
        assert r["result"]["_meta"]["gargoyle/receipt"]["request_context"]["principal"] == "alice@contoso.com"
        assert "pre_state_sha256" in r["result"]["_meta"]["gargoyle/execution"]
        # A refusal is a refusal.
        r = rpc(c, alice, {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "delete_file", "arguments": {"path": str(root / "n.md")}}}, sid).json()
        assert r["result"]["isError"] and r["result"]["_meta"][REASON_META_KEY] == "DESTRUCTIVE_TOOL"
        # A second person, a second session, the same upstream and the same evidence log.
        bob = tokens.mint("bob@contoso.com", mint_identity_token("bob@contoso.com", idp, "idp-1", "gargoyle-issuer"))
        r = rpc(c, bob, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}); sid2 = r.headers[SESSION_HEADER]
        rpc(c, bob, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid2)
        r = rpc(c, bob, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": str(root / "n.md")}}}, sid2).json()
        assert r["result"]["_meta"]["gargoyle/receipt"]["request_context"]["principal"] == "bob@contoso.com"
        lines = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        assert [e["principal"] for e in lines] == ["alice@contoso.com"] * 3 + ["bob@contoso.com"] and [e["seq"] for e in lines] == [1, 2, 3, 4]
        assert [e["client"] for e in lines] == ["t 0"] * 3 + [None]          # alice's client named itself; bob's did not
        # No session: told to initialize; DELETE ends one.
        assert rpc(c, alice, {"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}}, "stale").status_code == 404
        assert c.delete("/mcp/" + alice, headers={SESSION_HEADER: sid}).status_code == 200
        assert rpc(c, alice, {"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}}, sid).status_code == 404
    finally:
        up.close()


def test_http_upstream_speaks_streamable_http(tmp_path):
    """The gate fronting a remote MCP server: JSON and SSE answers, session id carried."""
    fake = FastAPI(); calls = []

    @fake.post("/mcp")
    async def mcp(request: Request):
        msg = await request.json(); calls.append((msg, dict(request.headers)))
        if "id" not in msg:
            return Response(status_code=202)
        if msg["method"] == "initialize":
            return Response(content=json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "graph", "version": "1"}}}),
                            media_type="application/json", headers={SESSION_HEADER: "up-1"})
        if msg["method"] == "tools/list":
            body = "event: message\ndata: " + json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": [{"name": "send_mail"}]}}) + "\n\n"
            return Response(content=body, media_type="text/event-stream")
        return Response(content=json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": "sent"}]}}), media_type="application/json")

    fc = TestClient(fake)

    class Shim:
        def post(self, url, data=None, headers=None, timeout=None): return fc.post("/mcp", content=data, headers=headers)
        def delete(self, url, headers=None, timeout=None): return fc.delete("/mcp", headers=headers)

    up = HttpUpstream("https://graph.example/mcp", "secret", http=Shim())
    init = up.send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init["result"]["serverInfo"]["name"] == "graph" and calls[0][1]["authorization"] == "Bearer secret"
    assert up.send({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert calls[-1][1][SESSION_HEADER.lower()] == "up-1"                       # session carried after initialize
    assert up.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})["result"]["tools"][0]["name"] == "send_mail"
    assert up.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "send_mail", "arguments": {}}})["result"]["content"][0]["text"] == "sent"

    # Behind the gate, with no state probe (the server is remote): free calls relay, policy still decides.
    class Allow:
        def pin(self): return PIN
        def decide(self, target_url, interaction): return Decision(ELIGIBLE)
    app = build_issuer_app(policy=Allow(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()}, audience="gargoyle-issuer")
    ic = TestClient(app)

    class IShim:
        def post(self, url, json=None, headers=None, timeout=None): return ic.post(url.replace("http://i", ""), json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return ic.get(url.replace("http://i", ""), headers=headers)
    tokens = TokenMap(entries={"t1": {"principal": "carol@contoso.com", "issuer_token": mint_identity_token("carol@contoso.com", idp, "idp-1", "gargoyle-issuer")}})
    gate = TestClient(build_remote_app(dict(CONFIG, target_id="mcp://graph"), tokens, upstream=up, issuer_url="http://i", issuer_http=IShim(), state_probe="none"))
    r = rpc(gate, "t1", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}); sid = r.headers[SESSION_HEADER]
    rpc(gate, "t1", {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
    r = rpc(gate, "t1", {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "send_mail", "arguments": {"to": "x"}}}, sid).json()
    assert r["result"]["_meta"][EXECUTED_META_KEY] is True and r["result"]["content"][0]["text"] == "sent"
    assert r["result"]["_meta"]["gargoyle/receipt"]["request_context"]["principal"] == "carol@contoso.com"


def test_remote_token_command_mints_a_capability_url(tmp_path, capsys):
    from gargoyle.cli import main, _read_env
    out = tmp_path / "deploy"
    assert main(["init", str(tmp_path / "p"), "--out", str(out), "--issuer-url", "https://gargoyle.lan"]) == 0
    assert "GARGOYLE_IDP_KEY_HEX" in _read_env(out / "issuer.env")          # kept, so tokens can be minted later
    assert main(["remote-token", "--out", str(out), "--principal", "dana@contoso.com", "--url", "https://gargoyle.lan:8444"]) == 0
    text = capsys.readouterr().out
    assert "https://gargoyle.lan:8444/mcp/" in text
    tokens = json.loads((out / "remote-tokens.json").read_text())["tokens"]
    (cap, entry), = tokens.items()
    assert entry["principal"] == "dana@contoso.com" and text.rstrip().endswith(cap)
    # The minted identity token is one the deployment's issuer accepts.
    from gargoyle.issuer_service import app_from_env
    import os
    env = _read_env(out / "issuer.env"); os.environ.update(env)
    try:
        c = TestClient(app_from_env())
        r = c.post("/issue", json={"target_url": "mcp://x", "tool": "read_file", "args": {}}, headers={"Authorization": "Bearer " + entry["issuer_token"]})
        assert r.status_code == 200 and r.json()["envelope"]["request_context"]["principal"] == "dana@contoso.com"
    finally:
        for k in env: os.environ.pop(k, None)
