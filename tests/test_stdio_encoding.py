"""MCP stdio is UTF-8 whatever the locale says.

The first Claude Desktop run on Windows decoded the client's UTF-8 with
cp1252: an em dash became three characters and an undefined byte a lone
surrogate, which the issuer accepted and then could not serialize, so the
approval page went dark. Both servers now read and write UTF-8 over the
raw buffers, the upstream pipe is UTF-8, and the issuer refuses arguments
that are not text."""

import io
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.fs_server import Root, serve
from gargoyle.issuer_service import REF_ISSUER_ARGS_NOT_TEXT, build_issuer_app
from gargoyle.jws import encode
from gargoyle.mcp_server import StdioUpstream, utf8_stdio
from gargoyle.policy import ELIGIBLE, Decision

DASH = "a \u2014 b"   # em dash: UTF-8 e2 80 94; cp1252 would read it as three characters


def _rpc(id_, method, params):
    return json.dumps({"jsonrpc": "2.0", "id": id_, "method": method, "params": params}) + "\n"


def test_fs_server_reads_utf8_from_a_cp1252_locale(tmp_path, monkeypatch):
    """sys.stdin as Windows would set it up (cp1252, surrogateescape) with
    UTF-8 bytes arriving: the file still gets the em dash."""
    root = tmp_path / "root"; root.mkdir()
    raw_in = io.BytesIO((_rpc(1, "tools/call", {"name": "write_file", "arguments": {"path": "n.md", "content": DASH}})).encode("utf-8"))
    class Keep(io.BytesIO):
        def close(self): pass   # the UTF-8 wrapper closes its buffer on collection; keep ours readable
    raw_out = Keep()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(raw_in, encoding="cp1252", errors="surrogateescape"))
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw_out, encoding="cp1252"))
    serve(Root(str(root)))
    assert (root / "n.md").read_bytes() == DASH.encode("utf-8")
    reply = json.loads(raw_out.getvalue().decode("utf-8"))
    assert reply["id"] == 1 and "error" not in reply


def test_utf8_stdio_leaves_given_streams_alone():
    a, b = io.StringIO(), io.StringIO()
    assert utf8_stdio(a, b) == (a, b)


def test_upstream_pipe_round_trips_non_ascii(tmp_path):
    root = tmp_path / "root"; root.mkdir()
    up = StdioUpstream([sys.executable, "-I", "-m", "gargoyle.fs_server", str(root)])
    try:
        up.send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        up.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        w = up.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                     "params": {"name": "write_file", "arguments": {"path": "n.md", "content": DASH}}})
        assert "error" not in w
        r = up.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "read_file", "arguments": {"path": "n.md"}}})
        assert r["result"]["content"][0]["text"] == DASH
    finally:
        up.close()
    assert (root / "n.md").read_text(encoding="utf-8") == DASH


def test_issuer_refuses_arguments_that_are_not_text():
    issuer, idp = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()

    class Allow:
        def pin(self): return {"policy_id": "p/1", "policy_sha256": "a" * 64}
        def decide(self, target_url, interaction): return Decision(ELIGIBLE, requires_approval=True)

    app = build_issuer_app(policy=Allow(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()})
    client = TestClient(app)
    from datetime import datetime, timedelta, timezone
    tok = encode({"sub": "spiffe://x/agent", "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")
    headers = {"Authorization": "Bearer " + tok}
    # What a cp1252 decode of UTF-8 produces for an undefined byte: a lone surrogate, JSON-escaped.
    body = '{"target_url": "mcp://x", "tool": "write_file", "args": {"path": "n.md", "content": "a \\udc9d b"}}'
    r = client.post("/issue", content=body, headers={**headers, "Content-Type": "application/json"})
    assert r.status_code == 400 and r.json()["detail"]["reason"] == REF_ISSUER_ARGS_NOT_TEXT
    # Nothing was held, so the approval page still renders.
    assert client.get("/pending", headers=headers).status_code == 200
    # Real text with the same dash is fine.
    ok = client.post("/issue", json={"target_url": "mcp://x", "tool": "write_file", "args": {"path": "n.md", "content": DASH}}, headers=headers)
    assert ok.status_code == 200 and ok.json()["issued"] is True
    assert client.get("/pending", headers=headers).status_code == 200
