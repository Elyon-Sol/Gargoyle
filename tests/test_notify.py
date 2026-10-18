"""Approval transport: a new hold is posted to a webhook as a notice with a
console link; the grant still comes only from the approver's key."""

from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import encode
from gargoyle.notify import hold_notice, notifier_from_env, webhook_notifier
from gargoyle.policy import ELIGIBLE, Decision


class Hold:
    def pin(self): return {"policy_id": "p/1", "policy_sha256": "a" * 64}
    def decide(self, target_url, interaction): return Decision(ELIGIBLE, None, True, 2)


class FakeHttp:
    def __init__(self, status=200, raise_exc=None): self.calls = []; self.status = status; self.raise_exc = raise_exc
    def post(self, url, json=None, timeout=None):
        if self.raise_exc: raise self.raise_exc
        self.calls.append((url, json)); return type("R", (), {"status_code": self.status})()


def test_every_new_hold_is_posted_with_a_console_link(capsys):
    issuer, idp = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    http = FakeHttp()
    app = build_issuer_app(policy=Hold(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           on_hold=webhook_notifier("https://hooks.example/abc", "https://gargoyle.lan/approve", http=http, background=False))
    c = TestClient(app)
    tok = encode({"sub": "spiffe://x/agent", "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")
    env = c.post("/issue", json={"target_url": "mcp://x", "tool": "write_file", "args": {"path": "n.md", "content": "x"}},
                 headers={"Authorization": "Bearer " + tok}).json()["envelope"]
    assert len(http.calls) == 1
    url, body = http.calls[0]
    assert url == "https://hooks.example/abc"
    assert body["text"].startswith("Gargoyle hold: write_file by spiffe://x/agent on mcp://x")
    assert "2 approvals needed" in body["text"] and body["text"].endswith("-> https://gargoyle.lan/approve")
    assert body["hold"]["approval_request_id"] == env["approval_request_id"] and body["hold"]["args"] == {"path": "n.md", "content": "x"}
    assert body["envelope"] == env and "approver_signature" not in str(body)      # notice, never a grant


def test_webhook_failure_never_touches_the_hold(capsys):
    issuer, idp = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    app = build_issuer_app(policy=Hold(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           on_hold=webhook_notifier("https://hooks.example/abc", http=FakeHttp(raise_exc=OSError("down")), background=False))
    c = TestClient(app)
    tok = encode({"sub": "spiffe://x/agent", "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")
    h = {"Authorization": "Bearer " + tok}
    assert c.post("/issue", json={"target_url": "mcp://x", "tool": "write_file", "args": {}}, headers=h).json()["issued"] is True
    assert len(c.get("/pending", headers=h).json()["pending"]) == 1
    assert "hold webhook failed" in capsys.readouterr().err
    # A non-2xx answer is reported too.
    http = FakeHttp(status=404)
    webhook_notifier("https://hooks.example/abc", http=http, background=False)({"request_context": {}}, None)
    assert "answered 404" in capsys.readouterr().err


def test_notifier_from_env_and_notice_shape():
    assert notifier_from_env({}) is None
    assert notifier_from_env({"GARGOYLE_HOLD_WEBHOOK_URL": "https://h"}, "https://issuer:8443/") is not None
    n = hold_notice({"request_context": {"tool": "t", "principal": "p", "on_behalf_of": "u"}, "target_url": "x",
                     "not_after": "2026-10-18T12:00:00+00:00", "approval_request_id": "r", "decision_sha256": "d"}, {"a": 1}, None)
    assert n["text"] == "Gargoyle hold: t by p on behalf of u on x (expires 2026-10-18T12:00:00+00:00)"
    assert n["hold"]["approvals_required"] == 1 and n["hold"]["approve_url"] is None
