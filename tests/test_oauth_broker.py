"""OAuth on the remote gate: the hosted client signs the user in with the
directory through the gate, and every receipt names the directory's UPN."""

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.approval import build_grant, sign_grant
from gargoyle.identity import principal_from_token
from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import encode
from gargoyle.mcp_server import StdioUpstream
from gargoyle.oauth_broker import (DEFAULT_REDIRECT_ALLOW, EntraBroker, OAuthGate, OAuthStore, gate_from_env,
                                   pkce_challenge)
from gargoyle.policy import ELIGIBLE, Decision, refuse
from gargoyle.remote import SESSION_HEADER, TokenMap, build_remote_app, mint_identity_token

issuer, executor, approver, idp, tenant_key = (Ed25519PrivateKey.generate() for _ in range(5))
TID = "11111111-2222-3333-4444-555555555555"
APP = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"          # the issuer API's app id: the audience of the user's token
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}
CLAUDE_CB = DEFAULT_REDIRECT_ALLOW[0]
BASE = "https://gate.example/graph"


class FsPolicy:
    def pin(self): return PIN
    def decide(self, target_url, interaction):
        t = interaction.get("tool")
        if t == "write_file": return Decision(ELIGIBLE, None, True)
        if t == "delete_file": return refuse("DESTRUCTIVE_TOOL")
        return Decision(ELIGIBLE)


def entra_token(upn: str, seconds: int = 3600) -> str:
    exp = int((datetime.now(timezone.utc) + timedelta(seconds=seconds)).timestamp())
    return encode({"sub": "pairwise-" + upn, "preferred_username": upn, "oid": "oid-" + upn, "tid": TID,
                   "iss": "https://login.microsoftonline.com/%s/v2.0" % TID, "aud": APP, "exp": exp}, tenant_key, "t-1")


KEYS = {"t-1": tenant_key.public_key()}


def verify(token: str) -> str:
    who = principal_from_token(token, KEYS, audience=["gargoyle-issuer", APP], tenant=TID, tenant_key_ids={"t-1"})
    if not who.get("principal"):
        raise RuntimeError(who["reason"])
    return who["principal"]


class FakeEntra:
    """The tenant's token endpoint: redeems codes it issued, honors PKCE,
    refreshes, and can be told to start refusing (the account was disabled)."""

    def __init__(self, token_seconds: int = 3600):
        self.codes = {}            # code -> (upn, challenge)
        self.refreshes = 0
        self.refuse_refresh = False
        self.token_seconds = token_seconds

    class R:
        def __init__(self, status, body): self.status_code, self._b = status, body; self.content = b"x"
        def json(self): return self._b

    def issue_code(self, authorize_url: str, upn: str) -> str:
        q = parse_qs(urlsplit(authorize_url).query)
        assert q["client_id"] == ["gate-app"] and q["code_challenge_method"] == ["S256"] and "offline_access" in q["scope"][0]
        code = "entra-code-%d" % len(self.codes)
        self.codes[code] = (upn, q["code_challenge"][0])
        return code, q["state"][0]

    def post(self, url, data=None, timeout=None):
        assert url.startswith("https://login.microsoftonline.com/%s/" % TID) and data["client_secret"] == "s3"
        if data["grant_type"] == "authorization_code":
            got = self.codes.pop(data["code"], None)
            if got is None or pkce_challenge(data["code_verifier"]) != got[1]:
                return self.R(400, {"error": "invalid_grant"})
            return self.R(200, {"access_token": entra_token(got[0], self.token_seconds), "expires_in": self.token_seconds,
                                "refresh_token": "rt-" + got[0]})
        if data["grant_type"] == "refresh_token":
            self.refreshes += 1
            if self.refuse_refresh or not data["refresh_token"].startswith("rt-"):
                return self.R(400, {"error": "invalid_grant", "error_description": "AADSTS50057 disabled"})
            upn = data["refresh_token"][3:]
            return self.R(200, {"access_token": entra_token(upn, self.token_seconds + self.refreshes), "expires_in": self.token_seconds})
        return self.R(400, {"error": "unsupported_grant_type"})


def _issuer():
    app = build_issuer_app(policy=FsPolicy(), signing_key=issuer, key_id="issuer-1",
                           idp_public_keys={"idp-1": idp.public_key(), **KEYS},
                           approver_public_keys={"approver-1": approver.public_key()}, audience=["gargoyle-issuer", APP])
    c = TestClient(app)

    class Shim:
        def post(self, url, json=None, headers=None, timeout=None): return c.post(url.replace("http://i", ""), json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return c.get(url.replace("http://i", ""), headers=headers)

    def human(seconds):
        tok = mint_identity_token("approver-1", idp, "idp-1", "gargoyle-issuer")
        h = {"Authorization": "Bearer " + tok}
        for hold in c.get("/pending", headers=h).json()["pending"]:
            env = hold["envelope"]
            g = sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                       grant_id="g-" + env["approval_request_id"], not_after=datetime.now(timezone.utc) + timedelta(minutes=5)),
                           approver, "approver-1")
            c.post("/grants", json=g, headers=h)
    return c, Shim(), human


CONFIG = {"pinned_public_keys": {"issuer-1": issuer.public_key()}, "record": PIN, "target_id": "mcp://fs",
          "approver_public_keys": {"approver-1": approver.public_key()}, "executor_signing_key": executor, "executor_key_id": "executor-1"}


def _gate(tmp_path, entra, access_ttl=3600):
    store = OAuthStore(str(tmp_path / "oauth-state.json"))
    broker = EntraBroker(TID, "gate-app", "s3", "api://%s/access" % APP, BASE + "/oauth/callback", http=entra)
    return OAuthGate(store, broker, BASE, verify, access_ttl=access_ttl)


def sign_in(c: TestClient, gate: OAuthGate, entra: FakeEntra, upn: str, client_id=None):
    """The whole dance a hosted client does, returning the bearer it ends with."""
    if client_id is None:
        r = c.post("/oauth/register", json={"redirect_uris": [CLAUDE_CB], "client_name": "Claude"})
        assert r.status_code == 201, r.text
        client_id = r.json()["client_id"]
    verifier = "v" * 43
    r = c.get("/oauth/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": CLAUDE_CB,
                                         "code_challenge": pkce_challenge(verifier), "code_challenge_method": "S256",
                                         "state": "client-state-1", "scope": "mcp", "resource": BASE + "/mcp"},
              follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("https://login.microsoftonline.com/" + TID), r.text
    code, state = entra.issue_code(r.headers["location"], upn)           # the user signed in at Entra
    r = c.get("/oauth/callback", params={"code": code, "state": state}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith(CLAUDE_CB + "?"), r.text
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert q["state"] == ["client-state-1"] and "code" in q
    r = c.post("/oauth/token", data={"grant_type": "authorization_code", "code": q["code"][0], "client_id": client_id,
                                     "redirect_uri": CLAUDE_CB, "code_verifier": verifier})
    assert r.status_code == 200, r.text
    tok = r.json()
    assert tok["token_type"] == "Bearer" and tok["refresh_token"] and tok["expires_in"] > 0
    return client_id, verifier, q["code"][0], tok


def rpc(c, bearer, msg, sid=None):
    h = {"Content-Type": "application/json", "Authorization": "Bearer " + bearer}
    if sid: h[SESSION_HEADER] = sid
    return c.post("/mcp", content=json.dumps(msg), headers=h)


def test_discovery_registration_and_the_sign_in_name_the_directory_user(tmp_path):
    root = tmp_path / "root"; root.mkdir(); (root / "n.md").write_text("one\n", encoding="utf-8", newline="\n")
    _, shim, human = _issuer()
    entra = FakeEntra()
    gate = _gate(tmp_path, entra)
    up = StdioUpstream([sys.executable, "-I", "-m", "gargoyle.fs_server", str(root)])
    try:
        app = build_remote_app(CONFIG, TokenMap(), upstream=up, issuer_url="http://i", issuer_http=shim,
                               audit_log=str(tmp_path / "audit.jsonl"), state_probe="filesystem", approval_timeout=30,
                               poll_seconds=0.01, sleep=human, oauth=gate)
        c = TestClient(app)
        # No bearer: 401 pointing at the resource metadata, which names this gate as the authorization server.
        r = c.post("/mcp", content="{}", headers={"Content-Type": "application/json"})
        assert r.status_code == 401 and 'resource_metadata="%s/.well-known/oauth-protected-resource"' % BASE in r.headers["WWW-Authenticate"]
        prm = c.get("/.well-known/oauth-protected-resource").json()
        assert prm["resource"] == BASE + "/mcp" and prm["authorization_servers"] == [BASE]
        asm = c.get("/.well-known/oauth-authorization-server").json()
        assert asm["registration_endpoint"] == BASE + "/oauth/register" and asm["code_challenge_methods_supported"] == ["S256"]
        assert c.get("/.well-known/openid-configuration").json()["token_endpoint"] == BASE + "/oauth/token"
        # Registration is open only to the callbacks the operator allows.
        r = c.post("/oauth/register", json={"redirect_uris": ["https://evil.example/cb"]})
        assert r.status_code == 400 and r.json()["error"] == "invalid_redirect_uri"
        assert c.post("/oauth/register", json={}).status_code == 400
        # Unknown client, unregistered redirect: no redirect at all.
        assert c.get("/oauth/authorize", params={"response_type": "code", "client_id": "nope", "redirect_uri": CLAUDE_CB,
                                                 "code_challenge": "x"}, follow_redirects=False).status_code == 400
        client_id, verifier, code, tok = sign_in(c, gate, entra, "alice@contoso.com")
        assert c.get("/oauth/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": "https://evil.example/",
                                                 "code_challenge": "x"}, follow_redirects=False).status_code == 400
        # A code is single use, and PKCE is checked.
        r = c.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "client_id": client_id,
                                         "redirect_uri": CLAUDE_CB, "code_verifier": verifier})
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
        # The session runs as the directory user: the receipt and the evidence name the UPN.
        r = rpc(c, tok["access_token"], {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                         "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "claude-ai", "version": "1"}}})
        assert r.status_code == 200, r.text
        sid = r.headers[SESSION_HEADER]
        rpc(c, tok["access_token"], {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
        r = rpc(c, tok["access_token"], {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                         "params": {"name": "read_file", "arguments": {"path": "n.md"}}}, sid).json()
        assert r["result"]["_meta"]["gargoyle/receipt"]["request_context"]["principal"] == "alice@contoso.com", r
        r = rpc(c, tok["access_token"], {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                         "params": {"name": "write_file", "arguments": {"path": "n.md", "content": "two\n"}}}, sid).json()
        assert r["result"]["_meta"]["gargoyle/receipt"]["request_context"]["principal"] == "alice@contoso.com"
        assert (root / "n.md").read_text(encoding="utf-8") == "two\n"
        rows = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        assert [e["principal"] for e in rows] == ["alice@contoso.com"] * 2 and rows[-1]["client"].startswith("claude-ai")
        # A second person; their bearer cannot touch alice's session.
        _, _, _, tok_b = sign_in(c, gate, entra, "bob@contoso.com", client_id)
        assert rpc(c, tok_b["access_token"], {"jsonrpc": "2.0", "id": 4, "method": "tools/list"}, sid).status_code == 404
        r = rpc(c, tok_b["access_token"], {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                           "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
        sid_b = r.headers[SESSION_HEADER]
        rpc(c, tok_b["access_token"], {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid_b)
        r = rpc(c, tok_b["access_token"], {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                                           "params": {"name": "read_file", "arguments": {"path": "n.md"}}}, sid_b).json()
        assert r["result"]["_meta"]["gargoyle/receipt"]["request_context"]["principal"] == "bob@contoso.com", r
        # Refresh rotates both tokens; the old pair is dead.
        r = c.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": client_id})
        assert r.status_code == 200
        tok2 = r.json()
        assert rpc(c, tok["access_token"], {"jsonrpc": "2.0", "id": 6, "method": "tools/list"}, sid).status_code == 401
        assert c.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]}).status_code == 400
        # The rotated bearer is a new credential: it opens its own session (the old session was alice's old bearer's).
        r = rpc(c, tok2["access_token"], {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                          "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
        assert r.status_code == 200
        # The store survives a restart: the same file, the same bearer.
        again = OAuthStore(str(tmp_path / "oauth-state.json"))
        assert again.lookup(tok2["access_token"])[1]["principal"] == "alice@contoso.com"
        assert again.lookup(tok["access_token"]) is None
        text = (tmp_path / "oauth-state.json").read_text(encoding="utf-8")
        assert tok2["access_token"] not in text and tok2["refresh_token"] not in text     # only hashes at rest
        # A session the client abandons.
        assert c.delete("/mcp", headers={"Authorization": "Bearer " + tok2["access_token"], SESSION_HEADER: r.headers[SESSION_HEADER]}).status_code == 200
    finally:
        up.close()


def test_the_entra_token_is_refreshed_ahead_of_expiry_and_a_refused_refresh_ends_the_session(tmp_path):
    entra = FakeEntra(token_seconds=60)             # inside the refresh-ahead window from the start
    gate = _gate(tmp_path, entra)
    app = build_remote_app(CONFIG, TokenMap(), upstream=None, issuer_url="http://i", issuer_http=None, oauth=gate)
    c = TestClient(app)
    _, _, _, tok = sign_in(c, gate, entra, "alice@contoso.com")
    key, rec = gate.store.lookup(tok["access_token"])
    first = rec["entra"]["access_token"]
    who = gate.authenticate("Bearer " + tok["access_token"])
    assert who is not None and who[1] == "alice@contoso.com" and entra.refreshes == 1
    assert gate.store.sessions[key]["entra"]["access_token"] != first
    assert who[2].token() == gate.store.sessions[key]["entra"]["access_token"]
    # The directory now refuses the refresh (account disabled, policy changed): the bearer is dead and the client is told so.
    entra.refuse_refresh = True
    assert gate.authenticate("Bearer " + tok["access_token"]) is None
    assert gate.store.lookup(tok["access_token"]) is None
    r = c.post("/mcp", content="{}", headers={"Content-Type": "application/json", "Authorization": "Bearer " + tok["access_token"]})
    assert r.status_code == 401 and "resource_metadata" in r.headers["WWW-Authenticate"]


def test_a_sign_in_the_directory_refuses_goes_back_to_the_client_as_an_error(tmp_path):
    entra = FakeEntra()
    gate = _gate(tmp_path, entra)
    app = build_remote_app(CONFIG, TokenMap(), upstream=None, oauth=gate)
    c = TestClient(app)
    client_id = c.post("/oauth/register", json={"redirect_uris": [CLAUDE_CB]}).json()["client_id"]
    r = c.get("/oauth/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": CLAUDE_CB,
                                         "code_challenge": pkce_challenge("v" * 43), "state": "s"}, follow_redirects=False)
    _, state = entra.issue_code(r.headers["location"], "alice@contoso.com")
    r = c.get("/oauth/callback", params={"error": "access_denied", "error_description": "AADSTS50105 not assigned", "state": state},
              follow_redirects=False)
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert r.status_code == 302 and q["error"] == ["access_denied"] and q["state"] == ["s"]
    # A transaction is single use; a stale or forged state gets no redirect.
    assert c.get("/oauth/callback", params={"code": "x", "state": state}, follow_redirects=False).status_code == 400
    # A token whose audience or tenant is wrong never becomes a session.
    r = c.get("/oauth/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": CLAUDE_CB,
                                         "code_challenge": pkce_challenge("v" * 43), "state": "s2"}, follow_redirects=False)
    code, state = entra.issue_code(r.headers["location"], "alice@contoso.com")
    gate.verify = lambda t: (_ for _ in ()).throw(RuntimeError("REF_IDENTITY_WRONG_TENANT"))
    r = c.get("/oauth/callback", params={"code": code, "state": state}, follow_redirects=False)
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert q["error"] == ["server_error"] and "REF_IDENTITY_WRONG_TENANT" in q["error_description"][0]
    assert gate.store.sessions == {}
    # Unregistered response types and missing PKCE go back to the client too.
    r = c.get("/oauth/authorize", params={"response_type": "token", "client_id": client_id, "redirect_uri": CLAUDE_CB, "state": "s3"},
              follow_redirects=False)
    assert parse_qs(urlsplit(r.headers["location"]).query)["error"] == ["unsupported_response_type"]
    r = c.get("/oauth/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": CLAUDE_CB}, follow_redirects=False)
    assert parse_qs(urlsplit(r.headers["location"]).query)["error"] == ["invalid_request"]


def test_gate_from_env_reads_the_deployment(tmp_path):
    ienv = {"GARGOYLE_ENTRA_TENANT": TID, "GARGOYLE_ISSUER_AUDIENCE": "gargoyle-issuer," + APP}
    assert gate_from_env({}, str(tmp_path), issuer_env=ienv) is None
    try:
        gate_from_env({"GARGOYLE_OAUTH_BASE_URL": BASE}, str(tmp_path), issuer_env=ienv)
        assert False
    except RuntimeError as exc:
        assert "CLIENT_ID" in str(exc)
    env = {"GARGOYLE_OAUTH_BASE_URL": BASE + "/", "GARGOYLE_OAUTH_ENTRA_CLIENT_ID": "gate-app",
           "GARGOYLE_OAUTH_ENTRA_CLIENT_SECRET": "s3", "GARGOYLE_OAUTH_ACCESS_TTL": "120"}
    g = gate_from_env(env, str(tmp_path), issuer_env=ienv, verify=verify)
    assert g.base_url == BASE and g.broker.tenant == TID and g.broker.scope == "api://%s/access" % APP
    assert g.broker.redirect_uri == BASE + "/oauth/callback" and g.redirect_allow == list(DEFAULT_REDIRECT_ALLOW)
    assert g.access_ttl == 120 and g.store.path == tmp_path / "oauth-state.json"
    g2 = gate_from_env(dict(env, GARGOYLE_OAUTH_REDIRECT_ALLOW="https://a.example/cb, http://localhost"), str(tmp_path), issuer_env=ienv, verify=verify)
    assert g2.register({"redirect_uris": ["http://localhost:8765/callback"]})[0] == 201
    assert g2.register({"redirect_uris": [CLAUDE_CB]})[0] == 400
