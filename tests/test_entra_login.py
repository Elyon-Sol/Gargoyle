"""`gargoyle login`: the middleware's token names a person. MSAL is faked:
a device flow that signs in alice, a cache that persists, a silent refresh
that works until the account is gone."""

import json
import os
from pathlib import Path

import pytest

from gargoyle.entra_login import EntraTokenSource, LoginRequired, device_code_login, token_source_from_env


class FakeCache:
    def __init__(self): self.state = "{}"; self.has_state_changed = False
    def deserialize(self, text): self.state = text
    def serialize(self): return self.state


class FakeMsal:
    SerializableTokenCache = FakeCache


class FakeApp:
    """Enough of msal.PublicClientApplication for the two flows."""
    sign_in_user = "alice@contoso.com"
    refresh_ok = True

    def __init__(self, client_id, authority, token_cache):
        self.client_id, self.authority, self.cache = client_id, authority, token_cache
        self.calls = []

    def initiate_device_flow(self, scopes):
        self.calls.append(("device_flow", scopes))
        return {"user_code": "ABCD-1234", "message": "To sign in, use a web browser to open https://microsoft.com/devicelogin and enter the code ABCD-1234"}

    def acquire_token_by_device_flow(self, flow):
        self.cache.state = json.dumps({"accounts": [self.sign_in_user]}); self.cache.has_state_changed = True
        return {"access_token": "at-1", "expires_in": 3600, "id_token_claims": {"preferred_username": self.sign_in_user}}

    def get_accounts(self):
        return [{"username": u} for u in json.loads(self.cache.state).get("accounts", [])]

    def acquire_token_silent(self, scopes, account):
        self.calls.append(("silent", scopes, account["username"]))
        return {"access_token": "at-refreshed"} if self.refresh_ok else {"error": "interaction_required", "error_description": "MFA"}


def test_device_code_login_persists_the_cache_and_names_the_user(tmp_path, capsys):
    cache = tmp_path / "cache.json"
    shown = []
    r = device_code_login("contoso.onmicrosoft.com", "client-1", "api://issuer/access", str(cache),
                          app_factory=FakeApp, msal_module=FakeMsal, prompt=shown.append)
    assert r["principal"] == "alice@contoso.com" and r["expires_in"] == 3600
    assert "ABCD-1234" in shown[0]
    assert json.loads(cache.read_text())["accounts"] == ["alice@contoso.com"]
    if os.name == "posix":
        assert oct(cache.stat().st_mode & 0o777) == "0o600"

    # The source refreshes silently from that cache, and knows who it is.
    src = EntraTokenSource("contoso.onmicrosoft.com", "client-1", "api://issuer/access", str(cache),
                           app_factory=FakeApp, msal_module=FakeMsal)
    assert src.principal == "alice@contoso.com" and src.token() == "at-refreshed"
    assert src._app.calls[-1] == ("silent", ["api://issuer/access"], "alice@contoso.com")


def test_no_account_or_failed_refresh_is_login_required(tmp_path):
    src = EntraTokenSource("t", "c", "s", str(tmp_path / "empty.json"), app_factory=FakeApp, msal_module=FakeMsal)
    with pytest.raises(LoginRequired):
        src.token()
    cache = tmp_path / "cache.json"
    device_code_login("t", "c", "s", str(cache), app_factory=FakeApp, msal_module=FakeMsal, prompt=lambda m: None)

    class Stale(FakeApp):
        refresh_ok = False
    with pytest.raises(LoginRequired, match="MFA"):
        EntraTokenSource("t", "c", "s", str(cache), app_factory=Stale, msal_module=FakeMsal).token()


def test_middleware_refuses_with_login_required_and_uses_a_fresh_token_per_call(tmp_path):
    from gargoyle.mcp_server import REF_TARGET_LOGIN_REQUIRED, IssuerClient
    cache = tmp_path / "cache.json"
    device_code_login("t", "c", "s", str(cache), app_factory=FakeApp, msal_module=FakeMsal, prompt=lambda m: None)
    seen = []

    class Http:
        def post(self, url, json=None, headers=None, timeout=None):
            seen.append(headers["Authorization"])
            return type("R", (), {"status_code": 200, "headers": {}, "json": lambda self: {"issued": True, "envelope": {"x": 1}}})()
    src = EntraTokenSource("t", "c", "s", str(cache), app_factory=FakeApp, msal_module=FakeMsal)
    client = IssuerClient("http://i", src, http=Http())
    assert client.issue("mcp://x", "read_file", {})["envelope"] == {"x": 1}
    assert seen == ["Bearer at-refreshed"]
    empty = EntraTokenSource("t", "c", "s", str(tmp_path / "none.json"), app_factory=FakeApp, msal_module=FakeMsal)
    assert IssuerClient("http://i", empty, http=Http()).issue("mcp://x", "read_file", {})["reason"] == REF_TARGET_LOGIN_REQUIRED


def test_token_source_from_env_requires_the_whole_set():
    assert token_source_from_env({}) is None
    with pytest.raises(RuntimeError):
        token_source_from_env({"GARGOYLE_MCP_ENTRA_TENANT": "t"})


def test_login_command_rewrites_the_client_config(tmp_path, monkeypatch, capsys):
    from gargoyle import cli
    from gargoyle import entra_login
    out = tmp_path / "deploy"
    assert cli.main(["init", str(tmp_path / "p"), "--out", str(out), "--entra-tenant", "contoso.onmicrosoft.com",
                     "--entra-audience", "api-client-id"]) == 0
    ienv = cli._read_env(out / "issuer.env")
    assert ienv["GARGOYLE_ENTRA_TENANT"] == "contoso.onmicrosoft.com" and ienv["GARGOYLE_ISSUER_AUDIENCE"] == "api-client-id"
    before = cli._read_env(out / "middleware.env"); assert "GARGOYLE_MCP_CLIENT_TOKEN" in before
    monkeypatch.setattr(entra_login, "_msal", lambda: FakeMsal)
    monkeypatch.setattr(entra_login, "_app", lambda tenant, client_id, cache, app_factory=None: FakeApp(client_id, tenant, cache.cache))
    assert cli.main(["login", "--tenant", "contoso.onmicrosoft.com", "--client-id", "pub-client", "--scope", "api://api-client-id/access",
                     "--out", str(out)]) == 0
    env = cli._read_env(out / "middleware.env")
    assert "GARGOYLE_MCP_CLIENT_TOKEN" not in env
    assert env["GARGOYLE_MCP_PRINCIPAL"] == "alice@contoso.com" and env["GARGOYLE_MCP_ENTRA_CLIENT_ID"] == "pub-client"
    assert env["GARGOYLE_MCP_ENTRA_TOKEN_CACHE"] == str(out / "entra-token-cache.json")
    mcp = json.loads((out / "mcp-config.json").read_text())["mcpServers"]["filesystem-gargoyle"]["env"]
    assert "GARGOYLE_MCP_CLIENT_TOKEN" not in mcp and mcp["GARGOYLE_MCP_PRINCIPAL"] == "alice@contoso.com"
    assert "signed in as alice@contoso.com" in capsys.readouterr().out
    # Everything the middleware needs to pick the Entra source is there.
    for k in ("GARGOYLE_MCP_ENTRA_TENANT", "GARGOYLE_MCP_ENTRA_CLIENT_ID", "GARGOYLE_MCP_ENTRA_SCOPE", "GARGOYLE_MCP_ENTRA_TOKEN_CACHE"):
        assert env[k] and mcp[k] == env[k]


def test_msal_gets_a_public_roots_http_client_and_is_built_lazily(tmp_path, monkeypatch):
    """REQUESTS_CA_BUNDLE pins the issuer's private CA for the middleware; MSAL
    must still trust the public roots. And nothing touches the network until
    the first token is asked for."""
    from gargoyle import entra_login
    import certifi
    built = []

    class CapturingMsal(FakeMsal):
        class PublicClientApplication:
            def __init__(self, client_id, authority, token_cache, http_client=None):
                built.append(http_client)
                self.inner = FakeApp(client_id, authority, token_cache)
            def get_accounts(self): return self.inner.get_accounts()
            def acquire_token_silent(self, scopes, account): return self.inner.acquire_token_silent(scopes, account)
    monkeypatch.setattr(entra_login, "_msal", lambda: CapturingMsal)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "private-ca.crt"))
    cache = tmp_path / "cache.json"
    device_code_login("t", "c", "s", str(cache), app_factory=FakeApp, msal_module=FakeMsal, prompt=lambda m: None)
    src = EntraTokenSource("t", "c", "s", str(cache), msal_module=CapturingMsal)
    assert built == []                                   # constructed nothing yet
    assert src.token() == "at-refreshed"
    assert len(built) == 1 and built[0].verify == certifi.where()   # public roots, not the private CA

    # A tenant that cannot be reached is a refusal at call time, not a crash at startup.
    class Unreachable(FakeMsal):
        class PublicClientApplication:
            def __init__(self, *a, **k): raise OSError("name resolution failed")
    monkeypatch.setattr(entra_login, "_msal", lambda: Unreachable)
    off = EntraTokenSource("t", "c", "s", str(cache), msal_module=Unreachable)
    with pytest.raises(LoginRequired, match="could not be reached"):
        off.token()
    assert off.principal is None
