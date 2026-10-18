"""Entra ID login for the client: the middleware's token names a person.

`gargoyle init` mints one shared client token. For a team, each workstation
should present its own user's identity, so that every receipt's principal
and every audit row names who asked. `gargoyle login` runs the Entra ID
device-code flow once (the user signs in from a browser on any device,
with the tenant's MFA), and stores MSAL's token cache in a private file.
The middleware then obtains a current access token from that cache before
each call to the issuer; MSAL refreshes it silently with the refresh token
until the tenant's policy says to sign in again.

Entra app registration (once per tenant):
  - an API app for the issuer, exposing one scope (for example
    api://<api-client-id>/access); the issuer's GARGOYLE_ISSUER_AUDIENCE is
    that app's client id (v2 tokens) or its app id URI (v1 tokens);
  - a public client app for `gargoyle login` with "Allow public client
    flows" on, granted that scope.

The issuer verifies the token against the tenant's published keys
(GARGOYLE_ENTRA_TENANT) and takes preferred_username, the UPN, as the
principal; groups and app roles in the token are inputs to the rules.

MSAL is an optional dependency: pip install "gargoyle-receipts[entra]".
"""

import json
import os
import stat
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

ENV_ENTRA_TENANT = "GARGOYLE_MCP_ENTRA_TENANT"
ENV_ENTRA_CLIENT_ID = "GARGOYLE_MCP_ENTRA_CLIENT_ID"
ENV_ENTRA_SCOPE = "GARGOYLE_MCP_ENTRA_SCOPE"
ENV_ENTRA_TOKEN_CACHE = "GARGOYLE_MCP_ENTRA_TOKEN_CACHE"

AUTHORITY = "https://login.microsoftonline.com/{tenant}"


class LoginRequired(Exception):
    """No usable account in the cache: run `gargoyle login`."""


def _msal():
    try:
        import msal
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError('Entra login needs msal: pip install "gargoyle-receipts[entra]"') from exc
    return msal


class TokenCache:
    """MSAL's serializable cache, persisted to a private file."""

    def __init__(self, path: str, msal_module: Any = None) -> None:
        self.path = Path(path)
        self._msal = msal_module or _msal()
        self.cache = self._msal.SerializableTokenCache()
        if self.path.exists():
            self.cache.deserialize(self.path.read_text(encoding="utf-8"))

    def save(self) -> None:
        if self.cache.has_state_changed:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(self.cache.serialize(), encoding="utf-8")
            try:
                os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass


def public_roots_http():
    """A requests session that trusts the public CA roots (certifi) whatever
    REQUESTS_CA_BUNDLE says. A deployment pins the issuer's private CA with
    that variable; Entra's endpoints are not signed by it, so the two trust
    domains must not share one setting. Proxies from the environment still
    apply."""
    import certifi
    import requests
    s = requests.Session()
    s.verify = certifi.where()
    return s


def _app(tenant: str, client_id: str, cache: TokenCache, app_factory: Optional[Callable] = None) -> Any:
    if app_factory is not None:
        return app_factory(client_id=client_id, authority=AUTHORITY.format(tenant=tenant), token_cache=cache.cache)
    return _msal().PublicClientApplication(client_id, authority=AUTHORITY.format(tenant=tenant), token_cache=cache.cache,
                                           http_client=public_roots_http())


def device_code_login(tenant: str, client_id: str, scope: str, cache_path: str, *,
                      app_factory: Optional[Callable] = None, msal_module: Any = None,
                      prompt: Callable[[str], None] = print) -> Dict[str, Any]:
    """Sign a user in by device code and store the cache. Returns
    {"principal": <UPN>, "expires_in": seconds, "cache_path": str}.
    Raises RuntimeError with Entra's error text when the sign-in fails."""
    cache = TokenCache(cache_path, msal_module)
    app = _app(tenant, client_id, cache, app_factory)
    flow = app.initiate_device_flow(scopes=[scope])
    if "user_code" not in flow:
        raise RuntimeError("device flow could not start: %s" % flow.get("error_description", flow))
    prompt(flow["message"])
    result = app.acquire_token_by_device_flow(flow)
    cache.save()
    if "access_token" not in result:
        raise RuntimeError("sign-in failed: %s" % result.get("error_description", result.get("error", result)))
    claims = result.get("id_token_claims") or {}
    principal = claims.get("preferred_username") or claims.get("upn") or claims.get("oid")
    if not principal:
        raise RuntimeError("the token names no user (no preferred_username, upn or oid)")
    return {"principal": principal, "expires_in": result.get("expires_in"), "cache_path": str(cache.path)}


class EntraTokenSource:
    """What the middleware calls for a bearer token: the cached account's
    current access token, refreshed silently by MSAL when needed."""

    def __init__(self, tenant: str, client_id: str, scope: str, cache_path: str, *,
                 app_factory: Optional[Callable] = None, msal_module: Any = None) -> None:
        self.scope = scope
        self._args = (tenant, client_id, cache_path, app_factory, msal_module)
        self._cache: Optional[TokenCache] = None
        self._app_obj: Any = None

    @property
    def _app(self) -> Any:
        # Built on first use: MSAL fetches the tenant's OpenID configuration
        # when the application object is created, and that must not happen
        # while the MCP client is starting the middleware, nor kill it if
        # the network is down. A failure here surfaces as LoginRequired on
        # the call, which the middleware turns into a refusal.
        if self._app_obj is None:
            tenant, client_id, cache_path, app_factory, msal_module = self._args
            self._cache = TokenCache(cache_path, msal_module)
            try:
                self._app_obj = _app(tenant, client_id, self._cache, app_factory)
            except Exception as exc:
                raise LoginRequired("Entra could not be reached to validate the sign-in: %s: %s"
                                    % (type(exc).__name__, str(exc)[:200])) from exc
        return self._app_obj

    def token(self) -> str:
        accounts: List[Dict[str, Any]] = self._app.get_accounts()
        if not accounts:
            raise LoginRequired("no Entra account in %s; run: gargoyle login" % self._cache.path)
        result = self._app.acquire_token_silent([self.scope], account=accounts[0]) or {}
        self._cache.save()
        if "access_token" not in result:
            raise LoginRequired("Entra token could not be refreshed (%s); run: gargoyle login"
                                % result.get("error_description", result.get("error", "no token")))
        return result["access_token"]

    @property
    def principal(self) -> Optional[str]:
        try:
            accounts = self._app.get_accounts()
        except LoginRequired:
            return None
        return accounts[0].get("username") if accounts else None


def token_source_from_env(environ: Dict[str, str]) -> Optional[EntraTokenSource]:
    """An EntraTokenSource when the four GARGOYLE_MCP_ENTRA_* variables are
    set, None when none is; a partial set raises."""
    keys = (ENV_ENTRA_TENANT, ENV_ENTRA_CLIENT_ID, ENV_ENTRA_SCOPE, ENV_ENTRA_TOKEN_CACHE)
    values = [environ.get(k) for k in keys]
    if not any(values):
        return None
    if not all(values):
        raise RuntimeError("set all of %s together" % ", ".join(keys))
    return EntraTokenSource(*values)
