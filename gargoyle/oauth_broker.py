"""OAuth on the remote gate: the hosted connector signs the user in with
Entra ID, and the receipts name them.

A hosted MCP client (claude.ai, Claude Desktop's custom connectors) can
do OAuth 2.1 against the server it connects to: discover the
authorization server from a 401, register itself (RFC 7591), send the
user through the authorization code flow with PKCE (RFC 7636), and put
the resulting bearer on every request. It cannot do that against Entra
directly: Entra has no dynamic registration and the client's callback
is not one the tenant would register. So the gate is the authorization
server the client sees, and Entra is the one the user sees:

    client -> GET  /.well-known/oauth-authorization-server   (where to register and authorize)
    client -> POST /oauth/register                            (a client id; redirect URIs from an allowlist)
    browser-> GET  /oauth/authorize?code_challenge=...        (the gate remembers the client's challenge,
                                                               sends the browser to Entra with its own)
    browser-> Entra sign-in: MFA, Conditional Access, the tenant's rules
    browser-> GET  /oauth/callback?code=...                   (the gate redeems Entra's code for the user's
                                                               access token to the issuer API and a refresh token,
                                                               verifies it, then hands the client a code of its own)
    client -> POST /oauth/token                               (PKCE verified; an opaque gate bearer comes back)
    client -> POST /mcp  Authorization: Bearer <gate token>   (every call runs as that user)

The gate presents the user's own Entra access token to the issuer, the
same token `gargoyle login` would put on a workstation call, refreshed
silently through the refresh token Entra gave at sign-in. The issuer
verifies it against the tenant's keys and the receipt's principal is the
token's UPN. Nothing here vouches for a user-to-URL mapping; the
directory does the naming.

What is stored (oauth-state.json beside the gate's keys, mode 600):
registered clients; sessions keyed by the SHA-256 of the gate's bearer,
each with the principal, the Entra access token and its expiry, the Entra
refresh token, and the SHA-256 of the gate refresh token. Authorization
transactions and codes are in memory and short-lived. A session whose
Entra refresh is rejected (the account disabled, the role removed, a
Conditional Access change) is deleted and the client is told 401, which
sends the user back through sign-in.
"""

import base64
import hashlib
import json
import os
import secrets
import stat
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit

ENTRA_AUTHORIZE = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
ENTRA_TOKEN = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

DEFAULT_REDIRECT_ALLOW = ("https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback")
CODE_TTL_SECONDS = 120
TXN_TTL_SECONDS = 600
REFRESH_AHEAD_SECONDS = 120


def _now() -> int:
    return int(time.time())


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def pkce_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


class OAuthStore:
    """Registered clients and live sessions, in one JSON file the gate owns."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self.clients: Dict[str, Dict[str, Any]] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}      # sha256(access token) -> session
        self.refresh_index: Dict[str, str] = {}             # sha256(refresh token) -> sha256(access token)
        if self.path is not None and self.path.exists():
            d = json.loads(self.path.read_text(encoding="utf-8"))
            self.clients = d.get("clients", {})
            self.sessions = d.get("sessions", {})
            self.refresh_index = d.get("refresh_index", {})

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps({"clients": self.clients, "sessions": self.sessions, "refresh_index": self.refresh_index},
                                  indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        os.replace(tmp, self.path)

    def register_client(self, redirect_uris: List[str], name: Optional[str]) -> Dict[str, Any]:
        cid = secrets.token_urlsafe(24)
        rec = {"client_id": cid, "redirect_uris": list(redirect_uris), "client_name": name or "", "created": _now()}
        with self._lock:
            self.clients[cid] = rec
            self.save()
        return dict(rec)

    def new_session(self, principal: str, entra: Dict[str, Any], client_id: str, ttl: int) -> Dict[str, str]:
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        rec = {"principal": principal, "client_id": client_id, "entra": entra, "issued": _now(),
               "expires": _now() + ttl, "refresh_sha256": _sha256(refresh)}
        with self._lock:
            self.sessions[_sha256(access)] = rec
            self.refresh_index[_sha256(refresh)] = _sha256(access)
            self.save()
        return {"access_token": access, "refresh_token": refresh, "expires_in": ttl}

    def lookup(self, access_token: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        key = _sha256(access_token)
        rec = self.sessions.get(key)
        if rec is None or rec["expires"] <= _now():
            return None
        return key, rec

    def rotate(self, refresh_token: str, ttl: int) -> Optional[Tuple[str, Dict[str, str]]]:
        """Trade a refresh token for a new access/refresh pair; the old pair dies."""
        with self._lock:
            old_key = self.refresh_index.pop(_sha256(refresh_token), None)
            rec = self.sessions.pop(old_key, None) if old_key else None
            if rec is None:
                self.save()
                return None
            access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            rec = dict(rec, issued=_now(), expires=_now() + ttl, refresh_sha256=_sha256(refresh))
            self.sessions[_sha256(access)] = rec
            self.refresh_index[_sha256(refresh)] = _sha256(access)
            self.save()
        return rec["principal"], {"access_token": access, "refresh_token": refresh, "expires_in": ttl}

    def update_entra(self, key: str, entra: Dict[str, Any]) -> None:
        with self._lock:
            if key in self.sessions:
                self.sessions[key]["entra"] = entra
                self.save()

    def drop(self, key: str) -> None:
        with self._lock:
            rec = self.sessions.pop(key, None)
            if rec is not None:
                self.refresh_index.pop(rec.get("refresh_sha256", ""), None)
            self.save()


class EntraBroker:
    """The gate's own client registration in the tenant: a confidential web
    client whose redirect is the gate's /oauth/callback. `http` is anything
    with a requests-style post()."""

    def __init__(self, tenant: str, client_id: str, client_secret: Optional[str], scope: str, redirect_uri: str,
                 *, http: Any = None, timeout: float = 15.0) -> None:
        self.tenant, self.client_id, self.client_secret = tenant, client_id, client_secret
        self.scope, self.redirect_uri, self._timeout = scope, redirect_uri, timeout
        self._http = http

    def _post(self, data: Dict[str, str]) -> Dict[str, Any]:
        http = self._http
        if http is None:
            import requests
            http = requests
        r = http.post(ENTRA_TOKEN.format(tenant=self.tenant), data=data, timeout=self._timeout)
        body = r.json() if r.content else {}
        if r.status_code != 200 or "access_token" not in body:
            raise RuntimeError("entra token endpoint: %s %s" % (r.status_code, body.get("error", "")))
        return body

    def authorize_url(self, state: str, code_challenge: str, login_hint: Optional[str] = None) -> str:
        q = {"client_id": self.client_id, "response_type": "code", "redirect_uri": self.redirect_uri,
             "scope": "openid profile offline_access " + self.scope, "state": state,
             "code_challenge": code_challenge, "code_challenge_method": "S256", "response_mode": "query"}
        if login_hint:
            q["login_hint"] = login_hint
        return ENTRA_AUTHORIZE.format(tenant=self.tenant) + "?" + urlencode(q)

    def _tokens(self, body: Dict[str, Any], previous_refresh: Optional[str]) -> Dict[str, Any]:
        return {"access_token": body["access_token"], "expires": _now() + int(body.get("expires_in", 3600)),
                "refresh_token": body.get("refresh_token") or previous_refresh}

    def exchange(self, code: str, verifier: str) -> Dict[str, Any]:
        data = {"client_id": self.client_id, "grant_type": "authorization_code", "code": code,
                "redirect_uri": self.redirect_uri, "code_verifier": verifier, "scope": self.scope}
        if self.client_secret:
            data["client_secret"] = self.client_secret
        return self._tokens(self._post(data), None)

    def refresh(self, refresh_token: str) -> Dict[str, Any]:
        data = {"client_id": self.client_id, "grant_type": "refresh_token", "refresh_token": refresh_token, "scope": self.scope}
        if self.client_secret:
            data["client_secret"] = self.client_secret
        return self._tokens(self._post(data), refresh_token)


class SessionTokenSource:
    """What the gate presents to the issuer for one session: the user's
    Entra access token, refreshed ahead of expiry. IssuerClient calls
    token(). A failed refresh raises; the gate turns that into a 401."""

    def __init__(self, store: OAuthStore, key: str, broker: EntraBroker) -> None:
        self._store, self._key, self._broker = store, key, broker

    def token(self) -> str:
        rec = self._store.sessions.get(self._key)
        if rec is None:
            raise RuntimeError("session gone")
        entra = rec["entra"]
        if entra["expires"] - _now() < REFRESH_AHEAD_SECONDS:
            if not entra.get("refresh_token"):
                raise RuntimeError("no refresh token")
            entra = self._broker.refresh(entra["refresh_token"])
            self._store.update_entra(self._key, entra)
        return entra["access_token"]


class OAuthGate:
    """Installs the authorization-server and resource-metadata routes on
    the remote app and authenticates bearers for /mcp.

    `verify(access_token) -> principal` checks the Entra access token the
    way the issuer will (gargoyle.identity.principal_from_token against the
    tenant's keys) and returns the UPN, or raises. The gate does this once
    at sign-in so the session is labeled with a verified name; the issuer
    repeats it on every call."""

    def __init__(self, store: OAuthStore, broker: EntraBroker, base_url: str, verify: Callable[[str], str], *,
                 redirect_allow: Optional[List[str]] = None, access_ttl: int = 3600) -> None:
        self.store, self.broker, self.verify = store, broker, verify
        self.base_url = base_url.rstrip("/")
        self.redirect_allow = list(redirect_allow or DEFAULT_REDIRECT_ALLOW)
        self.access_ttl = access_ttl
        self._txns: Dict[str, Dict[str, Any]] = {}     # gate state -> the client's request + the gate's verifier
        self._codes: Dict[str, Dict[str, Any]] = {}    # gate code -> what the client may redeem
        self._lock = threading.Lock()

    # metadata

    @property
    def resource(self) -> str:
        return self.base_url + "/mcp"

    @property
    def resource_metadata_url(self) -> str:
        return self.base_url + "/.well-known/oauth-protected-resource"

    def protected_resource_metadata(self) -> Dict[str, Any]:
        return {"resource": self.resource, "authorization_servers": [self.base_url],
                "bearer_methods_supported": ["header"], "scopes_supported": ["mcp"]}

    def authorization_server_metadata(self) -> Dict[str, Any]:
        b = self.base_url
        return {"issuer": b, "authorization_endpoint": b + "/oauth/authorize", "token_endpoint": b + "/oauth/token",
                "registration_endpoint": b + "/oauth/register", "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": ["mcp"], "revocation_endpoint_auth_methods_supported": ["none"]}

    def www_authenticate(self) -> str:
        return 'Bearer resource_metadata="%s"' % self.resource_metadata_url

    # the flow

    def _redirect_allowed(self, uri: str) -> bool:
        if uri in self.redirect_allow:
            return True
        u = urlsplit(uri)
        return u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost") and "http://localhost" in self.redirect_allow

    def register(self, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        uris = body.get("redirect_uris")
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
            return 400, {"error": "invalid_client_metadata", "error_description": "redirect_uris required"}
        bad = [u for u in uris if not self._redirect_allowed(u)]
        if bad:
            return 400, {"error": "invalid_redirect_uri", "error_description": "not an allowed redirect: " + ", ".join(bad)}
        rec = self.store.register_client(uris, body.get("client_name") if isinstance(body.get("client_name"), str) else None)
        return 201, {"client_id": rec["client_id"], "redirect_uris": rec["redirect_uris"], "client_name": rec["client_name"],
                     "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"],
                     "response_types": ["code"], "client_id_issued_at": rec["created"]}

    def _expire(self) -> None:
        t = _now()
        for d, ttl in ((self._txns, TXN_TTL_SECONDS), (self._codes, CODE_TTL_SECONDS)):
            for k in [k for k, v in d.items() if v["at"] + ttl < t]:
                d.pop(k, None)

    def authorize(self, q: Dict[str, str]) -> Tuple[str, Optional[str]]:
        """Returns (kind, value): ("redirect", url) to Entra or back to the
        client with an error, or ("error", text) for a 400."""
        client = self.store.clients.get(q.get("client_id", ""))
        redirect = q.get("redirect_uri", "")
        if client is None:
            return "error", "unknown client_id"
        if redirect not in client["redirect_uris"]:
            return "error", "redirect_uri not registered for this client"

        def back(err: str) -> Tuple[str, str]:
            p = {"error": err}
            if q.get("state"):
                p["state"] = q["state"]
            return "redirect", redirect + ("&" if "?" in redirect else "?") + urlencode(p)
        if q.get("response_type") != "code":
            return back("unsupported_response_type")
        if q.get("code_challenge_method", "S256") != "S256" or not q.get("code_challenge"):
            return back("invalid_request")
        verifier = secrets.token_urlsafe(48)
        state = secrets.token_urlsafe(24)
        with self._lock:
            self._expire()
            self._txns[state] = {"at": _now(), "client_id": client["client_id"], "redirect_uri": redirect,
                                 "code_challenge": q["code_challenge"], "client_state": q.get("state"), "verifier": verifier}
        return "redirect", self.broker.authorize_url(state, pkce_challenge(verifier), q.get("login_hint"))

    def callback(self, q: Dict[str, str]) -> Tuple[str, str]:
        with self._lock:
            self._expire()
            txn = self._txns.pop(q.get("state", ""), None)
        if txn is None:
            return "error", "unknown or expired sign-in transaction"
        redirect = txn["redirect_uri"]

        def back(err: str, desc: str = "") -> Tuple[str, str]:
            p = {"error": err}
            if desc:
                p["error_description"] = desc
            if txn.get("client_state"):
                p["state"] = txn["client_state"]
            return "redirect", redirect + ("&" if "?" in redirect else "?") + urlencode(p)
        if q.get("error") or not q.get("code"):
            return back("access_denied", q.get("error_description", q.get("error", "no code")))
        try:
            entra = self.broker.exchange(q["code"], txn["verifier"])
            principal = self.verify(entra["access_token"])
        except Exception as exc:
            return back("server_error", "sign-in could not be completed: %s" % exc)
        code = secrets.token_urlsafe(32)
        with self._lock:
            self._codes[code] = {"at": _now(), "client_id": txn["client_id"], "redirect_uri": redirect,
                                 "code_challenge": txn["code_challenge"], "principal": principal, "entra": entra}
        p = {"code": code}
        if txn.get("client_state"):
            p["state"] = txn["client_state"]
        return "redirect", redirect + ("&" if "?" in redirect else "?") + urlencode(p)

    def token(self, form: Dict[str, str]) -> Tuple[int, Dict[str, Any]]:
        grant = form.get("grant_type")
        if grant == "authorization_code":
            with self._lock:
                self._expire()
                rec = self._codes.pop(form.get("code", ""), None)
            if rec is None:
                return 400, {"error": "invalid_grant", "error_description": "unknown, used or expired code"}
            if form.get("client_id") != rec["client_id"] or form.get("redirect_uri", rec["redirect_uri"]) != rec["redirect_uri"]:
                return 400, {"error": "invalid_grant", "error_description": "client or redirect_uri does not match"}
            v = form.get("code_verifier", "")
            if not v or pkce_challenge(v) != rec["code_challenge"]:
                return 400, {"error": "invalid_grant", "error_description": "PKCE verification failed"}
            out = self.store.new_session(rec["principal"], rec["entra"], rec["client_id"], self.access_ttl)
            return 200, dict(out, token_type="Bearer", scope="mcp")
        if grant == "refresh_token":
            got = self.store.rotate(form.get("refresh_token", ""), self.access_ttl)
            if got is None:
                return 400, {"error": "invalid_grant", "error_description": "unknown or rotated refresh token"}
            return 200, dict(got[1], token_type="Bearer", scope="mcp")
        return 400, {"error": "unsupported_grant_type"}

    # the bearer on /mcp

    def authenticate(self, authorization: Optional[str]) -> Optional[Tuple[str, str, SessionTokenSource]]:
        """(session key, principal, token source) for a live bearer, else None.
        A session whose Entra refresh fails is dropped here, so the client
        gets a 401 and sends the user back through sign-in."""
        if not authorization or not authorization.lower().startswith("bearer "):
            return None
        found = self.store.lookup(authorization[7:].strip())
        if found is None:
            return None
        key, rec = found
        src = SessionTokenSource(self.store, key, self.broker)
        try:
            src.token()
        except Exception:
            self.store.drop(key)
            return None
        return key, rec["principal"], src

    def install(self, app: Any) -> None:
        from fastapi import Request, Response
        from fastapi.responses import JSONResponse, RedirectResponse

        def doc(d: Dict[str, Any]) -> Any:
            return JSONResponse(d, headers={"Cache-Control": "no-store"})

        for path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
            app.get(path)(lambda: doc(self.protected_resource_metadata()))
        for path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
            app.get(path)(lambda: doc(self.authorization_server_metadata()))

        @app.post("/oauth/register")
        async def register(request: Request):
            try:
                body = await request.json()
            except Exception:
                return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)
            status, out = self.register(body if isinstance(body, dict) else {})
            return JSONResponse(out, status_code=status)

        @app.get("/oauth/authorize")
        async def authorize(request: Request):
            kind, value = self.authorize(dict(request.query_params))
            if kind == "redirect":
                return RedirectResponse(value, status_code=302, headers={"Cache-Control": "no-store"})
            return Response(status_code=400, content=value or "bad request")

        @app.get("/oauth/callback")
        async def callback(request: Request):
            kind, value = self.callback(dict(request.query_params))
            if kind == "redirect":
                return RedirectResponse(value, status_code=302, headers={"Cache-Control": "no-store"})
            return Response(status_code=400, content=value)

        @app.post("/oauth/token")
        async def token(request: Request):
            # application/x-www-form-urlencoded, parsed here so no form library is needed; JSON is accepted too.
            raw = await request.body()
            if request.headers.get("content-type", "").split(";")[0].strip() == "application/json":
                try:
                    body = json.loads(raw or b"{}")
                except ValueError:
                    body = {}
                form = {k: v for k, v in body.items() if isinstance(v, str)} if isinstance(body, dict) else {}
            else:
                form = dict(parse_qsl(raw.decode("utf-8", "replace"), keep_blank_values=True))
            status, out = self.token(form)
            return JSONResponse(out, status_code=status, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


def verifier_for_tenant(tenant: str, audience: Any, *, http: Any = None) -> Callable[[str], str]:
    """A verify() for OAuthGate: the Entra access token must be the tenant's,
    for this audience, and name a user. Keys are fetched from the directory
    and refetched once on an unknown kid."""
    from gargoyle.identity import entra_keys, entra_tenant_id, principal_from_token
    tid = entra_tenant_id(tenant, http=http)
    keys: Dict[str, Any] = {}
    lock = threading.Lock()

    def check(token: str) -> str:
        with lock:
            if not keys:
                keys.update(entra_keys(tid, http=http))
            who = principal_from_token(token, keys, audience=audience, tenant=tid, tenant_key_ids=set(keys))
            if who.get("reason") == "REF_JWS_KEY_UNKNOWN":
                keys.update(entra_keys(tid, http=http))
                who = principal_from_token(token, keys, audience=audience, tenant=tid, tenant_key_ids=set(keys))
        if not who.get("principal"):
            raise RuntimeError(who.get("reason") or "no principal")
        return who["principal"]
    return check


def gate_from_env(environ: Dict[str, str], out_dir: str, *, issuer_env: Optional[Dict[str, str]] = None,
                  http: Any = None, verify: Optional[Callable[[str], str]] = None) -> Optional[OAuthGate]:
    """An OAuthGate when GARGOYLE_OAUTH_BASE_URL is set, else None.

        GARGOYLE_OAUTH_BASE_URL              the gate's public base, e.g. https://gate.example/graph
        GARGOYLE_OAUTH_ENTRA_CLIENT_ID       the gate's own registration (Web platform, redirect <base>/oauth/callback)
        GARGOYLE_OAUTH_ENTRA_CLIENT_SECRET   its client secret (confidential client)
        GARGOYLE_OAUTH_ENTRA_TENANT          default: the issuer's GARGOYLE_ENTRA_TENANT
        GARGOYLE_OAUTH_ENTRA_SCOPE           default: api://<issuer app id>/access from GARGOYLE_ISSUER_AUDIENCE
        GARGOYLE_OAUTH_REDIRECT_ALLOW        comma-separated client callbacks (default: Claude's)
        GARGOYLE_OAUTH_ACCESS_TTL            gate bearer lifetime in seconds (default 3600)
    """
    base = environ.get("GARGOYLE_OAUTH_BASE_URL")
    if not base:
        return None
    ienv = issuer_env or {}
    tenant = environ.get("GARGOYLE_OAUTH_ENTRA_TENANT") or ienv.get("GARGOYLE_ENTRA_TENANT")
    client_id = environ.get("GARGOYLE_OAUTH_ENTRA_CLIENT_ID")
    if not tenant or not client_id:
        raise RuntimeError("GARGOYLE_OAUTH_BASE_URL needs GARGOYLE_OAUTH_ENTRA_CLIENT_ID and a tenant "
                           "(GARGOYLE_OAUTH_ENTRA_TENANT or the issuer's GARGOYLE_ENTRA_TENANT)")
    audiences = [a.strip() for a in (ienv.get("GARGOYLE_ISSUER_AUDIENCE") or "").split(",") if a.strip()]
    app_aud = audiences[-1] if audiences else None
    scope = environ.get("GARGOYLE_OAUTH_ENTRA_SCOPE") or ("api://%s/access" % app_aud if app_aud else None)
    if not scope:
        raise RuntimeError("GARGOYLE_OAUTH_ENTRA_SCOPE is needed when the issuer's audience does not name the app")
    broker = EntraBroker(tenant, client_id, environ.get("GARGOYLE_OAUTH_ENTRA_CLIENT_SECRET"), scope,
                         base.rstrip("/") + "/oauth/callback", http=http)
    allow = [u.strip() for u in environ.get("GARGOYLE_OAUTH_REDIRECT_ALLOW", "").split(",") if u.strip()] or None
    store = OAuthStore(str(Path(out_dir) / "oauth-state.json"))
    check = verify or verifier_for_tenant(tenant, audiences or None, http=http)
    return OAuthGate(store, broker, base, check, redirect_allow=allow,
                     access_ttl=int(environ.get("GARGOYLE_OAUTH_ACCESS_TTL", "3600")))
