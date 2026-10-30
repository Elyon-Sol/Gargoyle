"""Remote middleware mode: the gate as a Streamable HTTP MCP server.

The stdio middleware sits on the workstation and fronts a local server.
Claude's hosted connectors (claude.ai in the browser, Claude Desktop's
custom connectors) reach an MCP server over HTTPS from Anthropic's side,
and Microsoft 365 servers are reached the same way. This module runs the
same gate behind an HTTP endpoint so those paths go through it too:

    POST /mcp/{token}      JSON-RPC in, JSON-RPC out (MCP Streamable HTTP)
    DELETE /mcp/{token}    end the session named by Mcp-Session-Id

Two ways a session gets its person:

    POST /mcp              Authorization: Bearer <gate token> from the OAuth
                           sign-in (gargoyle.oauth_broker): the user signed in
                           with Entra in their browser, and the gate presents
                           their own directory token to the issuer. The
                           receipt's principal is the token's UPN. A request
                           with no usable bearer is answered 401 with the
                           resource metadata URL, which is how the client
                           finds the sign-in.

`token` in the first form is a capability URL segment that names the
workstation user: the operator mints one per person (`gargoyle
remote-token`), mapping it to the principal the receipts will name and to
the identity token the gate presents to the issuer for that person. In
this mode the gate's operator vouches for the user-to-URL mapping, as an
API key does. Treat the URL as a credential; prefer OAuth where the
tenant is Entra. Device-bound identity remains the stdio mode's property.

The upstream is one shared server: a stdio process started once, or a
remote MCP server reached over Streamable HTTP (HttpUpstream), with an
optional static bearer. The gate initializes the upstream once and answers
each session's `initialize` itself; every session shares one replay cache,
one evidence log and one snapshot store, so single use holds across
sessions. Everything else is gargoyle.mcp_server unchanged.
"""

import json
import secrets
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from gargoyle.mcp_server import (EXECUTED_META_KEY, PROTOCOL_VERSION, REASON_META_KEY, SERVER_INFO, IssuerClient,
                                 ServerState, StdioUpstream, handle_message)
from gargoyle.replay_cache import InMemoryReplayCache

ENV_REMOTE_TOKENS = "GARGOYLE_REMOTE_TOKENS"        # remote-tokens.json: {token: {"principal", "issuer_token"}}
ENV_UPSTREAM_URL = "GARGOYLE_MCP_UPSTREAM_URL"       # front a remote MCP server instead of a stdio command
ENV_UPSTREAM_TOKEN = "GARGOYLE_MCP_UPSTREAM_TOKEN"   # optional bearer for that server

SESSION_HEADER = "Mcp-Session-Id"
PROTOCOL_HEADER = "MCP-Protocol-Version"


class HttpUpstream:
    """An MCP server reached over Streamable HTTP. Same contract as
    StdioUpstream: send(msg) returns the reply for a request, None for a
    notification. JSON responses and SSE responses are both accepted."""

    def __init__(self, url: str, token: Optional[str] = None, *, http: Any = None, timeout: float = 60.0) -> None:
        import requests
        self.url = url
        self._token = token
        self._http = http if http is not None else requests.Session()
        self._timeout = timeout
        self._session_id: Optional[str] = None
        self._lock = threading.Lock()

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
             PROTOCOL_HEADER: PROTOCOL_VERSION}
        if self._token:
            h["Authorization"] = "Bearer " + self._token
        if self._session_id:
            h[SESSION_HEADER] = self._session_id
        return h

    def send(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            r = self._http.post(self.url, data=json.dumps(msg), headers=self._headers(), timeout=self._timeout)
            sid = r.headers.get(SESSION_HEADER) or r.headers.get(SESSION_HEADER.lower())
            if sid:
                self._session_id = sid
            if "id" not in msg:
                return None
            if r.status_code >= 400:
                raise RuntimeError("upstream answered %s" % r.status_code)
            ctype = r.headers.get("content-type", "")
            if ctype.startswith("text/event-stream"):
                for line in r.text.splitlines():
                    if line.startswith("data:"):
                        try:
                            reply = json.loads(line[5:].strip())
                        except ValueError:
                            continue
                        if isinstance(reply, dict) and reply.get("id") == msg["id"]:
                            return reply
                raise RuntimeError("upstream stream ended without a reply")
            reply = r.json()
            if isinstance(reply, list):
                reply = next((m for m in reply if isinstance(m, dict) and m.get("id") == msg["id"]), None)
            if not isinstance(reply, dict):
                raise RuntimeError("upstream reply is not a JSON-RPC message")
            return reply

    def close(self) -> None:
        try:
            self._http.delete(self.url, headers=self._headers(), timeout=5)
        except Exception:
            pass


class TokenMap:
    """Capability tokens to {principal, issuer_token}, from a JSON file."""

    def __init__(self, path: Optional[str] = None, entries: Optional[Dict[str, Dict[str, str]]] = None) -> None:
        self.path = Path(path) if path else None
        self._entries: Dict[str, Dict[str, str]] = dict(entries or {})
        if self.path is not None and self.path.exists():
            self._entries.update(json.loads(self.path.read_text(encoding="utf-8")).get("tokens", {}))

    def lookup(self, token: str) -> Optional[Dict[str, str]]:
        e = self._entries.get(token)
        return dict(e) if isinstance(e, dict) and e.get("principal") and e.get("issuer_token") else None

    def mint(self, principal: str, issuer_token: str) -> str:
        token = secrets.token_urlsafe(32)
        self._entries[token] = {"principal": principal, "issuer_token": issuer_token}
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({"tokens": self._entries}, indent=2) + "\n", encoding="utf-8")
            try:
                import os, stat
                os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        return token


def build_remote_app(
    config: Dict[str, Any],
    tokens: TokenMap,
    *,
    upstream: Any = None,
    issuer_url: Optional[str] = None,
    audit_log: Optional[str] = None,
    state_probe: Any = "none",
    adapter_spec: Optional[str] = None,
    snapshot_dir: Optional[str] = None,
    issuer_http: Any = None,
    approval_timeout: float = 300.0,
    poll_seconds: float = 2.0,
    sleep=None,
    oauth: Any = None,
    state_root: Optional[str] = None,
):
    """The FastAPI app. `config` is config_from_env()'s result minus the
    principal (each token supplies one). `upstream` is a StdioUpstream or
    HttpUpstream already running; the gate initializes it once here.
    `oauth` is a gargoyle.oauth_broker.OAuthGate: it installs the sign-in
    routes and authenticates bearers on /mcp."""
    from fastapi import FastAPI, Header, Request, Response

    app = FastAPI(title="Gargoyle remote gate")
    replay = InMemoryReplayCache()
    sessions: Dict[str, ServerState] = {}
    owners: Dict[str, str] = {}                 # MCP session id -> the credential that opened it
    lock = threading.Lock()
    shared_evidence = None
    shared_snapshots = None

    upstream_init: Dict[str, Any] = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {"listChanged": False}},
                                     "serverInfo": SERVER_INFO}
    if upstream is not None:
        reply = upstream.send({"jsonrpc": "2.0", "id": "gargoyle-init", "method": "initialize",
                               "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                          "clientInfo": {"name": "gargoyle-remote", "version": SERVER_INFO["version"]}}})
        if isinstance(reply, dict) and isinstance(reply.get("result"), dict):
            upstream_init = dict(reply["result"])
            upstream_init["serverInfo"] = {"name": "gargoyle+" + str(upstream_init.get("serverInfo", {}).get("name", "upstream")),
                                           "version": SERVER_INFO["version"]}
        upstream.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    from gargoyle.mcp_server import gate_instructions
    import os as _os
    upstream_init["instructions"] = gate_instructions(config.get("target_id", "the gated target"), upstream_init.get("instructions"),
                                                      _os.environ.get("GARGOYLE_MCP_INSTRUCTIONS") or None)

    def new_state(principal: str, issuer_token: Any) -> ServerState:
        nonlocal shared_evidence, shared_snapshots
        ic = None
        if issuer_url:
            kw: Dict[str, Any] = {"http": issuer_http, "approval_timeout": approval_timeout, "poll_seconds": poll_seconds}
            if sleep is not None:
                kw["sleep"] = sleep
            ic = IssuerClient(issuer_url, issuer_token, **kw)
        st = ServerState(dict(config, principal=principal), replay_cache=replay, upstream=upstream, issuer_client=ic,
                         audit_log=audit_log, state_probe=state_probe, snapshot_dir=snapshot_dir, adapter_spec=adapter_spec,
                         state_root=state_root)
        # One log and one snapshot store for the whole process: the chain and
        # the sidecars must not interleave from several session objects.
        if st.evidence is not None:
            if shared_evidence is None:
                shared_evidence = st.evidence
            st.evidence = shared_evidence
        if st.snapshots is not None:
            if shared_snapshots is None:
                shared_snapshots = st.snapshots
            st.snapshots = shared_snapshots
        st.upstream_init = upstream_init   # type: ignore[attr-defined]
        return st

    def handle_one(st: ServerState, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = msg.get("method")
        if method == "initialize":
            from gargoyle.mcp_server import client_label
            st.client = client_label(msg.get("params"))
            return {"jsonrpc": "2.0", "id": msg.get("id"), "result": st.upstream_init}   # type: ignore[attr-defined]
        if method == "notifications/initialized":
            st.initialized = True
            return None
        return handle_message(st, msg)

    async def serve(owner: str, principal: str, issuer_token: Any, request: Request, mcp_session_id: Optional[str]) -> Response:
        try:
            body = await request.json()
        except Exception:
            return Response(status_code=400, content="not JSON")
        messages: List[Any] = body if isinstance(body, list) else [body]
        is_init = any(isinstance(m, dict) and m.get("method") == "initialize" for m in messages)
        with lock:
            if is_init or not mcp_session_id or mcp_session_id not in sessions:
                if not is_init:
                    return Response(status_code=404, content="no such session; initialize first")
                mcp_session_id = uuid.uuid4().hex
                sessions[mcp_session_id] = new_state(principal, issuer_token)
                owners[mcp_session_id] = owner
            elif owners.get(mcp_session_id) != owner:
                # A session belongs to the credential that opened it; another
                # bearer naming it gets nothing, not even its existence.
                return Response(status_code=404, content="no such session; initialize first")
            st = sessions[mcp_session_id]
        replies = [r for r in (handle_one(st, m) for m in messages if isinstance(m, dict)) if r is not None]
        headers = {SESSION_HEADER: mcp_session_id, PROTOCOL_HEADER: PROTOCOL_VERSION}
        if not replies:
            return Response(status_code=202, headers=headers)
        payload = replies[0] if not isinstance(body, list) else replies
        return Response(content=json.dumps(payload), media_type="application/json", headers=headers)

    def end(owner: str, mcp_session_id: Optional[str]) -> Response:
        with lock:
            if mcp_session_id and owners.get(mcp_session_id) == owner:
                sessions.pop(mcp_session_id, None)
                owners.pop(mcp_session_id, None)
        return Response(status_code=200)

    if oauth is not None:
        oauth.install(app)

        def unauthorized() -> Response:
            return Response(status_code=401, content="sign in", headers={"WWW-Authenticate": oauth.www_authenticate()})

        @app.post("/mcp")
        async def mcp_oauth_post(request: Request, mcp_session_id: Optional[str] = Header(default=None, alias=SESSION_HEADER)):
            who = oauth.authenticate(request.headers.get("authorization"))
            if who is None:
                return unauthorized()
            key, principal, source = who
            return await serve("oauth:" + key, principal, source, request, mcp_session_id)

        @app.get("/mcp")
        async def mcp_oauth_get(request: Request):
            if oauth.authenticate(request.headers.get("authorization")) is None:
                return unauthorized()
            return Response(status_code=405, content="no server-initiated stream")

        @app.delete("/mcp")
        async def mcp_oauth_delete(request: Request, mcp_session_id: Optional[str] = Header(default=None, alias=SESSION_HEADER)):
            who = oauth.authenticate(request.headers.get("authorization"))
            if who is None:
                return unauthorized()
            return end("oauth:" + who[0], mcp_session_id)

    @app.post("/mcp/{token}")
    async def mcp_post(token: str, request: Request,
                       mcp_session_id: Optional[str] = Header(default=None, alias=SESSION_HEADER)):
        who = tokens.lookup(token)
        if who is None:
            return Response(status_code=401, content="unknown token")
        return await serve("cap:" + token, who["principal"], who["issuer_token"], request, mcp_session_id)

    @app.get("/mcp/{token}")
    async def mcp_get(token: str):
        return Response(status_code=405, content="no server-initiated stream")

    @app.delete("/mcp/{token}")
    async def mcp_delete(token: str, mcp_session_id: Optional[str] = Header(default=None, alias=SESSION_HEADER)):
        if tokens.lookup(token) is None:
            return Response(status_code=401)
        return end("cap:" + token, mcp_session_id)

    app.state.sessions = sessions
    return app


def mint_identity_token(principal: str, idp_signing_key: Any, idp_key_id: str, audience: str, days: int = 365) -> str:
    """An identity token the issuer trusts for `principal`, signed by the
    pinned IdP key `gargoyle init` wrote; the gate presents it in this
    user's sessions."""
    from datetime import datetime, timedelta, timezone
    from gargoyle.jws import encode
    exp = int((datetime.now(timezone.utc) + timedelta(days=days)).timestamp())
    return encode({"sub": principal, "aud": audience, "exp": exp}, idp_signing_key, idp_key_id)
