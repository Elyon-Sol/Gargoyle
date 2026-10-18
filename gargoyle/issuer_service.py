"""The issuing service: an HTTP front for gargoyle.issuer that a middleware
or an agent harness calls to obtain receipts, with the hold and grant
exchange for flagged calls.

    POST /issue             Bearer <identity token>; body {target_url, tool, args, claims?}
                            -> {"issued": true, "envelope": ...}
                             | {"issued": false, "reason": ...}
    GET  /pending           Bearer; flagged receipts still waiting for a grant, each with
                            the full arguments the issuer saw, so a reviewer can read what
                            they are releasing (the receipt's args_sha256 binds them)
    POST /grants            Bearer; body = a signed grant for one of them; a hold whose
                            receipt requires several approvers collects grants until enough
                            distinct eligible approvers have signed
                            -> {"accepted": true|false, "reason": ...}
    POST /decline           Bearer; body {approval_request_id}: drop the hold, so the
                            middleware waiting on it stops at once instead of timing out
    GET  /grants/{approval_request_id}
                            Bearer; -> {"pending": bool, "grant": <grant>|null, "grants": [...],
                            "collected": n, "required": m, "declined": bool}; `grant` is the
                            single grant of a one-approver hold once released, `grants` the
                            whole set once complete (empty until then)
    GET  /approve, /approve.js
                            the approval console: a page that lists the holds and
                            signs grants in the browser with the approver's key
    GET  /record            the published record {policy_id, policy_sha256}
    GET  /keys              {issuer_key_id: public key hex}

The identity token (gargoyle.identity) is how the service knows who it is
issuing to: its subject (or actor) becomes the receipt's principal and a
delegation its on_behalf_of. The caller never names its own principal. The
policy is any gargoyle Policy: a RulesPolicy from a JSON file
(GARGOYLE_RULES_PATH) for deployments without a policy engine, else OpaPolicy
(GARGOYLE_OPA_URL).

A posted grant is checked here against the receipt it releases (provenance,
separation of duties, binding, expiry) so the pending list never holds a
grant that would be refused downstream; the executor checks and single-uses
it again when the call runs. The pending set is in memory: one instance.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response

STATIC = Path(__file__).resolve().parent / "static"

from gargoyle.approval import (REF_APPROVAL_APPROVER_NOT_ELIGIBLE, REF_APPROVAL_DUPLICATE_APPROVER,
                               verify_grant)
from gargoyle.envelope import approval_terms
from gargoyle.notify import notifier_from_env
from gargoyle.approvers import (DEFAULT_APPROVER_ROLE, ENV_APPROVER_GROUPS, ENV_APPROVER_ROLE, ENV_APPROVERS_PATH,
                                ApproverRegistry, may_enroll, valid_public_key_hex)
from gargoyle.identity import entra_keys, principal_from_token
from gargoyle.issuer import DEFAULT_TTL_SECONDS, issue
from gargoyle.policy import Policy

ENV_ISSUER_KEY_ID = "GARGOYLE_ISSUER_KEY_ID"
ENV_ISSUER_KEY_HEX = "GARGOYLE_ISSUER_KEY_HEX"           # raw Ed25519 private bytes, hex; never logged
ENV_RULES_PATH = "GARGOYLE_RULES_PATH"
ENV_OPA_URL = "GARGOYLE_OPA_URL"
ENV_OPA_DECISION_PATH = "GARGOYLE_OPA_DECISION_PATH"
ENV_IDP_KEY_ID = "GARGOYLE_IDP_KEY_ID"
ENV_IDP_PUBLIC_KEY_HEX = "GARGOYLE_IDP_PUBLIC_KEY_HEX"
ENV_ENTRA_TENANT = "GARGOYLE_ENTRA_TENANT"        # trust the tenant's JWKS instead of a pinned IdP key
ENV_AUDIENCE = "GARGOYLE_ISSUER_AUDIENCE"
ENV_APPROVER_KEY_ID = "GARGOYLE_APPROVER_KEY_ID"
ENV_APPROVER_PUBLIC_KEY_HEX = "GARGOYLE_APPROVER_PUBLIC_KEY_HEX"
ENV_RECEIPT_TTL = "GARGOYLE_RECEIPT_TTL_SECONDS"
ENV_CONSOLE_CLIENT_ID = "GARGOYLE_ENTRA_CLIENT_ID"   # the public client app the console signs in with (User-Client-Flow)
ENV_CONSOLE_SCOPE = "GARGOYLE_ENTRA_SCOPE"           # default api://<last audience>/access

REF_ISSUER_UNAUTHENTICATED = "REF_ISSUER_UNAUTHENTICATED"
REF_ISSUER_BAD_REQUEST = "REF_ISSUER_BAD_REQUEST"
REF_ISSUER_ARGS_NOT_TEXT = "REF_ISSUER_ARGS_NOT_TEXT"   # arguments carry characters no UTF-8 text has
REF_ISSUER_UNKNOWN_HOLD = "REF_ISSUER_UNKNOWN_HOLD"
REF_ISSUER_NO_APPROVER_TRUST = "REF_ISSUER_NO_APPROVER_TRUST"
REF_ISSUER_NOT_AN_APPROVER = "REF_ISSUER_NOT_AN_APPROVER"   # enrollment without the approver role or group


def build_issuer_app(
    *,
    policy: Policy,
    signing_key: Any,
    key_id: str,
    idp_public_keys: Dict[str, Any],
    approver_public_keys: Optional[Dict[str, Any]] = None,
    audience: Optional[str] = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    on_hold: Optional[Callable[[Dict[str, Any], Any], None]] = None,
    approver_registry: Optional[ApproverRegistry] = None,
    approver_role: str = DEFAULT_APPROVER_ROLE,
    approver_groups: Optional[list] = None,
    console_entra: Optional[Dict[str, str]] = None,
) -> FastAPI:
    """`on_hold(envelope, args)` is called once for every new hold (gargoyle.notify
    posts it to a webhook); it is notice, not admission, and its failure
    never affects the hold."""
    app = FastAPI(title="Gargoyle issuing service")
    app.state.pending: Dict[str, Dict[str, Any]] = {}     # approval_request_id -> envelope
    app.state.pending_args: Dict[str, Any] = {}           # approval_request_id -> the call's arguments
    app.state.grants: Dict[str, Dict[str, Any]] = {}      # approval_request_id -> grant
    app.state.declined: set = set()                       # approval_request_ids a human refused
    registry = approver_registry if approver_registry is not None else ApproverRegistry(None)
    static_approvers = dict(approver_public_keys or {})

    def approver_keys() -> Dict[str, Any]:
        """Static keys from configuration plus every enrolled approver, by UPN."""
        return {**static_approvers, **registry.keys()}

    def _refuse(status: int, reason: str) -> HTTPException:
        return HTTPException(status_code=status, detail={"reason": reason})

    def authenticate(authorization: Optional[str]) -> Dict[str, Any]:
        if not authorization or not authorization.startswith("Bearer "):
            raise _refuse(401, REF_ISSUER_UNAUTHENTICATED)
        who = principal_from_token(authorization[7:].strip(), idp_public_keys, audience=audience, now=now())
        if who["reason"] is not None:
            raise _refuse(401, who["reason"])
        return who

    @app.post("/issue")
    async def issue_receipt(request: Request, authorization: Optional[str] = Header(default=None)):
        who = authenticate(authorization)
        try:
            body = await request.json()
        except Exception:
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        if (not isinstance(body, dict) or not isinstance(body.get("target_url"), str)
                or not isinstance(body.get("tool"), str) or "args" not in body
                or not isinstance(body.get("claims", {}), dict)):
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        try:
            # Lone surrogates (a client that decoded UTF-8 with the wrong
            # codepage) would hash and sign but could never be shown to an
            # approver or written as UTF-8. Refuse them here, not in /pending.
            json.dumps(body["args"], ensure_ascii=False).encode("utf-8")
        except UnicodeEncodeError:
            raise _refuse(400, REF_ISSUER_ARGS_NOT_TEXT)
        # The policy sees the identity provider's groups and roles as claims;
        # the receipt binds only the call and the principal.
        interaction = {**body.get("claims", {}), "tool": body["tool"], "args": body["args"],
                       "principal": who["principal"], "groups": who.get("groups", []),
                       "roles": who.get("roles", [])}
        if who["on_behalf_of"]:
            interaction["on_behalf_of"] = who["on_behalf_of"]
        result = issue(policy, body["target_url"], interaction, signing_key=signing_key, key_id=key_id,
                       ttl_seconds=ttl_seconds, now=now())
        if result.envelope is None:
            return {"issued": False, "reason": result.decision.reason}
        if result.envelope["requires_approval"]:
            arid = result.envelope["approval_request_id"]
            app.state.pending[arid] = result.envelope
            app.state.pending_args[arid] = body["args"]
            if on_hold is not None:
                try:
                    on_hold(result.envelope, body["args"])
                except Exception as exc:          # notice only; the hold stands
                    import sys
                    sys.stderr.write("gargoyle: on_hold failed: %s\n" % exc)
        return {"issued": True, "envelope": result.envelope}

    @app.get("/pending")
    async def pending(authorization: Optional[str] = Header(default=None)):
        authenticate(authorization)
        current = now()
        live = {}
        for arid, env in list(app.state.pending.items()):
            if datetime.fromisoformat(env["not_after"]) <= current:
                del app.state.pending[arid]           # an expired hold can never be released
                app.state.pending_args.pop(arid, None)
                app.state.grants.pop(arid, None)
            elif not _complete(arid):
                have = app.state.grants.get(arid, [])
                live[arid] = {"envelope": env, "args": app.state.pending_args.get(arid),
                              "collected": len(have), "required": approval_terms(env)["required"],
                              "approvers": [g["approver_key_id"] for g in have]}
        return {"pending": list(live.values())}

    def _complete(arid: str) -> bool:
        env = app.state.pending.get(arid)
        return env is not None and len(app.state.grants.get(arid, [])) >= approval_terms(env)["required"]

    @app.post("/grants")
    async def post_grant(request: Request, authorization: Optional[str] = Header(default=None)):
        authenticate(authorization)
        try:
            grant = await request.json()
        except Exception:
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        arid = grant.get("approval_request_id") if isinstance(grant, dict) else None
        env = app.state.pending.get(arid) if isinstance(arid, str) else None
        if env is None:
            return {"accepted": False, "reason": REF_ISSUER_UNKNOWN_HOLD}
        trusted = approver_keys()
        if not trusted:
            return {"accepted": False, "reason": REF_ISSUER_NO_APPROVER_TRUST}
        g = verify_grant(grant, expected_decision_sha256=env["decision_sha256"],
                         expected_approval_request_id=arid, approver_public_keys=trusted,
                         gate_key_id=key_id, now=now())
        if not g["accepted"]:
            return {"accepted": False, "reason": g["reason"]}
        # The receipt's own terms: distinct approvers, from the named set if any.
        terms = approval_terms(env)
        have = app.state.grants.setdefault(arid, [])
        if any(h["approver_key_id"] == grant["approver_key_id"] for h in have):
            return {"accepted": False, "reason": REF_APPROVAL_DUPLICATE_APPROVER}
        if terms["approvers"] is not None and grant["approver_key_id"] not in terms["approvers"]:
            return {"accepted": False, "reason": REF_APPROVAL_APPROVER_NOT_ELIGIBLE}
        have.append(grant)
        return {"accepted": True, "reason": g["reason"], "collected": len(have), "required": terms["required"],
                "complete": len(have) >= terms["required"]}

    @app.post("/decline")
    async def decline(request: Request, authorization: Optional[str] = Header(default=None)):
        """A human's refusal: the hold is dropped, a waiting middleware learns
        at once. No signature is needed to say no; nothing can run on it."""
        authenticate(authorization)
        try:
            body = await request.json()
        except Exception:
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        arid = body.get("approval_request_id") if isinstance(body, dict) else None
        if not isinstance(arid, str) or arid not in app.state.pending:
            return {"declined": False, "reason": REF_ISSUER_UNKNOWN_HOLD}
        del app.state.pending[arid]
        app.state.pending_args.pop(arid, None)
        app.state.grants.pop(arid, None)
        app.state.declined.add(arid)
        return {"declined": True, "reason": None}

    @app.get("/grants/{approval_request_id}")
    async def get_grant(approval_request_id: str, authorization: Optional[str] = Header(default=None)):
        authenticate(authorization)
        env = app.state.pending.get(approval_request_id)
        have = app.state.grants.get(approval_request_id, [])
        complete = _complete(approval_request_id)
        return {"pending": env is not None,
                "grant": have[0] if complete and len(have) == 1 else None,
                "grants": list(have) if complete else [],
                "collected": len(have), "required": approval_terms(env)["required"] if env else None,
                "declined": approval_request_id in app.state.declined}

    @app.get("/approvers")
    async def approvers():
        """Public, like /record: the enrolled approvers' public keys by UPN,
        for the middleware and for audits. Static configured keys are not
        listed; they travel in config."""
        return {"approvers": registry.public_hex()}

    @app.post("/approvers/enroll")
    async def enroll(request: Request, authorization: Optional[str] = Header(default=None)):
        """Bind the caller's UPN to the public key their browser generated.
        Only a token carrying the approver role (or a configured group) may;
        the UPN comes from the token, never from the body."""
        who = authenticate(authorization)
        if not may_enroll(who, role=approver_role, groups=approver_groups):
            raise _refuse(403, REF_ISSUER_NOT_AN_APPROVER)
        try:
            body = await request.json()
        except Exception:
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        if not isinstance(body, dict) or not valid_public_key_hex(body.get("public_key_hex")):
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        result = registry.enroll(who["principal"], body["public_key_hex"], now=now())
        return {"enrolled": True, "key_id": who["principal"], "replaced": result["replaced"]}

    @app.get("/me")
    async def me(authorization: Optional[str] = Header(default=None)):
        """Who the console is signed in as, whether they may approve, and
        the public key enrolled for them (so the browser can tell whether
        its own key is the one on record)."""
        who = authenticate(authorization)
        upn = who["principal"]
        return {"principal": upn, "may_approve": may_enroll(who, role=approver_role, groups=approver_groups) or upn in static_approvers,
                "enrolled_public_key_hex": registry.public_hex().get(upn)}

    @app.get("/approve-config")
    async def approve_config():
        """Public: how the console signs in. `entra` is null when the site
        uses approver files instead."""
        return {"entra": console_entra}

    @app.get("/approve")
    async def approve_page():
        return Response((STATIC / "approve.html").read_bytes(), media_type="text/html; charset=utf-8")

    @app.get("/approve.js")
    async def approve_script():
        return Response((STATIC / "approve.js").read_bytes(), media_type="text/javascript; charset=utf-8")

    @app.get("/record")
    async def record():
        return policy.pin()

    @app.get("/keys")
    async def keys():
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return {key_id: signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}

    return app


def app_from_env() -> FastAPI:
    """The deployable app: OPA policy, issuer key, trusted identity-provider
    key and optional approver key from the environment. Missing required
    settings raise at startup; this service has nothing to do without them."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

    required = {k: os.environ.get(k) for k in (ENV_ISSUER_KEY_ID, ENV_ISSUER_KEY_HEX)}
    tenant = os.environ.get(ENV_ENTRA_TENANT)
    pinned_idp = os.environ.get(ENV_IDP_KEY_ID) and os.environ.get(ENV_IDP_PUBLIC_KEY_HEX)
    if not tenant:
        required.update({k: os.environ.get(k) for k in (ENV_IDP_KEY_ID, ENV_IDP_PUBLIC_KEY_HEX)})
    missing = [k for k, v in required.items() if not v]
    if missing:
        raise RuntimeError("issuer service needs " + ", ".join(missing))
    rules_path = os.environ.get(ENV_RULES_PATH)
    if rules_path:
        from gargoyle.rules import RulesPolicy
        policy = RulesPolicy(rules_path)
    elif os.environ.get(ENV_OPA_URL) and os.environ.get(ENV_OPA_DECISION_PATH):
        from gargoyle.opa import OpaPolicy
        policy = OpaPolicy(os.environ[ENV_OPA_URL], os.environ[ENV_OPA_DECISION_PATH])
    else:
        raise RuntimeError("issuer service needs %s (a rules file) or %s + %s (OPA)"
                           % (ENV_RULES_PATH, ENV_OPA_URL, ENV_OPA_DECISION_PATH))
    approver = None
    if os.environ.get(ENV_APPROVER_KEY_ID) or os.environ.get(ENV_APPROVER_PUBLIC_KEY_HEX):
        if not (os.environ.get(ENV_APPROVER_KEY_ID) and os.environ.get(ENV_APPROVER_PUBLIC_KEY_HEX)):
            raise RuntimeError("approver key id and public key go together")
        # Several approvers: comma-separated ids and hexes, in the same order.
        ids = [x.strip() for x in os.environ[ENV_APPROVER_KEY_ID].split(",")]
        hexes = [x.strip() for x in os.environ[ENV_APPROVER_PUBLIC_KEY_HEX].split(",")]
        if len(ids) != len(hexes) or not all(ids):
            raise RuntimeError("approver key ids and public keys must pair up")
        approver = {i: Ed25519PublicKey.from_public_bytes(bytes.fromhex(h)) for i, h in zip(ids, hexes)}
    return build_issuer_app(
        policy=policy,
        signing_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(required[ENV_ISSUER_KEY_HEX])),
        key_id=required[ENV_ISSUER_KEY_ID],
        # Both may be trusted at once: the tenant's keys for users who ran
        # `gargoyle login`, the pinned key for tokens `gargoyle init` minted
        # (the approver's, until approvers log in with Entra too).
        idp_public_keys={**(entra_keys(tenant) if tenant else {}),
                         **({os.environ[ENV_IDP_KEY_ID]: Ed25519PublicKey.from_public_bytes(bytes.fromhex(os.environ[ENV_IDP_PUBLIC_KEY_HEX]))}
                            if pinned_idp else {})},
        approver_public_keys=approver,
        audience=os.environ.get(ENV_AUDIENCE) or None,
        ttl_seconds=int(os.environ.get(ENV_RECEIPT_TTL, DEFAULT_TTL_SECONDS)),
        on_hold=notifier_from_env(os.environ),
        approver_registry=ApproverRegistry(os.environ.get(ENV_APPROVERS_PATH)),
        approver_role=os.environ.get(ENV_APPROVER_ROLE, DEFAULT_APPROVER_ROLE),
        approver_groups=[g.strip() for g in os.environ.get(ENV_APPROVER_GROUPS, "").split(",") if g.strip()] or None,
        console_entra=({"tenant": tenant, "client_id": os.environ[ENV_CONSOLE_CLIENT_ID],
                        "scope": os.environ.get(ENV_CONSOLE_SCOPE) or "api://%s/access" % (os.environ.get(ENV_AUDIENCE) or "").split(",")[-1].strip()}
                       if tenant and os.environ.get(ENV_CONSOLE_CLIENT_ID) else None),
    )
