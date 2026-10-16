"""The issuing service: an HTTP front for gargoyle.issuer that a middleware
or an agent harness calls to obtain receipts, with the hold and grant
exchange for flagged calls.

    POST /issue             Bearer <identity token>; body {target_url, tool, args, claims?}
                            -> {"issued": true, "envelope": ...}
                             | {"issued": false, "reason": ...}
    GET  /pending           Bearer; flagged receipts still waiting for a grant
    POST /grants            Bearer; body = a signed grant for one of them
                            -> {"accepted": true|false, "reason": ...}
    GET  /grants/{approval_request_id}
                            Bearer; -> {"pending": bool, "grant": <grant>|null}
    GET  /record            the published record {policy_id, policy_sha256}
    GET  /keys              {issuer_key_id: public key hex}

The identity token (gargoyle.identity) is how the service knows who it is
issuing to: its subject (or actor) becomes the receipt's principal and a
delegation its on_behalf_of. The caller never names its own principal. The
policy is any gargoyle Policy; the configured one is OpaPolicy.

A posted grant is checked here against the receipt it releases (provenance,
separation of duties, binding, expiry) so the pending list never holds a
grant that would be refused downstream; the executor checks and single-uses
it again when the call runs. The pending set is in memory: one instance.
"""

import os
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request

from gargoyle.approval import verify_grant
from gargoyle.identity import principal_from_token
from gargoyle.issuer import DEFAULT_TTL_SECONDS, issue
from gargoyle.policy import Policy

ENV_ISSUER_KEY_ID = "GARGOYLE_ISSUER_KEY_ID"
ENV_ISSUER_KEY_HEX = "GARGOYLE_ISSUER_KEY_HEX"           # raw Ed25519 private bytes, hex; never logged
ENV_OPA_URL = "GARGOYLE_OPA_URL"
ENV_OPA_DECISION_PATH = "GARGOYLE_OPA_DECISION_PATH"
ENV_IDP_KEY_ID = "GARGOYLE_IDP_KEY_ID"
ENV_IDP_PUBLIC_KEY_HEX = "GARGOYLE_IDP_PUBLIC_KEY_HEX"
ENV_AUDIENCE = "GARGOYLE_ISSUER_AUDIENCE"
ENV_APPROVER_KEY_ID = "GARGOYLE_APPROVER_KEY_ID"
ENV_APPROVER_PUBLIC_KEY_HEX = "GARGOYLE_APPROVER_PUBLIC_KEY_HEX"
ENV_RECEIPT_TTL = "GARGOYLE_RECEIPT_TTL_SECONDS"

REF_ISSUER_UNAUTHENTICATED = "REF_ISSUER_UNAUTHENTICATED"
REF_ISSUER_BAD_REQUEST = "REF_ISSUER_BAD_REQUEST"
REF_ISSUER_UNKNOWN_HOLD = "REF_ISSUER_UNKNOWN_HOLD"
REF_ISSUER_NO_APPROVER_TRUST = "REF_ISSUER_NO_APPROVER_TRUST"


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
) -> FastAPI:
    app = FastAPI(title="Gargoyle issuing service")
    app.state.pending: Dict[str, Dict[str, Any]] = {}     # approval_request_id -> envelope
    app.state.grants: Dict[str, Dict[str, Any]] = {}      # approval_request_id -> grant

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
        interaction = {**body.get("claims", {}), "tool": body["tool"], "args": body["args"],
                       "principal": who["principal"]}
        if who["on_behalf_of"]:
            interaction["on_behalf_of"] = who["on_behalf_of"]
        result = issue(policy, body["target_url"], interaction, signing_key=signing_key, key_id=key_id,
                       ttl_seconds=ttl_seconds, now=now())
        if result.envelope is None:
            return {"issued": False, "reason": result.decision.reason}
        if result.envelope["requires_approval"]:
            app.state.pending[result.envelope["approval_request_id"]] = result.envelope
        return {"issued": True, "envelope": result.envelope}

    @app.get("/pending")
    async def pending(authorization: Optional[str] = Header(default=None)):
        authenticate(authorization)
        current = now()
        live = {}
        for arid, env in list(app.state.pending.items()):
            if datetime.fromisoformat(env["not_after"]) <= current:
                del app.state.pending[arid]           # an expired hold can never be released
                app.state.grants.pop(arid, None)
            elif arid not in app.state.grants:
                live[arid] = env
        return {"pending": list(live.values())}

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
        if not approver_public_keys:
            return {"accepted": False, "reason": REF_ISSUER_NO_APPROVER_TRUST}
        g = verify_grant(grant, expected_decision_sha256=env["decision_sha256"],
                         expected_approval_request_id=arid, approver_public_keys=approver_public_keys,
                         gate_key_id=key_id, now=now())
        if not g["accepted"]:
            return {"accepted": False, "reason": g["reason"]}
        app.state.grants[arid] = grant
        return {"accepted": True, "reason": g["reason"]}

    @app.get("/grants/{approval_request_id}")
    async def get_grant(approval_request_id: str, authorization: Optional[str] = Header(default=None)):
        authenticate(authorization)
        return {"pending": approval_request_id in app.state.pending,
                "grant": app.state.grants.get(approval_request_id)}

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
    from gargoyle.opa import OpaPolicy

    required = {k: os.environ.get(k) for k in (ENV_ISSUER_KEY_ID, ENV_ISSUER_KEY_HEX, ENV_OPA_URL,
                                                ENV_OPA_DECISION_PATH, ENV_IDP_KEY_ID, ENV_IDP_PUBLIC_KEY_HEX)}
    missing = [k for k, v in required.items() if not v]
    if missing:
        raise RuntimeError("issuer service needs " + ", ".join(missing))
    approver = None
    if os.environ.get(ENV_APPROVER_KEY_ID) or os.environ.get(ENV_APPROVER_PUBLIC_KEY_HEX):
        if not (os.environ.get(ENV_APPROVER_KEY_ID) and os.environ.get(ENV_APPROVER_PUBLIC_KEY_HEX)):
            raise RuntimeError("approver key id and public key go together")
        approver = {os.environ[ENV_APPROVER_KEY_ID]:
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(os.environ[ENV_APPROVER_PUBLIC_KEY_HEX]))}
    return build_issuer_app(
        policy=OpaPolicy(required[ENV_OPA_URL], required[ENV_OPA_DECISION_PATH]),
        signing_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(required[ENV_ISSUER_KEY_HEX])),
        key_id=required[ENV_ISSUER_KEY_ID],
        idp_public_keys={required[ENV_IDP_KEY_ID]:
                         Ed25519PublicKey.from_public_bytes(bytes.fromhex(required[ENV_IDP_PUBLIC_KEY_HEX]))},
        approver_public_keys=approver,
        audience=os.environ.get(ENV_AUDIENCE) or None,
        ttl_seconds=int(os.environ.get(ENV_RECEIPT_TTL, DEFAULT_TTL_SECONDS)),
    )
