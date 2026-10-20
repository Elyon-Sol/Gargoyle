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
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response

STATIC = Path(__file__).resolve().parent / "static"

from gargoyle.approval import (REF_APPROVAL_APPROVER_NOT_ELIGIBLE, REF_APPROVAL_DUPLICATE_APPROVER,
                               verify_grant)
from gargoyle.envelope import approval_terms
from gargoyle.state import state_sha256, valid_description
from gargoyle.holdstore import ENV_HOLDS_PATH, HoldStore
from gargoyle.witness import WitnessLog
from gargoyle.plans import (REF_PLAN_MALFORMED, REF_PLAN_STEP_NOT_PLANNABLE, REF_PLAN_STEP_REFUSED, build_plan,
                            sign_plan, valid_step)
from gargoyle.notify import notifier_from_env
from gargoyle.approvers import (DEFAULT_APPROVER_ROLE, ENV_APPROVER_GROUPS, ENV_APPROVER_ROLE, ENV_APPROVERS_PATH,
                                ApproverRegistry, may_enroll, valid_public_key_hex)
from gargoyle.identity import entra_keys, entra_tenant_id, principal_from_token
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
ENV_MAX_OPEN_HOLDS = "GARGOYLE_MAX_OPEN_HOLDS"       # holds one principal may have waiting at once
DEFAULT_MAX_OPEN_HOLDS = 20

REF_ISSUER_UNAUTHENTICATED = "REF_ISSUER_UNAUTHENTICATED"
REF_ISSUER_BAD_REQUEST = "REF_ISSUER_BAD_REQUEST"
REF_ISSUER_ARGS_NOT_TEXT = "REF_ISSUER_ARGS_NOT_TEXT"   # arguments carry characters no UTF-8 text has
REF_ISSUER_UNKNOWN_HOLD = "REF_ISSUER_UNKNOWN_HOLD"
REF_ISSUER_NO_APPROVER_TRUST = "REF_ISSUER_NO_APPROVER_TRUST"
REF_ISSUER_NOT_AN_APPROVER = "REF_ISSUER_NOT_AN_APPROVER"   # enrollment without the approver role or group
REF_ISSUER_FORBIDDEN = "REF_ISSUER_FORBIDDEN"               # authenticated, but not an approver and not the hold's own principal
REF_ISSUER_TOO_MANY_HOLDS = "REF_ISSUER_TOO_MANY_HOLDS"     # the principal already has the cap's worth of holds waiting


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
    hold_store: Optional[HoldStore] = None,
    log_events: Optional[Callable[[Dict[str, Any]], None]] = None,
    witness: Optional[WitnessLog] = None,
    tenant: Optional[str] = None,
    tenant_key_ids: Optional[set] = None,
    max_open_holds: int = DEFAULT_MAX_OPEN_HOLDS,
) -> FastAPI:
    """`on_hold(envelope, args)` is called once for every new hold (gargoyle.notify
    posts it to a webhook); it is notice, not admission, and its failure
    never affects the hold."""
    app = FastAPI(title="Gargoyle issuing service")
    # Everything a human may be in the middle of acting on lives in the hold
    # store (gargoyle.holdstore): SQLite on disk in a deployment, memory in tests.
    store = hold_store if hold_store is not None else HoldStore(None)
    app.state.store = store
    app.state.pending = store.dict("pending")             # approval_request_id -> envelope
    app.state.pending_args = store.dict("pending_args")   # approval_request_id -> the call's arguments
    app.state.pending_state = store.dict("pending_state") # approval_request_id -> the target's state when held
    app.state.grants = store.dict("grants")               # approval_request_id -> [grant, ...]
    app.state.declined = store.set("declined")            # approval_request_ids a human refused
    app.state.pending_plans = store.dict("pending_plans") # approval_request_id -> signed plan (gargoyle.plans)
    app.state.started_at = now().isoformat()

    def event(kind: str, **fields: Any) -> None:
        """One structured line per decision the service makes, for the
        operator's log, and one signed entry in the witness log (gargoyle.witness),
        the independent record the client's evidence is reconciled against.
        Neither is the admission path."""
        if log_events is not None:
            try:
                log_events({"event": kind, "at": now().isoformat(), **fields})
            except Exception:
                pass
        if witness is not None:
            try:
                witness.record(kind, **fields)
            except Exception as exc:
                import sys as _sys
                _sys.stderr.write("gargoyle: witness log unwritable: %s\n" % exc)
    app.state.witness = witness
    registry = approver_registry if approver_registry is not None else ApproverRegistry(None)
    static_approvers = dict(approver_public_keys or {})

    def approver_keys() -> Dict[str, Any]:
        """Static keys from configuration plus every enrolled approver, by UPN."""
        return {**static_approvers, **registry.keys()}

    def is_approver(who: Dict[str, Any]) -> bool:
        """May this identity see every hold and the witness: the approver role
        or group, a configured approver key id, or an enrolled approver."""
        upn = who["principal"]
        return may_enroll(who, role=approver_role, groups=approver_groups) or upn in static_approvers or upn in registry

    def hold_owner(arid: str) -> Optional[str]:
        """The principal whose call is held under `arid` (a hold or a plan), or None."""
        env = app.state.pending.get(arid)
        if env is not None:
            return env.get("request_context", {}).get("principal")
        plan = app.state.pending_plans.get(arid)
        return plan.get("principal") if plan is not None else None

    def _open_holds(principal: str) -> int:
        """Held receipts and plans of `principal` still waiting on a release:
        not expired, not complete. A declined hold is already gone. One runaway
        client must not fill every approver's queue and the hold store."""
        current = now()
        n = 0
        for arid, env in app.state.pending.items():
            if (env.get("request_context", {}).get("principal") == principal
                    and datetime.fromisoformat(env["not_after"]) > current and not _complete(arid)):
                n += 1
        for arid, plan in app.state.pending_plans.items():
            if plan.get("principal") == principal and datetime.fromisoformat(plan["not_after"]) > current and not _complete(arid):
                n += 1
        return n

    def _refuse(status: int, reason: str) -> HTTPException:
        return HTTPException(status_code=status, detail={"reason": reason})

    def authenticate(authorization: Optional[str]) -> Dict[str, Any]:
        if not authorization or not authorization.startswith("Bearer "):
            raise _refuse(401, REF_ISSUER_UNAUTHENTICATED)
        who = principal_from_token(authorization[7:].strip(), idp_public_keys, audience=audience, now=now(),
                                   tenant=tenant, tenant_key_ids=tenant_key_ids)
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
        state = body.get("state")
        if state is not None:
            # The executor's description of the target before the call: its
            # hash is bound into the receipt; the description is shown to
            # the approver and seen by the policy.
            if not valid_description(state):
                raise _refuse(400, REF_ISSUER_BAD_REQUEST)
            interaction["state_sha256"] = state_sha256(state)
            interaction["state"] = {k: v for k, v in state.items() if k != "text"}
        if who["on_behalf_of"]:
            interaction["on_behalf_of"] = who["on_behalf_of"]
        result = issue(policy, body["target_url"], interaction, signing_key=signing_key, key_id=key_id,
                       ttl_seconds=ttl_seconds, now=now())
        if result.envelope is None:
            event("refused", principal=who["principal"], tool=body["tool"], reason=result.decision.reason)
            return {"issued": False, "reason": result.decision.reason}
        covered = False
        plan_id = body.get("plan_id")
        if result.envelope["requires_approval"] and isinstance(plan_id, str):
            # The executor says an approved plan covers this call. No card then:
            # the executor enforces the plan (step single use, grants, expiry)
            # and the console should not show a hold nobody needs to act on.
            # A false claim costs nothing here: without a valid release the
            # executor refuses the call.
            from gargoyle.plans import match_step
            for arid_p, plan in app.state.pending_plans.items():
                if plan["plan_id"] == plan_id and _complete(arid_p) and match_step(plan, body["tool"], body["args"]) is not None:
                    covered = True
                    break
        if result.envelope["requires_approval"] and not covered and _open_holds(who["principal"]) >= max_open_holds:
            # A service limit, not a policy decision: nothing is stored, the
            # signed envelope is dropped, the client reports the reason.
            event("refused", principal=who["principal"], tool=body["tool"], reason=REF_ISSUER_TOO_MANY_HOLDS)
            return {"issued": False, "reason": REF_ISSUER_TOO_MANY_HOLDS}
        event("issued", principal=who["principal"], tool=body["tool"], held=bool(result.envelope["requires_approval"]),
              **({"oid": who["oid"]} if who.get("oid") else {}),
              covered=covered, decision_id=result.envelope.get("decision_id"), decision_sha256=result.envelope["decision_sha256"],
              approval_request_id=result.envelope.get("approval_request_id"), args_sha256=result.envelope["request_context"]["args_sha256"])
        if result.envelope["requires_approval"] and not covered:
            arid = result.envelope["approval_request_id"]
            app.state.pending[arid] = result.envelope
            app.state.pending_args[arid] = body["args"]
            if state is not None:
                app.state.pending_state[arid] = state
            if on_hold is not None:
                try:
                    on_hold(result.envelope, body["args"])
                except Exception as exc:          # notice only; the hold stands
                    import sys
                    sys.stderr.write("gargoyle: on_hold failed: %s\n" % exc)
        return {"issued": True, "envelope": result.envelope}

    @app.post("/plans")
    async def post_plan(request: Request, authorization: Optional[str] = Header(default=None)):
        """A scoped grant request: every step judged by the policy; the plan
        signed and held when any step would be. Steps with exact arguments
        are judged on them; a pattern step is judged with its patterns as the
        argument values, so a broad pattern fails a narrow rule."""
        who = authenticate(authorization)
        try:
            body = await request.json()
        except Exception:
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        steps = body.get("steps") if isinstance(body, dict) else None
        if (not isinstance(body, dict) or not isinstance(body.get("target_url"), str) or not isinstance(steps, list)
                or not steps or len(steps) > 200 or not all(valid_step(s) or ("args" in s and isinstance(s.get("tool"), str)) for s in steps)
                or not isinstance(body.get("note", ""), str)):
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        from gargoyle.envelope import args_sha256
        norm, held, required, approvers = [], False, 1, set()
        for s in steps:
            if "args" in s:
                judged_args, step = s["args"], {"tool": s["tool"], "args_sha256": args_sha256(s["args"])}
            elif "args_sha256" in s:
                return {"issued": False, "reason": REF_PLAN_MALFORMED}        # a hash alone cannot be judged
            else:
                judged_args, step = dict(s["match"]), {"tool": s["tool"], "match": dict(s["match"])}
            interaction = {"tool": s["tool"], "args": judged_args, "principal": who["principal"],
                           "groups": who.get("groups", []), "roles": who.get("roles", [])}
            try:
                d = policy.decide(body["target_url"], interaction)
            except Exception:
                return {"issued": False, "reason": REF_PLAN_STEP_REFUSED}
            if not d.eligible:
                return {"issued": False, "reason": REF_PLAN_STEP_REFUSED, "step": len(norm)}
            if d.requires_approval:
                if not d.plannable:
                    return {"issued": False, "reason": REF_PLAN_STEP_NOT_PLANNABLE, "step": len(norm)}
                held = True
                required = max(required, d.approvals_required)
                if d.approvers:
                    approvers.update(d.approvers)
            norm.append(step)
        if held and _open_holds(who["principal"]) >= max_open_holds:
            event("refused", principal=who["principal"], tool="plan", reason=REF_ISSUER_TOO_MANY_HOLDS)
            return {"issued": False, "reason": REF_ISSUER_TOO_MANY_HOLDS}
        import uuid
        approval = None
        if required > 1 or approvers:
            approval = {"required": required, **({"approvers": sorted(approvers)} if approvers else {})}
        plan = sign_plan(build_plan(plan_id=str(uuid.uuid4()), approval_request_id=str(uuid.uuid4()), target_url=body["target_url"],
                                    principal=who["principal"], policy_pin=policy.pin(), steps=norm,
                                    not_after=now() + timedelta(seconds=min(ttl_seconds * 6, 3600)), note=body.get("note", ""),
                                    approval=approval), signing_key, key_id)
        if held:
            app.state.pending_plans[plan["approval_request_id"]] = plan
        event("plan", principal=who["principal"], steps=len(norm), held=held, plan_id=plan["plan_id"])
        return {"issued": True, "plan": plan, "held": held}

    def _plan_terms(plan):
        return approval_terms({"approval": plan["approval"]} if "approval" in plan else {})

    @app.get("/pending")
    async def pending(authorization: Optional[str] = Header(default=None)):
        """Approvers see every hold with its arguments; anyone else sees only
        the holds on their own calls. Held arguments are often file contents,
        and one user's are not another's to read."""
        who = authenticate(authorization)
        sees_all = is_approver(who)
        current = now()
        live = {}
        for arid, plan in list(app.state.pending_plans.items()):
            if datetime.fromisoformat(plan["not_after"]) <= current:
                del app.state.pending_plans[arid]
                app.state.grants.pop(arid, None)
            elif len(app.state.grants.get(arid, [])) < _plan_terms(plan)["required"]:
                if not sees_all and plan.get("principal") != who["principal"]:
                    continue
                have = app.state.grants.get(arid, [])
                live[arid] = {"plan": plan, "collected": len(have), "required": _plan_terms(plan)["required"],
                              "approvers": [g["approver_key_id"] for g in have]}
        for arid, env in list(app.state.pending.items()):
            if datetime.fromisoformat(env["not_after"]) <= current:
                del app.state.pending[arid]           # an expired hold can never be released
                app.state.pending_args.pop(arid, None)
                app.state.pending_state.pop(arid, None)
                app.state.grants.pop(arid, None)
            elif not _complete(arid):
                if not sees_all and env.get("request_context", {}).get("principal") != who["principal"]:
                    continue
                have = app.state.grants.get(arid, [])
                live[arid] = {"envelope": env, "args": app.state.pending_args.get(arid),
                              "state": app.state.pending_state.get(arid),
                              "collected": len(have), "required": approval_terms(env)["required"],
                              "approvers": [g["approver_key_id"] for g in have]}
        return {"pending": list(live.values())}

    def _complete(arid: str) -> bool:
        env = app.state.pending.get(arid)
        if env is None:
            plan = app.state.pending_plans.get(arid)
            return plan is not None and len(app.state.grants.get(arid, [])) >= _plan_terms(plan)["required"]
        return len(app.state.grants.get(arid, [])) >= approval_terms(env)["required"]

    @app.post("/grants")
    async def post_grant(request: Request, authorization: Optional[str] = Header(default=None)):
        authenticate(authorization)
        try:
            grant = await request.json()
        except Exception:
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        arid = grant.get("approval_request_id") if isinstance(grant, dict) else None
        env = app.state.pending.get(arid) if isinstance(arid, str) else None
        plan = app.state.pending_plans.get(arid) if isinstance(arid, str) else None
        if env is None and plan is None:
            return {"accepted": False, "reason": REF_ISSUER_UNKNOWN_HOLD}
        trusted = approver_keys()
        if not trusted:
            return {"accepted": False, "reason": REF_ISSUER_NO_APPROVER_TRUST}
        g = verify_grant(grant, expected_decision_sha256=env["decision_sha256"] if env else plan["plan_sha256"],
                         expected_approval_request_id=arid, approver_public_keys=trusted,
                         gate_key_id=key_id, now=now())
        if not g["accepted"]:
            return {"accepted": False, "reason": g["reason"]}
        # The receipt's (or plan's) own terms: distinct approvers, from the named set if any.
        terms = approval_terms(env) if env else _plan_terms(plan)
        have = list(app.state.grants.get(arid, []))
        if any(h["approver_key_id"] == grant["approver_key_id"] for h in have):
            return {"accepted": False, "reason": REF_APPROVAL_DUPLICATE_APPROVER}
        if terms["approvers"] is not None and grant["approver_key_id"] not in terms["approvers"]:
            return {"accepted": False, "reason": REF_APPROVAL_APPROVER_NOT_ELIGIBLE}
        have.append(grant)
        app.state.grants[arid] = have                      # written back: the store persists on assignment
        event("granted", approval_request_id=arid, approver=grant["approver_key_id"], collected=len(have), required=terms["required"],
              hold_kind="plan" if plan else "receipt")
        return {"accepted": True, "reason": g["reason"], "collected": len(have), "required": terms["required"],
                "complete": len(have) >= terms["required"]}

    @app.post("/decline")
    async def decline(request: Request, authorization: Optional[str] = Header(default=None)):
        """A human's refusal: the hold is dropped, a waiting middleware learns
        at once. No signature is needed to say no; nothing can run on it."""
        who = authenticate(authorization)
        try:
            body = await request.json()
        except Exception:
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        arid = body.get("approval_request_id") if isinstance(body, dict) else None
        if not isinstance(arid, str) or (arid not in app.state.pending and arid not in app.state.pending_plans):
            return {"declined": False, "reason": REF_ISSUER_UNKNOWN_HOLD}
        if not is_approver(who) and hold_owner(arid) != who["principal"]:
            raise _refuse(403, REF_ISSUER_FORBIDDEN)      # only an approver, or the person whose call it is, may cancel it
        app.state.pending_plans.pop(arid, None)
        app.state.pending.pop(arid, None)
        app.state.pending_args.pop(arid, None)
        app.state.pending_state.pop(arid, None)
        app.state.grants.pop(arid, None)
        app.state.declined.add(arid)
        event("declined", approval_request_id=arid, by=who["principal"])
        return {"declined": True, "reason": None}

    @app.get("/grants/{approval_request_id}")
    async def get_grant(approval_request_id: str, authorization: Optional[str] = Header(default=None)):
        authenticate(authorization)
        env = app.state.pending.get(approval_request_id) or app.state.pending_plans.get(approval_request_id)
        have = app.state.grants.get(approval_request_id, [])
        complete = _complete(approval_request_id)
        return {"pending": env is not None,
                "grant": have[0] if complete and len(have) == 1 else None,
                "grants": list(have) if complete else [],
                "collected": len(have), "required": (_plan_terms(env) if env and "plan_version" in env else approval_terms(env))["required"] if env else None,
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
        result = registry.enroll(who["principal"], body["public_key_hex"], now=now(), oid=who.get("oid"), tid=who.get("tid"))
        event("enrolled", approver=who["principal"], replaced=result["replaced"], oid=who.get("oid"))
        return {"enrolled": True, "key_id": who["principal"], "replaced": result["replaced"]}

    @app.post("/approvers/revoke")
    async def revoke(request: Request, authorization: Optional[str] = Header(default=None)):
        """An approver retires their own key (a lost or replaced device): from
        now on grants under it are refused here and at every middleware that
        asks this service for approver keys. Revoking someone else is the
        operator's act, done on the host with `gargoyle approvers revoke`,
        so that one compromised approver cannot remove the others."""
        who = authenticate(authorization)
        try:
            body = await request.json()
        except Exception:
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        upn = body.get("upn") if isinstance(body, dict) else None
        if not isinstance(upn, str) or not upn:
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        if upn != who["principal"]:
            raise _refuse(403, REF_ISSUER_FORBIDDEN)
        gone = registry.revoke(upn, revoked_by=who["principal"], now=now())
        if gone:
            event("revoked", approver=upn, by=who["principal"])
        return {"revoked": gone}

    @app.get("/me")
    async def me(authorization: Optional[str] = Header(default=None)):
        """Who the console is signed in as, whether they may approve, and
        the public key enrolled for them (so the browser can tell whether
        its own key is the one on record)."""
        who = authenticate(authorization)
        upn = who["principal"]
        return {"principal": upn, "may_approve": may_enroll(who, role=approver_role, groups=approver_groups) or upn in static_approvers,
                "enrolled_public_key_hex": registry.public_hex().get(upn)}

    @app.get("/witness")
    async def witness_entries(authorization: Optional[str] = Header(default=None)):
        """The issuer's signed witness log, for reconciliation with a client's
        evidence. It names every user's decisions, so it is for approvers."""
        if not is_approver(authenticate(authorization)):
            raise _refuse(403, REF_ISSUER_FORBIDDEN)
        return {"entries": list(witness.entries) if witness is not None else []}

    @app.get("/health")
    async def health():
        """Public, for a monitor: the service is up, which policy it runs,
        how much is waiting, and since when. No secrets."""
        return {"ok": True, "policy": policy.pin(), "issuer_key_id": key_id,
                "pending_receipts": len(app.state.pending), "pending_plans": len(app.state.pending_plans),
                "max_open_holds": max_open_holds,
                "enrolled_approvers": len(registry.public_hex()), "static_approvers": len(static_approvers),
                "entra": bool(console_entra), "persistent": store.path != ":memory:", "started_at": app.state.started_at}

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
    if tenant and not os.environ.get(ENV_AUDIENCE):
        # Fail closed: without an audience, any token the tenant ever issued
        # for any application would be accepted here.
        raise RuntimeError("issuer service with %s set needs %s (the issuer API's client id or app id URI)"
                           % (ENV_ENTRA_TENANT, ENV_AUDIENCE))
    tenant_id = entra_tenant_id(tenant) if tenant else None
    tenant_keys = entra_keys(tenant_id) if tenant else {}
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
        idp_public_keys={**tenant_keys,
                         **({os.environ[ENV_IDP_KEY_ID]: Ed25519PublicKey.from_public_bytes(bytes.fromhex(os.environ[ENV_IDP_PUBLIC_KEY_HEX]))}
                            if pinned_idp else {})},
        approver_public_keys=approver,
        audience=os.environ.get(ENV_AUDIENCE) or None,
        ttl_seconds=int(os.environ.get(ENV_RECEIPT_TTL, DEFAULT_TTL_SECONDS)),
        on_hold=notifier_from_env(os.environ),
        hold_store=HoldStore(os.environ.get(ENV_HOLDS_PATH) or None),
        max_open_holds=int(os.environ.get(ENV_MAX_OPEN_HOLDS, DEFAULT_MAX_OPEN_HOLDS)),
        witness=(WitnessLog(os.environ["GARGOYLE_WITNESS_PATH"], Ed25519PrivateKey.from_private_bytes(bytes.fromhex(required[ENV_ISSUER_KEY_HEX])),
                            required[ENV_ISSUER_KEY_ID]) if os.environ.get("GARGOYLE_WITNESS_PATH") else None),
        log_events=(lambda e: sys.stderr.write(json.dumps(e, sort_keys=True) + "\n")) if os.environ.get("GARGOYLE_LOG_JSON") else None,
        approver_registry=ApproverRegistry(os.environ.get(ENV_APPROVERS_PATH)),
        approver_role=os.environ.get(ENV_APPROVER_ROLE, DEFAULT_APPROVER_ROLE),
        approver_groups=[g.strip() for g in os.environ.get(ENV_APPROVER_GROUPS, "").split(",") if g.strip()] or None,
        tenant=tenant_id,
        tenant_key_ids=set(tenant_keys) if tenant else None,
        console_entra=({"tenant": tenant, "client_id": os.environ[ENV_CONSOLE_CLIENT_ID],
                        "scope": os.environ.get(ENV_CONSOLE_SCOPE) or "api://%s/access" % (os.environ.get(ENV_AUDIENCE) or "").split(",")[-1].strip()}
                       if tenant and os.environ.get(ENV_CONSOLE_CLIENT_ID) else None),
    )
