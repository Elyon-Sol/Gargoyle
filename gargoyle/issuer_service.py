# SPDX-License-Identifier: Apache-2.0
"""The issuing service: an HTTP front for gargoyle.issuer that a middleware
or an agent harness calls to obtain receipts, with the hold and grant
exchange for flagged calls.

    POST /issue             Bearer <identity token>; body {target_url, tool, args, claims?}
                            -> {"issued": true, "envelope": ...}
                             | {"issued": false, "reason": ...}
    GET  /pending           Bearer; flagged receipts still waiting for a grant, each with
                            the full arguments the issuer saw, so a reviewer can read what
                            they are releasing (the receipt's args_sha256 binds them), a
                            plain-language `summary` (gargoyle.holdtext) and whether the
                            caller's roles make them `eligible` to release it
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

import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Any, Callable, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response

STATIC = Path(__file__).resolve().parent / "static"

from gargoyle.approval import (REF_APPROVAL_APPROVER_NOT_ELIGIBLE, REF_APPROVAL_DUPLICATE_APPROVER,
                               REF_APPROVAL_ROLE_NOT_ELIGIBLE, attest_roles, verify_grant)
from gargoyle.envelope import approval_terms
from gargoyle.holdtext import describe_hold, describe_plan, request_fields
from gargoyle.emilia import EMILIA_MEMBER, verify_embedded_signoff
from gargoyle.state import state_sha256, text_consistent, valid_description
from gargoyle.holdstore import ENV_HOLDS_PATH, HoldStore
from gargoyle.witness import WitnessLog
from gargoyle.plans import (REF_PLAN_MALFORMED, REF_PLAN_STEP_NOT_PLANNABLE, REF_PLAN_STEP_REFUSED, build_plan,
                            sign_plan, valid_step)
from gargoyle.notify import notifier_from_env
from gargoyle.approvers import (DEFAULT_APPROVER_ROLE, ENV_APPROVER_GROUPS, ENV_APPROVER_ROLE, ENV_APPROVERS_PATH,
                                ApproverRegistry, RevokedKeyError, may_enroll, valid_public_key_hex)
from gargoyle.identity import ENTRA_ISSUER, _trusted_url, entra_keys, entra_tenant_id, oidc_discovery, oidc_keys, principal_from_token, provider
from gargoyle.jws import REF_JWS_KEY_UNKNOWN
from gargoyle.published_record_source import sign_published_record
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
ENV_OIDC_ISSUER = "GARGOYLE_OIDC_ISSUER"          # one or more OpenID Connect issuer URLs, comma-separated; keys come from discovery
ENV_CLAIM_NAME = "GARGOYLE_CLAIM_NAME"            # claims tried in order for the readable name (default preferred_username, upn, sub)
ENV_CLAIM_DISPLAY_NAME = "GARGOYLE_CLAIM_DISPLAY_NAME"   # the printed name (default name)
ENV_CLAIM_ROLES = "GARGOYLE_CLAIM_ROLES"          # default roles
ENV_CLAIM_GROUPS = "GARGOYLE_CLAIM_GROUPS"        # default groups
ENV_OIDC_CLIENT_ID = "GARGOYLE_OIDC_CLIENT_ID"    # the public client the approval console signs in with at the OIDC provider
ENV_OIDC_SCOPE = "GARGOYLE_OIDC_SCOPE"            # default "openid profile"
ENV_OIDC_CONSOLE_ISSUER = "GARGOYLE_OIDC_CONSOLE_ISSUER"   # which trusted provider the console uses (default: the first)
ENV_OIDC_LABEL = "GARGOYLE_OIDC_LABEL"            # the name on the console's sign-in button (default: the provider's host name)
ENV_RELEASE_MAX_AUTH_AGE = "GARGOYLE_RELEASE_MAX_AUTH_AGE"   # seconds: an enrolled approver's sign-in may be at most this old when they release
ENV_CLAIM_SUBJECT = "GARGOYLE_CLAIM_SUBJECT"      # the permanent id (default sub; oid for a login.microsoftonline.com issuer)
ENV_APPROVER_KEY_ID = "GARGOYLE_APPROVER_KEY_ID"
ENV_APPROVER_PUBLIC_KEY_HEX = "GARGOYLE_APPROVER_PUBLIC_KEY_HEX"
ENV_RECEIPT_TTL = "GARGOYLE_RECEIPT_TTL_SECONDS"
ENV_CONSOLE_CLIENT_ID = "GARGOYLE_ENTRA_CLIENT_ID"   # the public client app the console signs in with (User-Client-Flow)
ENV_CONSOLE_SCOPE = "GARGOYLE_ENTRA_SCOPE"           # default api://<last audience>/access
ENV_MAX_OPEN_HOLDS = "GARGOYLE_MAX_OPEN_HOLDS"       # holds one principal may have waiting at once
ENV_DECLINE_LIMIT = "GARGOYLE_DECLINE_LIMIT"           # declines of one (principal, tool, path) within the window before the issuer stops asking; 0 disables
ENV_DECLINE_WINDOW_HOURS = "GARGOYLE_DECLINE_WINDOW_HOURS"
ENV_ALLOW_SELF_APPROVAL = "GARGOYLE_ALLOW_SELF_APPROVAL"   # "1": a person may release their own call (default: refused)
DEFAULT_MAX_OPEN_HOLDS = 20
DEFAULT_DECLINE_LIMIT = 2
DEFAULT_DECLINE_WINDOW_HOURS = 24.0

REF_ISSUER_UNAUTHENTICATED = "REF_ISSUER_UNAUTHENTICATED"
REF_ISSUER_BAD_REQUEST = "REF_ISSUER_BAD_REQUEST"
REF_ISSUER_ARGS_NOT_TEXT = "REF_ISSUER_ARGS_NOT_TEXT"   # arguments carry characters no UTF-8 text has
REF_ISSUER_UNKNOWN_HOLD = "REF_ISSUER_UNKNOWN_HOLD"
REF_ISSUER_NO_APPROVER_TRUST = "REF_ISSUER_NO_APPROVER_TRUST"
REF_ISSUER_NOT_AN_APPROVER = "REF_ISSUER_NOT_AN_APPROVER"   # enrollment without the approver role or group
REF_ISSUER_FORBIDDEN = "REF_ISSUER_FORBIDDEN"               # authenticated, but not an approver and not the hold's own principal
REF_ISSUER_TOO_MANY_HOLDS = "REF_ISSUER_TOO_MANY_HOLDS"     # the principal already has the cap's worth of holds waiting
REF_ISSUER_DECLINED_RECENTLY = "REF_ISSUER_DECLINED_RECENTLY"  # the same principal, tool and path were declined too often lately; no new card
REF_ISSUER_KEY_REVOKED = "REF_ISSUER_KEY_REVOKED"           # enrollment offered a key that was revoked; a new key is needed
REF_ISSUER_KEY_ENROLLED = "REF_ISSUER_KEY_ENROLLED"          # another key is enrolled for this account; it must consent, or the operator revoke it
REF_ISSUER_HOLD_EXPIRED = "REF_ISSUER_HOLD_EXPIRED"          # the hold's receipt or plan expired; nothing can release it now
REF_ISSUER_SELF_APPROVAL = "REF_ISSUER_SELF_APPROVAL"        # the approver is the hold's requester (or the party acted for)
REF_ISSUER_SUBJECT_MISMATCH = "REF_ISSUER_SUBJECT_MISMATCH"  # the readable name is enrolled to a different person (another issuer or subject)
REF_ISSUER_AUTH_TIME_MISSING = "REF_ISSUER_AUTH_TIME_MISSING"  # a sign-in age rule is set and the token does not say when the person signed in
REF_ISSUER_AUTH_TOO_OLD = "REF_ISSUER_AUTH_TOO_OLD"            # the person signed in longer ago than the rule allows; sign in again
AUTH_TIME_SKEW_SECONDS = 60                                    # how far ahead of this service's clock a sign-in time may be
REF_ISSUER_STATE_TEXT_MISMATCH = "REF_ISSUER_STATE_TEXT_MISMATCH"  # the state text is not the bytes the state hash names


SUPERSEDE_PREFIX = b"gargoyle-enroll/1\n"


def supersede_message(new_public_key_hex: str) -> bytes:
    """What an enrolled key signs to hand its account to a new key."""
    return SUPERSEDE_PREFIX + new_public_key_hex.encode("ascii")


def _supersedes(current_hex: str, signature_hex: Any, new_hex: str) -> bool:
    """Does `signature_hex` (Ed25519, by the key `current_hex`) consent to `new_hex`?"""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(signature_hex, str) or len(signature_hex) != 128:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(current_hex)).verify(bytes.fromhex(signature_hex), supersede_message(new_hex))
        return True
    except (InvalidSignature, ValueError):
        return False


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
    decline_limit: int = DEFAULT_DECLINE_LIMIT,
    decline_window_hours: float = DEFAULT_DECLINE_WINDOW_HOURS,
    idp_key_refresh: Optional[Callable[[], Dict[str, Any]]] = None,
    allow_self_approval: bool = False,
    providers: Optional[List[Dict[str, Any]]] = None,
    release_max_auth_age: Optional[int] = None,
    console_oidc: Optional[Dict[str, Any]] = None,
) -> FastAPI:
    """`on_hold(envelope, args)` is called once for every new hold (gargoyle.notify
    posts it to a webhook); it is notice, not admission, and its failure
    never affects the hold. `idp_key_refresh()` returns the identity
    provider's current signing keys {kid: key}; it is called, at most once a
    minute, when a token names a kid the service does not know, so a key the
    directory rolled after startup is picked up without a restart.
    `providers` (gargoyle.identity.provider) are the OpenID Connect
    providers trusted: each owns its key ids, and a token under one of them
    must name that provider in `iss`. `release_max_auth_age` (seconds)
    makes an enrolled approver's release depend on how recently they
    signed in: the token's `auth_time` must be present and no older."""
    # The trusted identity keys are held in a dict this app owns: a refresh adds to them.
    idp_public_keys = dict(idp_public_keys)
    providers = [{**p, "key_ids": set(p["key_ids"])} for p in (providers or [])]
    owned: Dict[str, str] = {}
    for p in providers:
        for k in p["key_ids"]:
            if k in owned:
                # One key id, two providers: the key could not say which of them signed.
                raise ValueError("identity providers %s and %s both claim key id %r" % (owned[k], p["issuer"], k))
            owned[k] = p["issuer"]
    tenant_key_ids = set(tenant_key_ids) if tenant_key_ids is not None else None
    key_refreshed_at: list = [None]
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
    app.state.declined_why = store.dict("declined_why")   # approval_request_id -> the approver's words, for the submitter
    app.state.recent_declines = store.dict("recent_declines")  # decline key -> [{"at", "why"}], the cooldown's memory
    app.state.pending_plans = store.dict("pending_plans") # approval_request_id -> signed plan (gargoyle.plans)
    app.state.pending_about = store.dict("pending_about") # approval_request_id -> who asked for what, in words (for the witness)
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

    def _revoked_marks(entries: Dict[str, Dict[str, Any]]):
        # One mark per revocation, not per account: an account revoked,
        # re-enrolled and revoked again is two events (2026-10-30: the
        # second and third operator revokes of one approver went unwitnessed).
        return {(upn, e.get("public_key_hex"), e.get("revoked_at")) for upn, e in entries.items()}

    app.state.revoked_seen = _revoked_marks(registry.revoked_entries())

    def _notice_revocations() -> None:
        """An operator's `gargoyle approvers revoke` edits the file on the
        host; the first read after it puts a `revoked` entry in the witness,
        so the record shows who was trusted when. Revocations the service
        made itself were witnessed as they happened."""
        current = registry.revoked_entries()
        marks = _revoked_marks(current)
        for upn, _key, _at in sorted(marks - app.state.revoked_seen, key=lambda m: (m[0], m[2] or "")):
            event("revoked", approver=upn, by=current[upn].get("revoked_by"), revoked_at=current[upn].get("revoked_at"))
        app.state.revoked_seen = marks

    def approver_keys() -> Dict[str, Any]:
        _notice_revocations()
        """Static keys from configuration plus every enrolled approver, by UPN."""
        return {**static_approvers, **registry.keys()}

    def is_approver(who: Dict[str, Any]) -> bool:
        """May this identity see every hold and the witness: the approver role
        or group in today's token, or a configured approver key id. An
        enrolled key alone does not count: the directory decides who is an
        approver now, the registry only remembers which key is theirs."""
        upn = who["principal"]
        return may_enroll(who, role=approver_role, groups=approver_groups) or upn in static_approvers

    def _enrolled_speaks_for(who: Dict[str, Any], approver_key_id: str) -> bool:
        """May a grant under this key id be posted by `who`? A configured
        (static) key is trusted by configuration. An enrolled key releases a
        hold only when posted by its own account, under a token that still
        carries the approver role or group: losing the role ends the power
        at once, whatever key record remains (second review, finding 2)."""
        if approver_key_id in static_approvers or approver_key_id not in registry:
            return True
        return who["principal"] == approver_key_id and may_enroll(who, role=approver_role, groups=approver_groups)

    def hold_owner(arid: str) -> Optional[str]:
        """The principal whose call is held under `arid` (a hold or a plan), or None."""
        env = app.state.pending.get(arid)
        if env is not None:
            return env.get("request_context", {}).get("principal")
        plan = app.state.pending_plans.get(arid)
        return plan.get("principal") if plan is not None else None

    def decline_keys(principal: Optional[str], tool: Any, args: Any) -> List[str]:
        """What a decline is remembered by: the principal, the tool and the
        path it named (normalized as the rules compare it), so the next card
        for the same thing is not opened. A call with no path is not
        remembered: the cooldown is for one file asked for again and again."""
        from gargoyle.globs import normalize_path
        if not principal or not isinstance(tool, str) or not isinstance(args, dict):
            return []
        keys = []
        for k in ("path", "source", "file_path", "destination"):
            if isinstance(args.get(k), str) and args[k]:
                keys.append(hashlib.sha256(("%s|%s|%s" % (principal, tool, normalize_path(args[k]))).encode("utf-8")).hexdigest())
                break
        return keys

    def remember_decline(arid: str, why: Optional[str]) -> None:
        owner = hold_owner(arid)
        at = now().isoformat()
        targets = []
        if arid in app.state.pending:
            targets.append((app.state.pending[arid].get("request_context", {}).get("tool"), app.state.pending_args.get(arid)))
        plan = app.state.pending_plans.get(arid)
        if plan is not None:
            targets += [(s.get("tool"), s.get("args")) for s in plan.get("steps", []) if isinstance(s, dict)]
        for tool, args in targets:
            for key in decline_keys(owner, tool, args):
                had = [d for d in app.state.recent_declines.get(key, []) if _within_window(d.get("at"))]
                had.append({"at": at, "why": why})
                app.state.recent_declines[key] = had[-10:]

    def _within_window(at: Any) -> bool:
        try:
            return (now() - datetime.fromisoformat(at)).total_seconds() <= decline_window_hours * 3600
        except (TypeError, ValueError):
            return False

    def declined_recently(principal: str, tool: str, args: Any) -> Optional[Dict[str, Any]]:
        """The cooldown: when this principal has had this tool on this path
        declined `decline_limit` times inside the window, the issuer opens
        no new card and tells the client why (the last words the approver
        gave). Zero disables it. The approver's attention is the scarce
        thing here; a third card for the same file is fatigue, not review."""
        if decline_limit <= 0:
            return None
        for key in decline_keys(principal, tool, args):
            recent = [d for d in app.state.recent_declines.get(key, []) if _within_window(d.get("at"))]
            if len(recent) >= decline_limit:
                whys = [d.get("why") for d in recent if d.get("why")]
                return {"count": len(recent), "why": whys[-1] if whys else None, "last_at": recent[-1].get("at")}
        return None

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

    def _refresh_idp_keys() -> bool:
        """Fetch the identity providers' keys again (an unknown kid is how a
        key roll shows up), at most once a minute. True when new keys came.
        A provider's answer is adopted for its own key ids and for ids
        nobody holds yet; it never replaces a key another provider, the
        tenant or the configuration put there."""
        sources = [p for p in providers if p.get("refresh") is not None]
        if idp_key_refresh is None and not sources:
            return False
        current = now()
        last = key_refreshed_at[0]
        if last is not None and (current - last).total_seconds() < 60:
            return False
        key_refreshed_at[0] = current
        import sys
        added = False
        if idp_key_refresh is not None:
            try:
                fresh = idp_key_refresh()
            except Exception as exc:
                sys.stderr.write("gargoyle: identity key refresh failed: %s\n" % exc)
                fresh = {}
            fresh = {k: v for k, v in fresh.items() if not any(k in p["key_ids"] for p in providers)}
            added = any(k not in idp_public_keys for k in fresh)
            idp_public_keys.update(fresh)
            if tenant_key_ids is not None:
                tenant_key_ids.update(fresh)
        for p in sources:
            try:
                fresh = p["refresh"]()
            except Exception as exc:
                sys.stderr.write("gargoyle: key refresh for %s failed: %s\n" % (p["issuer"], exc))
                continue
            for k, v in fresh.items():
                if k in p["key_ids"] or k not in idp_public_keys:
                    added = added or k not in idp_public_keys
                    idp_public_keys[k] = v
                    p["key_ids"].add(k)
        return added

    def _identify(token: str) -> Dict[str, Any]:
        return principal_from_token(token, idp_public_keys, audience=audience, now=now(), tenant=tenant,
                                    tenant_key_ids=tenant_key_ids, providers=providers)

    def _ids(who: Dict[str, Any]) -> Dict[str, Any]:
        """Who asked, by permanent id (gargoyle-witness/3): beside the readable name, never instead of it."""
        return {"principal_id": who["subject_id"], **({"on_behalf_of_id": who["on_behalf_of_id"]} if who.get("on_behalf_of_id") else {})}

    def _same_person(name: str, who: Dict[str, Any]) -> bool:
        """Is `who` the person `name` was when its key was enrolled? Compared
        by permanent id: the issuer and subject, or the directory object id
        on an entry enrolled before ids were kept. A directory can hand a
        sign-in name to someone new; the key stays with the first person.
        An entry with no id on record has nothing to compare."""
        entry = registry.entries().get(name) or {}
        if entry.get("subject_id"):
            return entry["subject_id"] == who["subject_id"]
        if entry.get("oid"):
            return entry["oid"] == who.get("oid")
        return True

    def _signed_in(who: Dict[str, Any]) -> Dict[str, Any]:
        """When the person last signed in, when their token says (`auth_time`),
        and how long ago that was by this service's clock. The age is not
        tidied: a negative one says the provider's clock is ahead of ours,
        which a reader of the record needs to see."""
        at = who["claims"].get("auth_time")
        if not isinstance(at, int) or isinstance(at, bool):
            return {}
        return {"auth_time": at, "auth_age_seconds": int(now().timestamp()) - at}

    def _age_rule(approver_key_id: Any) -> Dict[str, Any]:
        """The sign-in age limit, on an entry about a release it applies to:
        one under an enrolled approver's key, while a limit is set."""
        if (release_max_auth_age is None or not isinstance(approver_key_id, str)
                or approver_key_id in static_approvers or approver_key_id not in registry):
            return {}
        return {"auth_max_age_seconds": release_max_auth_age}

    def authenticate(authorization: Optional[str]) -> Dict[str, Any]:
        if not authorization or not authorization.startswith("Bearer "):
            raise _refuse(401, REF_ISSUER_UNAUTHENTICATED)
        token = authorization[7:].strip()
        who = _identify(token)
        if who["reason"] == REF_JWS_KEY_UNKNOWN and _refresh_idp_keys():
            who = _identify(token)
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
        # The policy sees the identity provider's groups and roles; the receipt
        # binds only the call and the principal (and the token's delegation).
        # Anything the caller asserts in `claims` is kept apart under
        # interaction["claims"]: it never sets principal, on_behalf_of,
        # groups, roles or the state hash, which come from the token and the
        # described state alone (second review, finding 3).
        interaction = {"tool": body["tool"], "args": body["args"],
                       "principal": who["principal"], "groups": who.get("groups", []),
                       "roles": who.get("roles", [])}
        if body.get("claims"):
            interaction["claims"] = dict(body["claims"])
        state = body.get("state")
        if state is not None:
            # The executor's description of the target before the call: its
            # hash is bound into the receipt; the description is shown to
            # the approver and seen by the policy.
            if not valid_description(state):
                raise _refuse(400, REF_ISSUER_BAD_REQUEST)
            if not text_consistent(state):
                # The text shown to the approver must hash to the bound state.
                raise _refuse(400, REF_ISSUER_STATE_TEXT_MISMATCH)
            interaction["state_sha256"] = state_sha256(state)
            interaction["state"] = {k: v for k, v in state.items() if k != "text"}
        if who["on_behalf_of"]:
            interaction["on_behalf_of"] = who["on_behalf_of"]
        result = issue(policy, body["target_url"], interaction, signing_key=signing_key, key_id=key_id,
                       ttl_seconds=ttl_seconds, now=now())
        # What was asked, in the card's words and the paths it names, never the
        # payload: recorded on a refusal exactly as on a hold (issue #31), so a
        # quarter's refusals read as "Create run.ps1 in it-scripts: refused by
        # rule" and not as a tool name.
        asked = {"summary": describe_hold(body["tool"], body["args"], state)["sentence"],
                 "request": request_fields(body["tool"], body["args"])}
        if result.envelope is None:
            event("refused", principal=who["principal"], **_ids(who), tool=body["tool"], reason=result.decision.reason,
                  target_url=body["target_url"], policy=policy.pin(), **asked)
            return {"issued": False, "reason": result.decision.reason}
        covered = False
        plan_id = body.get("plan_id")
        if result.envelope["requires_approval"] and isinstance(plan_id, str) and result.decision.plannable:
            # The executor says an approved plan covers this call. No card then,
            # provided the plan's grants meet this receipt's own terms (as many
            # signatures, from its named approvers): the executor enforces the
            # same, so a hold here would be one nobody needs to act on. A call
            # the policy keeps individual is never covered. A false claim costs
            # nothing: without a valid release the executor refuses the call.
            from gargoyle.plans import grants_satisfy, match_step
            env_terms = approval_terms(result.envelope)
            for arid_p, plan in app.state.pending_plans.items():
                if (plan["plan_id"] == plan_id and _complete(arid_p) and match_step(plan, body["tool"], body["args"]) is not None
                        and grants_satisfy(env_terms, [g["approver_key_id"] for g in app.state.grants.get(arid_p, [])])):
                    covered = True
                    break
        cooled = declined_recently(who["principal"], body["tool"], body["args"]) if result.envelope["requires_approval"] and not covered else None
        if cooled is not None:
            event("refused", principal=who["principal"], **_ids(who), tool=body["tool"], reason=REF_ISSUER_DECLINED_RECENTLY,
                  declines=cooled["count"], target_url=body["target_url"], policy=result.envelope["policy"], **asked, **({"why": cooled["why"]} if cooled["why"] else {}))
            return {"issued": False, "reason": REF_ISSUER_DECLINED_RECENTLY, "why": cooled["why"], "declines": cooled["count"]}
        if result.envelope["requires_approval"] and not covered and _open_holds(who["principal"]) >= max_open_holds:
            # A service limit, not a policy decision: nothing is stored, the
            # signed envelope is dropped, the client reports the reason.
            event("refused", principal=who["principal"], **_ids(who), tool=body["tool"], reason=REF_ISSUER_TOO_MANY_HOLDS,
                  target_url=body["target_url"], policy=result.envelope["policy"], **asked)
            return {"issued": False, "reason": REF_ISSUER_TOO_MANY_HOLDS}
        about: Dict[str, Any] = {}
        if result.envelope["requires_approval"] and not covered:
            # The witness says what was asked, not only that something was:
            # the same sentence the card shows, and the paths, never the
            # payload (the hash binds that). A declined move reads as a
            # declined move of a named file a quarter later.
            about = asked
        event("issued", principal=who["principal"], **_ids(who), tool=body["tool"], held=bool(result.envelope["requires_approval"]),
              **({"oid": who["oid"]} if who.get("oid") else {}), **about,
              policy=result.envelope["policy"],      # which policy version decided; since gargoyle-witness/2 (the Acta export reads it)
              target_url=body["target_url"],         # one issuer, several gates: an audit of one gate's log skips the others' receipts
              covered=covered, state_bound=state is not None,   # whether the receipt binds the target's state (asked by the 2026-11-01 soak)
              decision_id=result.envelope.get("decision_id"), decision_sha256=result.envelope["decision_sha256"],
              approval_request_id=result.envelope.get("approval_request_id"), args_sha256=result.envelope["request_context"]["args_sha256"])
        if result.envelope["requires_approval"] and not covered:
            arid = result.envelope["approval_request_id"]
            app.state.pending[arid] = result.envelope
            app.state.pending_args[arid] = body["args"]
            app.state.pending_about[arid] = {"requested_by": who["principal"], "requested_by_id": who["subject_id"],
                                             **({"requested_for_id": who["on_behalf_of_id"]} if who.get("on_behalf_of_id") else {}),
                                             "tool": body["tool"], "target_url": body["target_url"], **about}
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
        norm, held, required, approvers, role_sets = [], False, 1, set(), []
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
                if "match" in step:
                    # A pattern step is judged by the strictest rule any call
                    # matching it could reach (gargoyle.rules.decide_rules_pattern).
                    # A policy that cannot judge patterns keeps them out of plans.
                    decide_pattern = getattr(policy, "decide_pattern", None)
                    if decide_pattern is None:
                        return {"issued": False, "reason": REF_PLAN_STEP_NOT_PLANNABLE, "step": len(norm)}
                    d = decide_pattern(body["target_url"], interaction)
                else:
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
                if d.approver_roles:
                    role_sets.append(set(d.approver_roles))
            norm.append(step)
        if held and _open_holds(who["principal"]) >= max_open_holds:
            event("refused", principal=who["principal"], **_ids(who), tool="plan", reason=REF_ISSUER_TOO_MANY_HOLDS, steps=len(norm),
                  **({"target_url": body["target_url"]} if isinstance(body.get("target_url"), str) else {}))
            return {"issued": False, "reason": REF_ISSUER_TOO_MANY_HOLDS}
        import uuid
        approval = None
        roles = set.intersection(*role_sets) if role_sets else set()
        if role_sets and not roles:
            # Steps routed to disjoint roles: no one approver may release the whole plan.
            return {"issued": False, "reason": REF_PLAN_STEP_NOT_PLANNABLE}
        if required > 1 or approvers or roles:
            approval = {"required": required, **({"approvers": sorted(approvers)} if approvers else {}),
                        **({"roles": sorted(roles)} if roles else {})}
        plan = sign_plan(build_plan(plan_id=str(uuid.uuid4()), approval_request_id=str(uuid.uuid4()), target_url=body["target_url"],
                                    principal=who["principal"], policy_pin=policy.pin(), steps=norm,
                                    not_after=now() + timedelta(seconds=min(ttl_seconds * 6, 3600)), note=body.get("note", ""),
                                    approval=approval), signing_key, key_id)
        about = {}
        if held:
            app.state.pending_plans[plan["approval_request_id"]] = plan
            about = {"summary": describe_plan(plan)["sentence"],
                     "request": {"steps": [{"tool": st.get("tool"), **request_fields(st.get("tool"), st.get("args") if isinstance(st.get("args"), dict) else st.get("match"))}
                                           for st in steps if isinstance(st, dict)]}}
            app.state.pending_about[plan["approval_request_id"]] = {"requested_by": who["principal"], "requested_by_id": who["subject_id"],
                                                                    "tool": "plan", "target_url": body["target_url"],
                                                                    "plan_id": plan["plan_id"], **about}
        event("plan", principal=who["principal"], **_ids(who), steps=len(norm), held=held, plan_id=plan["plan_id"], policy=plan.get("policy"), **about)
        return {"issued": True, "plan": plan, "held": held}

    def _plan_terms(plan):
        return approval_terms({"approval": plan["approval"]} if "approval" in plan else {})

    def _roles_held(who: Dict[str, Any], terms: Dict[str, Any]) -> list:
        """The receipt's `approval.roles` this identity's token carries (all
        of them when the receipt names none): the routing check."""
        wanted = terms.get("roles")
        mine = [r for r in (who.get("roles") or []) if isinstance(r, str)]
        return mine if not wanted else [r for r in mine if r in wanted]

    def _eligible(who: Dict[str, Any], terms: Dict[str, Any]) -> bool:
        return not terms.get("roles") or bool(_roles_held(who, terms))

    def _week(entries, kind: str, current: datetime):
        since = (current - timedelta(days=7)).isoformat()
        return [e for e in entries if e.get("event") == kind and isinstance(e.get("at"), str) and e["at"] >= since]

    def _week_stats(current: datetime, approver: Optional[str] = None) -> Dict[str, Any]:
        """Holds and releases over the last seven days from the witness, for
        the console's "you released N holds this week" and a monitor's view
        of approval load: the prompt to add a rule or a scoped grant."""
        entries = list(witness.entries) if witness is not None else []
        held = [e for e in _week(entries, "issued", current) if e.get("held") and not e.get("covered")]
        granted = _week(entries, "granted", current)
        if approver is not None:
            granted = [e for e in granted if e.get("approver") == approver]
        held_at = {e.get("approval_request_id"): e.get("at") for e in held}
        waits = []
        for e in granted:
            at = held_at.get(e.get("approval_request_id"))
            if at and e.get("collected", 1) >= e.get("required", 1):
                try:
                    waits.append((datetime.fromisoformat(e["at"]) - datetime.fromisoformat(at)).total_seconds())
                except (ValueError, TypeError):
                    pass
        waits.sort()
        by_tool: Dict[str, int] = {}
        for e in granted:
            tool = next((h.get("tool") for h in held if h.get("approval_request_id") == e.get("approval_request_id")), None)
            by_tool[tool or "?"] = by_tool.get(tool or "?", 0) + 1
        out = {"held_7d": len(held), "released_7d": len(granted), "released_by_tool_7d": by_tool,
               "median_release_seconds": (waits[len(waits) // 2] if waits else None)}
        if approver is None:
            by_role: Dict[str, int] = {}
            for e in granted:
                for r in e.get("roles") or ["*"]:
                    by_role[r] = by_role.get(r, 0) + 1
            out["released_by_role_7d"] = by_role
        return out

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
                _forget(arid)
            elif len(app.state.grants.get(arid, [])) < _plan_terms(plan)["required"]:
                if not sees_all and plan.get("principal") != who["principal"]:
                    continue
                have = app.state.grants.get(arid, [])
                live[arid] = {"plan": plan, "collected": len(have), "required": _plan_terms(plan)["required"],
                              "approvers": [g["approver_key_id"] for g in have],
                              "summary": describe_plan(plan), "eligible": _eligible(who, _plan_terms(plan))}
        for arid, env in list(app.state.pending.items()):
            if datetime.fromisoformat(env["not_after"]) <= current:
                _forget(arid)                         # an expired hold can never be released
            elif not _complete(arid):
                if not sees_all and env.get("request_context", {}).get("principal") != who["principal"]:
                    continue
                have = app.state.grants.get(arid, [])
                args, st = app.state.pending_args.get(arid), app.state.pending_state.get(arid)
                live[arid] = {"envelope": env, "args": args, "state": st,
                              "collected": len(have), "required": approval_terms(env)["required"],
                              "approvers": [g["approver_key_id"] for g in have],
                              "summary": describe_hold(env.get("request_context", {}).get("tool"), args, st),
                              "eligible": _eligible(who, approval_terms(env))}
        return {"pending": list(live.values())}

    def _about(arid: Any) -> Dict[str, Any]:
        """Who asked for the hold and for what, to put on the entry that
        answers it, so a release or a decline reads on its own."""
        a = app.state.pending_about.get(arid) if isinstance(arid, str) else None
        return dict(a) if isinstance(a, dict) else {}

    def _forget(arid: str) -> None:
        """Drop a hold or plan and everything kept for it."""
        app.state.pending.pop(arid, None)
        app.state.pending_about.pop(arid, None)
        app.state.pending_args.pop(arid, None)
        app.state.pending_state.pop(arid, None)
        app.state.pending_plans.pop(arid, None)
        app.state.grants.pop(arid, None)

    def _complete(arid: str) -> bool:
        env = app.state.pending.get(arid)
        if env is None:
            plan = app.state.pending_plans.get(arid)
            return plan is not None and len(app.state.grants.get(arid, [])) >= _plan_terms(plan)["required"]
        return len(app.state.grants.get(arid, [])) >= approval_terms(env)["required"]

    @app.post("/grants")
    async def post_grant(request: Request, authorization: Optional[str] = Header(default=None)):
        who = authenticate(authorization)
        try:
            grant = await request.json()
        except Exception:
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        arid = grant.get("approval_request_id") if isinstance(grant, dict) else None
        env = app.state.pending.get(arid) if isinstance(arid, str) else None
        plan = app.state.pending_plans.get(arid) if isinstance(arid, str) else None
        if env is None and plan is None:
            return {"accepted": False, "reason": REF_ISSUER_UNKNOWN_HOLD}
        def refused(reason: str) -> Dict[str, Any]:
            # A release that did not happen is a decision too: a revoked or
            # unknown key trying to release a hold belongs in the witness.
            kid = grant.get("approver_key_id")
            event("grant_refused", approval_request_id=arid, reason=reason, **({"approver": kid} if isinstance(kid, str) else {}),
                  posted_by=who["principal"], posted_by_id=who["subject_id"], **_signed_in(who), **_age_rule(kid), **_about(arid))
            return {"accepted": False, "reason": reason}
        if datetime.fromisoformat((env or plan)["not_after"]) <= now():
            # An expired hold can never be released: the executor refuses the
            # receipt whatever the grant says, so accepting one here would
            # only tell the approver that something ran. Drop it now, not on
            # the next listing (second review, finding 10).
            _forget(arid)
            return refused(REF_ISSUER_HOLD_EXPIRED)
        trusted = approver_keys()
        if not trusted:
            return refused(REF_ISSUER_NO_APPROVER_TRUST)
        g = verify_grant(grant, expected_decision_sha256=env["decision_sha256"] if env else plan["plan_sha256"],
                         expected_approval_request_id=arid, approver_public_keys=trusted,
                         gate_key_id=key_id, now=now())
        if not g["accepted"]:
            return refused(g["reason"])
        # An enrolled key belongs to a person; a configured (static) key to the configuration.
        enrolled = grant["approver_key_id"] not in static_approvers and grant["approver_key_id"] in registry
        if enrolled and who["principal"] == grant["approver_key_id"] and not _same_person(grant["approver_key_id"], who):
            # The name matches and the person does not: the directory gave
            # this sign-in name to someone else after the key was enrolled.
            return refused(REF_ISSUER_SUBJECT_MISMATCH)
        if not _enrolled_speaks_for(who, grant["approver_key_id"]):
            return refused(REF_ISSUER_NOT_AN_APPROVER)
        if enrolled and release_max_auth_age is not None:
            # A release is the person's act now, not the act of whoever holds
            # a token they obtained this morning: the provider's own statement
            # of when they signed in (`auth_time`, OpenID Connect Core 2) must
            # be there and recent. A time ahead of this clock is no statement.
            at = who["claims"].get("auth_time")
            age = int(now().timestamp()) - at if isinstance(at, int) and not isinstance(at, bool) else None
            if age is None or age < -AUTH_TIME_SKEW_SECONDS:
                return refused(REF_ISSUER_AUTH_TIME_MISSING)
            if age > release_max_auth_age:
                return refused(REF_ISSUER_AUTH_TOO_OLD)
        if not allow_self_approval:
            # Two people: the one asking and the one releasing. The approver
            # key id (a UPN for an enrolled key) may be neither the hold's
            # principal nor the party it acts for (second review, finding 8).
            parties = {hold_owner(arid)}
            if env is not None:
                parties.add((env.get("request_context") or {}).get("on_behalf_of"))
            # And by permanent id: a second sign-in name for the same person is still that person.
            party_ids = [i for i in (_about(arid).get("requested_by_id"), _about(arid).get("requested_for_id")) if i]
            if grant["approver_key_id"] in parties or (enrolled and who["subject_id"] in party_ids):
                return refused(REF_ISSUER_SELF_APPROVAL)
        # The receipt's (or plan's) own terms: distinct approvers, from the named set if any.
        terms = approval_terms(env) if env else _plan_terms(plan)
        have = list(app.state.grants.get(arid, []))
        if any(h["approver_key_id"] == grant["approver_key_id"] for h in have):
            return refused(REF_APPROVAL_DUPLICATE_APPROVER)
        if terms["approvers"] is not None and grant["approver_key_id"] not in terms["approvers"]:
            return refused(REF_APPROVAL_APPROVER_NOT_ELIGIBLE)
        roles_held = _roles_held(who, terms)
        if terms.get("roles") and not roles_held:
            # Routed to a role this token does not carry: the business
            # approver's grant on a technical-only hold, or the reverse.
            return refused(REF_APPROVAL_ROLE_NOT_ELIGIBLE)
        if env is not None and EMILIA_MEMBER in grant:
            # The console's second signature, over the EMILIA Authorization
            # Context for this hold: checked against the hold now so that an
            # export later carries only signoffs the approver actually made.
            s = verify_embedded_signoff(grant, env, trusted.get(grant["approver_key_id"]))
            if not s["accepted"]:
                return refused(s["reason"])
        if terms.get("roles"):
            # The executor cannot see the token; it sees the issuer's signed
            # word that the role was there, bound to this grant.
            grant = dict(grant)
            grant["role_attestation"] = attest_roles(grant, roles_held, signing_key, key_id)
        have.append(grant)
        app.state.grants[arid] = have                      # written back: the store persists on assignment
        if enrolled:
            registry.bind_subject(grant["approver_key_id"], who["subject_id"])     # an entry from before ids were kept learns its person here
            signer = {"approver_id": who["subject_id"], **({"approver_name": who["name"]} if who.get("name") else {})}
        else:
            # A configured key's grant may be carried in by any signed-in party: say who carried it, not who signed.
            signer = {"posted_by": who["principal"], "posted_by_id": who["subject_id"]}
        event("granted", approval_request_id=arid, approver=grant["approver_key_id"], **signer, meaning="approval", **_signed_in(who),
              **_age_rule(grant["approver_key_id"]),
              collected=len(have), required=terms["required"],
              hold_kind="plan" if plan else "receipt", **({"roles": sorted(roles_held)} if terms.get("roles") else {}), **_about(arid))
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
        why = body.get("reason") if isinstance(body, dict) else None
        if not isinstance(arid, str) or (arid not in app.state.pending and arid not in app.state.pending_plans):
            return {"declined": False, "reason": REF_ISSUER_UNKNOWN_HOLD}
        if why is not None and (not isinstance(why, str) or len(why) > 500):
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        if not is_approver(who) and hold_owner(arid) != who["principal"]:
            raise _refuse(403, REF_ISSUER_FORBIDDEN)      # only an approver, or the person whose call it is, may cancel it
        rejection = is_approver(who) and hold_owner(arid) != who["principal"]
        if rejection:
            # A human's decline is remembered; a gate withdrawing its own
            # timed-out hold is not a decision about the file.
            remember_decline(arid, why)
            if why:
                app.state.declined_why[arid] = why
        about = _about(arid)
        app.state.pending_plans.pop(arid, None)
        app.state.pending.pop(arid, None)
        app.state.pending_args.pop(arid, None)
        app.state.pending_state.pop(arid, None)
        app.state.pending_about.pop(arid, None)
        app.state.grants.pop(arid, None)
        app.state.declined.add(arid)
        event("declined", approval_request_id=arid, by=who["principal"], by_id=who["subject_id"],
              **({"by_name": who["name"]} if who.get("name") else {}), meaning="rejection" if rejection else "withdrawal", **_signed_in(who),
              **({"why": why} if why else {}), **about)
        return {"declined": True, "reason": None}

    @app.post("/sidedoors")
    async def sidedoors(request: Request, authorization: Optional[str] = Header(default=None)):
        """A gate's report of the other ways into its files (gargoyle.sidedoors):
        witnessed, so the operator's record names what the rules cannot
        reach, and the console's Activity shows it. Not an admission path:
        nothing is held or released on it."""
        who = authenticate(authorization)
        try:
            body = await request.json()
        except Exception:
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        target = body.get("target_url") if isinstance(body, dict) else None
        findings = body.get("findings") if isinstance(body, dict) else None
        if not isinstance(target, str) or not target or not isinstance(findings, list) or len(findings) > 100:
            raise _refuse(400, REF_ISSUER_BAD_REQUEST)
        clean = []
        for f in findings:
            if not isinstance(f, dict) or not isinstance(f.get("kind"), str) or not isinstance(f.get("path"), str):
                raise _refuse(400, REF_ISSUER_BAD_REQUEST)
            clean.append({"kind": f["kind"][:40], "path": f["path"][:300], "detail": str(f.get("detail") or "")[:200]})
        kinds: Dict[str, int] = {}
        for f in clean:
            kinds[f["kind"]] = kinds.get(f["kind"], 0) + 1
        event("sidedoors", principal=who["principal"], target_url=target, count=len(clean), kinds=kinds, findings=clean)
        return {"recorded": True, "count": len(clean)}

    @app.get("/grants/{approval_request_id}")
    async def get_grant(approval_request_id: str, authorization: Optional[str] = Header(default=None)):
        authenticate(authorization)
        env = app.state.pending.get(approval_request_id) or app.state.pending_plans.get(approval_request_id)
        have = app.state.grants.get(approval_request_id, [])
        complete = _complete(approval_request_id)
        out = {"pending": env is not None,
               "grant": have[0] if complete and len(have) == 1 else None,
               "grants": list(have) if complete else [],
               "collected": len(have), "required": (_plan_terms(env) if env and "plan_version" in env else approval_terms(env))["required"] if env else None,
               "declined": approval_request_id in app.state.declined}
        why = app.state.declined_why.get(approval_request_id) if out["declined"] else None
        if why:
            out["why"] = why                      # the approver's words, for the submitter
        return out

    @app.get("/approvers")
    async def approvers():
        """Public, like /record: the enrolled approvers' public keys by UPN,
        for the middleware and for audits. Static configured keys are not
        listed; they travel in config."""
        _notice_revocations()
        return {"approvers": registry.public_hex()}

    @app.get("/approvers/audit")
    async def approvers_audit():
        """Public, for `gargoyle audit --issuer`: every key each approver has
        held, current first, then replaced and revoked ones. A grant signed
        while a key was trusted still verifies; nothing here admits a key."""
        _notice_revocations()
        return {"approvers": registry.audit_keys_hex()}

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
        if who["principal"] in registry and not _same_person(who["principal"], who):
            # The name is enrolled to someone else. No signature from the old
            # key changes that; the operator revokes the old binding first.
            event("enroll_refused", approver=who["principal"], reason=REF_ISSUER_SUBJECT_MISMATCH, approver_id=who["subject_id"], oid=who.get("oid"))
            raise _refuse(409, REF_ISSUER_SUBJECT_MISMATCH)
        current = registry.public_hex().get(who["principal"])
        if current is not None and current != body["public_key_hex"]:
            # A bearer token alone must not swap the key holds are released
            # with: a second browser's key enrolls only with the first key's
            # signature over it (`supersede_signature`), or after the operator
            # revoked the first (`gargoyle approvers revoke <upn>`).
            if not _supersedes(current, body.get("supersede_signature"), body["public_key_hex"]):
                event("enroll_refused", approver=who["principal"], reason=REF_ISSUER_KEY_ENROLLED, approver_id=who["subject_id"], oid=who.get("oid"))
                raise _refuse(409, REF_ISSUER_KEY_ENROLLED)
        try:
            result = registry.enroll(who["principal"], body["public_key_hex"], now=now(), oid=who.get("oid"), tid=who.get("tid"),
                                     subject_id=who["subject_id"])
        except RevokedKeyError:
            # A revoked key stays revoked, whoever offers it; the console
            # generates a fresh one on this answer.
            event("enroll_refused", approver=who["principal"], reason=REF_ISSUER_KEY_REVOKED, approver_id=who["subject_id"], oid=who.get("oid"))
            raise _refuse(409, REF_ISSUER_KEY_REVOKED)
        event("enrolled", approver=who["principal"], approver_id=who["subject_id"], **({"approver_name": who["name"]} if who.get("name") else {}),
              replaced=result["replaced"], oid=who.get("oid"))
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
            event("revoked", approver=upn, by=who["principal"], by_id=who["subject_id"])
            app.state.revoked_seen = _revoked_marks(registry.revoked_entries())   # witnessed here, not again on the next read
        return {"revoked": gone}

    @app.get("/me")
    async def me(authorization: Optional[str] = Header(default=None)):
        """Who the console is signed in as, whether they may approve, and
        the public key enrolled for them (so the browser can tell whether
        its own key is the one on record)."""
        who = authenticate(authorization)
        upn = who["principal"]
        _notice_revocations()
        return {"principal": upn, "subject_id": who["subject_id"], "name": who.get("name"),
                # When this person signed in, as their token says (None when it does not), and how old the site
                # allows that to be at a release: the console warns up front when the two cannot meet.
                "signed_in_at": _signed_in(who).get("auth_time"), "sign_in_max_age": release_max_auth_age,
                "may_approve": may_enroll(who, role=approver_role, groups=approver_groups) or upn in static_approvers,
                "enrolled_public_key_hex": registry.public_hex().get(upn),
                "roles": [r for r in (who.get("roles") or []) if isinstance(r, str)],
                "approver_role": approver_role,
                **{k: v for k, v in _week_stats(now(), approver=upn).items() if k in ("released_7d", "released_by_tool_7d")}}

    @app.get("/witness")
    async def witness_entries(authorization: Optional[str] = Header(default=None), after: int = 0, limit: int = 0):
        """The issuer's signed witness log, for reconciliation with a client's
        evidence. It names every user's decisions, so it is for approvers.
        `after=<seq>` returns only the entries past that sequence number and
        `limit=<n>` at most the last n of those, so a console that polls
        gets the new lines, not the week; `seq` is the chain's tail."""
        if not is_approver(authenticate(authorization)):
            raise _refuse(403, REF_ISSUER_FORBIDDEN)
        entries = list(witness.entries) if witness is not None else []
        tail = entries[-1]["seq"] if entries else 0
        if after > 0:
            entries = [e for e in entries if e["seq"] > after]
        if limit > 0:
            entries = entries[-limit:]
        return {"entries": entries, "seq": tail}

    @app.get("/health")
    async def health():
        """Public, for a monitor: the service is up, which policy it runs,
        how much is waiting, and since when. No secrets."""
        # Live holds only, as /pending lists them: a completed hold stays in
        # the store until the gate collects its grant or it expires, and a
        # monitor must not read that as work waiting for an approver.
        current = now()
        live = lambda items: sum(1 for arid, item in items if datetime.fromisoformat(item["not_after"]) > current and not _complete(arid))
        return {"ok": True, "policy": policy.pin(), "issuer_key_id": key_id,
                "pending_receipts": live(list(app.state.pending.items())), "pending_plans": live(list(app.state.pending_plans.items())),
                "max_open_holds": max_open_holds,
                "enrolled_approvers": len(registry.public_hex()), "static_approvers": len(static_approvers),
                "entra": bool(console_entra), "persistent": store.path != ":memory:", "started_at": app.state.started_at,
                # The chain's tail, so a client can tell at a glance it talks to the issuer whose
                # witness it will later reconcile against (G7): sequence and entry hash, no content.
                "witness_head": ({"seq": witness.entries[-1].get("seq"), "entry_sha256": witness.entries[-1].get("entry_sha256")}
                                 if witness is not None and witness.entries else None),
                "week": _week_stats(current)}

    @app.get("/approve-config")
    async def approve_config():
        """Public: how the console signs in. `entra` is null when the site
        does not sign approvers in with Entra; `oidc` is present when the
        console signs in at an OpenID Connect provider (console_oidc_from_env).
        Client ids and endpoint addresses only: a public client has no secret."""
        return {"entra": console_entra, **({"oidc": console_oidc} if console_oidc else {})}

    @app.get("/approve")
    async def approve_page():
        return Response((STATIC / "approve.html").read_bytes(), media_type="text/html; charset=utf-8")

    @app.get("/approve.js")
    async def approve_script():
        return Response((STATIC / "approve.js").read_bytes(), media_type="text/javascript; charset=utf-8")

    app.state.record_pin = None
    app.state.record_serial = 0

    @app.get("/record")
    async def record():
        """The live policy pin in the signed published-record form (SPEC 9),
        so a middleware on another host can follow rule changes without a
        file copy: it verifies the issuer's signature with the key it
        already pins. The serial rises whenever the pin changes, so a
        rolled-back record is refused as stale."""
        pin = policy.pin()
        if pin != app.state.record_pin:
            app.state.record_pin = pin
            app.state.record_serial = max(int(now().timestamp()), app.state.record_serial + 1)
        return sign_published_record(pin, signing_key, key_id, serial=app.state.record_serial, now=now(), ttl_seconds=600)

    @app.get("/keys")
    async def keys():
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return {key_id: signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}

    @app.get("/.well-known/acta-keys.json")
    async def acta_keys():
        """The issuer key as a JWK Set (draft-farley-acta-signed-receipts
        section 5.3), the anchor an Acta verifier resolves `kid` through for
        receipts `gargoyle acta export` signs (gargoyle.acta). `valid_from` is
        the witness's first `started` entry (section 9.2)."""
        from gargoyle.acta import jwks_for, key_valid_from
        entries = list(witness.entries) if witness is not None else []
        return jwks_for(signing_key.public_key(), key_id, valid_from=key_valid_from(entries, key_id))

    @app.get("/.well-known/acta-policies/{digest_hex}.json")
    async def acta_policy(digest_hex: str):
        """The policy bundle (section 6.8.1) for the policy now in force,
        when its source is a file this service can read: name, bytes and the
        digest a verifier recomputes. Any other digest is 404, including an
        earlier version of the rules: the witness records which pin decided
        each call, and the bundle for a past pin is the operator's backup."""
        from gargoyle.acta import bundle_for_policy
        bundle = bundle_for_policy(policy, now().isoformat())
        if bundle is None or bundle["policy_digest"] != "sha256:" + digest_hex:
            raise HTTPException(status_code=404, detail={"reason": "no bundle for that digest"})
        return bundle

    return app


def redact_access_log(logger_name: str = "uvicorn.access") -> None:
    """The console returns from Microsoft as GET /approve?code=...; the code
    is single-use and bound to the browser's PKCE verifier, and it still has
    no place in an access log. Replace query strings on logged paths."""
    import logging
    import re

    class _Redact(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            if isinstance(record.args, tuple):
                record.args = tuple(re.sub(r"\?.*", "?<redacted>", a) if isinstance(a, str) and a.startswith("/") and "?" in a else a
                                    for a in record.args)
            return True
    logging.getLogger(logger_name).addFilter(_Redact())


def _software_version() -> str:
    try:
        from importlib.metadata import version
        return version("gargoyle-receipts")
    except Exception:
        return "unknown"


def witness_start_fields(issuers: List[str], max_auth_age: Optional[int]) -> Dict[str, Any]:
    """What the witness's `started` entry says the service ran under: the
    identity providers trusted, the software version, and the sign-in age
    limit when one is set."""
    return {"providers": list(issuers), "software_version": _software_version(),
            **({"auth_max_age_seconds": max_auth_age} if max_auth_age else {})}


def release_max_auth_age_from_env(environ: Any) -> Optional[int]:
    """GARGOYLE_RELEASE_MAX_AUTH_AGE as whole seconds, or None when unset.
    Anything but a positive whole number stops the service: a rule the
    operator meant to set must not be silently off."""
    raw = (environ.get(ENV_RELEASE_MAX_AUTH_AGE) or "").strip()
    if not raw:
        return None
    if not raw.isdigit() or int(raw) <= 0:
        raise RuntimeError("%s must be a positive whole number of seconds, not %r" % (ENV_RELEASE_MAX_AUTH_AGE, raw))
    return int(raw)


def console_oidc_from_env(environ: Any, providers: List[Dict[str, Any]], *, max_auth_age: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """What the approval console needs to sign a person in at one of the
    trusted OpenID Connect providers (authorization code with PKCE, a
    public client): the endpoints from that provider's own discovery
    document, the client id, the scope, a label for the button, and the
    site's sign-in age so the provider asks for a fresh sign-in. None when
    no console client is configured. Raises when the provider is not one
    of the trusted ones or its endpoints are not https."""
    from urllib.parse import urlsplit
    client_id = (environ.get(ENV_OIDC_CLIENT_ID) or "").strip()
    if not client_id:
        return None
    if not providers:
        raise RuntimeError("%s is set but %s names no provider" % (ENV_OIDC_CLIENT_ID, ENV_OIDC_ISSUER))
    want = (environ.get(ENV_OIDC_CONSOLE_ISSUER) or "").strip() or providers[0]["issuer"]
    p = next((p for p in providers if p["issuer"] == want), None)
    if p is None:
        raise RuntimeError("%s is not one of the providers in %s" % (want, ENV_OIDC_ISSUER))
    for name in ("authorization_endpoint", "token_endpoint"):
        if not _trusted_url(p.get(name)):
            raise RuntimeError("discovery for %s gives no https %s: %r" % (want, name, p.get(name)))
    return {"issuer": want, "client_id": client_id, "scope": (environ.get(ENV_OIDC_SCOPE) or "").strip() or "openid profile",
            "authorization_endpoint": p["authorization_endpoint"], "token_endpoint": p["token_endpoint"],
            "label": (environ.get(ENV_OIDC_LABEL) or "").strip() or urlsplit(want).hostname,
            **({"max_age": max_auth_age} if max_auth_age else {})}


def providers_from_env(environ: Any, *, http: Any = None):
    """The OpenID Connect providers named in GARGOYLE_OIDC_ISSUER, each
    read from its own discovery document: ([provider, ...], {kid: key}).
    The claim settings apply to all of them. Raises when a provider cannot
    be read or trusted, or when two of them publish the same key id (the
    key could not say which of them signed)."""
    from urllib.parse import urlsplit
    issuers = [i.strip() for i in (environ.get(ENV_OIDC_ISSUER) or "").split(",") if i.strip()]
    if len(set(issuers)) != len(issuers):
        raise RuntimeError("%s names an issuer twice" % ENV_OIDC_ISSUER)
    names = [c.strip() for c in (environ.get(ENV_CLAIM_NAME) or "").split(",") if c.strip()]
    out, keys, owner = [], {}, {}
    for iss in issuers:
        doc = oidc_discovery(iss, http=http)
        fresh = oidc_keys(doc["jwks_uri"], http=http)
        for k in fresh:
            if k in owner:
                raise RuntimeError("identity providers %s and %s both publish key id %r" % (owner[k], iss, k))
            owner[k] = iss
        # Entra's `sub` differs per application; `oid` is the person.
        subject = environ.get(ENV_CLAIM_SUBJECT) or ("oid" if urlsplit(iss).hostname == "login.microsoftonline.com" else "sub")
        out.append(provider(iss, key_ids=set(fresh), name_claims=names or None,
                            display_claim=environ.get(ENV_CLAIM_DISPLAY_NAME) or "name",
                            roles_claim=environ.get(ENV_CLAIM_ROLES) or "roles",
                            groups_claim=environ.get(ENV_CLAIM_GROUPS) or "groups", subject_claim=subject,
                            refresh=(lambda uri=doc["jwks_uri"]: oidc_keys(uri, http=http))))
        # For the console (console_oidc_from_env); not used in trusting a token.
        out[-1].update(authorization_endpoint=doc.get("authorization_endpoint"), token_endpoint=doc.get("token_endpoint"))
        keys.update(fresh)
    return out, keys


def app_from_env() -> FastAPI:
    """The deployable app: OPA policy, issuer key, trusted identity-provider
    key and optional approver key from the environment. Missing required
    settings raise at startup; this service has nothing to do without them."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

    required = {k: os.environ.get(k) for k in (ENV_ISSUER_KEY_ID, ENV_ISSUER_KEY_HEX)}
    tenant = os.environ.get(ENV_ENTRA_TENANT)
    pinned_idp = os.environ.get(ENV_IDP_KEY_ID) and os.environ.get(ENV_IDP_PUBLIC_KEY_HEX)
    oidc = bool((os.environ.get(ENV_OIDC_ISSUER) or "").strip())
    if not tenant and not oidc:
        required.update({k: os.environ.get(k) for k in (ENV_IDP_KEY_ID, ENV_IDP_PUBLIC_KEY_HEX)})
    missing = [k for k, v in required.items() if not v]
    if missing:
        raise RuntimeError("issuer service needs " + ", ".join(missing))
    if (tenant or oidc) and not os.environ.get(ENV_AUDIENCE):
        # Fail closed: without an audience, any token the provider ever issued
        # for any application would be accepted here.
        raise RuntimeError("issuer service with %s set needs %s (the issuer API's client id or app id URI)"
                           % (ENV_ENTRA_TENANT if tenant else ENV_OIDC_ISSUER, ENV_AUDIENCE))
    tenant_id = entra_tenant_id(tenant) if tenant else None
    tenant_keys = entra_keys(tenant_id) if tenant else {}
    oidc_providers, oidc_key_map = providers_from_env(os.environ)
    clash = set(oidc_key_map) & (set(tenant_keys) | ({os.environ[ENV_IDP_KEY_ID]} if pinned_idp else set()))
    if clash:
        # A key id trusted two ways could not say which rule its tokens are held to.
        raise RuntimeError("key id %s is published by an OIDC provider and also trusted through %s or %s"
                           % (", ".join(sorted(clash)), ENV_ENTRA_TENANT, ENV_IDP_KEY_ID))
    console_oidc = console_oidc_from_env(os.environ, oidc_providers, max_auth_age=release_max_auth_age_from_env(os.environ))
    if console_oidc and tenant and os.environ.get(ENV_CONSOLE_CLIENT_ID):
        raise RuntimeError("the console signs in one way: set %s or %s, not both" % (ENV_OIDC_CLIENT_ID, ENV_CONSOLE_CLIENT_ID))
    start_fields = witness_start_fields([p["issuer"] for p in oidc_providers] + ([ENTRA_ISSUER.format(tenant=tenant_id)] if tenant else []),
                                        release_max_auth_age_from_env(os.environ))
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
        providers=oidc_providers,
        release_max_auth_age=release_max_auth_age_from_env(os.environ),
        console_oidc=console_oidc,
        idp_public_keys={**tenant_keys, **oidc_key_map,
                         **({os.environ[ENV_IDP_KEY_ID]: Ed25519PublicKey.from_public_bytes(bytes.fromhex(os.environ[ENV_IDP_PUBLIC_KEY_HEX]))}
                            if pinned_idp else {})},
        approver_public_keys=approver,
        audience=os.environ.get(ENV_AUDIENCE) or None,
        ttl_seconds=int(os.environ.get(ENV_RECEIPT_TTL, DEFAULT_TTL_SECONDS)),
        on_hold=notifier_from_env(os.environ),
        hold_store=HoldStore(os.environ.get(ENV_HOLDS_PATH) or None),
        max_open_holds=int(os.environ.get(ENV_MAX_OPEN_HOLDS, DEFAULT_MAX_OPEN_HOLDS)),
        decline_limit=int(os.environ.get(ENV_DECLINE_LIMIT, DEFAULT_DECLINE_LIMIT)),
        decline_window_hours=float(os.environ.get(ENV_DECLINE_WINDOW_HOURS, DEFAULT_DECLINE_WINDOW_HOURS)),
        allow_self_approval=os.environ.get(ENV_ALLOW_SELF_APPROVAL, "").strip().lower() in ("1", "true", "yes"),
        witness=(WitnessLog(os.environ["GARGOYLE_WITNESS_PATH"], Ed25519PrivateKey.from_private_bytes(bytes.fromhex(required[ENV_ISSUER_KEY_HEX])),
                            required[ENV_ISSUER_KEY_ID], start_fields=start_fields) if os.environ.get("GARGOYLE_WITNESS_PATH") else None),
        log_events=(lambda e: sys.stderr.write(json.dumps(e, sort_keys=True) + "\n")) if os.environ.get("GARGOYLE_LOG_JSON") else None,
        approver_registry=ApproverRegistry(os.environ.get(ENV_APPROVERS_PATH)),
        approver_role=os.environ.get(ENV_APPROVER_ROLE, DEFAULT_APPROVER_ROLE),
        approver_groups=[g.strip() for g in os.environ.get(ENV_APPROVER_GROUPS, "").split(",") if g.strip()] or None,
        tenant=tenant_id,
        tenant_key_ids=set(tenant_keys) if tenant else None,
        idp_key_refresh=(lambda: entra_keys(tenant_id)) if tenant else None,
        console_entra=({"tenant": tenant, "client_id": os.environ[ENV_CONSOLE_CLIENT_ID],
                        "scope": os.environ.get(ENV_CONSOLE_SCOPE) or "api://%s/access" % (os.environ.get(ENV_AUDIENCE) or "").split(",")[-1].strip(),
                        **({"max_age": release_max_auth_age_from_env(os.environ)} if release_max_auth_age_from_env(os.environ) else {})}
                       if tenant and os.environ.get(ENV_CONSOLE_CLIENT_ID) else None),
    )
