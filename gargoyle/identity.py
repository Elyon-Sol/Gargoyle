"""The issuer-side identity input: who the receipt is for.

An issuing service must put an authenticated principal into every receipt
(SPEC.md section 3). Where that identity arrives as a token, this module
turns it into the two receipt fields:

    principal     the actor the call is made by (the agent)
    on_behalf_of  the party it acts for (the user), when the token says so

from a JWS the service trusts (a kid in `public_keys`; EdDSA, RS256 or
ES256, the algorithm fixed by the key's type), applying the claim
conventions in this order:

  - RFC 8693 delegation: `act.sub` is the actor and `sub` the party acted
    for, so principal = act.sub, on_behalf_of = sub (the innermost actor
    when `act` nests).
  - Transaction Tokens for Agents (draft): `agentic_ctx.actor` and
    `agentic_ctx.principal`, else an `actor` / `principal` pair at the top
    level, with the same mapping.
  - Entra ID and other OIDC providers: the subject is `preferred_username`
    (the UPN) or `upn` when present, since `sub` there is an opaque pairwise
    id; `oid` is kept in the result.
  - Otherwise: principal = sub, no on_behalf_of.

The result also carries `groups` and `roles` (Entra group ids or app
roles, Okta groups), as lists, so a rules file can match a department
without naming people. Expiry (`exp`) is enforced; `aud` is enforced when
`audience` is given; a token with no usable subject is refused.

Keys: pin them, or load the provider's JWKS with keys_from_jwks /
entra_keys (fetched from the tenant's discovery endpoint; cache and
refresh on an unknown kid, as every OIDC client does).
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set

from gargoyle.jws import (
    IDENTITY_ALGS, REF_JWS_AUDIENCE_MISMATCH, REF_JWS_EXPIRED, REF_JWS_MALFORMED, decode, keys_from_jwks,
)

REF_IDENTITY_NO_SUBJECT = "REF_IDENTITY_NO_SUBJECT"
REF_IDENTITY_WRONG_TENANT = "REF_IDENTITY_WRONG_TENANT"     # a directory token for some other tenant, or one that names none
ENTRA_JWKS_URL = "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
ENTRA_OPENID_URL = "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def entra_tenant_id(tenant: str, *, http: Any = None, timeout: float = 10.0) -> str:
    """The tenant id (a GUID) for a tenant given by id or by domain. Tokens
    name their tenant by id in `tid`, so the check in principal_from_token
    needs the id; a domain is resolved once, from the tenant's OpenID
    configuration, at startup. Raises on transport failure."""
    if _GUID.match(tenant):
        return tenant.lower()
    import requests
    http = http if http is not None else requests
    r = http.get(ENTRA_OPENID_URL.format(tenant=tenant), timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError("OpenID configuration fetch returned %s" % r.status_code)
    issuer = r.json().get("issuer") or ""
    m = re.search(r"/([0-9a-fA-F-]{36})/", issuer)
    if not m or not _GUID.match(m.group(1)):
        raise RuntimeError("OpenID configuration for %s names no tenant id: %r" % (tenant, issuer))
    return m.group(1).lower()


def entra_keys(tenant: str, *, http: Any = None, timeout: float = 10.0) -> Dict[str, Any]:
    """The tenant's current signing keys as {kid: public key}. `tenant` is
    the tenant id or domain. Raises on transport failure; callers cache the
    result and refetch on an unknown kid."""
    import requests
    http = http if http is not None else requests
    r = http.get(ENTRA_JWKS_URL.format(tenant=tenant), timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError("JWKS fetch returned %s" % r.status_code)
    return keys_from_jwks(r.json())


def _string_list(value: Any) -> list:
    if isinstance(value, str) and value:
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str) and v]
    return []


def _nonempty(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _innermost_actor(act: Any) -> Optional[str]:
    while isinstance(act, dict):
        inner = act.get("act")
        if not isinstance(inner, dict):
            return _nonempty(act.get("sub"))
        act = inner
    return None


def principal_from_token(token: str, public_keys: Dict[str, Any], *,
                         audience: Any = None, now: Optional[datetime] = None,
                         tenant: Optional[str] = None, tenant_key_ids: Optional[Set[str]] = None) -> Dict[str, Any]:
    """{"principal", "on_behalf_of" (or None), "claims", "reason": None} for
    a trusted identity token, or {"principal": None, "reason": code}.

    `tenant` (a tenant id) makes the token's `tid` part of trust: a token
    signed by one of `tenant_key_ids` (the keys fetched from the directory;
    every key when None) must carry that tid, and its `iss`, when present,
    must name it. Directory signing keys are shared across tenants, so a
    valid signature alone says only that some tenant issued the token.
    Tokens under other trusted keys (a pinned key `gargoyle init` wrote)
    name no tenant and are not held to one."""
    res = decode(token, public_keys, allowed_algs=IDENTITY_ALGS)
    if res["reason"] is not None:
        return {"principal": None, "reason": res["reason"]}
    claims = res["payload"]
    current = now if now is not None else datetime.now(timezone.utc)
    exp = claims.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool) or current.timestamp() >= exp:
        return {"principal": None, "reason": REF_JWS_EXPIRED}
    if audience is not None:
        # One audience, or several (a list, or a comma-separated string):
        # the issuer accepts init-minted tokens and a tenant's tokens side
        # by side while a site moves from one to the other.
        aud = claims.get("aud")
        presented = aud if isinstance(aud, list) else [aud]
        accepted = audience if isinstance(audience, (list, tuple)) else [a.strip() for a in str(audience).split(",")]
        if not any(a in presented for a in accepted if a):
            return {"principal": None, "reason": REF_JWS_AUDIENCE_MISMATCH}
    if tenant is not None and (tenant_key_ids is None or res["header"].get("kid") in tenant_key_ids):
        tid = _nonempty(claims.get("tid")); iss = _nonempty(claims.get("iss"))
        if tid is None or tid.lower() != tenant.lower() or (iss is not None and tenant.lower() not in iss.lower()):
            return {"principal": None, "reason": REF_IDENTITY_WRONG_TENANT}

    # OIDC providers' `sub` is opaque; the UPN is the identity people and
    # rules recognise.
    sub = _nonempty(claims.get("preferred_username")) or _nonempty(claims.get("upn")) or _nonempty(claims.get("sub"))
    actor = _innermost_actor(claims.get("act"))
    if actor is None:
        ctx = claims.get("agentic_ctx") if isinstance(claims.get("agentic_ctx"), dict) else claims
        a, p = _nonempty(ctx.get("actor")), _nonempty(ctx.get("principal"))
        if a is not None:
            actor, sub = a, p if p is not None else sub
    if actor is not None:
        principal, on_behalf_of = actor, sub
    elif sub is not None:
        principal, on_behalf_of = sub, None
    else:
        return {"principal": None, "reason": REF_IDENTITY_NO_SUBJECT}
    return {"principal": principal, "on_behalf_of": on_behalf_of, "claims": claims, "reason": None,
            "groups": _string_list(claims.get("groups")), "roles": _string_list(claims.get("roles")),
            "oid": _nonempty(claims.get("oid")), "tid": _nonempty(claims.get("tid"))}
