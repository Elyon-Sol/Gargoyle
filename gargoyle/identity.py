# SPDX-License-Identifier: Apache-2.0
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

Any OpenID Connect provider. `provider(issuer, key_ids=...)` describes
one: the issuer URL it names itself by, the key ids that are its own, and
which claims carry the readable name, the printed name, roles and groups.
Given `providers`, a token signed by a provider's key is trusted only when
its `iss` is that provider's issuer, exactly; one provider's key cannot
speak for another. The result then names the person twice: `principal`,
the readable name rules and people use, and `subject_id`, the pair
{"iss", "sub"} that stays the same when the readable name is changed or
handed to someone else. `oidc_discovery` and `oidc_keys` read a provider's
own discovery document and key set.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

from gargoyle.jws import (
    IDENTITY_ALGS, REF_JWS_AUDIENCE_MISMATCH, REF_JWS_EXPIRED, REF_JWS_MALFORMED, decode, keys_from_jwks,
)

REF_IDENTITY_NO_SUBJECT = "REF_IDENTITY_NO_SUBJECT"
REF_IDENTITY_WRONG_TENANT = "REF_IDENTITY_WRONG_TENANT"     # a directory token for some other tenant, or one that names none
REF_IDENTITY_WRONG_ISSUER = "REF_IDENTITY_WRONG_ISSUER"     # signed by a provider's key, but `iss` is not that provider's issuer
DEFAULT_NAME_CLAIMS = ("preferred_username", "upn", "sub")  # not `email`: an address is often editable by its holder
ENTRA_ISSUER = "https://login.microsoftonline.com/{tenant}/v2.0"
_LOOPBACK = ("localhost", "127.0.0.1", "::1")
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


def provider(issuer: str, *, key_ids: Optional[Iterable[str]] = None, name_claims: Optional[Iterable[str]] = None,
             display_claim: str = "name", roles_claim: str = "roles", groups_claim: str = "groups",
             subject_claim: str = "sub", refresh: Any = None) -> Dict[str, Any]:
    """One trusted OpenID Connect provider, for principal_from_token.

    `issuer` is compared with a token's `iss` as a string, exactly (OpenID
    Connect Core 3.1.3.7). `key_ids` are the kids of this provider's own
    signing keys. A claim setting names a claim, or a path into nested
    objects with dots (`realm_access.roles`). `name_claims` are tried in order for the readable name;
    the subject is used when none is present. `subject_claim` is the claim
    that never changes for a person: `sub`, or `oid` for Entra ID, whose
    `sub` differs per application. `refresh()` returns the provider's
    current keys {kid: key} (the issuing service calls it on an unknown kid)."""
    if not isinstance(issuer, str) or not issuer:
        raise ValueError("a provider needs its issuer URL")
    return {"issuer": issuer, "key_ids": set(key_ids or ()), "name_claims": list(name_claims or DEFAULT_NAME_CLAIMS),
            "display_claim": display_claim, "roles_claim": roles_claim, "groups_claim": groups_claim,
            "subject_claim": subject_claim, "refresh": refresh}


def _trusted_url(url: Any) -> bool:
    """https, or plain http to this machine only (a provider under test)."""
    from urllib.parse import urlsplit
    if not isinstance(url, str):
        return False
    try:
        u = urlsplit(url)
    except ValueError:
        return False
    return bool(u.hostname) and (u.scheme == "https" or (u.scheme == "http" and u.hostname in _LOOPBACK))


def oidc_discovery(issuer: str, *, http: Any = None, timeout: float = 10.0) -> Dict[str, Any]:
    """The provider's discovery document (OpenID Connect Discovery 1.0,
    section 4), accepted only when it can be trusted to speak for `issuer`:
    fetched over https (plain http for a provider on this machine), naming
    exactly `issuer` as its own, and giving a key address held to the same
    transport rule. Raises RuntimeError otherwise."""
    if not _trusted_url(issuer) or "?" in issuer or "#" in issuer:
        raise RuntimeError("OIDC issuer must be an https URL without query or fragment: %r" % issuer)
    if http is None:
        import requests as http
    r = http.get(issuer.rstrip("/") + "/.well-known/openid-configuration", timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError("discovery for %s returned %s" % (issuer, r.status_code))
    doc = r.json()
    if not isinstance(doc, dict) or doc.get("issuer") != issuer:
        raise RuntimeError("discovery for %s names another issuer: %r" % (issuer, doc.get("issuer") if isinstance(doc, dict) else None))
    if not _trusted_url(doc.get("jwks_uri")):
        raise RuntimeError("discovery for %s gives no https jwks_uri: %r" % (issuer, doc.get("jwks_uri")))
    return doc


def oidc_keys(jwks_uri: str, *, http: Any = None, timeout: float = 10.0) -> Dict[str, Any]:
    """The keys at a provider's `jwks_uri` as {kid: public key}. Raises on
    transport failure; callers cache and refetch on an unknown kid."""
    if not _trusted_url(jwks_uri):
        raise RuntimeError("jwks_uri must be https: %r" % jwks_uri)
    if http is None:
        import requests as http
    r = http.get(jwks_uri, timeout=timeout)
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


def _claim(claims: Dict[str, Any], name: str) -> Any:
    """The claim a setting names. A claim with exactly that name wins (a
    namespaced claim such as `https://example.com/roles` has dots in it);
    otherwise dots walk into nested objects (`realm_access.roles`, where
    Keycloak puts realm roles). A path that does not lead through objects
    gives None."""
    if name in claims:
        return claims[name]
    value: Any = claims
    for part in name.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _innermost_actor(act: Any) -> Optional[str]:
    while isinstance(act, dict):
        inner = act.get("act")
        if not isinstance(inner, dict):
            return _nonempty(act.get("sub"))
        act = inner
    return None


def principal_from_token(token: str, public_keys: Dict[str, Any], *,
                         audience: Any = None, now: Optional[datetime] = None,
                         tenant: Optional[str] = None, tenant_key_ids: Optional[Set[str]] = None,
                         providers: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """{"principal", "on_behalf_of" (or None), "claims", "reason": None} for
    a trusted identity token, or {"principal": None, "reason": code}.

    `tenant` (a tenant id) makes the token's `tid` part of trust: a token
    signed by one of `tenant_key_ids` (the keys fetched from the directory;
    every key when None) must carry that tid, and its `iss`, when present,
    must name it. Directory signing keys are shared across tenants, so a
    valid signature alone says only that some tenant issued the token.
    Tokens under other trusted keys (a pinned key `gargoyle init` wrote)
    name no tenant and are not held to one.

    `providers` (see provider()) does the same for any OpenID Connect
    provider: a token signed by one of a provider's keys must carry that
    provider's issuer in `iss`, exactly, and its permanent subject claim.

    The result names the person twice. `principal` is the readable name.
    `subject_id` is {"iss", "sub"}, the id that survives a rename: the
    provider's issuer and subject; for a tenant token the tenant's issuer
    and `oid`; for a pinned key "key:<kid>" and the subject. With
    delegation, `subject_id` is the actor's and `on_behalf_of_id` the
    party's. `name` is the printed name (the provider's display claim)
    when the token is the person's own."""
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
    kid = res["header"].get("kid")
    prov = next((p for p in (providers or ()) if kid in p["key_ids"]), None)
    name_claims, display_claim, roles_claim, groups_claim = DEFAULT_NAME_CLAIMS, "name", "roles", "groups"
    if prov is not None:
        # The key says which provider signed; the token must say the same.
        iss = claims.get("iss")
        if not isinstance(iss, str) or iss != prov["issuer"]:
            return {"principal": None, "reason": REF_IDENTITY_WRONG_ISSUER}
        subject = _nonempty(claims.get(prov["subject_claim"]))
        if subject is None:
            return {"principal": None, "reason": REF_IDENTITY_NO_SUBJECT}
        id_issuer = prov["issuer"]
        name_claims, display_claim = prov["name_claims"], prov["display_claim"]
        roles_claim, groups_claim = prov["roles_claim"], prov["groups_claim"]
    elif tenant is not None and (tenant_key_ids is None or kid in tenant_key_ids):
        tid = _nonempty(claims.get("tid")); iss = _nonempty(claims.get("iss"))
        if tid is None or tid.lower() != tenant.lower() or (iss is not None and tenant.lower() not in iss.lower()):
            return {"principal": None, "reason": REF_IDENTITY_WRONG_TENANT}
        # One id for a person whichever token version (and so `iss` spelling) the tenant issued.
        id_issuer, subject = ENTRA_ISSUER.format(tenant=tenant.lower()), _nonempty(claims.get("oid")) or _nonempty(claims.get("sub"))
    else:
        # A pinned key names no provider; whatever `iss` its token carries is not trusted as one.
        id_issuer, subject = "key:%s" % kid, _nonempty(claims.get("sub"))

    # OIDC providers' `sub` is opaque; the UPN is the identity people and
    # rules recognise.
    sub = next((v for v in (_nonempty(_claim(claims, c)) for c in name_claims) if v is not None), None) or subject
    party = subject if subject is not None else sub
    actor = _innermost_actor(claims.get("act"))
    if actor is None:
        ctx = claims.get("agentic_ctx") if isinstance(claims.get("agentic_ctx"), dict) else claims
        a, p = _nonempty(ctx.get("actor")), _nonempty(ctx.get("principal"))
        if a is not None:
            actor, sub = a, p if p is not None else sub
            party = p if p is not None else party
    if actor is not None:
        principal, on_behalf_of = actor, sub
        subject_id = {"iss": id_issuer, "sub": actor}
        on_behalf_of_id = {"iss": id_issuer, "sub": party} if party is not None else None
    elif sub is not None:
        principal, on_behalf_of = sub, None
        subject_id, on_behalf_of_id = {"iss": id_issuer, "sub": party}, None
    else:
        return {"principal": None, "reason": REF_IDENTITY_NO_SUBJECT}
    return {"principal": principal, "on_behalf_of": on_behalf_of, "claims": claims, "reason": None,
            "groups": _string_list(_claim(claims, groups_claim)), "roles": _string_list(_claim(claims, roles_claim)),
            "oid": _nonempty(claims.get("oid")), "tid": _nonempty(claims.get("tid")),
            "iss": id_issuer, "subject_id": subject_id, "on_behalf_of_id": on_behalf_of_id,
            "name": _nonempty(_claim(claims, display_claim)) if actor is None else None}
