"""The issuer-side identity input: who the receipt is for.

An issuing service must put an authenticated principal into every receipt
(SPEC.md section 3). Where that identity arrives as a token, this module
turns it into the two receipt fields:

    principal     the actor the call is made by (the agent)
    on_behalf_of  the party it acts for (the user), when the token says so

from a JWS the service trusts (EdDSA, a kid in `public_keys`), applying
the claim conventions in this order:

  - RFC 8693 delegation: `act.sub` is the actor and `sub` the party acted
    for, so principal = act.sub, on_behalf_of = sub (the innermost actor
    when `act` nests).
  - Transaction Tokens for Agents (draft): `agentic_ctx.actor` and
    `agentic_ctx.principal`, else an `actor` / `principal` pair at the top
    level, with the same mapping.
  - Otherwise: principal = sub, no on_behalf_of.

Expiry (`exp`) is enforced; `aud` is enforced when `audience` is given; a
token with no usable subject is refused. Nothing here fetches keys: the
service pins them or loads them from its identity provider's JWKS itself.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from gargoyle.jws import REF_JWS_AUDIENCE_MISMATCH, REF_JWS_EXPIRED, REF_JWS_MALFORMED, decode

REF_IDENTITY_NO_SUBJECT = "REF_IDENTITY_NO_SUBJECT"


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
                         audience: Optional[str] = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """{"principal", "on_behalf_of" (or None), "claims", "reason": None} for
    a trusted identity token, or {"principal": None, "reason": code}."""
    res = decode(token, public_keys)
    if res["reason"] is not None:
        return {"principal": None, "reason": res["reason"]}
    claims = res["payload"]
    current = now if now is not None else datetime.now(timezone.utc)
    exp = claims.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool) or current.timestamp() >= exp:
        return {"principal": None, "reason": REF_JWS_EXPIRED}
    if audience is not None:
        aud = claims.get("aud")
        allowed = aud if isinstance(aud, list) else [aud]
        if audience not in allowed:
            return {"principal": None, "reason": REF_JWS_AUDIENCE_MISMATCH}

    sub = _nonempty(claims.get("sub"))
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
    return {"principal": principal, "on_behalf_of": on_behalf_of, "claims": claims, "reason": None}
