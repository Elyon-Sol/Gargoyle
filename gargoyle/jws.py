"""JWS compact serialization (RFC 7515) with EdDSA (RFC 8037), the one
encoding Gargoyle shares with the rest of the world.

Gargoyle's own signatures are over canonical JSON (SPEC.md section 2),
which no JWT library understands. A receipt can also travel as a JWS so
that any library with EdDSA support verifies it:

    header   = {"alg": "EdDSA", "kid": <key id>, "typ": "JWT"}
    payload  = {"iss": <key id>, "jti": <decision_id>, "aud": <target_url>,
                "exp": <not_after as epoch seconds>, "iat": ...,
                "gargoyle": <the signed receipt, canonical signature included>}
    token    = b64url(header) "." b64url(payload) "." b64url(ed25519(signing_input))

The receipt inside carries its own canonical issuer_signature, so both
signatures are the issuer's: a JWT library checks the outer one and the
registered claims; a Gargoyle verifier checks the inner one and everything
else. decode_receipt() does both.

The same primitives read an identity token on the issuer side
(gargoyle.identity): a transaction token or a bearer JWT whose subject
becomes the receipt's principal. Receipts are EdDSA only. Identity tokens
from an enterprise provider (Entra ID, Okta) are RS256 or ES256, so decode()
accepts those too when the caller allows them and the key under `kid` is
of the matching type; the algorithm is taken from the key, never from the
header alone. "none" and everything else are refused, as is any token
without a kid the caller trusts.
"""

import base64
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from gargoyle.envelope import canonical_json

JWS_ALG = "EdDSA"
RECEIPT_ALGS = frozenset({"EdDSA"})
IDENTITY_ALGS = frozenset({"EdDSA", "RS256", "ES256"})

REF_JWS_MALFORMED = "REF_JWS_MALFORMED"
REF_JWS_ALG_UNSUPPORTED = "REF_JWS_ALG_UNSUPPORTED"
REF_JWS_KEY_UNKNOWN = "REF_JWS_KEY_UNKNOWN"
REF_JWS_SIGNATURE_INVALID = "REF_JWS_SIGNATURE_INVALID"
REF_JWS_EXPIRED = "REF_JWS_EXPIRED"
REF_JWS_AUDIENCE_MISMATCH = "REF_JWS_AUDIENCE_MISMATCH"
REF_JWS_PAYLOAD_MISMATCH = "REF_JWS_PAYLOAD_MISMATCH"   # registered claims disagree with the receipt


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or any(c not in "-_=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encode(payload: Dict[str, Any], signing_key: Any, key_id: str, header_extra: Optional[Dict[str, Any]] = None) -> str:
    """Compact JWS of `payload` (serialized canonically) signed with the
    Ed25519 `signing_key` under `kid` = key_id."""
    header = {"alg": JWS_ALG, "kid": key_id, "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    signing_input = b64url_encode(canonical_json(header).encode("utf-8")) + "." + \
        b64url_encode(canonical_json(payload).encode("utf-8"))
    signature = signing_key.sign(signing_input.encode("ascii"))
    return signing_input + "." + b64url_encode(signature)


def _alg_for_key(key: Any) -> Optional[str]:
    """The one algorithm a key may verify: EdDSA for Ed25519, RS256 for RSA,
    ES256 for P-256. Anything else is unsupported."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "EdDSA"
    if isinstance(key, rsa.RSAPublicKey):
        return "RS256"
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
        return "ES256"
    return None


def _verify(key: Any, alg: str, signature: bytes, message: bytes) -> None:
    """Raises on a bad signature."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
    if alg == "EdDSA":
        key.verify(signature, message)
    elif alg == "RS256":
        key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256":
        if len(signature) != 64:
            raise ValueError("ES256 signature is r||s, 64 bytes")
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        key.verify(utils.encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("unsupported alg")


def decode(token: str, public_keys: Dict[str, Any], allowed_algs=RECEIPT_ALGS) -> Dict[str, Any]:
    """Verify a compact JWS against `public_keys` ({kid: public key}) and
    return {"header", "payload", "reason": None}, or {"reason": code}. The
    header's alg must be in `allowed_algs` AND be the algorithm the key
    under kid is for; a header cannot talk a key into another algorithm.
    No claim is interpreted here; see decode_receipt and gargoyle.identity."""
    if not isinstance(token, str) or token.count(".") != 2:
        return {"reason": REF_JWS_MALFORMED}
    h, p, s = token.split(".")
    try:
        header = json.loads(b64url_decode(h))
        payload = json.loads(b64url_decode(p))
        signature = b64url_decode(s)
    except (ValueError, TypeError):
        return {"reason": REF_JWS_MALFORMED}
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return {"reason": REF_JWS_MALFORMED}
    alg = header.get("alg")
    if alg not in allowed_algs:
        return {"reason": REF_JWS_ALG_UNSUPPORTED}
    kid = header.get("kid")
    if not isinstance(kid, str) or not isinstance(public_keys, dict) or kid not in public_keys:
        return {"reason": REF_JWS_KEY_UNKNOWN}
    key = public_keys[kid]
    if _alg_for_key(key) != alg:
        return {"reason": REF_JWS_ALG_UNSUPPORTED}
    try:
        _verify(key, alg, signature, (h + "." + p).encode("ascii"))
    except Exception:
        return {"reason": REF_JWS_SIGNATURE_INVALID}
    return {"header": header, "payload": payload, "reason": None}


def keys_from_jwks(jwks: Any) -> Dict[str, Any]:
    """{kid: public key} from a JWKS document (RFC 7517): RSA (kty RSA, n, e),
    P-256 (kty EC, crv P-256, x, y) and Ed25519 (kty OKP, crv Ed25519, x).
    Entries without a kid, or of another type, are skipped, never guessed."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    out: Dict[str, Any] = {}
    entries = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(entries, list):
        return out
    for k in entries:
        if not isinstance(k, dict) or not isinstance(k.get("kid"), str):
            continue
        try:
            if k.get("kty") == "RSA":
                n = int.from_bytes(b64url_decode(k["n"]), "big")
                e = int.from_bytes(b64url_decode(k["e"]), "big")
                out[k["kid"]] = rsa.RSAPublicNumbers(e, n).public_key()
            elif k.get("kty") == "EC" and k.get("crv") == "P-256":
                x = int.from_bytes(b64url_decode(k["x"]), "big")
                y = int.from_bytes(b64url_decode(k["y"]), "big")
                out[k["kid"]] = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
            elif k.get("kty") == "OKP" and k.get("crv") == "Ed25519":
                out[k["kid"]] = ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(k["x"]))
        except Exception:
            continue
    return out


def _epoch(timestamp: str) -> int:
    return int(datetime.fromisoformat(timestamp).timestamp())


def encode_receipt(signed_envelope: Dict[str, Any], signing_key: Any) -> str:
    """The JWS form of a receipt signed by gargoyle.envelope.sign_envelope.
    The registered claims mirror the receipt so a JWT library can enforce
    expiry and audience on its own; the receipt itself rides under
    "gargoyle" with its canonical signature intact."""
    for key in ("issuer_key_id", "issuer_signature", "decision_id", "not_after", "target_url"):
        if key not in signed_envelope:
            raise ValueError("a JWS receipt needs a signed receipt with %s" % key)
    payload = {
        "iss": signed_envelope["issuer_key_id"],
        "jti": signed_envelope["decision_id"],
        "aud": signed_envelope["target_url"],
        "exp": _epoch(signed_envelope["not_after"]),
        "iat": _epoch(signed_envelope["timestamp_utc"]) if "timestamp_utc" in signed_envelope else None,
        "gargoyle": dict(signed_envelope),
    }
    if payload["iat"] is None:
        del payload["iat"]
    return encode(payload, signing_key, signed_envelope["issuer_key_id"])


def decode_receipt(token: str, issuer_public_keys: Dict[str, Any], *,
                   audience: Optional[str] = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Verify the outer JWS and return {"envelope": <receipt>, "reason": None},
    or {"envelope": None, "reason": code}. The receipt is then checked like
    any other (verify_envelope / Consumer.check). The registered claims must
    agree with the receipt they wrap: a mismatch is a forgery attempt, not a
    detail."""
    res = decode(token, issuer_public_keys)
    if res["reason"] is not None:
        return {"envelope": None, "reason": res["reason"]}
    payload, header = res["payload"], res["header"]
    env = payload.get("gargoyle")
    if not isinstance(env, dict):
        return {"envelope": None, "reason": REF_JWS_MALFORMED}
    if (env.get("issuer_key_id") != header.get("kid") or payload.get("iss") != header.get("kid")
            or payload.get("jti") != env.get("decision_id") or payload.get("aud") != env.get("target_url")):
        return {"envelope": None, "reason": REF_JWS_PAYLOAD_MISMATCH}
    try:
        if payload.get("exp") != _epoch(env["not_after"]):
            return {"envelope": None, "reason": REF_JWS_PAYLOAD_MISMATCH}
    except (KeyError, ValueError, TypeError):
        return {"envelope": None, "reason": REF_JWS_PAYLOAD_MISMATCH}
    if audience is not None and payload.get("aud") != audience:
        return {"envelope": None, "reason": REF_JWS_AUDIENCE_MISMATCH}
    current = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(payload.get("exp"), int) or isinstance(payload.get("exp"), bool) or current.timestamp() >= payload["exp"]:
        return {"envelope": None, "reason": REF_JWS_EXPIRED}
    return {"envelope": env, "reason": None}
