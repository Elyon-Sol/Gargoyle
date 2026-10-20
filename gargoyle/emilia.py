"""Interoperation with the EMILIA Protocol (draft-schrock-ep-authorization-
receipts, https://github.com/emiliaprotocol/emilia-protocol).

Two directions, both offline:

* verify_ep_receipt: a verifier for EMILIA's generic EP-RECEIPT-v1 envelope
  built on Gargoyle's canonical form (RFC 8785, gargoyle.envelope
  .canonical_json). EMILIA's canonicalizer is byte-identical to it on every
  payload in their published vectors, so the same bytes sign and verify on
  both sides.
* ep_receipt / trust_receipt: exports of Gargoyle artifacts into EMILIA's two
  profiles. An EP-RECEIPT-v1 envelope wraps any Gargoyle receipt or execution
  receipt under the issuer's or executor's Ed25519 key and verifies with
  @emilia-protocol/verify and emilia-verify as published. A Trust Receipt
  (EP-AUTHORIZATION-RECEIPT-v1) maps a Gargoyle chain onto EMILIA's action,
  contexts, signoffs, consumption and single-leaf log proof.

The one thing an export cannot manufacture is the approver's signoff: EMILIA
approvers sign the SHA-256 of the JCS Authorization Context (32 bytes, Class B
Ed25519), Gargoyle approvers sign the canonical grant. The bytes differ, so a
stored grant signature is not a signoff (EMILIA's verifier refuses it, as it
should). `context_hash_for` gives the digest an approver console would sign
alongside the grant to make exports lossless; until that is built, a Trust
Receipt export is structural only unless the signoff is supplied."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import uuid
from typing import Any, Dict, List, Optional

from gargoyle.envelope import canonical_json

EP_RECEIPT_VERSION = "EP-RECEIPT-v1"
MERKLE_V2 = "EP-MERKLE-v2"
CONTEXT_TYPE = "ep.signoff.v1"
NONCE_PREFIX = "gargoyle-emilia-nonce/1\n"
_SAFE_INT = 2 ** 53 - 1


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def spki_b64u(public_key: Any) -> str:
    """EMILIA pins keys as base64url SubjectPublicKeyInfo DER."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return b64u(public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


def in_profile(value: Any) -> bool:
    """EMILIA's I-JSON signing profile: strings, bools, null, safe integers.
    Gargoyle artifacts are inside it (hashes and timestamps are strings)."""
    if value is None or isinstance(value, (str, bool)):
        return True
    if isinstance(value, float):
        return math.isfinite(value) and value.is_integer() and abs(value) <= _SAFE_INT
    if isinstance(value, int):
        return -_SAFE_INT <= value <= _SAFE_INT
    if isinstance(value, list):
        return all(in_profile(v) for v in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and in_profile(v) for k, v in value.items())
    return False


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _hex_of(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    value = value[7:] if value.startswith("sha256:") else value
    value = value.lower()
    return value if len(value) == 64 and all(c in "0123456789abcdef" for c in value) else ""


def _leaf_v2(canonical: str) -> str:
    return hashlib.sha256(b"\x00" + canonical.encode("utf-8")).hexdigest()


def _pair_v2(left: str, right: str) -> str:
    return hashlib.sha256(b"\x01" + left.encode("utf-8") + right.encode("utf-8")).hexdigest()


# --- EMILIA -> Gargoyle: verify an EP-RECEIPT-v1 envelope ---------------------

def verify_ep_receipt(doc: Any, public_key_spki_b64u: str) -> Dict[str, Any]:
    """Version, Ed25519 over the canonical payload, and the EP-MERKLE-v2 anchor
    when present (a legacy v1 anchor is refused, as EMILIA's verifiers do by
    default). Never raises on bad input."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    checks: Dict[str, Any] = {"version": False, "signature": False, "anchor": None}

    def refuse(reason: str) -> Dict[str, Any]:
        return {"valid": False, "checks": checks, "error": reason}

    if not isinstance(doc, dict) or doc.get("@version") != EP_RECEIPT_VERSION:
        return refuse("unsupported version")
    checks["version"] = True
    payload, sig = doc.get("payload"), doc.get("signature")
    if not isinstance(payload, dict) or not payload or not isinstance(sig, dict):
        return refuse("payload and signature must be objects")
    if not isinstance(sig.get("algorithm"), str) or sig["algorithm"].lower() != "ed25519" or not sig.get("value"):
        return refuse("EP-RECEIPT-v1 requires Ed25519")
    if not in_profile(payload):
        return refuse("payload outside the EMILIA canonicalization profile")
    canonical = canonical_json(payload)
    try:
        pub = load_der_public_key(b64u_decode(public_key_spki_b64u))
        if not isinstance(pub, Ed25519PublicKey):
            return refuse("public key is not Ed25519")
        pub.verify(b64u_decode(str(sig["value"])), canonical.encode("utf-8"))
        checks["signature"] = True
    except InvalidSignature:
        return refuse("signature does not verify")
    except Exception as exc:  # malformed key or signature encoding
        return refuse("signature verification failed: %s" % exc)
    anchor = doc.get("anchor")
    if anchor is None:
        return {"valid": True, "checks": checks, "error": None}
    if not isinstance(anchor, dict):
        checks["anchor"] = False
        return refuse("anchor must be an object")
    if isinstance(anchor.get("merkle_proof"), list) and isinstance(anchor.get("leaf_hash"), str) and isinstance(anchor.get("merkle_root"), str):
        ok = anchor.get("alg") == MERKLE_V2 and len(anchor["merkle_proof"]) <= 20
        current = anchor["leaf_hash"]
        ok = ok and current == _leaf_v2(canonical)
        for step in anchor["merkle_proof"] if ok else []:
            if not isinstance(step, dict) or step.get("position") not in ("left", "right") or not isinstance(step.get("hash"), str):
                ok = False
                break
            current = _pair_v2(step["hash"], current) if step["position"] == "left" else _pair_v2(current, step["hash"])
        checks["anchor"] = ok and current == anchor["merkle_root"]
        if not checks["anchor"]:
            return refuse("anchor does not bind this payload to the root")
    return {"valid": True, "checks": checks, "error": None}


# --- Gargoyle -> EMILIA: exports ---------------------------------------------

def ep_receipt(payload: Dict[str, Any], signing_key: Any) -> Dict[str, Any]:
    """Wrap a Gargoyle receipt (or execution receipt, grant, evidence entry) in
    an EP-RECEIPT-v1 envelope signed by `signing_key` (Ed25519, .sign)."""
    if not isinstance(payload, dict) or not payload or not in_profile(payload):
        raise ValueError("payload must be a non-empty object inside the EMILIA profile")
    signature = signing_key.sign(canonical_json(payload).encode("utf-8"))
    return {"@version": EP_RECEIPT_VERSION, "payload": payload, "signature": {"algorithm": "Ed25519", "value": b64u(signature)}}


def action_object(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """EMILIA Action Object for a Gargoyle receipt: the bound call, the target,
    the principal, the policy id, and a back-reference to the native
    decision so the two artifacts name one action."""
    rc = receipt["request_context"]
    params: Dict[str, Any] = {"args_sha256": rc["args_sha256"]}
    if rc.get("state_sha256"):
        params["state_sha256"] = rc["state_sha256"]
    action = {
        "ep_version": "1.0",
        "action_type": "mcp.tools/call",
        "target": {"system": receipt["target_url"], "resource": rc["tool"]},
        "parameters": params,
        "initiator": rc["principal"],
        "policy_id": receipt["policy"]["policy_id"],
        "requested_at": receipt["timestamp_utc"],
        "gargoyle": {"envelope_version": receipt["envelope_version"], "decision_sha256": receipt["decision_sha256"],
                     "decision_id": receipt["decision_id"]},
    }
    if rc.get("on_behalf_of"):
        action["on_behalf_of"] = rc["on_behalf_of"]
    return action


def action_hash(action: Dict[str, Any]) -> str:
    return "sha256:" + _sha256_hex(canonical_json(action))


def authorization_instance(receipt: Dict[str, Any]) -> str:
    """The per-ceremony value shared by every context: Gargoyle's decision_id
    (a v4 UUID, 122 random bits) as base64url bytes."""
    return b64u(uuid.UUID(receipt["decision_id"]).bytes)


def context_nonce(receipt: Dict[str, Any], index: int) -> str:
    """Per-context nonce: 128 bits derived from the random approval_request_id
    and the approver index, distinct per context, stable per export."""
    digest = hashlib.sha256((NONCE_PREFIX + receipt["approval_request_id"] + "\n" + str(index)).encode("utf-8")).digest()
    return b64u(digest[:16])


def authorization_context(receipt: Dict[str, Any], approver_id: str, index: int, *, expires_at: Optional[str] = None,
                          action: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The Authorization Context an approver signs the hash of. policy_hash is
    Gargoyle's policy pin, so EMILIA's pin check and Gargoyle's are one."""
    action = action or action_object(receipt)
    terms = receipt.get("approval") or {}
    return {
        "ep_version": "1.0",
        "context_type": CONTEXT_TYPE,
        "action_hash": action_hash(action),
        "policy_id": receipt["policy"]["policy_id"],
        "policy_hash": "sha256:" + receipt["policy"]["policy_sha256"],
        "initiator": receipt["request_context"]["principal"],
        "authorization_instance": authorization_instance(receipt),
        "audience": receipt["target_url"],
        "approver": approver_id,
        "approver_index": index,
        "required_approvals": int(terms.get("required", 1)),
        "nonce": context_nonce(receipt, index),
        "issued_at": receipt["timestamp_utc"],
        "expires_at": expires_at or receipt["not_after"],
    }


def context_hash_for(context: Dict[str, Any]) -> bytes:
    """The 32 bytes an EMILIA approver signs (Class B: raw Ed25519 over them)."""
    return hashlib.sha256(canonical_json(context).encode("utf-8")).digest()


def signoff(context: Dict[str, Any], signature: bytes, approver_key_id: str, signed_at: str, key_class: str = "B") -> Dict[str, Any]:
    return {"context_hash": "sha256:" + context_hash_for(context).hex(), "signature": b64u(signature),
            "key_class": key_class, "approver_key_id": approver_key_id, "signed_at": signed_at}


def trust_receipt(receipt: Dict[str, Any], contexts: List[Dict[str, Any]], signoffs: List[Dict[str, Any]],
                  execution: Dict[str, Any], log_signing_key: Any, log_key_id: str) -> Dict[str, Any]:
    """An EP-AUTHORIZATION-RECEIPT-v1 Trust Receipt for one honored call. The
    log proof is a single-leaf EP-MERKLE-v2 tree whose checkpoint the given
    key signs (the issuer's key serves as EMILIA's log key); EMILIA's
    degenerate empty-path rule accepts exactly this shape. committed_at is
    the execution receipt's executed_at."""
    action = action_object(receipt)
    body: Dict[str, Any] = {
        "receipt_id": "ep:receipt:gargoyle:" + receipt["decision_id"],
        "action": action,
        "action_hash": action_hash(action),
        "contexts": [dict(c) for c in contexts],
        "signoffs": [dict(s) for s in signoffs],
        "consumption": {"nonce": authorization_instance(receipt), "state": "COMMITTED", "committed_at": execution["executed_at"]},
    }
    leaf = _leaf_v2(canonical_json(body))
    checkpoint = {"tree_size": 1, "root_hash": "sha256:" + leaf, "log_key_id": log_key_id, "merkle_alg": MERKLE_V2}
    checkpoint["log_signature"] = b64u(log_signing_key.sign(hashlib.sha256(canonical_json(checkpoint).encode("utf-8")).digest()))
    body["log_proof"] = {"alg": MERKLE_V2, "leaf_hash": "sha256:" + leaf, "leaf_index": 0, "inclusion_path": [], "checkpoint": checkpoint}
    body["approver_key_proofs"] = []
    return body


def approver_key_entry(approver_id: str, public_key: Any, *, valid_from: str, valid_to: str, key_class: str = "B") -> Dict[str, Any]:
    """The pinned directory entry EMILIA's verifier takes for one approver."""
    return {"approver_id": approver_id, "public_key": spki_b64u(public_key), "key_class": key_class,
            "valid_from": valid_from, "valid_to": valid_to}
