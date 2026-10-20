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

An EMILIA approver signs the SHA-256 of the JCS Authorization Context (32
bytes, Class B Ed25519); a Gargoyle approver signs the canonical grant. The
bytes differ, so a stored grant signature is not a signoff. The approval
console therefore signs both: it builds the Authorization Context for the
hold it shows (authorization_context, the same bytes this module computes),
signs its hash with the same browser key, and carries the result inside the
grant as the optional `emilia` member, which the grant signature then covers.
The issuer checks the member against the hold before storing the grant
(verify_embedded_signoff), and `gargoyle emilia` turns an evidence log into
Trust Receipts (trust_receipts_from_entries) whose signoffs the approver made
and whose log proof is a Merkle tree over the exported receipts, signed by
the executor's key."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from gargoyle.envelope import canonical_json

EP_RECEIPT_VERSION = "EP-RECEIPT-v1"
MERKLE_V2 = "EP-MERKLE-v2"
CONTEXT_TYPE = "ep.signoff.v1"
NONCE_PREFIX = "gargoyle-emilia-nonce/1\n"
EMILIA_MEMBER = "emilia"                      # the optional grant member: {"context": {...}, "signature": <hex>}
REF_EMILIA_SIGNOFF_MALFORMED = "REF_EMILIA_SIGNOFF_MALFORMED"
REF_EMILIA_CONTEXT_MISMATCH = "REF_EMILIA_CONTEXT_MISMATCH"
REF_EMILIA_SIGNATURE_INVALID = "REF_EMILIA_SIGNATURE_INVALID"
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


def context_nonce(receipt: Dict[str, Any], approver_id: str) -> str:
    """Per-context nonce: 128 bits derived from the random approval_request_id
    and the approver's id, so two approvers of one hold never share a nonce
    whatever order they sign in, and console and issuer compute the same."""
    digest = hashlib.sha256((NONCE_PREFIX + receipt["approval_request_id"] + "\n" + approver_id).encode("utf-8")).digest()
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
        "nonce": context_nonce(receipt, approver_id),
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


# --- the grant's embedded signoff -------------------------------------------

def _parse_instant(text: Any) -> Optional[datetime]:
    if not isinstance(text, str):
        return None
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo is not None else None


def verify_embedded_signoff(grant: Dict[str, Any], receipt: Dict[str, Any], public_keys: Any) -> Dict[str, Any]:
    """Check the grant's `emilia` member against the hold it releases: the
    context must be exactly the one this module derives from the receipt
    for the grant's approver (only approver_index and expires_at are the
    console's to choose, and expires_at may not outlive the receipt or the
    grant), and the signature must verify over the context hash under one
    of the approver's keys. Returns {"accepted", "reason"}."""
    from cryptography.exceptions import InvalidSignature
    member = grant.get(EMILIA_MEMBER)
    if not isinstance(member, dict) or not isinstance(member.get("context"), dict) or not isinstance(member.get("signature"), str):
        return {"accepted": False, "reason": REF_EMILIA_SIGNOFF_MALFORMED}
    ctx = member["context"]
    index, expires_at = ctx.get("approver_index"), ctx.get("expires_at")
    if isinstance(index, bool) or not isinstance(index, int) or index < 1:
        return {"accepted": False, "reason": REF_EMILIA_SIGNOFF_MALFORMED}
    exp = _parse_instant(expires_at)
    if exp is None:
        return {"accepted": False, "reason": REF_EMILIA_SIGNOFF_MALFORMED}
    for bound in (receipt.get("not_after"), grant.get("not_after")):
        limit = _parse_instant(bound)
        if limit is None or exp > limit:
            return {"accepted": False, "reason": REF_EMILIA_CONTEXT_MISMATCH}
    try:
        expected = authorization_context(receipt, grant["approver_key_id"], index, expires_at=expires_at)
    except (KeyError, TypeError, ValueError):
        return {"accepted": False, "reason": REF_EMILIA_CONTEXT_MISMATCH}
    if ctx != expected:
        return {"accepted": False, "reason": REF_EMILIA_CONTEXT_MISMATCH}
    try:
        signature = bytes.fromhex(member["signature"])
    except ValueError:
        return {"accepted": False, "reason": REF_EMILIA_SIGNATURE_INVALID}
    digest = context_hash_for(ctx)
    keys = list(public_keys) if isinstance(public_keys, (list, tuple)) else [public_keys]
    for key in keys:
        if key is None:
            continue
        try:
            key.verify(signature, digest)
            return {"accepted": True, "reason": None}
        except InvalidSignature:
            continue
        except Exception:
            continue
    return {"accepted": False, "reason": REF_EMILIA_SIGNATURE_INVALID}


def signoff_from_grant(grant: Dict[str, Any], signed_at: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """The EMILIA signoff a grant carries, or None when the approver's
    console did not sign one (an approver CLI, or a console older than
    this member). signed_at is not in the grant; the caller passes the
    evidence entry's time, which lies inside the context window."""
    member = grant.get(EMILIA_MEMBER) if isinstance(grant, dict) else None
    if not isinstance(member, dict) or not isinstance(member.get("context"), dict):
        return None
    return signoff(member["context"], bytes.fromhex(member["signature"]), grant["approver_key_id"], signed_at or member["context"]["issued_at"])


# --- Merkle tree over exported receipts (EP-MERKLE-v2) ------------------------

def merkle_tree(leaves: List[str]) -> "tuple[str, List[List[Dict[str, str]]]]":
    """Root and one inclusion path per leaf (hex leaf hashes in), with
    EMILIA's positional pair rule: an odd node is promoted unchanged, so
    every path folds back to the root under their verify_merkle_anchor."""
    if not leaves:
        raise ValueError("no leaves")
    paths: List[List[Dict[str, str]]] = [[] for _ in leaves]
    level = [(h, [i]) for i, h in enumerate(leaves)]       # (hash, leaf indexes under it)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 == len(level):
                nxt.append(level[i])
                continue
            (lh, li), (rh, ri) = level[i], level[i + 1]
            for leaf in li:
                paths[leaf].append({"hash": rh, "position": "right"})
            for leaf in ri:
                paths[leaf].append({"hash": lh, "position": "left"})
            nxt.append((_pair_v2(lh, rh), li + ri))
        level = nxt
    return level[0][0], paths


def trust_receipts_from_entries(entries: List[Any], *, log_signing_key: Any, log_key_id: str) -> Dict[str, Any]:
    """Every honored, flagged evidence entry whose grants all carry an EMILIA
    signoff becomes a Trust Receipt; the receipts form one Merkle tree whose
    checkpoint `log_signing_key` signs. Returns {"receipts": [...],
    "checkpoint": {...}, "skipped": n} where skipped counts honored flagged
    entries without a signoff on every grant."""
    from gargoyle.approval import as_grant_list
    bodies: List[Dict[str, Any]] = []
    skipped = 0
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("kind") != "honored":
            continue
        receipt, execution = entry.get("receipt"), entry.get("execution")
        if not isinstance(receipt, dict) or not receipt.get("requires_approval") or not isinstance(execution, dict):
            continue
        grants = [g for g in as_grant_list(entry.get("grant")) if isinstance(g, dict)]
        signoffs = [signoff_from_grant(g, entry.get("at")) for g in grants]
        if not grants or any(s is None for s in signoffs):
            skipped += 1
            continue
        contexts = [g[EMILIA_MEMBER]["context"] for g in grants]
        action = action_object(receipt)
        bodies.append({
            "receipt_id": "ep:receipt:gargoyle:" + receipt["decision_id"],
            "action": action,
            "action_hash": action_hash(action),
            "contexts": contexts,
            "signoffs": signoffs,
            "consumption": {"nonce": authorization_instance(receipt), "state": "COMMITTED", "committed_at": execution["executed_at"]},
        })
    if not bodies:
        return {"receipts": [], "checkpoint": None, "skipped": skipped}
    leaves = [_leaf_v2(canonical_json(b)) for b in bodies]
    root, paths = merkle_tree(leaves)
    checkpoint = {"tree_size": len(leaves), "root_hash": "sha256:" + root, "log_key_id": log_key_id, "merkle_alg": MERKLE_V2}
    checkpoint["log_signature"] = b64u(log_signing_key.sign(hashlib.sha256(canonical_json(checkpoint).encode("utf-8")).digest()))
    receipts = []
    for i, body in enumerate(bodies):
        out = dict(body)
        out["log_proof"] = {"alg": MERKLE_V2, "leaf_hash": "sha256:" + leaves[i], "leaf_index": i, "inclusion_path": paths[i], "checkpoint": checkpoint}
        out["approver_key_proofs"] = []
        receipts.append(out)
    return {"receipts": receipts, "checkpoint": checkpoint, "skipped": skipped}


def verification_for(trust_receipt: Dict[str, Any], approver_keys_hex: Dict[str, Any], log_public_key: Any) -> Dict[str, Any]:
    """EMILIA's pinned trust inputs for one exported receipt: for each
    signoff, the approver key (among the id's current and past keys) that
    verifies it, and the log key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    entries: Dict[str, Any] = {}
    for so in trust_receipt["signoffs"]:
        kid = so["approver_key_id"]
        candidates = approver_keys_hex.get(kid)
        candidates = list(candidates) if isinstance(candidates, (list, tuple)) else [candidates]
        digest = bytes.fromhex(so["context_hash"][7:])
        for hexkey in candidates:
            if not isinstance(hexkey, str):
                continue
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(hexkey))
            try:
                pub.verify(b64u_decode(so["signature"]), digest)
            except Exception:
                continue
            entries[kid] = {"approver_id": kid, "public_key": spki_b64u(pub), "key_class": "B"}
            break
    return {"approver_keys": entries, "log_public_key": spki_b64u(log_public_key)}
