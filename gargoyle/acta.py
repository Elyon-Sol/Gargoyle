# SPDX-License-Identifier: Apache-2.0
"""Acta signed decision receipts (draft-farley-acta-signed-receipts-03).

Two directions, as with EMILIA (gargoyle.emilia):

- a verifier for the draft's envelope shape (`verify_receipt`,
  `verify_sequence`): the signing input of section 6.6, the chain link of
  section 6.7, key resolution outside the receipt (section 9.5) with the
  validity window of section 9.2, and the combination rule the -04 editor's
  copy states in its section 5.3: a check that failed outweighs one that
  could not run, so the outcome is `invalid`, else `undecidable`, else
  `valid`. Archival mode only (section 9.1): a receipt's age is reported,
  never judged;
- an exporter (`export_witness`): the issuer's witness (SPEC.md 15.1) as a
  chain of `protectmcp:decision` receipts signed by the issuer key, one per
  decision the issuer took, plus a signed commitment to the chain's length
  and tail. Acta's own chain cannot show that its tail is complete (section
  9.7); the witness is the issuer-signed record outside the chain that the
  draft says is needed, and every exported receipt names the witness entry
  it came from.

A Gargoyle receipt (SPEC.md 3) is not re-encoded: the export is the
issuer's statement about its decisions, in Acta's vocabulary, signed at
export time. The native receipt, grant and execution receipt stay the
evidence; the `gargoyle` member of each payload points back to them.

Policy digests follow section 6.8 (`acta-policy-digest-v1`). The manifest
for a Gargoyle pin names one file: `rules.json` under engine
`gargoyle.rules/1` for the shipped rules policy (its pin is the SHA-256 of
the rules file's bytes, which is what the manifest wants), `policy.json`
under the policy id otherwise. The issuer serves the current bundle at
`/.well-known/acta-policies/<hex>.json` and its key at
`/.well-known/acta-keys.json` (section 5.3).
"""

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from gargoyle.envelope import canonical_json
from gargoyle.jws import b64url_decode, b64url_encode

ACTA_DRAFT = "draft-farley-acta-signed-receipts-03"
DECISION_TYPE = "protectmcp:decision"
COMMITMENT_TYPE = "gargoyle:chain-commitment"
POLICY_DIGEST_CONSTRUCTION = "acta-policy-digest-v1"
POLICY_BUNDLE_SCHEMA = "acta.policy-bundle.v1"
RULES_FILE_NAME = "rules.json"

VALID, INVALID, UNDECIDABLE = "valid", "invalid", "undecidable"
EXIT = {VALID: 0, INVALID: 1, UNDECIDABLE: 2}

# Finding codes. Where the ecosystem's reference verifier names a check, the
# same name is used, so a conformance index can be read against this output.
UNKNOWN_FORMAT = "unknown_format"
MALFORMED_PAYLOAD = "malformed_payload"
ISSUER_KID_MISMATCH = "issuer_kid_mismatch"
SIGNATURE_IN_SIGNING_INPUT = "signature_in_signing_input"
MALFORMED_CHAIN_LINK = "malformed_chain_link"
UNSUPPORTED_CHAIN_HASH_ALGORITHM = "unsupported_chain_hash_algorithm"
CHAIN_BREAK = "chain_break"
KEY_NOT_FOUND = "key_not_found"
KEY_OUTSIDE_VALIDITY_WINDOW = "key_outside_validity_window"
UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
ALGORITHM_KEY_MISMATCH = "algorithm_key_mismatch"
SIGNATURE_INVALID = "signature_invalid"
# Warnings and information: never decide the outcome.
EMBEDDED_KEY_IGNORED = "embedded_key_ignored"
NULL_CHAIN_LINK = "null_chain_link"
FIRST_RECEIPT_LINKS_OUTSIDE = "first_receipt_links_outside"

_EMBEDDED_KEY_MEMBERS = ("public_key", "publicKey", "pubkey", "verification_key", "verification_jwk", "jwk", "jwks")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_TZ = re.compile(r"(Z|[+-]\d\d:\d\d)$")


# --- the chain link (section 6.7) -------------------------------------------

def receipt_link(receipt: Dict[str, Any]) -> str:
    """`"sha256:" + hex(SHA-256(JCS(receipt)))` over the whole signed receipt,
    signature included, so a re-signed receipt is a different link."""
    return "sha256:" + hashlib.sha256(canonical_json(receipt).encode("utf-8")).hexdigest()


def _read_link(value: Any) -> Tuple[str, Optional[str], Optional[str]]:
    """How a `previousReceiptHash` reads: (kind, target, code). kind is
    `absent`, `null`, `ok` (target is the normalized "sha256:<hex>" link),
    `malformed` or `unsupported` (another hash algorithm named)."""
    if value is None:
        return "null", None, None
    if not isinstance(value, str):
        return "malformed", None, MALFORMED_CHAIN_LINK
    if _HEX64.match(value):
        return "ok", "sha256:" + value, None          # the bare form of earlier revisions: read, never emitted
    if ":" not in value:
        return "malformed", None, MALFORMED_CHAIN_LINK
    alg, _, digest = value.partition(":")
    if alg != "sha256":
        if re.match(r"^[a-z0-9-]+$", alg):
            return "unsupported", None, UNSUPPORTED_CHAIN_HASH_ALGORITHM
        return "malformed", None, MALFORMED_CHAIN_LINK
    if _HEX64.match(digest):
        return "ok", value, None
    return "malformed", None, MALFORMED_CHAIN_LINK


# --- keys (sections 5.3, 9.2, 9.5) --------------------------------------------

def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not _RFC3339_TZ.search(value):
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo is not None else None


def keys_from_jwks(jwks: Any, source: str = "jwks") -> Dict[str, Dict[str, Any]]:
    """{kid: {"key", "kty", "valid_from", "valid_until", "source"}} from a
    JWK Set. Ed25519 (OKP) and P-256 (EC) keys; others are skipped. The
    window members are the draft's `valid_from` / `valid_until` (section
    9.2), read as [from, until)."""
    from gargoyle.jws import keys_from_jwks as _keys
    parsed = _keys(jwks)
    out: Dict[str, Dict[str, Any]] = {}
    for entry in (jwks.get("keys") if isinstance(jwks, dict) else None) or []:
        if not isinstance(entry, dict) or entry.get("kid") not in parsed:
            continue
        out[entry["kid"]] = {"key": parsed[entry["kid"]], "kty": entry.get("kty"), "source": source,
                             "valid_from": _parse_time(entry.get("valid_from")), "valid_until": _parse_time(entry.get("valid_until"))}
    return out


def jwks_for(public_key: Any, kid: str, *, valid_from: Optional[str] = None) -> Dict[str, Any]:
    """The issuer's JWK Set (section 5.3): one Ed25519 key."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64url_encode(raw), "use": "sig", "alg": "EdDSA"}
    if valid_from:
        key["valid_from"] = valid_from
    return {"keys": [key]}


def _verify_signature(alg: Any, key_entry: Dict[str, Any], sig_hex: Any, message: bytes) -> Optional[Tuple[str, str]]:
    """None when the signature verifies, else (severity, code)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    key = key_entry["key"]
    if not isinstance(sig_hex, str) or not re.match(r"^[0-9a-f]+$", sig_hex) or len(sig_hex) % 2:
        return INVALID, SIGNATURE_INVALID
    sig = bytes.fromhex(sig_hex)
    try:
        if alg == "EdDSA":
            if not isinstance(key, ed25519.Ed25519PublicKey):
                return INVALID, ALGORITHM_KEY_MISMATCH
            key.verify(sig, message)
        elif alg == "ES256":
            if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
                return INVALID, ALGORITHM_KEY_MISMATCH
            if len(sig) != 64:
                return INVALID, SIGNATURE_INVALID
            key.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), message, ec.ECDSA(hashes.SHA256()))
        elif isinstance(alg, str) and alg:
            return UNDECIDABLE, UNSUPPORTED_ALGORITHM
        else:
            return INVALID, UNKNOWN_FORMAT
    except InvalidSignature:
        return INVALID, SIGNATURE_INVALID
    except (ValueError, TypeError):
        return INVALID, SIGNATURE_INVALID
    return None


# --- one receipt (sections 5.2, 6.6, 6.7, 9.5) ----------------------------------

def _is_envelope(receipt: Any) -> bool:
    return (isinstance(receipt, dict) and set(receipt) == {"payload", "signature"} and isinstance(receipt["payload"], dict)
            and isinstance(receipt["signature"], dict) and {"alg", "kid", "sig"} <= set(receipt["signature"])
            and all(isinstance(receipt["signature"][k], str) for k in ("alg", "kid", "sig")))


def verify_receipt(receipt: Any, keys: Optional[Dict[str, Dict[str, Any]]] = None, *,
                   previous: Optional[Dict[str, Any]] = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Verify one envelope-shape receipt. `keys` is the resolved key set
    (`keys_from_jwks`); None means no key was supplied, so the signature
    cannot be checked. `previous` is a receipt this one must follow.

    Returns {"outcome", "code", "exit", "findings": [{"severity", "code",
    "detail"}], "kid", "alg", "issued_at", "age_seconds", "key_status",
    "key_source", "link": {...}, "receipt_hash"}. Every check runs; the
    outcome is `invalid` if any check failed, `undecidable` if any could not
    run, else `valid`, and `code` names the check that decided it."""
    findings: List[Dict[str, Any]] = []

    def note(severity: str, code: str, detail: str = "") -> None:
        findings.append({"severity": severity, "code": code, "detail": detail})

    result: Dict[str, Any] = {"shape": None, "kid": None, "alg": None, "issued_at": None, "age_seconds": None,
                              "key_status": None, "key_source": None, "link": {"present": False, "value": None, "target": None},
                              "receipt_hash": None}
    if not _is_envelope(receipt):
        note(UNDECIDABLE, UNKNOWN_FORMAT, "not the envelope shape of section 2.1: exactly {payload, signature{alg, kid, sig}}")
        return _finish(result, findings)
    payload, sig = receipt["payload"], receipt["signature"]
    result.update(shape="envelope", kid=sig["kid"], alg=sig["alg"], receipt_hash=receipt_link(receipt))

    # Section 2.2: the members every payload carries.
    issued = _parse_time(payload.get("issued_at"))
    if not isinstance(payload.get("type"), str) or not payload["type"] or issued is None or not isinstance(payload.get("issuer_id"), str):
        note(INVALID, MALFORMED_PAYLOAD, "type, issued_at (RFC 3339 with a timezone) and issuer_id are required")
    else:
        result["issued_at"] = payload["issued_at"]
        result["age_seconds"] = max(0, int(((now or datetime.now(timezone.utc)) - issued).total_seconds()))
        if payload["issuer_id"] != sig["kid"]:
            note(INVALID, ISSUER_KID_MISMATCH, "issuer_id must match signature.kid")
    # Section 6.6: the object canonicalized never contains a signature member.
    if "signature" in payload:
        note(INVALID, SIGNATURE_IN_SIGNING_INPUT, "the payload carries a signature member")
    # Section 9.5: a key inside the receipt is never used; say so.
    embedded = [m for m in _EMBEDDED_KEY_MEMBERS if m in payload]
    if embedded:
        note("warning", EMBEDDED_KEY_IGNORED, "payload member(s) %s not used for verification" % ", ".join(embedded))

    # Section 6.7: the chain link, alone and against a supplied predecessor.
    link_kind, link_target, link_code = ("absent", None, None) if "previousReceiptHash" not in payload else _read_link(payload["previousReceiptHash"])
    result["link"] = {"present": link_kind not in ("absent", "null"), "value": payload.get("previousReceiptHash"),
                      "target": link_target, "kind": link_kind}
    if link_kind == "malformed":
        note(INVALID, MALFORMED_CHAIN_LINK, "previousReceiptHash is not \"sha256:\" and 64 lowercase hex characters")
    elif link_kind == "unsupported":
        note(UNDECIDABLE, UNSUPPORTED_CHAIN_HASH_ALGORITHM, "previousReceiptHash names a hash algorithm other than sha256")
    elif link_kind == "null":
        note("warning", NULL_CHAIN_LINK, "previousReceiptHash is null; an issuer must omit the member instead (section 2.2)")
    if previous is not None:
        if link_kind == "ok":
            expected = receipt_link(previous) if isinstance(previous, dict) else None
            if link_target != expected:
                note(INVALID, CHAIN_BREAK, "previousReceiptHash is not the link of the receipt supplied")
        elif link_kind in ("absent", "null"):
            note(INVALID, CHAIN_BREAK, "no link: an unchained receipt does not follow the receipt supplied")
        # malformed and unsupported are already recorded; neither can follow anything.

    # Sections 5.2 and 9.2: the key, from outside the receipt, within its window.
    entry = (keys or {}).get(sig["kid"])
    if entry is None:
        note(UNDECIDABLE, KEY_NOT_FOUND, "no key for kid %r in the supplied key set" % sig["kid"] if keys else "no key set supplied")
    else:
        result["key_source"] = entry.get("source")
        vf, vu = entry.get("valid_from"), entry.get("valid_until")
        if vf is None and vu is None:
            result["key_status"] = "no_window"
        elif issued is not None and ((vf is not None and issued < vf) or (vu is not None and issued >= vu)):
            result["key_status"] = "outside"
            note(INVALID, KEY_OUTSIDE_VALIDITY_WINDOW, "issued_at is outside the key's [valid_from, valid_until)")
        else:
            result["key_status"] = "inside" if issued is not None else None
        failure = _verify_signature(sig["alg"], entry, sig["sig"], canonical_json(payload).encode("utf-8"))
        if failure is not None:
            note(failure[0], failure[1], "signature over JCS(payload) under alg %r" % sig["alg"])
    return _finish(result, findings)


def _finish(result: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    severities = [f["severity"] for f in findings]
    outcome = INVALID if INVALID in severities else (UNDECIDABLE if UNDECIDABLE in severities else VALID)
    code = next((f["code"] for f in findings if f["severity"] == outcome), None)
    result.update(outcome=outcome, code=code, exit=EXIT[outcome], findings=findings,
                  warnings=[f["code"] for f in findings if f["severity"] == "warning"])
    return result


# --- a sequence (-04 section 6.7.1) --------------------------------------------

def verify_sequence(receipts: Iterable[Any], keys: Optional[Dict[str, Dict[str, Any]]] = None, *,
                    now: Optional[datetime] = None) -> Dict[str, Any]:
    """Receipts in file order. A receipt with no link (or a null one, with a
    warning) begins a chain; a link on the first receipt is reported, not
    failed; any other link must be the link of the line before it, else
    `chain_break`. Returns {"outcome", "code", "exit", "count", "chains",
    "chain_breaks", "line": the line the outcome turns on, "results"}."""
    results, chains, breaks, prev = [], 0, 0, None
    for n, receipt in enumerate(receipts, 1):
        r = verify_receipt(receipt, keys, now=now)
        kind = r["link"].get("kind")
        if kind in ("absent", "null") or r["shape"] is None:
            chains += 1
        elif prev is None:
            chains += 1
            r["findings"].append({"severity": "info", "code": FIRST_RECEIPT_LINKS_OUTSIDE, "detail": "the first receipt links to one not supplied"})
        elif kind == "ok":
            if r["link"]["target"] != receipt_link(prev):
                breaks += 1
                r["findings"].append({"severity": INVALID, "code": CHAIN_BREAK, "detail": "previousReceiptHash is not the link of line %d" % (n - 1)})
                r = _finish({k: v for k, v in r.items() if k not in ("outcome", "code", "exit", "findings", "warnings")}, r["findings"])
        r["line"] = n
        results.append(r)
        prev = receipt if r["shape"] else None
    worst = max((r["outcome"] for r in results), key=lambda o: EXIT[o] if o != INVALID else 9, default=VALID)
    decided = next((r for r in results if r["outcome"] == worst), None)
    return {"outcome": worst, "code": decided["code"] if decided else None, "exit": EXIT[worst], "count": len(results),
            "chains": chains, "chain_breaks": breaks, "line": decided["line"] if decided else None, "results": results}


# --- policy digest and bundle (section 6.8) ------------------------------------

def policy_digest(engine: str, files: Iterable[Tuple[str, str]]) -> Tuple[str, Dict[str, Any]]:
    """`acta-policy-digest-v1` over a manifest of (name, sha256) pairs sorted
    by name. Returns ("sha256:<hex>", manifest)."""
    entries = sorted(({"name": n, "sha256": h} for n, h in files), key=lambda e: e["name"])
    manifest = {"construction": POLICY_DIGEST_CONSTRUCTION, "engine": engine, "files": entries}
    return "sha256:" + hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest(), manifest


def manifest_for_pin(pin: Dict[str, Any]) -> Tuple[str, str]:
    """(engine, file name) the Gargoyle convention gives a policy pin, so a
    digest can be computed from the pin alone, for entries whose policy file
    is long gone. The shipped rules policy pins the SHA-256 of its file's
    bytes: that file, named `rules.json`. Anything else is structured
    configuration hashed by its own policy: `policy.json` under the policy
    id as engine (section 6.8's rule for configuration that is not a source file)."""
    pid = str(pin.get("policy_id", ""))
    if pid.startswith("gargoyle.rules/"):
        return pid, RULES_FILE_NAME
    return pid, "policy.json"


def policy_digest_for_pin(pin: Dict[str, Any]) -> str:
    engine, name = manifest_for_pin(pin)
    return policy_digest(engine, [(name, str(pin["policy_sha256"]))])[0]


def policy_bundle(engine: str, files: Iterable[Tuple[str, str]], generated_at: str) -> Dict[str, Any]:
    """The published form of section 6.8.1: name, hash and content of every
    policy file, with the digest a verifier recomputes from the content."""
    named = [(n, c) for n, c in files]
    digest, manifest = policy_digest(engine, [(n, hashlib.sha256(c.encode("utf-8")).hexdigest()) for n, c in named])
    by_name = dict(named)
    return {"schema": POLICY_BUNDLE_SCHEMA, "construction": POLICY_DIGEST_CONSTRUCTION, "engine": engine, "policy_digest": digest,
            "files": [{"name": e["name"], "sha256": e["sha256"], "content": by_name[e["name"]]} for e in manifest["files"]],
            "generated_at": generated_at}


def verify_policy_bundle(bundle: Any) -> Dict[str, Any]:
    """Recompute a bundle from its own bytes (section 6.8.1)."""
    if not isinstance(bundle, dict) or bundle.get("schema") != POLICY_BUNDLE_SCHEMA or bundle.get("construction") != POLICY_DIGEST_CONSTRUCTION \
            or not isinstance(bundle.get("files"), list) or not isinstance(bundle.get("engine"), str):
        return {"accepted": False, "reason": "malformed_bundle"}
    files = []
    for f in bundle["files"]:
        if not isinstance(f, dict) or not isinstance(f.get("name"), str) or not isinstance(f.get("content"), str):
            return {"accepted": False, "reason": "malformed_bundle"}
        if hashlib.sha256(f["content"].encode("utf-8")).hexdigest() != f.get("sha256"):
            return {"accepted": False, "reason": "file_hash_mismatch", "name": f["name"]}
        files.append((f["name"], f["sha256"]))
    digest, _ = policy_digest(bundle["engine"], files)
    if digest != bundle.get("policy_digest"):
        return {"accepted": False, "reason": "policy_digest_mismatch", "computed": digest}
    return {"accepted": True, "policy_digest": digest}


def bundle_for_policy(policy: Any, generated_at: str) -> Optional[Dict[str, Any]]:
    """The current bundle of a live policy, when its source is a file the
    service can read (the shipped rules policy); None otherwise (an OPA
    policy's modules live in OPA, so only the digest is known)."""
    pin = policy.pin()
    engine, name = manifest_for_pin(pin)
    path = getattr(policy, "path", None)
    if not isinstance(path, str) or name != RULES_FILE_NAME:
        return None
    try:
        with open(path, "rb") as f:
            raw = f.read()
        content = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    if hashlib.sha256(raw).hexdigest() != pin.get("policy_sha256"):
        return None                                       # changed between the pin and the read; the next request sees both move
    return policy_bundle(engine, [(name, content)], generated_at)


# --- the export (SPEC.md 15.1 -> protectmcp:decision) -----------------------------

def _sign(payload: Dict[str, Any], signing_key: Any, kid: str) -> Dict[str, Any]:
    sig = signing_key.sign(canonical_json(payload).encode("utf-8")).hex()
    return {"payload": payload, "signature": {"alg": "EdDSA", "kid": kid, "sig": sig}}


def _refs(entry: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    refs = {"witness_seq": entry.get("seq"), "witness_entry_sha256": entry.get("entry_sha256"), **extra}
    return {k: v for k, v in refs.items() if v is not None}


def export_witness(entries: Iterable[Any], *, signing_key: Any, key_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """The issuer's decisions as an Acta receipt chain. One receipt per
    `issued` (allow, or require_approval when held), `refused` (deny),
    completed `granted` of a receipt hold (allow, reason approval_granted)
    and `declined` (deny, reason approval_declined) entry, in witness order,
    each linked to the one before (section 6.7) and naming the witness entry
    it came from. `policy_digest` is section 6.8 over the pin the witness
    recorded (gargoyle-witness/2); entries without one carry no digest.
    Plans, lifecycle events and partial grants are counted, not exported.

    Returns {"receipts", "commitment", "witness_head", "counts"}. The
    commitment is a signed `gargoyle:chain-commitment` naming the chain's
    length and terminal link and the witness head: the statement outside the
    chain that section 9.7 asks for."""
    receipts: List[Dict[str, Any]] = []
    holds: Dict[str, Dict[str, Any]] = {}
    counts = {"issued": 0, "refused": 0, "granted": 0, "declined": 0, "skipped": 0, "unresolved_hold": 0, "no_policy": 0}
    head = None
    prev: Optional[Dict[str, Any]] = None

    def emit(entry: Dict[str, Any], tool: Any, decision: str, pin: Any, *, reason: Optional[str] = None, **refs: Any) -> None:
        nonlocal prev
        payload: Dict[str, Any] = {"type": DECISION_TYPE, "tool_name": str(tool), "decision": decision,
                                   "issued_at": str(entry.get("at")), "issuer_id": key_id}
        if reason:
            payload["reason"] = reason
        if isinstance(pin, dict) and isinstance(pin.get("policy_sha256"), str):
            payload["policy_digest"] = policy_digest_for_pin(pin)
        else:
            counts["no_policy"] += 1
        if prev is not None:
            payload["previousReceiptHash"] = receipt_link(prev)
        payload["gargoyle"] = _refs(entry, **refs)
        receipt = _sign(payload, signing_key, key_id)
        receipts.append(receipt)
        prev = receipt

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        head = {"seq": entry.get("seq"), "entry_sha256": entry.get("entry_sha256")}
        ev = entry.get("event")
        if ev == "issued":
            counts["issued"] += 1
            refs = {"decision_id": entry.get("decision_id"), "decision_sha256": entry.get("decision_sha256"),
                    "args_sha256": entry.get("args_sha256"), "target_url": entry.get("target_url")}
            if entry.get("held") and not entry.get("covered"):
                arid = entry.get("approval_request_id")
                if isinstance(arid, str):
                    holds[arid] = {"tool": entry.get("tool"), "policy": entry.get("policy"), **refs}
                emit(entry, entry.get("tool"), "require_approval", entry.get("policy"), approval_request_id=arid, **refs)
            else:
                emit(entry, entry.get("tool"), "allow", entry.get("policy"), reason="covered_by_plan" if entry.get("covered") else None, **refs)
        elif ev == "refused" and isinstance(entry.get("tool"), str) and entry.get("tool") != "plan":
            counts["refused"] += 1
            emit(entry, entry["tool"], "deny", entry.get("policy"), reason=str(entry.get("reason") or "refused"), target_url=entry.get("target_url"))
        elif ev in ("granted", "declined"):
            arid = entry.get("approval_request_id")
            if ev == "granted" and (entry.get("hold_kind") == "plan" or not (isinstance(entry.get("collected"), int) and isinstance(entry.get("required"), int)
                                                                          and entry["collected"] >= entry["required"])):
                counts["skipped"] += 1
                continue
            hold = holds.get(arid) if isinstance(arid, str) else None
            tool = (hold or {}).get("tool") or entry.get("tool")
            if not isinstance(tool, str) or tool == "plan":
                counts["unresolved_hold" if tool != "plan" else "skipped"] += 1
                continue
            counts[ev] += 1
            refs = {k: (hold or {}).get(k) for k in ("decision_id", "decision_sha256", "args_sha256", "target_url")}
            if ev == "granted":
                emit(entry, tool, "allow", (hold or {}).get("policy"), reason="approval_granted", approval_request_id=arid,
                     approvers_collected=entry.get("collected"), approvers_required=entry.get("required"), **refs)
            else:
                emit(entry, tool, "deny", (hold or {}).get("policy"), reason="approval_declined", approval_request_id=arid, **refs)
        else:
            counts["skipped"] += 1

    commitment = None
    if receipts:
        at = (now or datetime.now(timezone.utc)).isoformat()
        commitment = _sign({"type": COMMITMENT_TYPE, "issuer_id": key_id, "issued_at": at, "count": len(receipts),
                            "terminal_hash": receipt_link(receipts[-1]), "witness_head": head,
                            "witness_range": {"first_seq": receipts[0]["payload"]["gargoyle"].get("witness_seq"),
                                              "last_seq": receipts[-1]["payload"]["gargoyle"].get("witness_seq")}},
                           signing_key, key_id)
    return {"receipts": receipts, "commitment": commitment, "witness_head": head, "counts": counts}


def verify_commitment(commitment: Any, receipts: List[Dict[str, Any]], keys: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """The commitment's signature, and that it names exactly these receipts:
    their count and the link of the last. A shorter set is reported as
    truncated (section 9.7), a longer one as beyond the commitment."""
    r = verify_receipt(commitment, keys)
    if r["outcome"] != VALID:
        return {"accepted": False, "reason": r["code"], "verification": r}
    p = commitment["payload"]
    if p.get("type") != COMMITMENT_TYPE or not isinstance(p.get("count"), int) or not isinstance(p.get("terminal_hash"), str):
        return {"accepted": False, "reason": "malformed_commitment"}
    if len(receipts) < p["count"]:
        return {"accepted": False, "reason": "truncated", "committed": p["count"], "held": len(receipts)}
    if len(receipts) > p["count"]:
        return {"accepted": False, "reason": "beyond_commitment", "committed": p["count"], "held": len(receipts)}
    if not receipts or receipt_link(receipts[-1]) != p["terminal_hash"]:
        return {"accepted": False, "reason": "terminal_hash_mismatch"}
    return {"accepted": True, "count": p["count"], "terminal_hash": p["terminal_hash"], "witness_head": p.get("witness_head")}


def read_jsonl(path: str) -> List[Any]:
    out: List[Any] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    out.append(None)
    return out
