"""EMILIA Protocol interoperation: their vectors against Gargoyle's canonical
form, and Gargoyle exports in their two receipt profiles. When the EMILIA
repository is checked out and GARGOYLE_EMILIA_REPO points at it, the exports
are also fed through EMILIA's own Python verifier."""
import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle import emilia
from gargoyle.approval import build_grant, sign_grant
from gargoyle.envelope import build_envelope, canonical_json, sign_envelope
from gargoyle.execution import build_execution_receipt, sign_execution_receipt, verify_chain

FIX = Path(__file__).parent / "fixtures" / "emilia"
T0 = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


def _key(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def test_emilia_receipt_vectors_verify_under_gargoyles_canonical_form():
    vectors = json.loads((FIX / "receipts.v1.json").read_text())["vectors"]
    assert len(vectors) == 14
    for v in vectors:
        result = emilia.verify_ep_receipt(v["document"], v.get("public_key", ""))
        assert result["valid"] == v["expect"]["valid"], (v["id"], result)


def _depth(value, n=0):
    if isinstance(value, dict):
        return max([n + 1] + [_depth(x, n + 1) for x in value.values()])
    if isinstance(value, list):
        return max([n + 1] + [_depth(x, n + 1) for x in value])
    return n


def _lone_surrogate(value):
    if isinstance(value, str):
        return any(0xD800 <= ord(c) <= 0xDFFF for c in value)
    if isinstance(value, list):
        return any(_lone_surrogate(x) for x in value)
    if isinstance(value, dict):
        return any(_lone_surrogate(k) or _lone_surrogate(x) for k, x in value.items())
    return False


def _dup_hook(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("duplicate member")
    return dict(pairs)


def test_emilia_canonicalization_vectors_match_rfc8785_canonical_json():
    """EMILIA's strict gate (duplicate names, lone surrogates, depth over 64,
    I-JSON profile) and then SHA-256 over Gargoyle's RFC 8785 bytes."""
    vectors = json.loads((FIX / "canonicalization.v1.json").read_text())["vectors"]
    assert len(vectors) == 35
    for v in vectors:
        spec = v["canonicalization"]
        try:
            obj = json.loads(spec["input_json"], object_pairs_hook=_dup_hook)
            ok = not _lone_surrogate(obj) and _depth(obj) <= 64 and emilia.in_profile(obj)
        except (ValueError, RecursionError):
            ok = False
        digest = hashlib.sha256(canonical_json(obj).encode()).hexdigest() if ok else None
        assert (digest is not None and digest == spec.get("expected_digest")) == v["expect"]["valid"], (v["id"], spec.get("note"))


def _chain():
    issuer, approver, executor = _key("gargoyle-spec-issuer"), _key("gargoyle-spec-approver"), _key("gargoyle-spec-executor")
    call = {"tool": "write_file", "args": {"path": "C:\\finance\\q3.md", "content": "..."}, "principal": "claude@hearthcorp.com", "on_behalf_of": "jdoe@hearthcorp.com"}
    pin = {"policy_id": "gargoyle.rules/1", "policy_sha256": "19" * 32}
    env = build_envelope(decision="ELIGIBLE", target_url="mcp://filesystem/C:\\finance", call=call, policy_pin=pin,
                         timestamp_utc=T0.isoformat(), requires_approval=True, approval={"required": 1})
    receipt = sign_envelope(env, issuer, "issuer-1", not_after=T0 + timedelta(minutes=5), decision_id=str(uuid.uuid4()), approval_request_id=str(uuid.uuid4()))
    grant = sign_grant(build_grant(decision_sha256=receipt["decision_sha256"], approval_request_id=receipt["approval_request_id"],
                                   grant_id=str(uuid.uuid4()), not_after=T0 + timedelta(minutes=10)), approver, "sysops@hearthcorp.com")
    execution = sign_execution_receipt(build_execution_receipt(envelope=receipt, outputs={"ok": True}, executed_at=T0 + timedelta(minutes=1)), executor, "executor-1")
    chain = verify_chain(receipt, execution, issuer_public_keys={"issuer-1": issuer.public_key()}, executor_public_keys={"executor-1": executor.public_key()},
                         grant=grant, approver_public_keys={"sysops@hearthcorp.com": approver.public_key()})
    assert chain["accepted"], chain
    return issuer, approver, executor, receipt, grant, execution


def test_gargoyle_receipt_exports_as_ep_receipt_and_verifies_both_ways():
    issuer, approver, executor, receipt, grant, execution = _chain()
    for payload, signer in ((receipt, issuer), (execution, executor), (grant, approver)):
        doc = emilia.ep_receipt(payload, signer)
        assert emilia.verify_ep_receipt(doc, emilia.spki_b64u(signer.public_key()))["valid"]
        assert not emilia.verify_ep_receipt(doc, emilia.spki_b64u(executor.public_key() if signer is issuer else issuer.public_key()))["valid"]
    doc = emilia.ep_receipt(receipt, issuer)
    doc["payload"]["request_context"]["args_sha256"] = "0" * 64
    assert not emilia.verify_ep_receipt(doc, emilia.spki_b64u(issuer.public_key()))["valid"]


def _trust_receipt(issuer, approver, receipt, grant, execution, *, reuse_grant_signature=False):
    ctx = emilia.authorization_context(receipt, grant["approver_key_id"], 1, expires_at=min(receipt["not_after"], grant["not_after"]))
    signature = bytes.fromhex(grant["approver_signature"]) if reuse_grant_signature else approver.sign(emilia.context_hash_for(ctx))
    so = emilia.signoff(ctx, signature, grant["approver_key_id"], (T0 + timedelta(seconds=30)).isoformat())
    tr = emilia.trust_receipt(receipt, [ctx], [so], execution, issuer, "issuer-1")
    verification = {"approver_keys": {grant["approver_key_id"]: emilia.approver_key_entry(grant["approver_key_id"], approver.public_key(), valid_from="2026-01-01T00:00:00Z", valid_to="2036-01-01T00:00:00Z")},
                    "log_public_key": emilia.spki_b64u(issuer.public_key())}
    return tr, verification


def test_trust_receipt_export_is_internally_consistent_by_the_drafts_rules():
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    issuer, approver, executor, receipt, grant, execution = _chain()
    tr, verification = _trust_receipt(issuer, approver, receipt, grant, execution)
    assert emilia.in_profile({k: v for k, v in tr.items() if k not in ("signoffs", "log_proof", "approver_key_proofs")})
    assert tr["action_hash"] == "sha256:" + hashlib.sha256(canonical_json(tr["action"]).encode()).hexdigest()
    ctx = tr["contexts"][0]
    assert ctx["action_hash"] == tr["action_hash"] and ctx["policy_hash"] == "sha256:" + receipt["policy"]["policy_sha256"]
    assert ctx["authorization_instance"] == tr["consumption"]["nonce"]
    so = tr["signoffs"][0]
    assert so["context_hash"] == "sha256:" + hashlib.sha256(canonical_json(ctx).encode()).hexdigest()
    approver.public_key().verify(emilia.b64u_decode(so["signature"]), bytes.fromhex(so["context_hash"][7:]))
    assert ctx["approver"] != tr["action"]["initiator"]
    body = {k: v for k, v in tr.items() if k not in ("log_proof", "approver_key_proofs")}
    leaf = hashlib.sha256(b"\x00" + canonical_json(body).encode()).hexdigest()
    cp = tr["log_proof"]["checkpoint"]
    assert tr["log_proof"]["leaf_hash"] == cp["root_hash"] == "sha256:" + leaf and cp["tree_size"] == 1 and tr["log_proof"]["inclusion_path"] == []
    signed = {k: v for k, v in cp.items() if k != "log_signature"}
    load_der_public_key(emilia.b64u_decode(verification["log_public_key"])).verify(emilia.b64u_decode(cp["log_signature"]), hashlib.sha256(canonical_json(signed).encode()).digest())


def test_a_stored_gargoyle_grant_signature_is_not_an_emilia_signoff():
    """The approver signed the canonical grant, not the context digest: the
    bytes differ, so a lossless export needs the console to sign both."""
    issuer, approver, executor, receipt, grant, execution = _chain()
    tr, _ = _trust_receipt(issuer, approver, receipt, grant, execution, reuse_grant_signature=True)
    so = tr["signoffs"][0]
    with pytest.raises(Exception):
        approver.public_key().verify(emilia.b64u_decode(so["signature"]), bytes.fromhex(so["context_hash"][7:]))


REPO = os.environ.get("GARGOYLE_EMILIA_REPO")


@pytest.mark.skipif(not REPO, reason="set GARGOYLE_EMILIA_REPO to a checkout of emiliaprotocol/emilia-protocol")
def test_emilias_own_verifiers_accept_the_exports(tmp_path):
    issuer, approver, executor, receipt, grant, execution = _chain()
    tr_ok, verification = _trust_receipt(issuer, approver, receipt, grant, execution)
    tr_reused, _ = _trust_receipt(issuer, approver, receipt, grant, execution, reuse_grant_signature=True)
    tr_self = json.loads(json.dumps(tr_ok)); tr_self["action"]["initiator"] = grant["approver_key_id"]
    doc = emilia.ep_receipt(receipt, issuer)
    bad = json.loads(json.dumps(doc)); bad["payload"]["request_context"]["args_sha256"] = "0" * 64
    receipts = tmp_path / "r.json"; trusts = tmp_path / "t.json"
    receipts.write_text(json.dumps({"suite": "GARGOYLE EP-RECEIPT-v1", "vectors": [
        {"id": "receipt", "expect": {"valid": True}, "public_key": emilia.spki_b64u(issuer.public_key()), "document": doc},
        {"id": "tampered", "expect": {"valid": False}, "public_key": emilia.spki_b64u(issuer.public_key()), "document": bad}]}))
    trusts.write_text(json.dumps({"suite": "GARGOYLE EP-TRUST-RECEIPT-v1", "vectors": [
        {"id": "chain", "expect": {"valid": True}, "trust_receipt": tr_ok, "verification": verification},
        {"id": "grant_signature_reused", "expect": {"valid": False}, "trust_receipt": tr_reused, "verification": verification},
        {"id": "self_approval", "expect": {"valid": False}, "trust_receipt": tr_self, "verification": verification}]}))
    for path in (receipts, trusts):
        out = subprocess.run([sys.executable, "-I", os.path.join(REPO, "conformance/runners/run_py.py"), str(path)], cwd=REPO, capture_output=True, text=True, check=True).stdout
        got = {r["id"]: r["valid"] for r in json.loads(out)}
        want = {v["id"]: v["expect"]["valid"] for v in json.loads(path.read_text())["vectors"]}
        assert got == want, (path.name, got)
