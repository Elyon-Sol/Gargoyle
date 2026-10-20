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
from gargoyle.approval import build_grant, sign_grant, verify_grant
from gargoyle.envelope import build_envelope, canonical_json, sign_envelope
from gargoyle.execution import build_execution_receipt, sign_execution_receipt, verify_chain

FIX = Path(__file__).parent / "fixtures" / "emilia"
T0 = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


def _key(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def test_emilia_receipt_vectors_verify_under_gargoyles_canonical_form():
    vectors = json.loads((FIX / "receipts.v1.json").read_text(encoding="utf-8"))["vectors"]
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
    vectors = json.loads((FIX / "canonicalization.v1.json").read_text(encoding="utf-8"))["vectors"]
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
    exported = _exported_log(tmp_path)                    # three receipts under one multi-leaf checkpoint
    doc = emilia.ep_receipt(receipt, issuer)
    bad = json.loads(json.dumps(doc)); bad["payload"]["request_context"]["args_sha256"] = "0" * 64
    receipts = tmp_path / "r.json"; trusts = tmp_path / "t.json"
    receipts.write_text(json.dumps({"suite": "GARGOYLE EP-RECEIPT-v1", "vectors": [
        {"id": "receipt", "expect": {"valid": True}, "public_key": emilia.spki_b64u(issuer.public_key()), "document": doc},
        {"id": "tampered", "expect": {"valid": False}, "public_key": emilia.spki_b64u(issuer.public_key()), "document": bad}]}))
    trusts.write_text(json.dumps({"suite": "GARGOYLE EP-TRUST-RECEIPT-v1", "vectors": [
        {"id": "chain", "expect": {"valid": True}, "trust_receipt": tr_ok, "verification": verification},
        {"id": "grant_signature_reused", "expect": {"valid": False}, "trust_receipt": tr_reused, "verification": verification},
        {"id": "self_approval", "expect": {"valid": False}, "trust_receipt": tr_self, "verification": verification}] + exported}))
    import shutil
    runners = [[sys.executable, "-I", os.path.join(REPO, "conformance/runners/run_py.py")]]
    if shutil.which("node"):
        runners.append(["node", os.path.join(REPO, "conformance/runners/run-js.mjs")])
    for runner in runners:
        for path in (receipts, trusts):
            out = subprocess.run(runner + [str(path)], cwd=REPO, capture_output=True, text=True, check=True).stdout
            got = {r["id"]: r["valid"] for r in json.loads(out.strip().splitlines()[0])}
            want = {v["id"]: v["expect"]["valid"] for v in json.loads(path.read_text())["vectors"]}
            assert got == want, (runner[0], path.name, got)


# --- the dual signature: the console signs the EMILIA context beside the grant ---

def _signed_grant_with_signoff(receipt, approver, approver_id, *, index=1, grant_not_after=None, context_edit=None, signer=None):
    grant_not_after = grant_not_after or (T0 + timedelta(minutes=10))
    grant = build_grant(decision_sha256=receipt["decision_sha256"], approval_request_id=receipt["approval_request_id"],
                        grant_id=str(uuid.uuid4()), not_after=grant_not_after)
    ctx = emilia.authorization_context(receipt, approver_id, index, expires_at=min(receipt["not_after"], grant["not_after"]))
    if context_edit:
        context_edit(ctx)
    grant[emilia.EMILIA_MEMBER] = {"context": ctx, "signature": (signer or approver).sign(emilia.context_hash_for(ctx)).hex()}
    return sign_grant(grant, approver, approver_id)


def test_a_grant_carrying_a_signoff_verifies_as_a_grant_and_the_signoff_checks_against_the_hold():
    issuer, approver, executor, receipt, _, execution = _chain()
    grant = _signed_grant_with_signoff(receipt, approver, "sysops@hearthcorp.com")
    ok = verify_grant(grant, expected_decision_sha256=receipt["decision_sha256"], expected_approval_request_id=receipt["approval_request_id"],
                      approver_public_keys={"sysops@hearthcorp.com": approver.public_key()}, gate_key_id="issuer-1", now=T0)
    assert ok["accepted"], ok                              # the member is inside the grant signature; verifiers ignore what they do not know
    assert emilia.verify_embedded_signoff(grant, receipt, approver.public_key()) == {"accepted": True, "reason": None}
    assert emilia.verify_embedded_signoff(grant, receipt, [executor.public_key(), approver.public_key()])["accepted"]   # key history: any of them
    # The whole chain, exported, verifies by the draft's rules with the approver's real signoff.
    chain = verify_chain(receipt, execution, issuer_public_keys={"issuer-1": issuer.public_key()}, executor_public_keys={"executor-1": executor.public_key()},
                         grant=grant, approver_public_keys={"sysops@hearthcorp.com": approver.public_key()})
    assert chain["accepted"]


def test_the_issuer_side_check_refuses_a_signoff_that_does_not_match_the_hold():
    issuer, approver, executor, receipt, _, _ = _chain()
    other = Ed25519PrivateKey.generate()
    cases = {
        "wrong key": (dict(signer=other), emilia.REF_EMILIA_SIGNATURE_INVALID),
        "policy hash edited": (dict(context_edit=lambda c: c.__setitem__("policy_hash", "sha256:" + "00" * 32)), emilia.REF_EMILIA_CONTEXT_MISMATCH),
        "another action": (dict(context_edit=lambda c: c.__setitem__("action_hash", "sha256:" + "11" * 32)), emilia.REF_EMILIA_CONTEXT_MISMATCH),
        "approver renamed": (dict(context_edit=lambda c: c.__setitem__("approver", "someone@else")), emilia.REF_EMILIA_CONTEXT_MISMATCH),
        "expires after the grant": (dict(context_edit=lambda c: c.__setitem__("expires_at", (T0 + timedelta(hours=5)).isoformat())), emilia.REF_EMILIA_CONTEXT_MISMATCH),
        "index zero": (dict(index=0), emilia.REF_EMILIA_SIGNOFF_MALFORMED),
    }
    for name, (kw, reason) in cases.items():
        grant = _signed_grant_with_signoff(receipt, approver, "sysops@hearthcorp.com", **kw)
        assert emilia.verify_embedded_signoff(grant, receipt, approver.public_key()) == {"accepted": False, "reason": reason}, name
    bare = _signed_grant_with_signoff(receipt, approver, "sysops@hearthcorp.com")
    bare[emilia.EMILIA_MEMBER] = {"context": "no"}
    assert emilia.verify_embedded_signoff(bare, receipt, approver.public_key())["reason"] == emilia.REF_EMILIA_SIGNOFF_MALFORMED


def test_the_issuer_checks_the_member_before_storing_the_grant():
    from fastapi.testclient import TestClient
    from gargoyle.issuer_service import build_issuer_app
    from gargoyle.jws import encode
    from gargoyle.policy import ELIGIBLE, Decision
    issuer, approver, idp = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()

    class Flagging:
        def pin(self): return {"policy_id": "rules/1", "policy_sha256": "ab" * 32}
        def decide(self, target_url, interaction): return Decision(ELIGIBLE, requires_approval=True)
    c = TestClient(build_issuer_app(policy=Flagging(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                                    approver_public_keys={"approver-alice": approver.public_key()}))
    tok = lambda sub: "Bearer " + encode({"sub": sub, "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")
    hold = lambda: c.post("/issue", json={"target_url": "mcp://fs", "tool": "write_file", "args": {"path": "a"}}, headers={"Authorization": tok("agent")}).json()["envelope"]
    env = hold()
    good = _signed_grant_with_signoff(env, approver, "approver-alice", grant_not_after=datetime.now(timezone.utc) + timedelta(minutes=5))
    r = c.post("/grants", json=good, headers={"Authorization": tok("approver-alice")}).json()
    assert r["accepted"] and r["complete"], r
    env2 = hold()
    bad = _signed_grant_with_signoff(env2, approver, "approver-alice", grant_not_after=datetime.now(timezone.utc) + timedelta(minutes=5),
                                     context_edit=lambda ctx: ctx.__setitem__("audience", "mcp://somewhere-else"))
    r = c.post("/grants", json=bad, headers={"Authorization": tok("approver-alice")}).json()
    assert r == {"accepted": False, "reason": emilia.REF_EMILIA_CONTEXT_MISMATCH}
    plain = sign_grant(build_grant(decision_sha256=env2["decision_sha256"], approval_request_id=env2["approval_request_id"], grant_id="g-plain",
                                   not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), approver, "approver-alice")
    assert c.post("/grants", json=plain, headers={"Authorization": tok("approver-alice")}).json()["accepted"]   # a CLI approver, no member: still fine


def _fold(leaf_hex, path):
    cur = leaf_hex
    for step in path:
        cur = hashlib.sha256(b"\x01" + ((step["hash"] + cur) if step["position"] == "left" else (cur + step["hash"])).encode()).hexdigest()
    return cur


def _write_log(path, rows):
    """A chained evidence log with chosen entry times (EvidenceLog stamps now)."""
    from gargoyle.evidence import GENESIS, build_entry
    prev, seq, lines = GENESIS, 1, []
    for row in rows:
        entry = build_entry(seq=seq, prev_sha256=prev, **row)
        lines.append(json.dumps(entry, sort_keys=True)); prev, seq = entry["entry_sha256"], seq + 1
    Path(path).write_text("\n".join(lines) + "\n")


def _exported_log(tmp_path):
    """Three approved calls with console signoffs, one without, one refused;
    returns EMILIA vectors for the three under one Merkle checkpoint."""
    from gargoyle.evidence import HONORED, REFUSED
    issuer, approver, executor, _, _, _ = _chain()
    rows = []
    for n in range(4):
        call = {"tool": "write_file", "args": {"path": "C:\\finance\\f%d.md" % n}, "principal": "claude@hearthcorp.com"}
        env = build_envelope(decision="ELIGIBLE", target_url="mcp://filesystem/C:\\finance", call=call, policy_pin={"policy_id": "gargoyle.rules/1", "policy_sha256": "19" * 32},
                             timestamp_utc=(T0 + timedelta(minutes=n)).isoformat(), requires_approval=True)
        receipt = sign_envelope(env, issuer, "issuer-1", not_after=T0 + timedelta(minutes=n + 5), decision_id=str(uuid.uuid4()), approval_request_id=str(uuid.uuid4()))
        if n < 3:
            grant = _signed_grant_with_signoff(receipt, approver, "sysops@hearthcorp.com", grant_not_after=T0 + timedelta(minutes=n + 10))
        else:
            grant = sign_grant(build_grant(decision_sha256=receipt["decision_sha256"], approval_request_id=receipt["approval_request_id"], grant_id="g-cli",
                                           not_after=T0 + timedelta(minutes=n + 10)), approver, "sysops@hearthcorp.com")
        execution = sign_execution_receipt(build_execution_receipt(envelope=receipt, outputs={"ok": True}, executed_at=T0 + timedelta(minutes=n, seconds=40)), executor, "executor-1")
        rows.append(dict(kind=HONORED, tool="write_file", args=call["args"], principal=call["principal"], reason="ACCEPT", receipt=receipt, grant=grant, execution=execution,
                         at=T0 + timedelta(minutes=n, seconds=41)))
    rows.append(dict(kind=REFUSED, tool="delete_file", args={"path": "x"}, principal="claude@hearthcorp.com", reason="REF_TARGET_POLICY_REFUSED", at=T0 + timedelta(minutes=9)))
    _write_log(tmp_path / "audit.jsonl", rows)
    from gargoyle.evidence import read_log
    result = emilia.trust_receipts_from_entries(read_log(str(tmp_path / "audit.jsonl")), log_signing_key=executor, log_key_id="executor-1")
    assert result["skipped"] == 1 and len(result["receipts"]) == 3
    approvers_hex = {"sysops@hearthcorp.com": [Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex(), approver.public_key().public_bytes_raw().hex()]}
    return [{"id": r["receipt_id"], "expect": {"valid": True}, "trust_receipt": r, "verification": emilia.verification_for(r, approvers_hex, executor.public_key())}
            for r in result["receipts"]]


def test_an_evidence_log_exports_as_trust_receipts_under_one_merkle_checkpoint(tmp_path):
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    vectors = _exported_log(tmp_path)
    roots = {v["trust_receipt"]["log_proof"]["checkpoint"]["root_hash"] for v in vectors}
    assert len(roots) == 1
    for i, v in enumerate(vectors):
        tr = v["trust_receipt"]; lp = tr["log_proof"]; cp = lp["checkpoint"]
        body = {k: x for k, x in tr.items() if k not in ("log_proof", "approver_key_proofs")}
        leaf = hashlib.sha256(b"\x00" + canonical_json(body).encode()).hexdigest()
        assert lp["leaf_hash"] == "sha256:" + leaf and lp["leaf_index"] == i and cp["tree_size"] == 3
        assert lp["inclusion_path"] and "sha256:" + _fold(leaf, lp["inclusion_path"]) == cp["root_hash"]
        signed = {k: x for k, x in cp.items() if k != "log_signature"}
        load_der_public_key(emilia.b64u_decode(v["verification"]["log_public_key"])).verify(emilia.b64u_decode(cp["log_signature"]), hashlib.sha256(canonical_json(signed).encode()).digest())
        key = v["verification"]["approver_keys"]["sysops@hearthcorp.com"]        # the key that verifies, chosen from the id's history
        load_der_public_key(emilia.b64u_decode(key["public_key"])).verify(emilia.b64u_decode(tr["signoffs"][0]["signature"]), bytes.fromhex(tr["signoffs"][0]["context_hash"][7:]))
        assert tr["signoffs"][0]["signed_at"] == tr["contexts"][0]["issued_at"][:16] + tr["signoffs"][0]["signed_at"][16:]    # the evidence entry's time, inside the window


def test_gargoyle_emilia_command_writes_the_export(tmp_path, capsys):
    from gargoyle.cli import main, _read_env
    from gargoyle.evidence import HONORED
    out, proj = tmp_path / "deploy", tmp_path / "proj"; proj.mkdir()
    assert main(["init", str(proj), "--out", str(out)]) == 0
    ienv, aenv, menv = _read_env(out / "issuer.env"), _read_env(out / "approver.env"), _read_env(out / "middleware.env")
    issuer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ienv["GARGOYLE_ISSUER_KEY_HEX"]))
    approver = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(aenv["GARGOYLE_APPROVER_KEY_HEX"]))
    executor = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(menv["GARGOYLE_MCP_EXECUTOR_KEY_HEX"]))
    call = {"tool": "write_file", "args": {"path": "a.md"}, "principal": "claude@hearthcorp.com"}
    env = build_envelope(decision="ELIGIBLE", target_url=menv["GARGOYLE_MCP_TARGET_ID"], call=call, policy_pin={"policy_id": "gargoyle.rules/1", "policy_sha256": "19" * 32},
                         timestamp_utc=T0.isoformat(), requires_approval=True)
    receipt = sign_envelope(env, issuer, "issuer-1", not_after=T0 + timedelta(minutes=5), decision_id=str(uuid.uuid4()), approval_request_id=str(uuid.uuid4()))
    grant = _signed_grant_with_signoff(receipt, approver, aenv["GARGOYLE_APPROVER_KEY_ID"])
    execution = sign_execution_receipt(build_execution_receipt(envelope=receipt, outputs={}, executed_at=T0 + timedelta(minutes=1)), executor, "executor-1")
    _write_log(tmp_path / "audit.jsonl", [dict(kind=HONORED, tool="write_file", args=call["args"], principal=call["principal"], reason="ACCEPT",
                                               receipt=receipt, grant=grant, execution=execution, at=T0 + timedelta(minutes=1, seconds=1))])
    assert main(["emilia", "--log", str(tmp_path / "audit.jsonl"), "--out", str(out), "--write", str(tmp_path / "tr.json")]) == 0
    assert "1 trust receipts" in capsys.readouterr().out
    doc = json.loads((tmp_path / "tr.json").read_text())
    v = doc["vectors"][0]
    assert v["trust_receipt"]["contexts"][0]["approver"] == aenv["GARGOYLE_APPROVER_KEY_ID"] and aenv["GARGOYLE_APPROVER_KEY_ID"] in v["verification"]["approver_keys"]
    assert v["verification"]["log_public_key"] == emilia.spki_b64u(executor.public_key())
