# SPDX-License-Identifier: Apache-2.0
"""Acta signed decision receipts (draft-farley-acta-signed-receipts-03):
the ecosystem's verifier vectors against gargoyle.acta, and the issuer's
witness exported as a receipt chain that verifies under the issuer's own
JWK Set. When GARGOYLE_ACTA_VERIFY names an Acta verifier command (for
example `npx @veritasacta/verify`), the export is also fed through it."""
import hashlib
import json
import os
import shlex
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle import acta
from gargoyle.approval import build_grant, sign_grant
from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import encode
from gargoyle.rules import RULES_POLICY_ID, RulesPolicy
from gargoyle.witness import WitnessLog, read_witness, verify_witness

FIX = Path(__file__).parent / "fixtures" / "acta"
issuer, idp, approver = (Ed25519PrivateKey.generate() for _ in range(3))
TARGET = "mcp://fs.example"
RULES = {"version": "acta-test", "default": "deny", "rules": [
    {"tools": ["read_*"], "action": "allow"},
    {"tools": ["write_file"], "action": "hold"},
    {"tools": ["delete_*"], "action": "deny", "reason": "DESTRUCTIVE_TOOL"},
]}


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _cases():
    out = []
    for suite in ("key-window", "signing-input", "revocation"):
        for c in _load(FIX / suite / "index.json")["cases"]:
            out.append(pytest.param(suite, c, id="%s/%s+%s" % (suite, c["file"], c["jwks"])))
    for c in _load(FIX / "chain-link" / "index.json")["cases"]:
        out.append(pytest.param("chain-link", c, id="chain-link/%s/%s%s" % (c["file"], c["check"], ("/" + c["previous"]) if c.get("previous") else "")))
    return out


@pytest.mark.parametrize("suite,case", _cases())
def test_verifier_vectors_reach_the_published_verdict(suite, case):
    """ScopeBlind's verifier-vectors (fixtures/acta/README.md): the verdict, and
    the code and key status where the index names them. revocation is scored
    under -04, which defines no revocation: the signed-after-revocation receipt
    is accepted and its key reported inside the window, as the index says."""
    d = FIX / suite
    keys = acta.keys_from_jwks(_load(d / case["jwks"])) if case.get("jwks") else None
    check = case.get("check", "alone")
    if check == "sequence":
        r = acta.verify_sequence(acta.read_jsonl(str(d / case["file"])), keys)
        assert (r["chains"], r["chain_breaks"]) == (case["chains"], case["chain_breaks"])
        if case.get("warn"):
            assert any(acta.NULL_CHAIN_LINK in x["warnings"] for x in r["results"])
    else:
        previous = _load(d / case["previous"]) if check == "supplied-predecessor" else None
        r = acta.verify_receipt(_load(d / case["file"]), keys, previous=previous)
        if case.get("warn"):
            assert acta.NULL_CHAIN_LINK in r["warnings"]
        if case.get("key_status"):
            assert r["key_status"] == case["key_status"]
    assert (r["outcome"] == acta.VALID) == (case["expected"] == "ACCEPT"), r
    if "outcome" in case:
        assert (r["outcome"], r["exit"]) == (case["outcome"], case["exit"])
    if case.get("code"):
        assert r["code"] == case["code"]


def test_timeliness_vectors_accept_under_the_draft_and_the_link_holds():
    d = FIX / "timeliness"
    keys = acta.keys_from_jwks(_load(d / "jwks.json"))
    for f in ("genesis.json", "receipt.json"):
        assert acta.verify_receipt(_load(d / f), keys)["outcome"] == acta.VALID
    linked = acta.verify_receipt(_load(d / "receipt.json"), keys, previous=_load(d / "genesis.json"))
    assert linked["outcome"] == acta.VALID and linked["age_seconds"] > 0
    # The commitment the suite proposes names the genesis link: the same section 6.7 computation.
    assert _load(d / "commitment.json")["payload"]["terminal_hash"] == acta.receipt_link(_load(d / "genesis.json"))


@pytest.mark.parametrize("name", ["acta-envelope.json", "decision-receipt.json"])
def test_a_key_inside_the_receipt_is_never_trusted(name):
    """Section 9.5: with no key set, or with a key set that lacks the kid, the
    receipt's own public_key member changes nothing."""
    receipt = _load(FIX / "embedded-key" / name)
    assert acta.verify_receipt(receipt, None)["outcome"] != acta.VALID
    other = acta.keys_from_jwks(_load(FIX / "key-window" / "jwks.json"))
    r = acta.verify_receipt(receipt, other)
    assert r["outcome"] != acta.VALID
    if r["shape"] == "envelope":
        assert acta.EMBEDDED_KEY_IGNORED in r["warnings"] and r["code"] == acta.KEY_NOT_FOUND


def test_policy_digest_reproduces_the_test_vector_value():
    """Section 6.8 over the suite's Cedar policy equals the digest its
    expected chain carries (computed independently by their harness)."""
    cedar = (FIX / "policy" / "autoresearch-safe.cedar").read_bytes()
    digest, manifest = acta.policy_digest("cedar", [("autoresearch-safe.cedar", hashlib.sha256(cedar).hexdigest())])
    expected = json.loads((FIX / "policy" / "expected-chain.jsonl").read_text(encoding="utf-8").splitlines()[0])["policy_digest"]
    assert digest == expected
    assert manifest["files"][0]["name"] == "autoresearch-safe.cedar"
    bundle = acta.policy_bundle("cedar", [("autoresearch-safe.cedar", cedar.decode("utf-8"))], "2026-11-06T00:00:00Z")
    assert bundle["policy_digest"] == expected and acta.verify_policy_bundle(bundle)["accepted"]
    bundle["files"][0]["content"] += "\n"
    assert acta.verify_policy_bundle(bundle)["reason"] == "file_hash_mismatch"


def _token():
    return encode({"sub": "agent@contoso.com", "aud": "gargoyle-issuer",
                   "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")


def _rig(tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps(RULES, indent=1), encoding="utf-8")
    w = WitnessLog(str(tmp_path / "witness.jsonl"), issuer, "issuer-1")
    app = build_issuer_app(policy=RulesPolicy(str(rules)), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           approver_public_keys={"approver-1": approver.public_key()}, audience="gargoyle-issuer", witness=w)
    c = TestClient(app)
    h = {"Authorization": "Bearer " + _token()}

    def issue(tool, path):
        return c.post("/issue", json={"target_url": TARGET, "tool": tool, "args": {"path": path}}, headers=h).json()

    def release(env):
        g = sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                   grant_id="g-" + env["approval_request_id"], not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), approver, "approver-1")
        return c.post("/grants", json=g, headers=h).json()

    assert issue("read_file", "a.txt")["issued"]                                      # allow
    held = issue("write_file", "b.txt"); assert held["issued"] and held["envelope"]["requires_approval"]
    assert release(held["envelope"])["complete"]                                      # granted
    assert issue("delete_file", "c.txt") == {"issued": False, "reason": "DESTRUCTIVE_TOOL"}  # refused by rule
    held2 = issue("write_file", "d.txt")
    assert c.post("/decline", json={"approval_request_id": held2["envelope"]["approval_request_id"], "reason": "not now"}, headers=h).json()["declined"]
    return c, w, rules


def test_witness_export_is_an_acta_chain_the_issuers_jwks_verifies(tmp_path):
    c, w, rules = _rig(tmp_path)
    entries = read_witness(str(tmp_path / "witness.jsonl"))
    assert verify_witness(entries, issuer_public_keys={"issuer-1": issuer.public_key()})["accepted"]
    issued = [e for e in entries if e["event"] == "issued"]
    assert all(e["witness_version"] == "gargoyle-witness/2" and e["policy"]["policy_id"] == RULES_POLICY_ID for e in issued)
    pin = issued[0]["policy"]

    result = acta.export_witness(entries, signing_key=issuer, key_id="issuer-1")
    receipts = result["receipts"]
    assert [r["payload"]["decision"] for r in receipts] == ["allow", "require_approval", "allow", "deny", "require_approval", "deny"]
    assert [r["payload"].get("reason") for r in receipts] == [None, None, "approval_granted", "DESTRUCTIVE_TOOL", None, "approval_declined"]
    assert [r["payload"]["tool_name"] for r in receipts] == ["read_file", "write_file", "write_file", "delete_file", "write_file", "write_file"]
    assert result["counts"]["no_policy"] == 0 and result["witness_head"]["seq"] == entries[-1]["seq"]
    # Every payload is the draft's shape: no arguments, no principal, the Gargoyle references under one member.
    for r in receipts:
        assert r["payload"]["issuer_id"] == r["signature"]["kid"] == "issuer-1" and "principal" not in r["payload"] and "args" not in r["payload"]
        assert r["payload"]["gargoyle"]["witness_seq"] and r["payload"]["gargoyle"]["witness_entry_sha256"]
    assert receipts[2]["payload"]["gargoyle"]["decision_id"] == receipts[1]["payload"]["gargoyle"]["decision_id"]   # the release names the hold's decision

    # The issuer's own well-known key set verifies every receipt, and the chain holds as a sequence.
    jwks = c.get("/.well-known/acta-keys.json").json()
    keys = acta.keys_from_jwks(jwks, source="jwks:issuer")
    started = next(e for e in entries if e["event"] == "started")
    assert jwks["keys"][0] == {"kty": "OKP", "crv": "Ed25519", "kid": "issuer-1", "x": jwks["keys"][0]["x"], "use": "sig", "alg": "EdDSA",
                               "valid_from": started["at"]}                      # section 9.2: the window opens when the witness did
    assert acta.key_valid_from(entries, "issuer-1") == started["at"] and acta.key_valid_from([], "issuer-1") is None
    for n, r in enumerate(receipts):
        v = acta.verify_receipt(r, keys, previous=receipts[n - 1] if n else None)
        assert v["outcome"] == acta.VALID and v["key_source"] == "jwks:issuer" and v["key_status"] == "inside", v
    # A receipt dated before the window is outside it, whoever signed it.
    early = json.loads(json.dumps(receipts[0])); early["payload"]["issued_at"] = "2020-01-01T00:00:00Z"
    assert acta.verify_receipt(early, keys)["key_status"] == "outside"
    seq = acta.verify_sequence(receipts, keys)
    assert (seq["outcome"], seq["chains"], seq["chain_breaks"], seq["count"]) == (acta.VALID, 1, 0, 6)

    # The policy digest is section 6.8 over the pin, and the issuer's bundle recomputes to it.
    digest = receipts[0]["payload"]["policy_digest"]
    assert digest == acta.policy_digest_for_pin(pin) == acta.policy_digest(RULES_POLICY_ID, [("rules.json", pin["policy_sha256"])])[0]
    bundle = c.get("/.well-known/acta-policies/%s.json" % digest.split(":")[1]).json()
    assert bundle["schema"] == "acta.policy-bundle.v1" and bundle["policy_digest"] == digest and bundle["files"][0]["name"] == "rules.json"
    assert acta.verify_policy_bundle(bundle)["accepted"] and json.loads(bundle["files"][0]["content"]) == RULES
    assert c.get("/.well-known/acta-policies/%s.json" % ("0" * 64)).status_code == 404

    # The commitment names the chain; a shorter set is truncation, a tampered receipt is invalid and breaks the link after it.
    assert acta.verify_commitment(result["commitment"], receipts, keys)["accepted"]
    assert acta.verify_commitment(result["commitment"], receipts[:-1], keys)["reason"] == "truncated"
    forged = json.loads(json.dumps(receipts))
    forged[3]["payload"]["decision"] = "allow"
    assert acta.verify_receipt(forged[3], keys)["code"] == acta.SIGNATURE_INVALID
    broken = acta.verify_sequence(forged, keys)
    assert broken["outcome"] == acta.INVALID and broken["chain_breaks"] == 1 and broken["results"][4]["code"] == acta.CHAIN_BREAK


def test_witness_version_1_entries_still_verify(tmp_path, monkeypatch):
    """gargoyle-witness/1 entries (no policy member) verify beside version 2 ones in one file."""
    import gargoyle.witness as wmod
    monkeypatch.setattr(wmod, "WITNESS_VERSION", "gargoyle-witness/1")
    w = WitnessLog(str(tmp_path / "w.jsonl"), issuer, "issuer-1")
    w.record("issued", decision_id="d-1", principal="p", tool="read_file", held=False)
    monkeypatch.undo()
    w2 = WitnessLog(str(tmp_path / "w.jsonl"), issuer, "issuer-1")
    w2.record("issued", decision_id="d-2", principal="p", tool="read_file", held=False, policy={"policy_id": RULES_POLICY_ID, "policy_sha256": "a" * 64})
    entries = read_witness(str(tmp_path / "w.jsonl"))
    assert [e["witness_version"] for e in entries] == ["gargoyle-witness/1"] * 2 + ["gargoyle-witness/2"] * 2
    assert verify_witness(entries, issuer_public_keys={"issuer-1": issuer.public_key()})["accepted"]
    out = acta.export_witness(entries, signing_key=issuer, key_id="issuer-1")
    assert len(out["receipts"]) == 2 and "policy_digest" not in out["receipts"][0]["payload"] and "policy_digest" in out["receipts"][1]["payload"]
    assert out["counts"]["no_policy"] == 1


def test_cli_exports_and_verifies(tmp_path, capsys):
    from gargoyle.cli import main
    c, w, rules = _rig(tmp_path)
    (tmp_path / "issuer.env").write_text("GARGOYLE_ISSUER_KEY_ID=issuer-1\nGARGOYLE_ISSUER_KEY_HEX=%s\nGARGOYLE_RULES_PATH=%s\n"
                                         % (issuer.private_bytes_raw().hex(), rules), encoding="utf-8")
    out = tmp_path / "acta"
    assert main(["acta", "export", "--witness", str(tmp_path / "witness.jsonl"), "--out", str(out), "--env", str(tmp_path / "issuer.env")]) == 0
    text = capsys.readouterr().out
    assert "6 Acta receipts" in text
    summary = _load(out / "EXPORT.json")
    assert summary["receipts"] == 6 and set(summary["files"]) >= {"receipts.jsonl", "acta-keys.json", "commitment.json"}
    assert any(f.startswith("policy-bundle-") for f in summary["files"])
    assert _load(out / "acta-keys.json")["keys"][0]["valid_from"] == read_witness(str(tmp_path / "witness.jsonl"))[0]["at"]
    assert main(["acta", "verify", "--replay-chain", str(out / "receipts.jsonl"), "--jwks", str(out / "acta-keys.json")]) == 0
    assert capsys.readouterr().out.startswith("valid")
    lines = (out / "receipts.jsonl").read_text(encoding="utf-8").splitlines()
    (tmp_path / "r1.json").write_text(lines[0]); (tmp_path / "r2.json").write_text(lines[1])
    assert main(["acta", "verify", str(tmp_path / "r2.json"), "--previous", str(tmp_path / "r1.json"), "--jwks", str(out / "acta-keys.json"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "valid"
    assert main(["acta", "verify", str(tmp_path / "r2.json")]) == 2            # no key set: undecidable
    assert capsys.readouterr().out.startswith("undecidable key_not_found")
    # A witness that does not verify under the key is not exported.
    (tmp_path / "other.env").write_text("GARGOYLE_ISSUER_KEY_ID=issuer-1\nGARGOYLE_ISSUER_KEY_HEX=%s\n" % Ed25519PrivateKey.generate().private_bytes_raw().hex())
    assert main(["acta", "export", "--witness", str(tmp_path / "witness.jsonl"), "--out", str(tmp_path / "x"), "--env", str(tmp_path / "other.env")]) == 1


@pytest.mark.skipif(not os.environ.get("GARGOYLE_ACTA_VERIFY"), reason="set GARGOYLE_ACTA_VERIFY to an Acta verifier command, e.g. 'npx @veritasacta/verify'")
def test_export_verifies_under_an_outside_acta_verifier(tmp_path):
    """The acceptance that matters: a verifier written from the draft by
    someone else, run over our export with our JWK Set."""
    c, w, rules = _rig(tmp_path)
    entries = read_witness(str(tmp_path / "witness.jsonl"))
    result = acta.export_witness(entries, signing_key=issuer, key_id="issuer-1")
    (tmp_path / "acta-keys.json").write_text(json.dumps(acta.jwks_for(issuer.public_key(), "issuer-1", valid_from=acta.key_valid_from(entries, "issuer-1"))), encoding="utf-8")
    (tmp_path / "receipts.jsonl").write_text("".join(json.dumps(r) + "\n" for r in result["receipts"]), encoding="utf-8")
    cmd = shlex.split(os.environ["GARGOYLE_ACTA_VERIFY"])
    for n, r in enumerate(result["receipts"]):
        f = tmp_path / ("r%d.json" % n)
        f.write_text(json.dumps(r), encoding="utf-8")
        args = cmd + [str(f), "--jwks", str(tmp_path / "acta-keys.json"), "--mode", "receipt", "--json"]
        if n:
            args += ["--previous", str(tmp_path / ("r%d.json" % (n - 1)))]
        p = subprocess.run(args, capture_output=True, text=True, cwd=str(tmp_path))
        assert p.returncode == 0, (p.stdout, p.stderr)
    p = subprocess.run(cmd + ["--replay-chain", str(tmp_path / "receipts.jsonl"), "--jwks", str(tmp_path / "acta-keys.json"), "--json"],
                       capture_output=True, text=True, cwd=str(tmp_path))
    assert p.returncode == 0, (p.stdout, p.stderr)
    (tmp_path / "RESULT.json").write_text(p.stdout, encoding="utf-8")
