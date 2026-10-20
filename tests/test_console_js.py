"""The browser console's JavaScript must sign exactly what the reference
signs: under Node (same WebCrypto), approve.js recomputes the conformance
vectors' argument hash and approver signature from the seed label."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "tests" / "fixtures" / "wire_vectors.json"
SCRIPT = r'''
import { argsSha256, buildGrant, canonicalJson, importApproverKey, signGrant } from "%s";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
const V = JSON.parse(readFileSync(%s, "utf8"));
const b64url = (b) => Buffer.from(b).toString("base64url");
const seed = createHash("sha256").update(V.approver_seed_label).digest();
const key = await importApproverKey({ d: b64url(seed), x: b64url(Buffer.from(V.approver_public_key_hex, "hex")) });
const grant = await signGrant(buildGrant({ decisionSha256: V.grant.decision_sha256, approvalRequestId: V.grant.approval_request_id,
                                           grantId: V.grant.grant_id, notAfter: V.grant.not_after }), key, V.grant.approver_key_id);
const hashRegion = {}; for (const [k, v] of Object.entries(V.signed)) if (!["decision_sha256","timestamp_utc","issuer_key_id","issuer_signature","not_after","decision_id","approval_request_id"].includes(k)) hashRegion[k] = v;
console.log(JSON.stringify({ args_sha256: await argsSha256(V.call.args), grant, hash_region: canonicalJson(hashRegion) }));
'''


@pytest.mark.skipif(shutil.which("node") is None, reason="Node not available")
def test_console_signing_matches_the_reference_vectors(tmp_path):
    script = tmp_path / "check.mjs"
    script.write_text(SCRIPT % ((ROOT / "gargoyle" / "static" / "approve.js").as_uri(), json.dumps(str(VECTORS))))      # a JSON string literal: a Windows path has backslashes that JS would read as escapes
    proc = subprocess.run(["node", str(script)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr[-2000:]
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    vectors = json.loads(VECTORS.read_text())
    assert out["args_sha256"] == vectors["args_sha256"]
    assert out["hash_region"] == vectors["hash_region"]
    assert out["grant"] == vectors["grant"]            # byte-equal signature from the browser-side code


PKCE_SCRIPT = r'''
import { pkceChallenge, authorizeUrl } from "%s";
const challenge = await pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
const url = authorizeUrl({ tenant: "t", clientId: "c", scope: "api://a/access", redirectUri: "https://g/approve", challenge, state: "s1" });
console.log(JSON.stringify({ challenge, url }));
'''


def test_console_pkce_matches_rfc_7636(tmp_path):
    """Appendix B of RFC 7636: the S256 challenge for the given verifier."""
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    script = tmp_path / "pkce.mjs"
    script.write_text(PKCE_SCRIPT % (ROOT / "gargoyle" / "static" / "approve.js").as_uri())
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True, text=True, check=True).stdout)
    assert out["challenge"] == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert out["url"].startswith("https://login.microsoftonline.com/t/oauth2/v2.0/authorize?")
    assert "code_challenge_method=S256" in out["url"] and "client_id=c" in out["url"] and "scope=api%3A%2F%2Fa%2Faccess+openid+profile" in out["url"]


EMILIA_SCRIPT = r'''
import { earlier, emiliaContext, emiliaSignoff, importApproverKey } from "%s";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
const V = JSON.parse(readFileSync(%s, "utf8"));
const b64url = (b) => Buffer.from(b).toString("base64url");
const seed = createHash("sha256").update(V.approver_seed_label).digest();
const key = await importApproverKey({ d: b64url(seed), x: b64url(Buffer.from(V.approver_public_key_hex, "hex")) });
const context = await emiliaContext(V.signed, V.grant.approver_key_id, 1, earlier(V.signed.not_after, V.grant.not_after));
console.log(JSON.stringify(await emiliaSignoff(context, key)));
'''


@pytest.mark.skipif(shutil.which("node") is None, reason="Node not available")
def test_console_emilia_signoff_matches_the_python_module(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from gargoyle import emilia
    vectors = json.loads(VECTORS.read_text())
    script = tmp_path / "emilia.mjs"
    script.write_text(EMILIA_SCRIPT % ((ROOT / "gargoyle" / "static" / "approve.js").as_uri(), json.dumps(str(VECTORS))))
    proc = subprocess.run(["node", str(script)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr[-2000:]
    member = json.loads(proc.stdout.strip().splitlines()[-1])
    receipt, grant = vectors["signed"], vectors["grant"]
    expected = emilia.authorization_context(receipt, grant["approver_key_id"], 1, expires_at=min(receipt["not_after"], grant["not_after"]))
    assert member["context"] == expected
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(vectors["approver_public_key_hex"]))
    pub.verify(bytes.fromhex(member["signature"]), emilia.context_hash_for(member["context"]))
    carried = dict(grant); carried[emilia.EMILIA_MEMBER] = member
    assert emilia.verify_embedded_signoff(carried, receipt, pub) == {"accepted": True, "reason": None}
