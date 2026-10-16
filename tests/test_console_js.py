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
const V = JSON.parse(readFileSync("%s", "utf8"));
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
    script.write_text(SCRIPT % ((ROOT / "gargoyle" / "static" / "approve.js").as_uri(), str(VECTORS)))
    proc = subprocess.run(["node", str(script)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr[-2000:]
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    vectors = json.loads(VECTORS.read_text())
    assert out["args_sha256"] == vectors["args_sha256"]
    assert out["hash_region"] == vectors["hash_region"]
    assert out["grant"] == vectors["grant"]            # byte-equal signature from the browser-side code
