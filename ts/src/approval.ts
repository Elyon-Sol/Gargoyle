/** Approval grants (SPEC.md section 8). */
import type { KeyObject } from "node:crypto";
import { canonicalJson, Json } from "./canonical.js";
import { signHex, verifyHex } from "./crypto.js";
import { KeyMap, notAfterValid, Verdict } from "./verifier.js";

export const GRANT_VERSION = "1.0";
export const REF_APPROVAL_MALFORMED = "REF_APPROVAL_MALFORMED";
export const REF_APPROVAL_MISSING_GRANT_ID = "REF_APPROVAL_MISSING_GRANT_ID";
export const REF_APPROVAL_SIGNATURE_INVALID = "REF_APPROVAL_SIGNATURE_INVALID";
export const REF_APPROVAL_KEY_UNKNOWN = "REF_APPROVAL_KEY_UNKNOWN";
export const REF_APPROVAL_SOD = "REF_APPROVAL_SOD";
export const REF_APPROVAL_BINDING_MISMATCH = "REF_APPROVAL_BINDING_MISMATCH";
export const REF_APPROVAL_REQUEST_MISMATCH = "REF_APPROVAL_REQUEST_MISMATCH";
export const REF_APPROVAL_EXPIRED = "REF_APPROVAL_EXPIRED";
export const REF_APPROVAL_REPLAY = "REF_APPROVAL_REPLAY";
export const ACCEPT_GRANT_VALID = "GRANT_VALID";

export type Grant = Record<string, Json>;
const REQUIRED = ["grant_version", "decision_sha256", "approval_request_id", "grant_id", "not_after", "approver_key_id", "approver_signature"];
const reject = (reason: string): Verdict => ({ accepted: false, reason });

export function buildGrant(opts: { decisionSha256: string; approvalRequestId: string; grantId: string; notAfter: string }): Grant {
  if (!opts.grantId) throw new Error("grant_id is mandatory");
  return { grant_version: GRANT_VERSION, decision_sha256: opts.decisionSha256, approval_request_id: opts.approvalRequestId,
           grant_id: opts.grantId, not_after: opts.notAfter };
}

export function signGrant(grant: Grant, signingKey: KeyObject, keyId: string): Grant {
  const signed: Grant = { ...grant, approver_key_id: keyId };
  const region: Grant = {}; for (const [k, v] of Object.entries(signed)) if (k !== "approver_signature") region[k] = v;
  signed.approver_signature = signHex(signingKey, canonicalJson(region));
  return signed;
}

export function verifyGrant(grant: unknown, opts: {
  expectedDecisionSha256: string; expectedApprovalRequestId: string; approverPublicKeys: KeyMap;
  gateKeyId: string | null | undefined; now?: Date; clockSkewMs?: number;
}): Verdict {
  if (typeof grant !== "object" || grant === null || Array.isArray(grant)) return reject(REF_APPROVAL_MALFORMED);
  const g = grant as Record<string, Json>;
  for (const k of REQUIRED) if (!(k in g)) return reject(REF_APPROVAL_MALFORMED);
  if (typeof g.grant_id !== "string" || !g.grant_id) return reject(REF_APPROVAL_MISSING_GRANT_ID);
  const keyId = g.approver_key_id, sig = g.approver_signature;
  if (typeof keyId !== "string" || typeof sig !== "string") return reject(REF_APPROVAL_SIGNATURE_INVALID);
  if (keyId === opts.gateKeyId) return reject(REF_APPROVAL_SOD);
  const key = opts.approverPublicKeys[keyId];
  if (!key) return reject(REF_APPROVAL_KEY_UNKNOWN);
  const region: Grant = {}; for (const [k, v] of Object.entries(g)) if (k !== "approver_signature") region[k] = v;
  if (!verifyHex(key, canonicalJson(region), sig)) return reject(REF_APPROVAL_SIGNATURE_INVALID);
  if (g.decision_sha256 !== opts.expectedDecisionSha256) return reject(REF_APPROVAL_BINDING_MISMATCH);
  if (g.approval_request_id !== opts.expectedApprovalRequestId) return reject(REF_APPROVAL_REQUEST_MISMATCH);
  if (g.not_after === null || g.not_after === undefined) return reject(REF_APPROVAL_EXPIRED);
  if (!notAfterValid(g.not_after, opts.now ?? new Date(), opts.clockSkewMs ?? 0)) return reject(REF_APPROVAL_EXPIRED);
  return { accepted: true, reason: ACCEPT_GRANT_VALID };
}
