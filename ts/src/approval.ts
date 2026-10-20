/** Approval grants (SPEC.md section 8). */
import type { KeyObject } from "node:crypto";
import { canonicalJson, Json } from "./canonical.js";
import { signHex, verifyHex } from "./crypto.js";
import { KeyMap, notAfterValid, Verdict } from "./verifier.js";
import { approvalTerms, Envelope } from "./envelope.js";

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
export const REF_APPROVAL_INSUFFICIENT = "REF_APPROVAL_INSUFFICIENT";
export const REF_APPROVAL_DUPLICATE_APPROVER = "REF_APPROVAL_DUPLICATE_APPROVER";
export const REF_APPROVAL_APPROVER_NOT_ELIGIBLE = "REF_APPROVAL_APPROVER_NOT_ELIGIBLE";
export const ACCEPT_GRANT_VALID = "GRANT_VALID";
export const ACCEPT_GRANTS_SUFFICIENT = "GRANTS_SUFFICIENT";

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
  expectedDecisionSha256: string; expectedApprovalRequestId: string; approverPublicKeys: KeyMap | Record<string, KeyObject | KeyObject[]>;
  gateKeyId: string | null | undefined; now?: Date; clockSkewMs?: number;
}): Verdict {
  if (typeof grant !== "object" || grant === null || Array.isArray(grant)) return reject(REF_APPROVAL_MALFORMED);
  const g = grant as Record<string, Json>;
  for (const k of REQUIRED) if (!(k in g)) return reject(REF_APPROVAL_MALFORMED);
  if (typeof g.grant_id !== "string" || !g.grant_id) return reject(REF_APPROVAL_MISSING_GRANT_ID);
  const keyId = g.approver_key_id, sig = g.approver_signature;
  if (typeof keyId !== "string" || typeof sig !== "string") return reject(REF_APPROVAL_SIGNATURE_INVALID);
  if (keyId === opts.gateKeyId) return reject(REF_APPROVAL_SOD);
  // Several keys for one approver id (an audit of grants from before the approver's
  // browser key was replaced or revoked): the signature is valid if any verifies it.
  const found = (opts.approverPublicKeys as Record<string, KeyObject | KeyObject[]>)[keyId];
  const keys = Array.isArray(found) ? found : found ? [found] : [];
  if (keys.length === 0) return reject(REF_APPROVAL_KEY_UNKNOWN);
  const region: Grant = {}; for (const [k, v] of Object.entries(g)) if (k !== "approver_signature") region[k] = v;
  if (!keys.some((key) => verifyHex(key, canonicalJson(region), sig))) return reject(REF_APPROVAL_SIGNATURE_INVALID);
  if (g.decision_sha256 !== opts.expectedDecisionSha256) return reject(REF_APPROVAL_BINDING_MISMATCH);
  if (g.approval_request_id !== opts.expectedApprovalRequestId) return reject(REF_APPROVAL_REQUEST_MISMATCH);
  if (g.not_after === null || g.not_after === undefined) return reject(REF_APPROVAL_EXPIRED);
  if (!notAfterValid(g.not_after, opts.now ?? new Date(), opts.clockSkewMs ?? 0)) return reject(REF_APPROVAL_EXPIRED);
  return { accepted: true, reason: ACCEPT_GRANT_VALID };
}

/** One grant or a list of them, as a list; null/undefined is the empty list. */
export function asGrantList(grant: unknown): unknown[] {
  if (grant === undefined || grant === null) return [];
  return Array.isArray(grant) ? grant : [grant];
}

/**
 * The grant set against the receipt's own terms (SPEC.md section 8.0): each grant
 * verifies, no approver twice, every approver eligible, at least `required` of them.
 */
export function verifyGrants(grants: unknown, opts: {
  envelope: Envelope; approverPublicKeys: KeyMap; now?: Date; clockSkewMs?: number;
}): Verdict & { grants: Grant[] } {
  const terms = approvalTerms(opts.envelope);
  const items = asGrantList(grants);
  const seen: string[] = [];
  for (const grant of items) {
    const g = verifyGrant(grant, {
      expectedDecisionSha256: opts.envelope.decision_sha256 as string,
      expectedApprovalRequestId: opts.envelope.approval_request_id as string,
      approverPublicKeys: opts.approverPublicKeys, gateKeyId: opts.envelope.issuer_key_id as string,
      now: opts.now, clockSkewMs: opts.clockSkewMs,
    });
    if (!g.accepted) return { ...g, grants: [] };
    const keyId = (grant as Grant).approver_key_id as string;
    if (seen.includes(keyId)) return { accepted: false, reason: REF_APPROVAL_DUPLICATE_APPROVER, grants: [] };
    if (terms.approvers !== null && !terms.approvers.includes(keyId)) return { accepted: false, reason: REF_APPROVAL_APPROVER_NOT_ELIGIBLE, grants: [] };
    seen.push(keyId);
  }
  if (seen.length < terms.required) return { accepted: false, reason: REF_APPROVAL_INSUFFICIENT, grants: [] };
  return { accepted: true, reason: ACCEPT_GRANTS_SUFFICIENT, grants: items as Grant[] };
}
