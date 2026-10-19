/** Receipts: build, hash, sign, and the currency check (SPEC.md sections 3-5). */
import type { KeyObject } from "node:crypto";
import { canonicalJson, Json } from "./canonical.js";
import { sha256Hex, signHex } from "./crypto.js";

export const ENVELOPE_VERSION = "gargoyle/3";
export const REASSERTED = "REASSERTED";
export const INVALIDATED = "INVALIDATED";
export const RE_EVALUATE_REQUIRED = "RE-EVALUATE-REQUIRED";

export const HASH_EXCLUDED_KEYS = [
  "decision_sha256", "timestamp_utc", "issuer_key_id", "issuer_signature",
  "not_after", "decision_id", "approval_request_id",
] as const;
export const SIGNATURE_EXCLUDED_KEYS = ["issuer_signature", "timestamp_utc"] as const;

export interface PolicyPin { policy_id: string; policy_sha256: string }
export interface Call { tool: string; args: Json; principal: string; on_behalf_of?: string; state_sha256?: string }
export type Envelope = Record<string, Json>;

export function argsSha256(args: Json): string {
  return sha256Hex(canonicalJson(args));
}

export function validPrincipal(p: unknown): p is string {
  return typeof p === "string" && p.length > 0;
}

export function validPin(pin: unknown): pin is PolicyPin {
  if (typeof pin !== "object" || pin === null) return false;
  const p = pin as Record<string, unknown>;
  return typeof p.policy_id === "string" && p.policy_id.length > 0
    && typeof p.policy_sha256 === "string" && p.policy_sha256.length === 64;
}

function without(obj: Record<string, Json>, keys: readonly string[]): Record<string, Json> {
  const out: Record<string, Json> = {};
  for (const [k, v] of Object.entries(obj)) if (!keys.includes(k)) out[k] = v;
  return out;
}

export function decisionSha256Of(envelope: Envelope): string {
  return sha256Hex(canonicalJson(without(envelope, HASH_EXCLUDED_KEYS)));
}

/** The receipt's optional `approval` member (SPEC.md section 3). */
export type ApprovalTerms = { required: number; approvers?: string[] };

export function validApproval(approval: unknown): approval is ApprovalTerms {
  if (typeof approval !== "object" || approval === null || Array.isArray(approval)) return false;
  const a = approval as Record<string, Json>;
  const keys = Object.keys(a);
  if (!keys.includes("required") || keys.some((k) => k !== "required" && k !== "approvers")) return false;
  if (typeof a.required !== "number" || !Number.isInteger(a.required) || a.required < 1) return false;
  if ("approvers" in a) {
    const list = a.approvers;
    if (!Array.isArray(list) || list.length === 0 || !list.every((x) => typeof x === "string" && x)) return false;
    if (new Set(list).size !== list.length || list.length < a.required) return false;
  }
  return true;
}

/** {required, approvers} for a flagged receipt: its `approval` member, or the default of one from anyone. */
export function approvalTerms(envelope: Envelope): { required: number; approvers: string[] | null } {
  const a = envelope.approval;
  if (validApproval(a)) return { required: a.required, approvers: a.approvers ?? null };
  return { required: 1, approvers: null };
}

export function buildEnvelope(opts: {
  decision: string; targetUrl: string; call: Call; policyPin: PolicyPin;
  timestampUtc?: string; requiresApproval?: boolean; approval?: ApprovalTerms;
}): Envelope {
  if (opts.approval !== undefined && (!opts.requiresApproval || !validApproval(opts.approval))) {
    throw new Error("approval must be {required >= 1, approvers?: [key ids]} on a flagged receipt");
  }
  if (!validPin(opts.policyPin)) throw new Error("policy_pin must be {policy_id, policy_sha256 (64 hex)}");
  if (typeof opts.call.tool !== "string" || !opts.call.tool) throw new Error("call.tool must be a non-empty string");
  if (!validPrincipal(opts.call.principal)) throw new Error("call.principal must be a non-empty string");
  const obo = opts.call.on_behalf_of;
  if (obo !== undefined && !validPrincipal(obo)) throw new Error("call.on_behalf_of, when present, must be a non-empty string");
  const envelope: Envelope = {
    envelope_version: ENVELOPE_VERSION,
    decision: opts.decision,
    requires_approval: opts.requiresApproval ?? false,
    target_url: opts.targetUrl,
    policy: { policy_id: opts.policyPin.policy_id, policy_sha256: opts.policyPin.policy_sha256 },
    request_context: { tool: opts.call.tool, args_sha256: argsSha256(opts.call.args), principal: opts.call.principal },
    timestamp_utc: opts.timestampUtc ?? new Date().toISOString().replace("Z", "+00:00"),
  };
  if (obo !== undefined) (envelope.request_context as Record<string, Json>).on_behalf_of = obo;
  const st = opts.call.state_sha256;
  if (st !== undefined) {
    if (typeof st !== "string" || st.length !== 64) throw new Error("call.state_sha256, when present, must be 64 hex characters");
    (envelope.request_context as Record<string, Json>).state_sha256 = st;
  }
  if (opts.approval !== undefined) {
    const approval: Record<string, Json> = { required: opts.approval.required };
    if (opts.approval.approvers) approval.approvers = [...opts.approval.approvers].sort();
    envelope.approval = approval;
  }
  envelope.decision_sha256 = decisionSha256Of(envelope);
  return envelope;
}

export function signEnvelope(envelope: Envelope, signingKey: KeyObject, keyId: string, opts: {
  notAfter?: string; decisionId?: string; approvalRequestId?: string;
} = {}): Envelope {
  const signed: Envelope = { ...envelope, issuer_key_id: keyId };
  if (opts.notAfter !== undefined) signed.not_after = opts.notAfter;
  if (opts.decisionId !== undefined) signed.decision_id = opts.decisionId;
  if (opts.approvalRequestId !== undefined) signed.approval_request_id = opts.approvalRequestId;
  signed.issuer_signature = signHex(signingKey, canonicalJson(without(signed, SIGNATURE_EXCLUDED_KEYS)));
  return signed;
}

export function signedRegion(envelope: Envelope): string {
  return canonicalJson(without(envelope, SIGNATURE_EXCLUDED_KEYS));
}

/** SPEC.md section 6 step 3: integrity, then the pin against the live pin. */
export function reassert(envelope: Envelope, livePin: PolicyPin): { outcome: string } {
  const stored = envelope.decision_sha256;
  if (typeof stored !== "string" || stored !== decisionSha256Of(envelope)) return { outcome: INVALIDATED };
  const pinned = envelope.policy;
  if (typeof pinned !== "object" || pinned === null || Array.isArray(pinned)
    || (pinned as Record<string, Json>).policy_id !== livePin.policy_id
    || (pinned as Record<string, Json>).policy_sha256 !== livePin.policy_sha256) {
    return { outcome: RE_EVALUATE_REQUIRED };
  }
  return { outcome: REASSERTED };
}
