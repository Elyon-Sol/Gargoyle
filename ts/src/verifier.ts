/** Target-side receipt verification (SPEC.md section 6). Pure. */
import type { KeyObject } from "node:crypto";
import { canonicalJson, Json } from "./canonical.js";
import { verifyHex } from "./crypto.js";
import { argsSha256, Call, Envelope, ENVELOPE_VERSION, INVALIDATED, PolicyPin, REASSERTED, RE_EVALUATE_REQUIRED, reassert, signedRegion, validPrincipal } from "./envelope.js";

export const REF_VERIFY_ENVELOPE_ABSENT = "REF_VERIFY_ENVELOPE_ABSENT";
export const REF_VERIFY_VERSION_UNSUPPORTED = "REF_VERIFY_VERSION_UNSUPPORTED";
export const REF_VERIFY_REASSERT_INVALIDATED = "REF_VERIFY_REASSERT_INVALIDATED";
export const REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED = "REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED";
export const REF_VERIFY_BINDING_MISMATCH = "REF_VERIFY_BINDING_MISMATCH";
export const REF_VERIFY_PRINCIPAL_MISMATCH = "REF_VERIFY_PRINCIPAL_MISMATCH";
export const REF_VERIFY_SIGNATURE_INVALID = "REF_VERIFY_SIGNATURE_INVALID";
export const REF_VERIFY_SIGNATURE_UNKNOWN_KEY = "REF_VERIFY_SIGNATURE_UNKNOWN_KEY";
export const REF_VERIFY_SIGNATURE_EXPIRED = "REF_VERIFY_SIGNATURE_EXPIRED";
export const REF_VERIFY_KEY_UNKNOWN = "REF_VERIFY_KEY_UNKNOWN";
export const REF_VERIFY_KEY_REVOKED = "REF_VERIFY_KEY_REVOKED";
export const REF_VERIFY_KEY_OUT_OF_WINDOW = "REF_VERIFY_KEY_OUT_OF_WINDOW";
export const REF_VERIFY_KEY_ROLE_NOT_ISSUER = "REF_VERIFY_KEY_ROLE_NOT_ISSUER";
export const REF_VERIFY_REPLAY = "REF_VERIFY_REPLAY";
export const ACCEPT_REASSERTED_AND_BOUND = "REASSERTED_AND_BOUND";
export const ACCEPT_PROVENANCE = "PROVENANCE_VERIFIED";

export interface Verdict { accepted: boolean; reason: string }
export type KeyMap = Record<string, KeyObject>;
/** A validated key-record view: {key_id: {publicKey, revoked, notBefore, notAfter, role?}}. */
export interface KeyRecordEntry { publicKey: KeyObject; revoked: boolean; notBefore: Date; notAfter: Date; role?: string | null }
export type KeyRecordView = Record<string, KeyRecordEntry>;

const REQUIRED_ENVELOPE_KEYS = ["policy", "request_context", "decision_sha256", "target_url", "requires_approval"];
const REQUEST_CONTEXT_KEYS = ["tool", "args_sha256", "principal"];
const CALL_KEYS = ["tool", "args", "principal"];
const OPTIONAL_CALL_KEYS = ["on_behalf_of"];

const reject = (reason: string): Verdict => ({ accepted: false, reason });

/** Timestamp with an explicit offset; naive or malformed -> null. */
export function parseAware(value: unknown): Date | null {
  if (typeof value !== "string") return null;
  if (!/(?:[+-]\d{2}:\d{2}|Z)$/.test(value)) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function notAfterValid(notAfterRaw: unknown, now: Date, clockSkewMs = 0): boolean {
  if (notAfterRaw === null || notAfterRaw === undefined) return true;
  const na = parseAware(notAfterRaw);
  if (na === null) return false;
  return now.getTime() < na.getTime() + clockSkewMs;
}

export interface ProvenanceOptions {
  pinnedPublicKeys?: KeyMap; keyRecordView?: KeyRecordView; now?: Date; clockSkewMs?: number;
}

/** Steps 1 and 2: structure, trusted issuer signature, expiry. No live call needed. */
export function verifyProvenance(envelope: unknown, opts: ProvenanceOptions): Verdict {
  const skew = opts.clockSkewMs ?? 0;
  if (skew < 0) throw new Error("clockSkewMs must be non-negative");
  if (!opts.pinnedPublicKeys && !opts.keyRecordView) throw new Error("verifyProvenance needs trusted issuer keys");
  const now = opts.now ?? new Date();

  if (typeof envelope !== "object" || envelope === null || Array.isArray(envelope)) return reject(REF_VERIFY_ENVELOPE_ABSENT);
  const env = envelope as Record<string, Json>;
  for (const k of REQUIRED_ENVELOPE_KEYS) if (!(k in env)) return reject(REF_VERIFY_ENVELOPE_ABSENT);
  if (env.envelope_version !== ENVELOPE_VERSION) return reject(REF_VERIFY_VERSION_UNSUPPORTED);
  const rc = env.request_context;
  if (typeof rc !== "object" || rc === null || Array.isArray(rc)) return reject(REF_VERIFY_ENVELOPE_ABSENT);
  for (const k of REQUEST_CONTEXT_KEYS) if (!(k in rc)) return reject(REF_VERIFY_ENVELOPE_ABSENT);
  if ("on_behalf_of" in rc && !validPrincipal(rc.on_behalf_of)) return reject(REF_VERIFY_ENVELOPE_ABSENT);
  if (typeof env.requires_approval !== "boolean") return reject(REF_VERIFY_ENVELOPE_ABSENT);
  if (env.requires_approval && !validPrincipal(env.approval_request_id)) return reject(REF_VERIFY_ENVELOPE_ABSENT);

  const keyId = env.issuer_key_id, signatureHex = env.issuer_signature;
  if (typeof keyId !== "string" || typeof signatureHex !== "string") return reject(REF_VERIFY_SIGNATURE_INVALID);
  let publicKey: KeyObject | undefined;
  if (opts.keyRecordView) {
    const entry = opts.keyRecordView[keyId];
    if (!entry) return reject(REF_VERIFY_KEY_UNKNOWN);
    if (entry.revoked) return reject(REF_VERIFY_KEY_REVOKED);
    if (entry.role !== undefined && entry.role !== null && entry.role !== "issuer") return reject(REF_VERIFY_KEY_ROLE_NOT_ISSUER);
    const t = now.getTime();
    if (!(entry.notBefore.getTime() - skew <= t && t < entry.notAfter.getTime() + skew)) return reject(REF_VERIFY_KEY_OUT_OF_WINDOW);
    publicKey = entry.publicKey;
  } else {
    publicKey = opts.pinnedPublicKeys![keyId];
    if (!publicKey) return reject(REF_VERIFY_SIGNATURE_UNKNOWN_KEY);
  }
  if (!verifyHex(publicKey, signedRegion(env), signatureHex)) return reject(REF_VERIFY_SIGNATURE_INVALID);
  if (!notAfterValid(env.not_after, now, skew)) return reject(REF_VERIFY_SIGNATURE_EXPIRED);
  return { accepted: true, reason: ACCEPT_PROVENANCE };
}

export interface VerifyOptions extends ProvenanceOptions {
  /** The live pin: a fetched record or the policy's own pin. Required. */
  recordSource: PolicyPin;
}

/** The whole check: provenance, currency, binding. Pure; replay is the consumer's job. */
export function verifyEnvelope(envelope: unknown, call: unknown, targetUrl: string, opts: VerifyOptions): Verdict {
  if (!opts.recordSource) throw new Error("verifyEnvelope needs a recordSource (the live policy pin)");
  const provenance = verifyProvenance(envelope, opts);
  if (!provenance.accepted) return provenance;
  const env = envelope as Record<string, Json>;
  const rc = env.request_context as Record<string, Json>;

  let outcome: string;
  try { outcome = reassert(env, opts.recordSource).outcome; } catch { return reject(REF_VERIFY_ENVELOPE_ABSENT); }
  if (outcome === INVALIDATED) return reject(REF_VERIFY_REASSERT_INVALIDATED);
  if (outcome === RE_EVALUATE_REQUIRED) return reject(REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED);
  if (outcome !== REASSERTED) return reject(REF_VERIFY_REASSERT_INVALIDATED);

  if (typeof call !== "object" || call === null || Array.isArray(call)) return reject(REF_VERIFY_BINDING_MISMATCH);
  const c = call as Record<string, unknown>;
  const keys = Object.keys(c);
  if (keys.some((k) => !CALL_KEYS.includes(k) && !OPTIONAL_CALL_KEYS.includes(k)) || CALL_KEYS.some((k) => !keys.includes(k))) return reject(REF_VERIFY_BINDING_MISMATCH);
  if (!validPrincipal(c.principal) || !validPrincipal(rc.principal)) return reject(REF_VERIFY_PRINCIPAL_MISMATCH);
  if (rc.principal !== c.principal) return reject(REF_VERIFY_PRINCIPAL_MISMATCH);
  if ("on_behalf_of" in c && (!validPrincipal(c.on_behalf_of) || rc.on_behalf_of !== c.on_behalf_of)) return reject(REF_VERIFY_PRINCIPAL_MISMATCH);
  if (env.target_url !== targetUrl) return reject(REF_VERIFY_BINDING_MISMATCH);
  if (typeof rc.tool !== "string" || rc.tool !== c.tool) return reject(REF_VERIFY_BINDING_MISMATCH);
  let liveHash: string;
  try { liveHash = argsSha256(c.args as Json); } catch { return reject(REF_VERIFY_BINDING_MISMATCH); }
  if (rc.args_sha256 !== liveHash) return reject(REF_VERIFY_BINDING_MISMATCH);
  return { accepted: true, reason: ACCEPT_REASSERTED_AND_BOUND };
}

export type { Call, Envelope, PolicyPin };
export { canonicalJson };
