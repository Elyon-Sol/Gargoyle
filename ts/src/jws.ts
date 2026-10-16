/** JWS compact serialization with EdDSA (RFC 7515, RFC 8037): the receipt's interoperable form. */
import type { KeyObject } from "node:crypto";
import { canonicalJson, Json } from "./canonical.js";
import { signHex, verifyHex } from "./crypto.js";
import { Envelope } from "./envelope.js";
import { KeyMap } from "./verifier.js";

export const JWS_ALG = "EdDSA";
export const REF_JWS_MALFORMED = "REF_JWS_MALFORMED";
export const REF_JWS_ALG_UNSUPPORTED = "REF_JWS_ALG_UNSUPPORTED";
export const REF_JWS_KEY_UNKNOWN = "REF_JWS_KEY_UNKNOWN";
export const REF_JWS_SIGNATURE_INVALID = "REF_JWS_SIGNATURE_INVALID";
export const REF_JWS_EXPIRED = "REF_JWS_EXPIRED";
export const REF_JWS_AUDIENCE_MISMATCH = "REF_JWS_AUDIENCE_MISMATCH";
export const REF_JWS_PAYLOAD_MISMATCH = "REF_JWS_PAYLOAD_MISMATCH";

export const b64urlEncode = (data: Buffer | string): string =>
  (typeof data === "string" ? Buffer.from(data, "utf8") : data).toString("base64url");
export function b64urlDecode(text: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("not base64url");
  return Buffer.from(text, "base64url");
}

export function encode(payload: Record<string, Json>, signingKey: KeyObject, keyId: string): string {
  const header = { alg: JWS_ALG, kid: keyId, typ: "JWT" };
  const signingInput = b64urlEncode(canonicalJson(header)) + "." + b64urlEncode(canonicalJson(payload));
  return signingInput + "." + Buffer.from(signHex(signingKey, signingInput), "hex").toString("base64url");
}

export interface Decoded { header?: Record<string, Json>; payload?: Record<string, Json>; reason: string | null }

export function decode(token: unknown, publicKeys: KeyMap): Decoded {
  if (typeof token !== "string" || token.split(".").length !== 3) return { reason: REF_JWS_MALFORMED };
  const [h, p, s] = token.split(".");
  let header: unknown, payload: unknown, signature: Buffer;
  try { header = JSON.parse(b64urlDecode(h).toString("utf8")); payload = JSON.parse(b64urlDecode(p).toString("utf8")); signature = b64urlDecode(s); }
  catch { return { reason: REF_JWS_MALFORMED }; }
  if (typeof header !== "object" || header === null || Array.isArray(header)
      || typeof payload !== "object" || payload === null || Array.isArray(payload)) return { reason: REF_JWS_MALFORMED };
  const hd = header as Record<string, Json>;
  if (hd.alg !== JWS_ALG) return { reason: REF_JWS_ALG_UNSUPPORTED };
  if (typeof hd.kid !== "string" || !(hd.kid in publicKeys)) return { reason: REF_JWS_KEY_UNKNOWN };
  if (!verifyHex(publicKeys[hd.kid], h + "." + p, signature.toString("hex"))) return { reason: REF_JWS_SIGNATURE_INVALID };
  return { header: hd, payload: payload as Record<string, Json>, reason: null };
}

const epoch = (ts: string): number => Math.floor(new Date(ts).getTime() / 1000);

export function encodeReceipt(signed: Envelope, signingKey: KeyObject): string {
  for (const k of ["issuer_key_id", "issuer_signature", "decision_id", "not_after", "target_url"]) if (!(k in signed)) throw new Error("a JWS receipt needs a signed receipt with " + k);
  const payload: Record<string, Json> = {
    iss: signed.issuer_key_id, jti: signed.decision_id, aud: signed.target_url, exp: epoch(signed.not_after as string), gargoyle: { ...signed },
  };
  if (typeof signed.timestamp_utc === "string") payload.iat = epoch(signed.timestamp_utc);
  return encode(payload, signingKey, signed.issuer_key_id as string);
}

export function decodeReceipt(token: unknown, issuerPublicKeys: KeyMap, opts: { audience?: string; now?: Date } = {}): { envelope: Envelope | null; reason: string | null } {
  const res = decode(token, issuerPublicKeys);
  if (res.reason !== null) return { envelope: null, reason: res.reason };
  const payload = res.payload!, header = res.header!;
  const env = payload.gargoyle;
  if (typeof env !== "object" || env === null || Array.isArray(env)) return { envelope: null, reason: REF_JWS_MALFORMED };
  const e = env as Envelope;
  if (e.issuer_key_id !== header.kid || payload.iss !== header.kid || payload.jti !== e.decision_id || payload.aud !== e.target_url) return { envelope: null, reason: REF_JWS_PAYLOAD_MISMATCH };
  if (typeof e.not_after !== "string" || payload.exp !== epoch(e.not_after)) return { envelope: null, reason: REF_JWS_PAYLOAD_MISMATCH };
  if (opts.audience !== undefined && payload.aud !== opts.audience) return { envelope: null, reason: REF_JWS_AUDIENCE_MISMATCH };
  const now = opts.now ?? new Date();
  if (typeof payload.exp !== "number" || now.getTime() / 1000 >= payload.exp) return { envelope: null, reason: REF_JWS_EXPIRED };
  return { envelope: e, reason: null };
}
