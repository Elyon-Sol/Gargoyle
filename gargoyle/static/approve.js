// Gargoyle approval console: the browser-side half of a human approval.
// The approver's Ed25519 key never leaves this page; the issuer receives only
// the signed grant, exactly as it does from gargoyle-approver. canonicalJson,
// argsSha256 and grant signing match SPEC.md byte for byte (tests/test_console_js.py
// checks them against the conformance vectors under Node).

// RFC 8785 canonical JSON. Scalars through JSON.stringify (its escaping and
// number format are the JCS rules); objects emitted by hand, because
// JSON.stringify moves integer-like member names to the front.
export function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new TypeError("non-finite numbers are not JSON");
    if (value === undefined) throw new TypeError("value is not JSON: undefined");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(value[k])).join(",") + "}";
}

const subtle = () => globalThis.crypto.subtle;
const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");

export async function sha256Hex(text) {
  return hex(await subtle().digest("SHA-256", new TextEncoder().encode(text)));
}

export async function argsSha256(args) {
  return sha256Hex(canonicalJson(args));
}

/** Import an approver key from the JSON `gargoyle init` wrote: {kty:"OKP", crv:"Ed25519", d, x}. */
export async function importApproverKey(jwk) {
  return subtle().importKey("jwk", { kty: "OKP", crv: "Ed25519", d: jwk.d, x: jwk.x }, { name: "Ed25519" }, false, ["sign"]);
}

export function buildGrant({ decisionSha256, approvalRequestId, grantId, notAfter }) {
  if (!grantId) throw new Error("grant_id is mandatory");
  return { grant_version: "1.0", decision_sha256: decisionSha256, approval_request_id: approvalRequestId, grant_id: grantId, not_after: notAfter };
}

export async function signGrant(grant, key, keyId) {
  const signed = { ...grant, approver_key_id: keyId };
  const region = {};
  for (const [k, v] of Object.entries(signed)) if (k !== "approver_signature") region[k] = v;
  const sig = await subtle().sign({ name: "Ed25519" }, key, new TextEncoder().encode(canonicalJson(region)));
  signed.approver_signature = hex(sig);
  return signed;
}

/** ISO-8601 with an explicit +00:00 offset, as the reference writes it. */
export function isoUtc(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, "+00:00");
}

export function newGrantId() {
  const b = new Uint8Array(16); globalThis.crypto.getRandomValues(b);
  return hex(b.buffer);
}
