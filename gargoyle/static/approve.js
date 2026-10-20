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

// ---- Entra ID sign-in (OAuth 2.0 authorization code with PKCE, RFC 7636), no library ----

const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export function randomVerifier() {
  const bytes = new Uint8Array(32); globalThis.crypto.getRandomValues(bytes);
  return b64url(bytes);                                   // 43 chars of the unreserved set
}

export async function pkceChallenge(verifier) {
  return b64url(await subtle().digest("SHA-256", new TextEncoder().encode(verifier)));
}

export function authorizeUrl({ tenant, clientId, scope, redirectUri, challenge, state }) {
  const q = new URLSearchParams({ client_id: clientId, response_type: "code", redirect_uri: redirectUri, response_mode: "query",
                                  scope: scope + " openid profile", code_challenge: challenge, code_challenge_method: "S256", state });
  return `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize?${q}`;
}

export async function exchangeCode({ tenant, clientId, scope, redirectUri, code, verifier }, fetchImpl = globalThis.fetch) {
  const body = new URLSearchParams({ client_id: clientId, grant_type: "authorization_code", code, redirect_uri: redirectUri,
                                     code_verifier: verifier, scope: scope + " openid profile" });
  const r = await fetchImpl(`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
                            { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
  const tok = await r.json();
  if (!r.ok || !tok.access_token) throw new Error(tok.error_description || tok.error || ("token endpoint " + r.status));
  return tok;                                             // { access_token, expires_in, id_token, ... }
}

// ---- The approver's own key: generated here, non-extractable, kept in IndexedDB ----

export async function generateApproverKey() {
  return subtle().generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);   // private half can never be exported
}

export async function publicKeyHex(keyPair) {
  return hex(await subtle().exportKey("raw", keyPair.publicKey));
}

const DB = "gargoyle-approver", STORE = "keys";
function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result); req.onerror = () => reject(req.error);
  });
}
export async function loadStoredKey(name) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE).objectStore(STORE).get(name);
    req.onsuccess = () => resolve(req.result || null); req.onerror = () => reject(req.error);
  });
}
export async function storeKey(name, keyPair) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite"); tx.objectStore(STORE).put(keyPair, name);
    tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
  });
}

// ---- What a held write changes: a line diff of the state the executor saw against the proposed content ----

export function lineDiff(before, after) {
  const a = before.split("\n"), b = after.split("\n");
  const n = a.length, m = b.length;
  const lcs = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
  const out = []; let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push({ op: " ", text: a[i] }); i++; j++; }
    else if (lcs[i + 1][j] >= lcs[i][j + 1]) { out.push({ op: "-", text: a[i] }); i++; }
    else { out.push({ op: "+", text: b[j] }); j++; }
  }
  while (i < n) out.push({ op: "-", text: a[i++] });
  while (j < m) out.push({ op: "+", text: b[j++] });
  return out;
}


// EMILIA Protocol signoff (gargoyle/emilia.py mirrors this byte for byte).
// The console signs two things for one hold: the Gargoyle grant, and the
// SHA-256 of the JCS Authorization Context EMILIA's verifiers expect. The
// second travels inside the grant as its `emilia` member, so the grant
// signature covers it and the issuer can check it against the hold.
const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const hexToBytes = (h) => Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16));
const uuidBytes = (u) => hexToBytes(u.replace(/-/g, ""));

export function emiliaAction(env) {
  const rc = env.request_context;
  const parameters = { args_sha256: rc.args_sha256 };
  if (rc.state_sha256) parameters.state_sha256 = rc.state_sha256;
  const action = {
    ep_version: "1.0", action_type: "mcp.tools/call",
    target: { system: env.target_url, resource: rc.tool },
    parameters, initiator: rc.principal, policy_id: env.policy.policy_id, requested_at: env.timestamp_utc,
    gargoyle: { envelope_version: env.envelope_version, decision_sha256: env.decision_sha256, decision_id: env.decision_id },
  };
  if (rc.on_behalf_of) action.on_behalf_of = rc.on_behalf_of;
  return action;
}

export async function emiliaContext(env, approverId, index, expiresAt) {
  const nonceDigest = await subtle().digest("SHA-256", new TextEncoder().encode("gargoyle-emilia-nonce/1\n" + env.approval_request_id + "\n" + approverId));
  return {
    ep_version: "1.0", context_type: "ep.signoff.v1",
    action_hash: "sha256:" + (await sha256Hex(canonicalJson(emiliaAction(env)))),
    policy_id: env.policy.policy_id, policy_hash: "sha256:" + env.policy.policy_sha256,
    initiator: env.request_context.principal,
    authorization_instance: b64u(uuidBytes(env.decision_id)), audience: env.target_url,
    approver: approverId, approver_index: index, required_approvals: env.approval?.required ?? 1,
    nonce: b64u(nonceDigest.slice(0, 16)), issued_at: env.timestamp_utc, expires_at: expiresAt,
  };
}

/** {context, signature}: the approver's Ed25519 signature over the 32-byte context hash (EMILIA Class B). */
export async function emiliaSignoff(context, key) {
  const digest = await subtle().digest("SHA-256", new TextEncoder().encode(canonicalJson(context)));
  return { context, signature: hex(await subtle().sign({ name: "Ed25519" }, key, digest)) };
}

/** The earlier of two instants, returned as the exact string that names it. */
export function earlier(a, b) { return new Date(a) <= new Date(b) ? a : b; }
