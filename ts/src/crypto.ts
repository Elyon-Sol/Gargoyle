/** Ed25519 and SHA-256 over Node's crypto, with raw 32-byte keys as the reference does. */
import { createHash, createPrivateKey, createPublicKey, KeyObject, sign, verify } from "node:crypto";

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** A public key object from the 32 raw Ed25519 bytes (hex or Buffer). */
export function publicKeyFromRaw(raw: string | Uint8Array): KeyObject {
  const bytes = typeof raw === "string" ? Buffer.from(raw, "hex") : Buffer.from(raw);
  if (bytes.length !== 32) throw new Error("an Ed25519 public key is 32 bytes");
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, bytes]), format: "der", type: "spki" });
}

/** A private key object from the 32-byte seed (hex or Buffer). */
export function privateKeyFromSeed(seed: string | Uint8Array): KeyObject {
  const bytes = typeof seed === "string" ? Buffer.from(seed, "hex") : Buffer.from(seed);
  if (bytes.length !== 32) throw new Error("an Ed25519 seed is 32 bytes");
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, bytes]), format: "der", type: "pkcs8" });
}

export function publicKeyRawHex(key: KeyObject): string {
  const pub = key.type === "private" ? createPublicKey(key) : key;
  return Buffer.from(pub.export({ type: "spki", format: "der" })).subarray(SPKI_PREFIX.length).toString("hex");
}

export function signHex(key: KeyObject, message: string): string {
  return sign(null, Buffer.from(message, "utf8"), key).toString("hex");
}

export function verifyHex(key: KeyObject, message: string, signatureHex: string): boolean {
  try {
    const sig = Buffer.from(signatureHex, "hex");
    if (sig.length !== 64 || sig.toString("hex") !== signatureHex.toLowerCase()) return false;
    return verify(null, Buffer.from(message, "utf8"), key, sig);
  } catch {
    return false;
  }
}
