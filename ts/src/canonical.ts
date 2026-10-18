/**
 * Canonical JSON per RFC 8785 (JSON Canonicalization Scheme), byte-compatible
 * with the reference implementation: members sorted by UTF-16 code units, no
 * whitespace, strings escaped only where JSON requires it (non-ASCII stays
 * literal UTF-8), numbers as ECMAScript Number::toString. Scalars go through
 * JSON.stringify, which already follows those rules; objects are emitted by
 * hand, because JSON.stringify would move integer-like member names such as
 * "1" to the front whatever order they were sorted into. NaN and infinities
 * are not JSON and throw.
 */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export function canonicalJson(value: unknown): string {
  if (value === null || value === true || value === false || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite numbers are not JSON");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
  }
  throw new TypeError("value is not JSON: " + typeof value);
}
