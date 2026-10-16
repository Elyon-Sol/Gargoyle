/**
 * Canonical JSON, byte-compatible with the reference implementation
 * (Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)):
 * keys sorted, no whitespace, every non-ASCII and control character escaped
 * as \uXXXX (lowercase hex) except the short forms \b \f \n \r \t.
 *
 * Numbers: integers are written as integers. Non-integral numbers are
 * written as JavaScript does; a Python producer writes floats as the
 * shortest round-tripping decimal too, but the two can still differ (1.0 vs
 * 1, exponents), so keep arguments to strings, integers, booleans, null,
 * arrays and objects. NaN and infinities are not JSON and throw.
 */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function escapeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    const ch = s[i];
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (code < 0x20 || code > 0x7e) out += "\\u" + code.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite numbers are not JSON");
    if (Number.isInteger(value)) return value.toFixed(0);
    return String(value);
  }
  if (typeof value === "string") return escapeString(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return "{" + keys.map((k) => escapeString(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
  }
  throw new TypeError("value is not JSON: " + typeof value);
}
