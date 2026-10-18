import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalJson } from "../src/canonical.js";

test("canonical JSON is RFC 8785", () => {
  assert.equal(canonicalJson({ b: 2, a: 1, c: { y: 20, x: 10 } }), '{"a":1,"b":2,"c":{"x":10,"y":20}}');
  assert.equal(canonicalJson({ b: 2, a: { k: "caf\u00e9" } }), '{"a":{"k":"caf\u00e9"},"b":2}');
  assert.equal(canonicalJson("tab\there \u007f del \ud83d\ude00"), '"tab\\there \u007f del \ud83d\ude00"');
  assert.equal(canonicalJson([null, true, false, 0, -1, 1.5, "x", 1.0, 1e21, 1e-7, 0.000001]), '[null,true,false,0,-1,1.5,"x",1,1e+21,1e-7,0.000001]');
  assert.equal(canonicalJson({}), "{}");
  assert.equal(canonicalJson([]), "[]");
  assert.throws(() => canonicalJson(Number.NaN));
  assert.throws(() => canonicalJson(undefined));
  // RFC 8785 section 3.2.3 example.
  const input = JSON.parse('{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/", "literals": [null, true, false]}');
  assert.equal(canonicalJson(input), '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"\u20ac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}');
  // RFC 8785 section 3.2.3 key ordering example: UTF-16 code units, so the emoji sorts before U+FB33.
  const keys = JSON.parse('{"\\u20ac": "Euro Sign", "\\r": "Carriage Return", "\\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One", "\\ud83d\\ude00": "Emoji: Grinning Face", "\\u0080": "Control", "\\u00f6": "Latin Small Letter O With Diaeresis"}');
  const out = canonicalJson(keys);
  const order = ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\ud83d\ude00", "\ufb33"].map((k) => out.indexOf(JSON.stringify(k) + ":"));
  assert.ok(order.every((pos, i) => pos >= 0 && (i === 0 || pos > order[i - 1])), out);
});
