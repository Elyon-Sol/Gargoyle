import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalJson } from "../src/canonical.js";

test("canonical JSON matches the reference serializer", () => {
  assert.equal(canonicalJson({ b: 2, a: 1, c: { y: 20, x: 10 } }), '{"a":1,"b":2,"c":{"x":10,"y":20}}');
  assert.equal(canonicalJson({ b: 2, a: { k: "caf\u00e9" } }), '{"a":{"k":"caf\\u00e9"},"b":2}');
  assert.equal(canonicalJson("tab\there \u007f del \ud83d\ude00"), '"tab\\there \\u007f del \\ud83d\\ude00"');
  assert.equal(canonicalJson([null, true, false, 0, -1, 1.5, "x"]), '[null,true,false,0,-1,1.5,"x"]');
  assert.equal(canonicalJson({}), "{}");
  assert.equal(canonicalJson([]), "[]");
  assert.throws(() => canonicalJson(Number.NaN));
  assert.throws(() => canonicalJson(undefined));
});
