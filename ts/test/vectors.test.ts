/**
 * Conformance: every vector in tests/fixtures/wire_vectors.json (and quoted
 * in SPEC.md section 11) is recomputed here from the seed labels. Byte
 * equality of hashes and signatures proves this canonical JSON and these
 * regions match the reference implementation exactly.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  ACCEPT_CHAIN_VERIFIED, ACCEPT_REASSERTED_AND_BOUND, Consumer, HASH_EXCLUDED_KEYS, REF_APPROVAL_REPLAY,
  REF_TARGET_APPROVAL_REQUIRED, REF_VERIFY_BINDING_MISMATCH, REF_VERIFY_PRINCIPAL_MISMATCH, REF_VERIFY_REPLAY,
  REF_VERIFY_SIGNATURE_INVALID, buildEnvelope, buildExecutionReceipt, buildGrant, canonicalJson, decisionSha256Of,
  privateKeyFromSeed, publicKeyFromRaw, publicKeyRawHex, signEnvelope, signExecutionReceipt, signGrant,
  verifyChain, verifyEnvelope, encodeReceipt, decodeReceipt, REF_JWS_PAYLOAD_MISMATCH, REF_JWS_ALG_UNSUPPORTED, encode,
  REF_APPROVAL_INSUFFICIENT, REF_APPROVAL_APPROVER_NOT_ELIGIBLE, REF_VERIFY_ENVELOPE_ABSENT, verifyGrants,
} from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(path.resolve(here, "../../../tests/fixtures/wire_vectors.json"), "utf8"));
const keyFor = (label: string) => privateKeyFromSeed(createHash("sha256").update(label).digest());

function recompute() {
  const issuer = keyFor(V.issuer_seed_label), approver = keyFor(V.approver_seed_label), executor = keyFor(V.executor_seed_label);
  const env = buildEnvelope({ decision: "ELIGIBLE", targetUrl: V.unsigned.target_url, call: V.call, policyPin: V.unsigned.policy,
                              timestampUtc: V.unsigned.timestamp_utc, requiresApproval: V.unsigned.requires_approval });
  const signed = signEnvelope(env, issuer, V.signed.issuer_key_id,
                              { notAfter: V.signed.not_after, decisionId: V.signed.decision_id, approvalRequestId: V.signed.approval_request_id });
  const grant = signGrant(buildGrant({ decisionSha256: env.decision_sha256 as string, approvalRequestId: V.grant.approval_request_id,
                                       grantId: V.grant.grant_id, notAfter: V.grant.not_after }), approver, V.grant.approver_key_id);
  const execution = signExecutionReceipt(buildExecutionReceipt({ envelope: signed, outputs: V.outputs, executedAt: V.execution.executed_at }),
                                         executor, V.execution.executor_key_id);
  return { issuer, approver, executor, env, signed, grant, execution };
}

test("keys derive from the seed labels", () => {
  const { issuer, approver, executor } = recompute();
  assert.equal(publicKeyRawHex(issuer), V.issuer_public_key_hex);
  assert.equal(publicKeyRawHex(approver), V.approver_public_key_hex);
  assert.equal(publicKeyRawHex(executor), V.executor_public_key_hex);
});

test("receipt, grant and execution receipt recompute byte for byte", () => {
  const { env, signed, grant, execution } = recompute();
  assert.deepEqual(env, V.unsigned);
  assert.deepEqual(signed, V.signed);
  assert.deepEqual(grant, V.grant);
  assert.deepEqual(execution, V.execution);
  assert.equal(canonicalJson(Object.fromEntries(Object.entries(signed).filter(([k]) => !(HASH_EXCLUDED_KEYS as readonly string[]).includes(k)))), V.hash_region);
  assert.equal(canonicalJson(Object.fromEntries(Object.entries(signed).filter(([k]) => k !== "issuer_signature" && k !== "timestamp_utc"))), V.signed_region);
  assert.equal(canonicalJson(Object.fromEntries(Object.entries(execution).filter(([k]) => k !== "executor_signature"))), V.execution_signed_region);
  assert.equal(decisionSha256Of(signed), V.unsigned.decision_sha256);
});

test("the vectors verify: envelope, chain, consumer with grant", () => {
  const { issuer, approver, executor, signed, grant, execution } = recompute();
  const now = new Date("2026-10-16T12:01:00+00:00");
  const issuerKeys = { [V.signed.issuer_key_id]: publicKeyFromRaw(V.issuer_public_key_hex) };
  const r = verifyEnvelope(signed, V.call, signed.target_url as string, { recordSource: V.signed.policy, pinnedPublicKeys: issuerKeys, now });
  assert.deepEqual(r, { accepted: true, reason: ACCEPT_REASSERTED_AND_BOUND });
  const chain = verifyChain(signed, execution, {
    issuerPublicKeys: issuerKeys, executorPublicKeys: { [V.execution.executor_key_id]: publicKeyFromRaw(V.executor_public_key_hex) },
    grant, approverPublicKeys: { [V.grant.approver_key_id]: publicKeyFromRaw(V.approver_public_key_hex) }, outputs: V.outputs, checkOutputs: true,
  });
  assert.equal(chain.reason, ACCEPT_CHAIN_VERIFIED);
  assert.deepEqual(chain.steps.map((s) => s[0]), ["authorization", "approval", "execution"]);

  const consumer = new Consumer({ targetId: signed.target_url as string, record: V.signed.policy, pinnedPublicKeys: issuerKeys,
                                  approverPublicKeys: { [V.grant.approver_key_id]: publicKeyFromRaw(V.approver_public_key_hex) },
                                  executorSigningKey: executor, executorKeyId: V.execution.executor_key_id });
  assert.deepEqual(consumer.check(signed, V.call, { now }), { accepted: false, reason: REF_TARGET_APPROVAL_REQUIRED });
  assert.equal(consumer.check(signed, V.call, { grant, now }).accepted, true);
  assert.deepEqual(consumer.check(signed, V.call, { grant, now }), { accepted: false, reason: REF_APPROVAL_REPLAY });
  const attested = consumer.attest(signed, V.outputs, V.execution.executed_at);
  assert.deepEqual(attested, V.execution);
  void issuer; void approver;
});

test("binding, principal, tamper and replay refusals", () => {
  const { signed } = recompute();
  const issuerKeys = { [V.signed.issuer_key_id]: publicKeyFromRaw(V.issuer_public_key_hex) };
  const now = new Date("2026-10-16T12:01:00+00:00");
  const opts = { recordSource: V.signed.policy, pinnedPublicKeys: issuerKeys, now };
  assert.equal(verifyEnvelope(signed, { ...V.call, args: { amount: 250000, to: "acct-9" } }, signed.target_url as string, opts).reason, REF_VERIFY_BINDING_MISMATCH);
  assert.equal(verifyEnvelope(signed, { ...V.call, principal: "agent-8" }, signed.target_url as string, opts).reason, REF_VERIFY_PRINCIPAL_MISMATCH);
  assert.equal(verifyEnvelope(signed, { ...V.call, extra: 1 } as never, signed.target_url as string, opts).reason, REF_VERIFY_BINDING_MISMATCH);
  assert.equal(verifyEnvelope({ ...signed, requires_approval: false }, V.call, signed.target_url as string, opts).reason, REF_VERIFY_SIGNATURE_INVALID);
  assert.equal(verifyEnvelope(signed, { ...V.call, args: { to: "acct-9", amount: 250 } }, signed.target_url as string, opts).accepted, true);
  const free = new Consumer({ targetId: signed.target_url as string, record: V.signed.policy, pinnedPublicKeys: issuerKeys });
  assert.equal(free.check({ ...signed }, V.call, { now }).reason, REF_TARGET_APPROVAL_REQUIRED);
  assert.throws(() => verifyEnvelope(signed, V.call, signed.target_url as string, { recordSource: V.signed.policy, now }));
  void REF_VERIFY_REPLAY;
});

test("the JWS form recomputes and decodes to the same receipt", () => {
  const { issuer, signed } = recompute();
  assert.equal(encodeReceipt(signed, issuer), V.jws);
  const issuerKeys = { [V.signed.issuer_key_id]: publicKeyFromRaw(V.issuer_public_key_hex) };
  const now = new Date("2026-10-16T12:01:00+00:00");
  const res = decodeReceipt(V.jws, issuerKeys, { audience: signed.target_url as string, now });
  assert.equal(res.reason, null);
  assert.deepEqual(res.envelope, V.signed);
  const [h, p, s] = (V.jws as string).split(".");
  const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  assert.equal(decodeReceipt(encode({ ...payload, jti: "other" }, issuer, V.signed.issuer_key_id), issuerKeys, { now }).reason, REF_JWS_PAYLOAD_MISMATCH);
  assert.equal(decodeReceipt(Buffer.from('{"alg":"none","kid":"x"}').toString("base64url") + "." + p + "." + s, issuerKeys, { now }).reason, REF_JWS_ALG_UNSUPPORTED);
  void h;
});

test("delegation: on_behalf_of is bound when the target knows it", () => {
  const { signed } = recompute();
  const issuerKeys = { [V.signed.issuer_key_id]: publicKeyFromRaw(V.issuer_public_key_hex) };
  const opts = { recordSource: V.signed.policy, pinnedPublicKeys: issuerKeys, now: new Date("2026-10-16T12:01:00+00:00") };
  const { on_behalf_of, ...withoutDelegation } = V.call;
  assert.equal(verifyEnvelope(signed, V.call, signed.target_url as string, opts).accepted, true);
  assert.equal(verifyEnvelope(signed, withoutDelegation, signed.target_url as string, opts).accepted, true);
  assert.equal(verifyEnvelope(signed, { ...V.call, on_behalf_of: "user-43" }, signed.target_url as string, opts).reason, REF_VERIFY_PRINCIPAL_MISMATCH);
  void on_behalf_of;
});

test("threshold vector: terms in the hash region, two grants needed", () => {
  const T = V.threshold;
  const issuer = keyFor(V.issuer_seed_label), alice = keyFor(V.approver_seed_label), bob = keyFor(T.approver_2_seed_label), executor = keyFor(V.executor_seed_label);
  assert.equal(publicKeyRawHex(bob), T.approver_2_public_key_hex);
  const env = buildEnvelope({ decision: "ELIGIBLE", targetUrl: V.unsigned.target_url, call: V.call, policyPin: V.unsigned.policy,
                              timestampUtc: V.unsigned.timestamp_utc, requiresApproval: true, approval: T.approval });
  const signed = signEnvelope(env, issuer, T.signed.issuer_key_id,
                              { notAfter: T.signed.not_after, decisionId: T.signed.decision_id, approvalRequestId: T.signed.approval_request_id });
  assert.deepEqual(env, T.unsigned);
  assert.deepEqual(signed, T.signed);
  assert.equal(canonicalJson(Object.fromEntries(Object.entries(signed).filter(([k]) => !(HASH_EXCLUDED_KEYS as readonly string[]).includes(k)))), T.hash_region);
  const grants = T.grants.map((g: Record<string, string>, i: number) => signGrant(buildGrant({
    decisionSha256: env.decision_sha256 as string, approvalRequestId: g.approval_request_id, grantId: g.grant_id, notAfter: g.not_after,
  }), i === 0 ? alice : bob, g.approver_key_id));
  assert.deepEqual(grants, T.grants);
  const execution = signExecutionReceipt(buildExecutionReceipt({ envelope: signed, outputs: V.outputs, executedAt: T.execution.executed_at }),
                                         executor, T.execution.executor_key_id);
  assert.deepEqual(execution, T.execution);

  const now = new Date("2026-10-16T12:01:00+00:00");
  const issuerKeys = { [T.signed.issuer_key_id]: publicKeyFromRaw(V.issuer_public_key_hex) };
  const approvers = { "approver-alice": publicKeyFromRaw(V.approver_public_key_hex), "approver-bob": publicKeyFromRaw(T.approver_2_public_key_hex),
                      "approver-carol": publicKeyFromRaw(V.executor_public_key_hex) };
  assert.equal(verifyGrants(grants[0], { envelope: signed, approverPublicKeys: approvers, now }).reason, REF_APPROVAL_INSUFFICIENT);
  assert.equal(verifyGrants(grants, { envelope: signed, approverPublicKeys: approvers, now }).accepted, true);
  const carol = signGrant(buildGrant({ decisionSha256: env.decision_sha256 as string, approvalRequestId: "req-0002", grantId: "g-c", notAfter: T.grants[0].not_after }), executor, "approver-carol");
  assert.equal(verifyGrants([grants[0], carol], { envelope: signed, approverPublicKeys: approvers, now }).reason, REF_APPROVAL_APPROVER_NOT_ELIGIBLE);
  const consumer = new Consumer({ targetId: signed.target_url as string, record: T.signed.policy, pinnedPublicKeys: issuerKeys, approverPublicKeys: approvers });
  assert.equal(consumer.check(signed, V.call, { grant: grants[1], now }).reason, REF_APPROVAL_INSUFFICIENT);
  assert.equal(consumer.check(signed, V.call, { grant: grants, now }).accepted, true);
  const chain = verifyChain(signed, execution, { issuerPublicKeys: issuerKeys, executorPublicKeys: { [T.execution.executor_key_id]: publicKeyFromRaw(V.executor_public_key_hex) },
                                                 grant: grants, approverPublicKeys: approvers });
  assert.equal(chain.reason, ACCEPT_CHAIN_VERIFIED);
  // Lowering the threshold breaks the signature; a malformed member is unusable.
  const opts = { recordSource: T.signed.policy, pinnedPublicKeys: issuerKeys, now };
  assert.equal(verifyEnvelope({ ...signed, approval: { required: 1, approvers: T.approval.approvers } }, V.call, signed.target_url as string, opts).reason, REF_VERIFY_SIGNATURE_INVALID);
  assert.equal(verifyEnvelope({ ...signed, approval: { required: 0 } }, V.call, signed.target_url as string, opts).reason, REF_VERIFY_ENVELOPE_ABSENT);
  assert.equal(verifyEnvelope({ ...V.signed, requires_approval: false, approval: { required: 1 } }, V.call, V.signed.target_url, opts).reason, REF_VERIFY_ENVELOPE_ABSENT);
});
