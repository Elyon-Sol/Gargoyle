/** Execution receipts and the offline chain (SPEC.md section 13). */
import type { KeyObject } from "node:crypto";
import { canonicalJson, Json } from "./canonical.js";
import { signHex, verifyHex } from "./crypto.js";
import { argsSha256, Envelope } from "./envelope.js";
import { asGrantList, verifyGrants } from "./approval.js";
import { KeyMap, parseAware, Verdict, verifyProvenance } from "./verifier.js";

export const EXECUTION_VERSION = "gargoyle-execution/1";
export const REF_EXEC_MALFORMED = "REF_EXEC_MALFORMED";
export const REF_EXEC_KEY_UNKNOWN = "REF_EXEC_KEY_UNKNOWN";
export const REF_EXEC_SIGNATURE_INVALID = "REF_EXEC_SIGNATURE_INVALID";
export const REF_EXEC_BINDING_MISMATCH = "REF_EXEC_BINDING_MISMATCH";
export const REF_EXEC_OUTPUTS_MISMATCH = "REF_EXEC_OUTPUTS_MISMATCH";
export const REF_EXEC_GRANT_MISSING = "REF_EXEC_GRANT_MISSING";
export const ACCEPT_EXECUTION_BOUND = "EXECUTION_BOUND";
export const ACCEPT_CHAIN_VERIFIED = "CHAIN_VERIFIED";

export type ExecutionReceipt = Record<string, Json>;
const BOUND = ["decision_id", "decision_sha256", "policy", "target_url", "request_context"];
const REQUIRED = ["execution_version", ...BOUND, "outputs_sha256", "executed_at", "executor_key_id", "executor_signature"];
const reject = (reason: string): Verdict => ({ accepted: false, reason });

export function buildExecutionReceipt(opts: { envelope: Envelope; outputs: Json; executedAt?: string }): ExecutionReceipt {
  for (const k of BOUND) if (!(k in opts.envelope)) throw new Error("honored receipt lacks " + k);
  if (typeof opts.envelope.decision_id !== "string" || !opts.envelope.decision_id) throw new Error("the honored receipt must carry a decision_id");
  const executedAt = opts.executedAt ?? new Date().toISOString().replace("Z", "+00:00");
  if (parseAware(executedAt) === null) throw new Error("executed_at must carry an offset");
  return {
    execution_version: EXECUTION_VERSION,
    decision_id: opts.envelope.decision_id,
    decision_sha256: opts.envelope.decision_sha256,
    policy: opts.envelope.policy,
    target_url: opts.envelope.target_url,
    request_context: opts.envelope.request_context,
    outputs_sha256: argsSha256(opts.outputs),
    executed_at: executedAt,
  };
}

export function signExecutionReceipt(execution: ExecutionReceipt, signingKey: KeyObject, keyId: string): ExecutionReceipt {
  const signed: ExecutionReceipt = { ...execution, executor_key_id: keyId };
  signed.executor_signature = signHex(signingKey, canonicalJson(signedRegion(signed)));
  return signed;
}

function signedRegion(execution: ExecutionReceipt): ExecutionReceipt {
  const region: ExecutionReceipt = {}; for (const [k, v] of Object.entries(execution)) if (k !== "executor_signature") region[k] = v;
  return region;
}

export function verifyExecutionReceipt(execution: unknown, envelope: unknown, executorPublicKeys: KeyMap,
                                       opts: { outputs?: Json; checkOutputs?: boolean } = {}): Verdict {
  if (typeof execution !== "object" || execution === null || Array.isArray(execution)) return reject(REF_EXEC_MALFORMED);
  if (typeof envelope !== "object" || envelope === null || Array.isArray(envelope)) return reject(REF_EXEC_MALFORMED);
  const ex = execution as ExecutionReceipt, env = envelope as Envelope;
  for (const k of REQUIRED) if (!(k in ex)) return reject(REF_EXEC_MALFORMED);
  if (ex.execution_version !== EXECUTION_VERSION) return reject(REF_EXEC_MALFORMED);
  const keyId = ex.executor_key_id, sig = ex.executor_signature;
  if (typeof keyId !== "string" || typeof sig !== "string") return reject(REF_EXEC_MALFORMED);
  const key = executorPublicKeys[keyId];
  if (!key) return reject(REF_EXEC_KEY_UNKNOWN);
  if (!verifyHex(key, canonicalJson(signedRegion(ex)), sig)) return reject(REF_EXEC_SIGNATURE_INVALID);
  for (const k of BOUND) if (!(k in env) || canonicalJson(ex[k]) !== canonicalJson(env[k])) return reject(REF_EXEC_BINDING_MISMATCH);
  if (opts.checkOutputs) {
    try { if (argsSha256(opts.outputs as Json) !== ex.outputs_sha256) return reject(REF_EXEC_OUTPUTS_MISMATCH); }
    catch { return reject(REF_EXEC_OUTPUTS_MISMATCH); }
  }
  return { accepted: true, reason: ACCEPT_EXECUTION_BOUND };
}

export interface ChainResult { accepted: boolean; reason: string; steps: [string, string][] }

export function verifyChain(envelope: unknown, execution: unknown, opts: {
  issuerPublicKeys: KeyMap; executorPublicKeys: KeyMap; grant?: unknown; approverPublicKeys?: KeyMap;
  outputs?: Json; checkOutputs?: boolean;
}): ChainResult {
  const steps: [string, string][] = [];
  if (typeof execution !== "object" || execution === null || Array.isArray(execution)) return { accepted: false, reason: REF_EXEC_MALFORMED, steps };
  const executedAt = parseAware((execution as ExecutionReceipt).executed_at);
  if (executedAt === null) return { accepted: false, reason: REF_EXEC_MALFORMED, steps };

  const provenance = verifyProvenance(envelope, { pinnedPublicKeys: opts.issuerPublicKeys, now: executedAt });
  steps.push(["authorization", provenance.reason]);
  if (!provenance.accepted) return { accepted: false, reason: provenance.reason, steps };
  const env = envelope as Envelope;

  if (env.requires_approval) {
    if (asGrantList(opts.grant).length === 0) {
      steps.push(["approval", REF_EXEC_GRANT_MISSING]);
      return { accepted: false, reason: REF_EXEC_GRANT_MISSING, steps };
    }
    const g = verifyGrants(opts.grant, { envelope: env, approverPublicKeys: opts.approverPublicKeys ?? {}, now: executedAt });
    steps.push(["approval", g.reason]);
    if (!g.accepted) return { accepted: false, reason: g.reason, steps };
  }
  const e = verifyExecutionReceipt(execution, env, opts.executorPublicKeys, { outputs: opts.outputs, checkOutputs: opts.checkOutputs });
  steps.push(["execution", e.reason]);
  if (!e.accepted) return { accepted: false, reason: e.reason, steps };
  return { accepted: true, reason: ACCEPT_CHAIN_VERIFIED, steps };
}
