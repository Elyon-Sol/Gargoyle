/**
 * The consumer: live pin, trusted keys, verify, grant, single-use claims,
 * attest (SPEC.md sections 6-8 and 13). Replay state is an in-memory cache
 * by default; implement ReplayCache over a shared store for more than one
 * process.
 */
import type { KeyObject } from "node:crypto";
import { Json } from "./canonical.js";
import { Call, Envelope, PolicyPin } from "./envelope.js";
import { REF_APPROVAL_REPLAY, asGrantList, verifyGrants } from "./approval.js";
import { buildExecutionReceipt, ExecutionReceipt, signExecutionReceipt } from "./execution.js";
import { KeyMap, KeyRecordView, parseAware, REF_VERIFY_REPLAY, Verdict, verifyEnvelope } from "./verifier.js";

export const REF_TARGET_NO_DECISION_ID = "REF_TARGET_NO_DECISION_ID";
export const REF_TARGET_APPROVAL_REQUIRED = "REF_TARGET_APPROVAL_REQUIRED";
export const REF_TARGET_NO_APPROVER_TRUST = "REF_TARGET_NO_APPROVER_TRUST";
const GRANT_CLAIM_PREFIX = "grant:";

export interface ReplayCache { checkAndClaim(id: string, notAfter: Date | null, now: Date): boolean }

export class InMemoryReplayCache implements ReplayCache {
  private seen = new Map<string, Date | null>();
  checkAndClaim(id: string, notAfter: Date | null, now: Date): boolean {
    for (const [k, exp] of this.seen) if (exp !== null && exp.getTime() <= now.getTime()) this.seen.delete(k);
    if (this.seen.has(id)) return false;
    this.seen.set(id, notAfter);
    return true;
  }
}

export interface ConsumerOptions {
  targetId: string;
  record: PolicyPin;                       // the live pin (a validated record or the policy's pin)
  pinnedPublicKeys?: KeyMap;
  keyRecordView?: KeyRecordView;
  approverPublicKeys?: KeyMap;
  replayCache?: ReplayCache;
  clockSkewMs?: number;
  executorSigningKey?: KeyObject;
  executorKeyId?: string;
}

export class Consumer {
  readonly targetId: string;
  readonly replayCache: ReplayCache;
  private readonly opts: ConsumerOptions;

  constructor(opts: ConsumerOptions) {
    if (!opts.record) throw new Error("supply record (the live policy pin)");
    if (!opts.pinnedPublicKeys && !opts.keyRecordView) throw new Error("supply issuer-key trust: pinnedPublicKeys or keyRecordView");
    if ((opts.executorSigningKey === undefined) !== (opts.executorKeyId === undefined)) throw new Error("supply executorSigningKey and executorKeyId together");
    if ((opts.clockSkewMs ?? 0) < 0) throw new Error("clockSkewMs must be non-negative");
    this.opts = opts;
    this.targetId = opts.targetId;
    this.replayCache = opts.replayCache ?? new InMemoryReplayCache();
  }

  get attests(): boolean { return this.opts.executorSigningKey !== undefined; }

  private approverKeys(gateKeyId: unknown, now: Date): KeyMap {
    const view = this.opts.keyRecordView;
    if (view) {
      const out: KeyMap = {};
      const skew = this.opts.clockSkewMs ?? 0;
      for (const [id, e] of Object.entries(view)) {
        if (id === gateKeyId || e.role !== "approver" || e.revoked) continue;
        const t = now.getTime();
        if (!(e.notBefore.getTime() - skew <= t && t < e.notAfter.getTime() + skew)) continue;
        out[id] = e.publicKey;
      }
      return out;
    }
    return { ...(this.opts.approverPublicKeys ?? {}) };
  }

  /** Decide whether to honor `envelope` for `call`; the caller runs the side effect only on honored. */
  check(envelope: unknown, call: Call, opts: { grant?: unknown; now?: Date } = {}): Verdict {
    const now = opts.now ?? new Date();
    const skew = this.opts.clockSkewMs ?? 0;
    const keys = this.opts.pinnedPublicKeys ?? (this.opts.keyRecordView ? undefined : {});
    const result = verifyEnvelope(envelope, call, this.targetId, {
      recordSource: this.opts.record, pinnedPublicKeys: keys, keyRecordView: this.opts.keyRecordView, now, clockSkewMs: skew,
    });
    if (!result.accepted) return result;
    const env = envelope as Envelope;
    const decisionId = env.decision_id;
    if (typeof decisionId !== "string" || !decisionId) return { accepted: false, reason: REF_TARGET_NO_DECISION_ID };

    if (env.requires_approval) {
      if (asGrantList(opts.grant).length === 0) return { accepted: false, reason: REF_TARGET_APPROVAL_REQUIRED };
      const approvers = this.approverKeys(env.issuer_key_id, now);
      if (Object.keys(approvers).length === 0) return { accepted: false, reason: REF_TARGET_NO_APPROVER_TRUST };
      // One grant or several: the receipt's own terms say how many distinct approvers, and which.
      const g = verifyGrants(opts.grant, { envelope: env, approverPublicKeys: approvers, now, clockSkewMs: skew });
      if (!g.accepted) return { accepted: false, reason: g.reason };
      for (const grant of g.grants) {
        const gexp = parseAware(grant.not_after);
        if (!this.replayCache.checkAndClaim(GRANT_CLAIM_PREFIX + (grant.grant_id as string), gexp && new Date(gexp.getTime() + skew), now)) {
          return { accepted: false, reason: REF_APPROVAL_REPLAY };
        }
      }
    }
    const exp = parseAware(env.not_after);
    if (!this.replayCache.checkAndClaim(decisionId, exp && new Date(exp.getTime() + skew), now)) {
      return { accepted: false, reason: REF_VERIFY_REPLAY };
    }
    return result;
  }

  /** The signed execution receipt for a call this consumer honored and the caller has run. */
  attest(envelope: Envelope, outputs: Json, executedAt?: string): ExecutionReceipt {
    if (!this.attests) throw new Error("this consumer has no executor signing key; cannot attest");
    return signExecutionReceipt(buildExecutionReceipt({ envelope, outputs, executedAt }),
                                this.opts.executorSigningKey!, this.opts.executorKeyId!);
  }
}
