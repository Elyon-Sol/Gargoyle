"""Scoped grants: one approval for a bounded plan, every step still bound.

A card per held call is right for a mailbox rule and wrong for the
twentieth cell edit of a reconciliation. A plan lets the assistant say
what it intends to do, as a list of steps, and lets a human approve that
scope once. Each step is a tool plus either the exact arguments (bound by
hash) or argument patterns (globs on string arguments). The issuer judges
every step under the policy, signs the plan with its pin and an expiry,
and holds it like a flagged receipt; the approver's grant covers the
plan's hash. Later, each flagged receipt for a call that matches an
unconsumed step is released by the plan: the step is claimed once in the
replay store, the receipt once as always.

What a plan trades: the approver sees scope, not content. The policy
therefore decides which tools may be planned (`"plan": false` on a hold
rule keeps them individual; sends should stay individual), and the
evidence records, for every plan-released call, the plan, the step, and
the arguments, so an audit can re-run the match offline.

    plan = {
      "plan_version": "gargoyle-plan/1",
      "plan_id": ..., "approval_request_id": ...,
      "target_url": ..., "principal": ...,
      "policy": {policy_id, policy_sha256},
      "steps": [{"tool": ..., "args_sha256": <hex>} | {"tool": ..., "match": {<arg>: <glob>}}],
      "approval": {"required": n, "approvers": [...]}?,
      "note": <the assistant's stated purpose>,
      "not_after": ...,
      "plan_sha256": sha256(canonical_json(plan minus plan_sha256, issuer_key_id, issuer_signature)),
      "issuer_key_id": ..., "issuer_signature": ...
    }
    release = {"plan": plan, "grants": [grant...], "step": i, "args": <the call's arguments>}
"""

import fnmatch
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from gargoyle.approval import as_grant_list, verify_grant, verify_role_attestation
from gargoyle.globs import glob_match
from gargoyle.envelope import approval_terms, args_sha256, canonical_json, valid_approval
from gargoyle.verifier import not_after_valid

PLAN_VERSION = "gargoyle-plan/1"
_HASH_EXCLUDED = ("plan_sha256", "issuer_key_id", "issuer_signature")
_SIGNATURE_EXCLUDED = ("issuer_signature",)

REF_PLAN_MALFORMED = "REF_PLAN_MALFORMED"
REF_PLAN_KEY_UNKNOWN = "REF_PLAN_KEY_UNKNOWN"
REF_PLAN_SIGNATURE_INVALID = "REF_PLAN_SIGNATURE_INVALID"
REF_PLAN_EXPIRED = "REF_PLAN_EXPIRED"
REF_PLAN_BINDING_MISMATCH = "REF_PLAN_BINDING_MISMATCH"      # not this principal, target or policy
REF_PLAN_NO_MATCHING_STEP = "REF_PLAN_NO_MATCHING_STEP"
REF_PLAN_STEP_CONSUMED = "REF_PLAN_STEP_CONSUMED"
REF_PLAN_STEP_REFUSED = "REF_PLAN_STEP_REFUSED"              # issuer: the policy refused a step
REF_PLAN_STEP_NOT_PLANNABLE = "REF_PLAN_STEP_NOT_PLANNABLE"  # issuer: the rule keeps that tool individual
REF_PLAN_GRANTS = "REF_PLAN_GRANTS"                          # the grants do not release this plan (reason in detail)
REF_PLAN_TERMS_WEAKER = "REF_PLAN_TERMS_WEAKER"              # the plan's grants do not meet the receipt's own approval terms
REF_PLAN_RECEIPT_NOT_PLANNABLE = "REF_PLAN_RECEIPT_NOT_PLANNABLE"  # the receipt says this call is approved individually
ACCEPT_PLAN_RELEASE = "PLAN_RELEASE"


def valid_step(step: Any) -> bool:
    if not isinstance(step, dict) or not isinstance(step.get("tool"), str) or not step["tool"]:
        return False
    if "args_sha256" in step:
        return (set(step) == {"tool", "args_sha256"} and isinstance(step["args_sha256"], str)
                and len(step["args_sha256"]) == 64)
    if "match" in step:
        m = step["match"]
        return (set(step) == {"tool", "match"} and isinstance(m, dict) and bool(m)
                and all(isinstance(k, str) and k and isinstance(v, str) for k, v in m.items()))
    return False


def plan_sha256_of(plan: Dict[str, Any]) -> str:
    body = {k: v for k, v in plan.items() if k not in _HASH_EXCLUDED}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def build_plan(*, plan_id: str, approval_request_id: str, target_url: str, principal: str, policy_pin: Dict[str, str],
               steps: List[Dict[str, Any]], not_after: datetime, note: str = "",
               approval: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not steps or not all(valid_step(s) for s in steps):
        raise ValueError("steps must be a non-empty list of {tool, args_sha256} or {tool, match}")
    if not_after.tzinfo is None:
        raise ValueError("not_after must be timezone-aware")
    if approval is not None and not valid_approval(approval):
        raise ValueError("approval must be {'required': int >= 1, 'approvers'?: [...], 'roles'?: [...]}")
    plan: Dict[str, Any] = {
        "plan_version": PLAN_VERSION, "plan_id": plan_id, "approval_request_id": approval_request_id,
        "target_url": target_url, "principal": principal,
        "policy": {"policy_id": policy_pin["policy_id"], "policy_sha256": policy_pin["policy_sha256"]},
        "steps": [dict(s) for s in steps], "note": note, "not_after": not_after.isoformat(),
    }
    if approval is not None:
        plan["approval"] = {"required": approval["required"], **({"approvers": sorted(approval["approvers"])} if "approvers" in approval else {}),
                            **({"roles": sorted(approval["roles"])} if "roles" in approval else {})}
    plan["plan_sha256"] = plan_sha256_of(plan)
    return plan


def sign_plan(plan: Dict[str, Any], signing_key: Any, key_id: str) -> Dict[str, Any]:
    signed = dict(plan, issuer_key_id=key_id)
    region = {k: v for k, v in signed.items() if k not in _SIGNATURE_EXCLUDED}
    signed["issuer_signature"] = signing_key.sign(canonical_json(region).encode("utf-8")).hex()
    return signed


def verify_plan(plan: Any, *, issuer_public_keys: Dict[str, Any], now: Optional[datetime] = None,
                clock_skew: timedelta = timedelta(0)) -> Dict[str, Any]:
    """Structure, issuer signature, hash, expiry. Pure."""
    required = ("plan_version", "plan_id", "approval_request_id", "target_url", "principal", "policy", "steps",
                "note", "not_after", "plan_sha256", "issuer_key_id", "issuer_signature")
    if not isinstance(plan, dict) or any(k not in plan for k in required) or plan["plan_version"] != PLAN_VERSION:
        return {"accepted": False, "reason": REF_PLAN_MALFORMED}
    if (not isinstance(plan["steps"], list) or not plan["steps"] or not all(valid_step(s) for s in plan["steps"])
            or ("approval" in plan and not valid_approval(plan["approval"]))
            or not isinstance(plan["principal"], str) or not plan["principal"]):
        return {"accepted": False, "reason": REF_PLAN_MALFORMED}
    key = issuer_public_keys.get(plan["issuer_key_id"]) if isinstance(plan["issuer_key_id"], str) else None
    if key is None:
        return {"accepted": False, "reason": REF_PLAN_KEY_UNKNOWN}
    region = {k: v for k, v in plan.items() if k not in _SIGNATURE_EXCLUDED}
    try:
        key.verify(bytes.fromhex(plan["issuer_signature"]), canonical_json(region).encode("utf-8"))
    except Exception:
        return {"accepted": False, "reason": REF_PLAN_SIGNATURE_INVALID}
    if plan_sha256_of(plan) != plan["plan_sha256"]:
        return {"accepted": False, "reason": REF_PLAN_SIGNATURE_INVALID}
    if not not_after_valid(plan["not_after"], now=now, clock_skew=clock_skew):
        return {"accepted": False, "reason": REF_PLAN_EXPIRED}
    return {"accepted": True, "reason": "PLAN_VALID"}


def step_matches(step: Dict[str, Any], tool: str, args: Any) -> bool:
    if step.get("tool") != tool:
        return False
    if "args_sha256" in step:
        try:
            return args_sha256(args) == step["args_sha256"]
        except (TypeError, ValueError):
            return False
    if not isinstance(args, dict):
        return False
    for key, glob in step["match"].items():
        value = args.get(key)
        if not isinstance(value, str) or not glob_match(glob, value):
            return False
    return True


def match_step(plan: Dict[str, Any], tool: str, args: Any, consumed: Any = ()) -> Optional[int]:
    """The first unconsumed step the call matches, or None."""
    for i, step in enumerate(plan.get("steps", [])):
        if i in consumed:
            continue
        if step_matches(step, tool, args):
            return i
    return None


def verify_plan_release(release: Any, envelope: Dict[str, Any], call: Dict[str, Any], *,
                        issuer_public_keys: Dict[str, Any], approver_public_keys: Dict[str, Any],
                        now: Optional[datetime] = None, clock_skew: timedelta = timedelta(0)) -> Dict[str, Any]:
    """Does `release` ({"plan", "grants", "step", "args"?}) release `envelope`
    for `call`? Checks, first failure wins: the plan verifies; it names this
    receipt's principal, target and policy pin; the step exists and matches
    the call (`call["args"]`, or release["args"] when the auditor has no
    live call); the grants release the plan under its own approval terms.
    Single use of the step is the caller's claim (plan_id:step). Pure."""
    if not isinstance(release, dict) or not isinstance(release.get("plan"), dict) or not isinstance(release.get("step"), int):
        return {"accepted": False, "reason": REF_PLAN_MALFORMED}
    plan = release["plan"]
    v = verify_plan(plan, issuer_public_keys=issuer_public_keys, now=now, clock_skew=clock_skew)
    if not v["accepted"]:
        return v
    rc = envelope.get("request_context") or {}
    if (plan["principal"] != rc.get("principal") or plan["target_url"] != envelope.get("target_url")
            or plan["policy"] != envelope.get("policy")):
        return {"accepted": False, "reason": REF_PLAN_BINDING_MISMATCH}
    # The receipt's own terms come first: a call the policy keeps individual
    # is never released by a plan, whatever the plan says.
    env_terms = approval_terms(envelope)
    if not env_terms.get("plannable", True):
        return {"accepted": False, "reason": REF_PLAN_RECEIPT_NOT_PLANNABLE}
    i = release["step"]
    if i < 0 or i >= len(plan["steps"]):
        return {"accepted": False, "reason": REF_PLAN_NO_MATCHING_STEP}
    args = call.get("args") if isinstance(call, dict) and "args" in call else release.get("args")
    if args is None or rc.get("tool") != plan["steps"][i]["tool"] or not step_matches(plan["steps"][i], rc.get("tool"), args):
        return {"accepted": False, "reason": REF_PLAN_NO_MATCHING_STEP}
    try:
        if args_sha256(args) != rc.get("args_sha256"):
            return {"accepted": False, "reason": REF_PLAN_NO_MATCHING_STEP}
    except (TypeError, ValueError):
        return {"accepted": False, "reason": REF_PLAN_NO_MATCHING_STEP}
    # The grants release the plan: same checks as a receipt's grant set, with
    # the plan's hash and hold id and the plan's approval terms.
    terms = plan.get("approval") or {"required": 1}
    seen: List[str] = []
    for grant in as_grant_list(release.get("grants")):
        g = verify_grant(grant, expected_decision_sha256=plan["plan_sha256"], expected_approval_request_id=plan["approval_request_id"],
                         approver_public_keys=approver_public_keys, gate_key_id=plan.get("issuer_key_id"), now=now, clock_skew=clock_skew)
        if not g["accepted"]:
            return {"accepted": False, "reason": g["reason"]}
        kid = grant["approver_key_id"]
        if kid in seen or (terms.get("approvers") and kid not in terms["approvers"]):
            return {"accepted": False, "reason": REF_PLAN_GRANTS}
        if terms.get("roles"):
            r = verify_role_attestation(grant, required_roles=terms["roles"], issuer_public_keys=issuer_public_keys,
                                        gate_key_id=plan.get("issuer_key_id"))
            if not r["accepted"]:
                return {"accepted": False, "reason": r["reason"]}
        seen.append(kid)
    if len(seen) < terms.get("required", 1):
        return {"accepted": False, "reason": REF_PLAN_GRANTS}
    # And the receipt's own signed terms: the plan's grants must be at least
    # as many, from the receipt's named approvers if it names any. A plan
    # approved by one junior never releases a two-signature finance write.
    if not grants_satisfy(env_terms, seen):
        return {"accepted": False, "reason": REF_PLAN_TERMS_WEAKER}
    if env_terms.get("roles"):
        # A receipt routed to a role is released by a plan only through
        # grants the issuer attested for that role (checked above when the
        # plan names roles; here against the receipt's own, which may differ).
        for kid in seen:
            att = next((g for g in as_grant_list(release.get("grants")) if g.get("approver_key_id") == kid), None)
            r = verify_role_attestation(att, required_roles=env_terms["roles"], issuer_public_keys=issuer_public_keys,
                                        gate_key_id=plan.get("issuer_key_id"))
            if not r["accepted"]:
                return {"accepted": False, "reason": REF_PLAN_TERMS_WEAKER}
    return {"accepted": True, "reason": ACCEPT_PLAN_RELEASE, "step": i}


def grants_satisfy(terms: Dict[str, Any], approver_key_ids: Any) -> bool:
    """Do these distinct approver ids meet `terms` ({"required", "approvers"})?"""
    named = terms.get("approvers")
    eligible = {k for k in approver_key_ids if named is None or k in named}
    return len(eligible) >= int(terms.get("required", 1))


def is_plan_release(grant: Any) -> bool:
    return isinstance(grant, dict) and "plan" in grant and "step" in grant
