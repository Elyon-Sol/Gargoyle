"""Execution receipts: the executor's signed statement of what actually ran.

An authorization receipt (gargoyle.envelope) says a policy allowed one call.
An execution receipt says that call ran, once, and what came out:

    execution = {
        "execution_version": "gargoyle-execution/1",
        "decision_id":        <the authorization receipt's decision_id>,
        "decision_sha256":    <its decision hash>,
        "policy":             <its policy pin: which policy version allowed this>,
        "target_url":         <its target>,
        "request_context":    <its {tool, args_sha256, principal}>,
        "outputs_sha256":     sha256(canonical_json(outputs)),
        "executed_at":        <timestamp>,
        "executor_key_id":    ..., "executor_signature": ...
    }

The executor copies the bound fields out of the receipt it honored and
signs the lot together with the outputs hash, so the two receipts chain on
decision_id and decision_sha256 and the execution receipt carries, inside
its own signature, the policy pin that authorized the run. An auditor with
the issuer's, approver's and executor's public keys can later check, with
no network and no live state (verify_chain):

    1. the authorization receipt was well-formed, issuer-signed and unexpired
       at executed_at (verifier.verify_provenance);
    2. if it was flagged, a trusted approver's grant released exactly it
       (approval.verify_grant);
    3. the execution receipt is executor-signed and binds to that receipt
       field for field, and to the outputs when they are supplied.

What this does not prove: that the side effect happened as the outputs
claim (the executor is trusted for that, as it is for everything else it
runs), or that no other execution receipt exists for the same decision_id
(single use is the replay cache's guarantee at execution time; an evidence
log is the place to prove it afterwards).
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from gargoyle.approval import verify_grant
from gargoyle.envelope import args_sha256, canonical_json
from gargoyle.verifier import verify_provenance

EXECUTION_VERSION = "gargoyle-execution/1"

# Refusal codes.
REF_EXEC_MALFORMED = "REF_EXEC_MALFORMED"                  # not an execution receipt
REF_EXEC_KEY_UNKNOWN = "REF_EXEC_KEY_UNKNOWN"              # executor key not trusted
REF_EXEC_SIGNATURE_INVALID = "REF_EXEC_SIGNATURE_INVALID"
REF_EXEC_BINDING_MISMATCH = "REF_EXEC_BINDING_MISMATCH"    # does not describe this authorization
REF_EXEC_OUTPUTS_MISMATCH = "REF_EXEC_OUTPUTS_MISMATCH"    # supplied outputs hash differently
# verify_chain: a flagged receipt with no grant to check.
REF_EXEC_GRANT_MISSING = "REF_EXEC_GRANT_MISSING"

ACCEPT_EXECUTION_BOUND = "EXECUTION_BOUND"
ACCEPT_CHAIN_VERIFIED = "CHAIN_VERIFIED"

# Copied from the authorization receipt, so the execution receipt names
# exactly what was authorized.
_BOUND_FROM_RECEIPT = ("decision_id", "decision_sha256", "policy", "target_url", "request_context")
_REQUIRED_KEYS = ("execution_version", *_BOUND_FROM_RECEIPT, "outputs_sha256",
                  "executed_at", "executor_key_id", "executor_signature")
_SIGNATURE_EXCLUDED_KEYS = ("executor_signature",)


def _reject(reason: str) -> Dict[str, Any]:
    return {"accepted": False, "reason": reason}


def _accept(reason: str) -> Dict[str, Any]:
    return {"accepted": True, "reason": reason}


def build_execution_receipt(
    *,
    envelope: Dict[str, Any],
    outputs: Any,
    executed_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """The unsigned execution receipt for a call the executor has just run
    under `envelope` (a receipt it honored, so decision_id is present) with
    `outputs` (any JSON value; only its hash is recorded). `executed_at`
    must be timezone-aware; it defaults to now."""
    if not isinstance(envelope, dict):
        raise TypeError("envelope must be the honored authorization receipt")
    for key in _BOUND_FROM_RECEIPT:
        if key not in envelope:
            raise KeyError(key)
    if not isinstance(envelope["decision_id"], str) or not envelope["decision_id"]:
        raise ValueError("the honored receipt must carry a decision_id")
    if executed_at is None:
        executed_at = datetime.now(timezone.utc)
    if executed_at.tzinfo is None:
        raise ValueError("executed_at must be timezone-aware (UTC)")
    return {
        "execution_version": EXECUTION_VERSION,
        "decision_id": envelope["decision_id"],
        "decision_sha256": envelope["decision_sha256"],
        "policy": dict(envelope["policy"]),
        "target_url": envelope["target_url"],
        "request_context": dict(envelope["request_context"]),
        "outputs_sha256": args_sha256(outputs),
        "executed_at": executed_at.isoformat(),
    }


def sign_execution_receipt(execution: Dict[str, Any], signing_key: Any, key_id: str) -> Dict[str, Any]:
    """A signed copy (the input is not modified). The signature covers
    everything but itself, executed_at included: when it ran is evidence."""
    signed = dict(execution)
    signed["executor_key_id"] = key_id
    region = {k: v for k, v in signed.items() if k not in _SIGNATURE_EXCLUDED_KEYS}
    signed["executor_signature"] = signing_key.sign(canonical_json(region).encode("utf-8")).hex()
    return signed


def verify_execution_receipt(
    execution: Any,
    envelope: Dict[str, Any],
    executor_public_keys: Dict[str, Any],
    *,
    outputs: Any = None,
    check_outputs: bool = False,
) -> Dict[str, Any]:
    """Is `execution` the executor's genuine statement that `envelope`'s
    call ran? Checks, first failure wins: structure (REF_EXEC_MALFORMED),
    a trusted executor key (REF_EXEC_KEY_UNKNOWN), the signature
    (REF_EXEC_SIGNATURE_INVALID), field-for-field binding to `envelope`
    (REF_EXEC_BINDING_MISMATCH), and, with check_outputs, that `outputs`
    hash to outputs_sha256 (REF_EXEC_OUTPUTS_MISMATCH). Pure."""
    if not isinstance(execution, dict) or not isinstance(envelope, dict):
        return _reject(REF_EXEC_MALFORMED)
    for key in _REQUIRED_KEYS:
        if key not in execution:
            return _reject(REF_EXEC_MALFORMED)
    if execution["execution_version"] != EXECUTION_VERSION:
        return _reject(REF_EXEC_MALFORMED)
    key_id, signature_hex = execution["executor_key_id"], execution["executor_signature"]
    if not isinstance(key_id, str) or not isinstance(signature_hex, str):
        return _reject(REF_EXEC_MALFORMED)
    if not isinstance(executor_public_keys, dict):
        return _reject(REF_EXEC_KEY_UNKNOWN)
    public_key = executor_public_keys.get(key_id)
    if public_key is None:
        return _reject(REF_EXEC_KEY_UNKNOWN)
    region = {k: v for k, v in execution.items() if k not in _SIGNATURE_EXCLUDED_KEYS}
    try:
        public_key.verify(bytes.fromhex(signature_hex), canonical_json(region).encode("utf-8"))
    except Exception:
        return _reject(REF_EXEC_SIGNATURE_INVALID)
    for key in _BOUND_FROM_RECEIPT:
        if key not in envelope or canonical_json(execution[key]) != canonical_json(envelope[key]):
            return _reject(REF_EXEC_BINDING_MISMATCH)
    if check_outputs:
        try:
            if args_sha256(outputs) != execution["outputs_sha256"]:
                return _reject(REF_EXEC_OUTPUTS_MISMATCH)
        except (TypeError, ValueError):
            return _reject(REF_EXEC_OUTPUTS_MISMATCH)
    return _accept(ACCEPT_EXECUTION_BOUND)


def verify_chain(
    envelope: Any,
    execution: Any,
    *,
    issuer_public_keys: Dict[str, Any],
    executor_public_keys: Dict[str, Any],
    grant: Any = None,
    approver_public_keys: Optional[Dict[str, Any]] = None,
    outputs: Any = None,
    check_outputs: bool = False,
) -> Dict[str, Any]:
    """Offline, stateless audit of one call: authorization, release (if
    flagged) and execution, each signed by a different key. `now` for the
    receipt's and grant's expiry is the execution receipt's executed_at,
    because what matters is that they were valid when the call ran.
    Returns {"accepted", "reason", "steps": [...]}, the steps naming each
    check's result so an auditor sees where a chain breaks."""
    steps = []
    if not isinstance(execution, dict) or not isinstance(execution.get("executed_at"), str):
        return {"accepted": False, "reason": REF_EXEC_MALFORMED, "steps": steps}
    try:
        executed_at = datetime.fromisoformat(execution["executed_at"])
        if executed_at.tzinfo is None:
            raise ValueError("naive")
    except (ValueError, TypeError):
        return {"accepted": False, "reason": REF_EXEC_MALFORMED, "steps": steps}

    provenance = verify_provenance(envelope, pinned_public_keys=issuer_public_keys, now=executed_at)
    steps.append(("authorization", provenance["reason"]))
    if not provenance["accepted"]:
        return {"accepted": False, "reason": provenance["reason"], "steps": steps}

    if envelope["requires_approval"]:
        if grant is None:
            steps.append(("approval", REF_EXEC_GRANT_MISSING))
            return {"accepted": False, "reason": REF_EXEC_GRANT_MISSING, "steps": steps}
        g = verify_grant(
            grant,
            expected_decision_sha256=envelope["decision_sha256"],
            expected_approval_request_id=envelope["approval_request_id"],
            approver_public_keys=approver_public_keys or {},
            gate_key_id=envelope.get("issuer_key_id"),
            now=executed_at,
        )
        steps.append(("approval", g["reason"]))
        if not g["accepted"]:
            return {"accepted": False, "reason": g["reason"], "steps": steps}

    e = verify_execution_receipt(execution, envelope, executor_public_keys,
                                 outputs=outputs, check_outputs=check_outputs)
    steps.append(("execution", e["reason"]))
    if not e["accepted"]:
        return {"accepted": False, "reason": e["reason"], "steps": steps}
    return {"accepted": True, "reason": ACCEPT_CHAIN_VERIFIED, "steps": steps}
