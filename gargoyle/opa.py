"""A Policy backed by Open Policy Agent: the allow/deny decision comes from
a real policy engine, and the receipt pins the exact policy set OPA held.

    from gargoyle.opa import OpaPolicy
    policy = OpaPolicy("http://127.0.0.1:8181", "gargoyle/decision")
    result = issue(policy, target_url, interaction, signing_key=key, key_id=kid)

decide() POSTs the interaction as `input` to /v1/data/<decision_path> and
reads OPA's `result`:

    true                                          -> ELIGIBLE
    {"allow": true, "requires_approval": bool?,   -> ELIGIBLE (held iff
     "reason": str?}                                 requires_approval is true)
    false, {"allow": false, ...}, undefined, or
    anything else                                 -> REFUSE

A rule like this is enough:

    package gargoyle
    default decision := {"allow": false, "reason": "DEFAULT_DENY"}
    decision := {"allow": true, "requires_approval": input.tool == "transfer_funds"} {
        input.principal == "spiffe://example.org/agents/payments"
        input.tool in {"read_balance", "transfer_funds"}
    }

pin() reads every policy module OPA holds (GET /v1/policies) and hashes
their ids and raw text, so `policy_sha256` changes whenever a module is
added, removed or edited, and every receipt issued under the old set stops
being honored (RE-EVALUATE-REQUIRED) until it is decided again.
`policy_id` is "opa:<decision_path>" unless the deployer names it.

Fail closed: OPA unreachable, a non-200, a body that is not JSON, an
undefined result (no `result` key), or a result in no recognized shape is a
REFUSE with a reason naming the failure, never an ELIGIBLE. A policy that
cannot be pinned raises from pin(), which the issuer turns into a refusal.
`requires_approval` is taken only as an explicit boolean; anything else
holds the call (fail toward oversight).
"""

import hashlib
from typing import Any, Dict, Mapping, Optional

import requests

from gargoyle.envelope import canonical_json
from gargoyle.policy import ELIGIBLE, Decision, refuse

OPA_UNAVAILABLE = "OPA_UNAVAILABLE"      # transport failure, non-200, non-JSON body
OPA_UNDEFINED = "OPA_UNDEFINED"          # the decision document is undefined
OPA_DENIED = "OPA_DENIED"                # the policy said no and gave no reason
OPA_UNRECOGNIZED_RESULT = "OPA_UNRECOGNIZED_RESULT"  # a result in no known shape


class OpaPolicy:
    def __init__(
        self,
        url: str,
        decision_path: str,
        *,
        policy_id: Optional[str] = None,
        session: Optional[Any] = None,
        timeout: float = 5.0,
    ) -> None:
        if not isinstance(url, str) or not url or not isinstance(decision_path, str) or not decision_path:
            raise ValueError("OpaPolicy needs OPA's base URL and the decision document path")
        self.url = url.rstrip("/")
        self.decision_path = decision_path.strip("/")
        self.policy_id = policy_id or "opa:" + self.decision_path
        self._session = session if session is not None else requests.Session()
        self.timeout = timeout

    def pin(self) -> Dict[str, str]:
        """{"policy_id", "policy_sha256"}: the SHA-256 over the canonical JSON
        of [[id, raw], ...] for every module OPA holds, sorted by id."""
        response = self._session.get(self.url + "/v1/policies", timeout=self.timeout)
        if response.status_code != 200:
            raise RuntimeError("OPA /v1/policies returned %s" % response.status_code)
        modules = response.json().get("result")
        if not isinstance(modules, list):
            raise RuntimeError("OPA /v1/policies returned no module list")
        digest_input = sorted(
            [str(m.get("id")), str(m.get("raw"))] for m in modules if isinstance(m, dict)
        )
        sha = hashlib.sha256(canonical_json(digest_input).encode("utf-8")).hexdigest()
        return {"policy_id": self.policy_id, "policy_sha256": sha}

    def decide(self, target_url: str, interaction: Mapping[str, Any]) -> Decision:
        try:
            if not isinstance(interaction, Mapping):
                return refuse(OPA_UNRECOGNIZED_RESULT)
            body = {"input": {**dict(interaction), "target_url": target_url}}
            response = self._session.post(
                self.url + "/v1/data/" + self.decision_path, json=body, timeout=self.timeout
            )
            if response.status_code != 200:
                return refuse(OPA_UNAVAILABLE)
            document = response.json()
        except Exception:
            return refuse(OPA_UNAVAILABLE)
        if not isinstance(document, dict) or "result" not in document:
            return refuse(OPA_UNDEFINED)
        result = document["result"]
        if result is True:
            return Decision(ELIGIBLE)
        if result is False:
            return refuse(OPA_DENIED)
        if isinstance(result, dict) and isinstance(result.get("allow"), bool):
            reason = result.get("reason")
            reason = reason if isinstance(reason, str) and reason else None
            if not result["allow"]:
                return refuse(reason or OPA_DENIED)
            hold = result.get("requires_approval", False)
            required = result.get("approvals_required", 1)
            approvers = result.get("approvers")
            if (isinstance(required, bool) or not isinstance(required, int) or required < 1
                    or (approvers is not None and (not isinstance(approvers, list) or not approvers
                                                   or not all(isinstance(a, str) and a for a in approvers)))):
                return refuse(OPA_UNRECOGNIZED_RESULT)
            # Only an explicit false frees the call; anything else holds it.
            if hold is False:
                return Decision(ELIGIBLE)
            return Decision(ELIGIBLE, None, True, required, tuple(approvers) if approvers else None)
        return refuse(OPA_UNRECOGNIZED_RESULT)
