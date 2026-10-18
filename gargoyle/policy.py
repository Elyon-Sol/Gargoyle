"""The decision interface.

Gargoyle does not decide whether a call is allowed. A Policy does. Gargoyle
asks the policy, records which policy answered (its pin), and turns an
ELIGIBLE answer into a signed, single-use receipt. A receipt stays valid only
while the policy that issued it is unchanged: when the live pin differs from
the pin in the receipt, the receipt must be re-evaluated (envelope.reassert).

A policy is any object with two methods:

    pin()                          -> {"policy_id": str, "policy_sha256": str}
    decide(target_url, interaction) -> Decision

`policy_id` names the decision logic and its version (for example
"opa:payments/2" or "gargoyle.rules/1"). `policy_sha256` is the
SHA-256 of the configuration the logic ran on (a rules file, an OPA
bundle, a Cedar policy set). Change either and every outstanding receipt
issued under the old pin stops being honored. An integrator wrapping a
policy engine computes both from whatever identifies that engine's state.

Policies must be fail-closed: any exception inside decide() is treated by the
issuer as REFUSE, and an implementation should prefer REFUSE over guessing.

The interaction a policy sees is the call the receipt will bind ("tool",
"args", "principal", with principal the identity the issuing service
authenticated) plus whatever claims the integrator attaches for the policy.
A policy may decide on any of it; the receipt records only the call and the
policy pin.

Two policies ship: gargoyle.rules.RulesPolicy (a JSON rules file) and
gargoyle.opa.OpaPolicy (Open Policy Agent). Any object with the two methods
is a policy.
"""

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Protocol, runtime_checkable

ELIGIBLE = "ELIGIBLE"
REFUSE = "REFUSE"

POLICY_INTERNAL = "POLICY_INTERNAL"   # the policy raised: fail closed


@dataclass(frozen=True)
class Decision:
    """A policy's answer. `reason` names why on REFUSE. `requires_approval`
    asks the issuer's caller to hold the call for a human-signed grant
    (gargoyle.approval) before presenting the receipt."""

    outcome: str
    reason: Optional[str] = None
    requires_approval: bool = False

    @property
    def eligible(self) -> bool:
        return self.outcome == ELIGIBLE


def refuse(reason: str) -> Decision:
    return Decision(REFUSE, reason, False)


@runtime_checkable
class Policy(Protocol):
    def pin(self) -> Dict[str, str]:
        ...

    def decide(self, target_url: str, interaction: Mapping[str, Any]) -> Decision:
        ...


def valid_pin(pin: Any) -> bool:
    """True iff `pin` is a well-formed policy pin."""
    return (
        isinstance(pin, dict)
        and isinstance(pin.get("policy_id"), str)
        and bool(pin["policy_id"])
        and isinstance(pin.get("policy_sha256"), str)
        and len(pin["policy_sha256"]) == 64
    )


def evaluate(interaction, policy: Policy, target_url: str = "") -> str:
    """The bare outcome string for `interaction` under `policy`."""
    return policy.decide(target_url, interaction).outcome
