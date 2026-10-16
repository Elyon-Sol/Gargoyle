"""The decision interface, and the reference manifest policy.

Gargoyle does not decide whether a call is allowed. A Policy does. Gargoyle
asks the policy, records which policy answered (its pin), and turns an
ELIGIBLE answer into a signed, single-use receipt. A receipt stays valid only
while the policy that issued it is unchanged: when the live pin differs from
the pin in the receipt, the receipt must be re-evaluated (envelope.reassert).

A policy is any object with two methods:

    pin()                          -> {"policy_id": str, "policy_sha256": str}
    decide(target_url, interaction) -> Decision

`policy_id` names the decision logic and its version (for example
"opa:payments/2" or "gargoyle.manifest-subset/1"). `policy_sha256` is the
SHA-256 of the configuration the logic ran on (a manifest file, an OPA
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

ManifestPolicy is the reference implementation: a JSON manifest names the
authority tokens (AR) and operation tokens (R) a call must declare, the call
declares its tokens (AP, OP), and the call is ELIGIBLE when AP covers AR and
OP covers R. The tokens are caller-asserted claims and the policy ignores
tool, args and principal. Use it for tests and examples, and put a real
policy engine behind the Policy interface for anything else.
"""

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Protocol, runtime_checkable

ELIGIBLE = "ELIGIBLE"
REFUSE = "REFUSE"

MANIFEST_POLICY_ID = "gargoyle.manifest-subset/1"

# ManifestPolicy refusal reasons: a closed set naming the FIRST failing check.
POLICY_MALFORMED = "POLICY_MALFORMED"                    # manifest unreadable or ill-formed
REQUIRED_SETS_UNRESOLVED = "REQUIRED_SETS_UNRESOLVED"    # unknown or malformed interaction_type
AUTHORITY_MISSING = "AUTHORITY_MISSING"                  # AP does not cover AR
COVERAGE_MISSING = "COVERAGE_MISSING"                    # OP does not cover R
POLICY_PIN_MISMATCH = "POLICY_PIN_MISMATCH"              # caller expected another manifest
POLICY_INTERNAL = "POLICY_INTERNAL"                      # fail-closed catch-all


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


# ---------------------------------------------------------------------------
# Manifest helpers (pure; used by ManifestPolicy, impact and the MCP server)
# ---------------------------------------------------------------------------


def load_manifest(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def manifest_sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def safe_set(value):
    """A list of strings as a set, else None. Never coerces (a dict, a string
    or a list with a non-string member is malformed, not iterable input)."""
    if not isinstance(value, list):
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return set(value)


def safe_manifest(manifest):
    """Return the manifest if well-formed, else None (fail closed).

    Required: string lists AR and R, string version. Optional
    `interaction_types`: a map of type name -> {AR, R, high_impact} where
    (a) each type's tokens are a subset of the top-level AR u R vocabulary,
    (b) high_impact is an explicit boolean, and (c) high_impact matches
    whether the type's tokens intersect the manifest's HIGH_IMPACT set (that
    last check is skipped when HIGH_IMPACT is absent or malformed, which
    impact.safe_high_impact already fails closed on)."""
    if not isinstance(manifest, dict):
        return None

    AR = manifest.get("AR")
    R = manifest.get("R")
    version = manifest.get("version")

    if safe_set(AR) is None or safe_set(R) is None:
        return None
    if not isinstance(version, str):
        return None

    types = manifest.get("interaction_types")
    if types is not None:
        if not isinstance(types, dict):
            return None
        vocab = set(AR) | set(R)
        hi_raw = manifest.get("HIGH_IMPACT")
        hi_set = safe_set(hi_raw) if isinstance(hi_raw, list) else None
        for name, spec in types.items():
            if not isinstance(name, str) or not isinstance(spec, dict):
                return None
            tAR = safe_set(spec.get("AR"))
            tR = safe_set(spec.get("R"))
            if tAR is None or tR is None:
                return None
            ttok = tAR | tR
            if not ttok <= vocab:
                return None  # (a) type token outside the manifest vocabulary
            flag = spec.get("high_impact")
            if not isinstance(flag, bool):
                return None  # (b) explicit boolean required
            if hi_set is not None and bool(ttok & hi_set) != flag:
                return None  # (c) mislabeled type

    return manifest


def resolve_required_sets(manifest, interaction):
    """(AR, R) the call must cover, selected by its declared interaction_type.

    No `interaction_types` in the manifest, or no type declared by the call:
    the top-level sets. Under a typed manifest that default is the full
    vocabulary, which makes an undeclared call high-impact (fail toward
    oversight). An unknown or malformed declared type: (None, None) -> REFUSE.
    Assumes `manifest` passed safe_manifest."""
    types = manifest.get("interaction_types")
    if not isinstance(types, dict):
        return manifest.get("AR"), manifest.get("R")
    itype = interaction.get("interaction_type") if isinstance(interaction, Mapping) else None
    if itype is None:
        return manifest.get("AR"), manifest.get("R")
    spec = types.get(itype)
    if not isinstance(spec, dict):
        return None, None
    return spec.get("AR"), spec.get("R")


def authority_covered(interaction, AR) -> bool:
    """AP (the call's declared authorities) is a superset of AR."""
    AP_set = safe_set(interaction.get("AP"))
    AR_set = safe_set(AR)
    if AP_set is None or AR_set is None:
        return False
    return AP_set >= AR_set


def coverage_covered(interaction, R) -> bool:
    """OP (the call's declared operations) is a superset of R."""
    OP_set = safe_set(interaction.get("OP"))
    R_set = safe_set(R)
    if OP_set is None or R_set is None:
        return False
    return OP_set >= R_set


def manifest_pin_matches(interaction, manifest, live_sha256) -> bool:
    """The call's expected_manifest_version / expected_manifest_sha256 name
    the manifest actually loaded. Both are caller-asserted: this lets a caller
    refuse to be evaluated against a manifest it did not expect."""
    expected_version = interaction.get("expected_manifest_version")
    actual_version = manifest.get("version")
    if not isinstance(expected_version, str) or not isinstance(actual_version, str):
        return False
    if expected_version != actual_version:
        return False
    expected_sha = interaction.get("expected_manifest_sha256")
    return isinstance(expected_sha, str) and expected_sha == live_sha256


# ---------------------------------------------------------------------------
# ManifestPolicy
# ---------------------------------------------------------------------------


class ManifestPolicy:
    """The reference policy: token-subset checks against a JSON manifest.

    `path` is the manifest the deployer chose; there is no default, so no
    policy is ever evaluated against a file nobody named. The manifest is
    read from `path` on every call, so editing the file
    changes the pin immediately and invalidates receipts issued under the old
    bytes. The checks run in a fixed order and the first failure is the
    refusal reason: manifest well-formed, required sets resolvable, authority
    covered, operations covered, caller's manifest pin matches."""

    def __init__(self, path: str) -> None:
        if not isinstance(path, str) or not path:
            raise ValueError("ManifestPolicy needs the path of its manifest")
        self.path = path

    def pin(self) -> Dict[str, str]:
        return {"policy_id": MANIFEST_POLICY_ID, "policy_sha256": manifest_sha256(self.path)}

    def decide(self, target_url: str, interaction: Mapping[str, Any]) -> Decision:
        # Imported here: impact depends on this module's helpers.
        from gargoyle.impact import requires_approval

        try:
            if not isinstance(interaction, Mapping):
                return refuse(POLICY_MALFORMED)
            with open(self.path, "rb") as f:
                raw = f.read()
            live_sha256 = hashlib.sha256(raw).hexdigest()
            manifest = safe_manifest(json.loads(raw.decode("utf-8")))
            if manifest is None:
                return refuse(POLICY_MALFORMED)

            AR, R = resolve_required_sets(manifest, interaction)
            if AR is None or R is None:
                return refuse(REQUIRED_SETS_UNRESOLVED)
            if not authority_covered(interaction, AR):
                return refuse(AUTHORITY_MISSING)
            if not coverage_covered(interaction, R):
                return refuse(COVERAGE_MISSING)
            if not manifest_pin_matches(interaction, manifest, live_sha256):
                return refuse(POLICY_PIN_MISMATCH)

            return Decision(ELIGIBLE, None, requires_approval(dict(interaction), manifest))
        except Exception:
            return refuse(POLICY_INTERNAL)


def evaluate(interaction, policy: Policy, target_url: str = "") -> str:
    """The bare outcome string for `interaction` under `policy`."""
    return policy.decide(target_url, interaction).outcome
