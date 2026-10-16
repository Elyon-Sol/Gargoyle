"""The decision interface: ManifestPolicy, and issuing receipts from any Policy."""

import json
import shutil
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.envelope import RE_EVALUATE_REQUIRED, REASSERTED, reassert
from gargoyle.issuer import (
    DEFAULT_TTL_SECONDS,
    ISSUE_POLICY_ERROR,
    ISSUE_UNBINDABLE_CALL,
    issue,
)
from gargoyle.policy import (
    AUTHORITY_MISSING,
    COVERAGE_MISSING,
    ELIGIBLE,
    MANIFEST_POLICY_ID,
    POLICY_INTERNAL,
    POLICY_MALFORMED,
    POLICY_PIN_MISMATCH,
    REFUSE,
    REQUIRED_SETS_UNRESOLVED,
    Decision,
    ManifestPolicy,
    Policy,
    authority_covered,
    coverage_covered,
    load_manifest,
    manifest_pin_matches,
    manifest_sha256,
)
from gargoyle.verifier import ACCEPT_REASSERTED_AND_BOUND, verify_envelope

SHA = manifest_sha256()
TARGET = "https://target.example.com/act"


def call(**over):
    base = {
        "tool": "t",
        "args": {"k": 1},
        "principal": "agent-7",
        "AP": ["identity", "role"],
        "OP": ["session", "request"],
        "expected_manifest_version": "1.0",
        "expected_manifest_sha256": SHA,
    }
    base.update(over)
    return base


def bound(interaction):
    """What a target sees of `interaction`: the three fields a receipt binds."""
    return {k: interaction[k] for k in ("tool", "args", "principal")}


# ---------------------------------------------------------------------------
# Subset checks
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fn,key,required", [
    (authority_covered, "AP", ["identity", "role"]),
    (coverage_covered, "OP", ["session", "request"]),
])
def test_subset_checks(fn, key, required):
    a, b = required
    assert fn({key: [a, b]}, required) is True                    # equal
    assert fn({key: [b, a, "extra", "more"]}, required) is True   # superset, any order
    assert fn({key: [a, a, b]}, required) is True                 # duplicates collapse
    assert fn({key: [a]}, required) is False                      # missing one
    assert fn({key: []}, required) is False                       # empty
    assert fn({key: [a, b]}, []) is True                          # nothing required
    for bad in (f"{a},{b}", 42, [[a], [b]], None, {a: True, b: True}):
        assert fn({key: bad}, required) is False                  # never coerced
    assert fn({}, required) is False                              # absent


def test_manifest_pin_match_and_mismatch():
    m = load_manifest()
    assert manifest_pin_matches(call(), m, SHA) is True
    assert manifest_pin_matches(call(expected_manifest_version="2.0"), m, SHA) is False
    assert manifest_pin_matches(call(expected_manifest_sha256="0" * 64), m, SHA) is False
    for key in ("expected_manifest_version", "expected_manifest_sha256"):
        c = call(); del c[key]
        assert manifest_pin_matches(c, m, SHA) is False


# ---------------------------------------------------------------------------
# ManifestPolicy.decide
# ---------------------------------------------------------------------------

CASES = [
    ("eligible", call(), ELIGIBLE, None),
    ("superset_extra_tokens", call(AP=["identity", "role", "admin"], OP=["session", "request", "x"]), ELIGIBLE, None),
    ("ap_missing", {k: v for k, v in call().items() if k != "AP"}, REFUSE, AUTHORITY_MISSING),
    ("op_missing", {k: v for k, v in call().items() if k != "OP"}, REFUSE, COVERAGE_MISSING),
    ("ap_partial", call(AP=["role"]), REFUSE, AUTHORITY_MISSING),
    ("op_partial", call(OP=["session"]), REFUSE, COVERAGE_MISSING),
    ("ap_string", call(AP="identity,role"), REFUSE, AUTHORITY_MISSING),
    ("ap_dict", call(AP={"identity": True, "role": True}), REFUSE, AUTHORITY_MISSING),
    ("ap_nested", call(AP=[["identity"], ["role"]]), REFUSE, AUTHORITY_MISSING),
    ("ap_lookalike_unicode", call(AP=["identity", "rol\u0435"]), REFUSE, AUTHORITY_MISSING),
    ("ap_case", call(AP=["Identity", "Role"]), REFUSE, AUTHORITY_MISSING),
    ("ap_whitespace", call(AP=["identity ", " role"]), REFUSE, AUTHORITY_MISSING),
    ("ap_duplicates_only", call(AP=["identity", "identity"]), REFUSE, AUTHORITY_MISSING),
    ("version_drift", call(expected_manifest_version="2.0"), REFUSE, POLICY_PIN_MISMATCH),
    ("version_float", call(expected_manifest_version=1.0), REFUSE, POLICY_PIN_MISMATCH),
    ("version_whitespace", call(expected_manifest_version="1.0 "), REFUSE, POLICY_PIN_MISMATCH),
    ("sha_wrong", call(expected_manifest_sha256="0" * 64), REFUSE, POLICY_PIN_MISMATCH),
    ("sha_missing", {k: v for k, v in call().items() if k != "expected_manifest_sha256"}, REFUSE, POLICY_PIN_MISMATCH),
    ("empty", {}, REFUSE, AUTHORITY_MISSING),
    ("not_a_mapping", ["AP"], REFUSE, POLICY_MALFORMED),
]


@pytest.mark.parametrize("name,interaction,outcome,reason", CASES, ids=[c[0] for c in CASES])
def test_manifest_policy_cases(name, interaction, outcome, reason):
    d = ManifestPolicy().decide(TARGET, interaction)
    assert (d.outcome, d.reason) == (outcome, reason)


def _policy_at(tmp_path, manifest):
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps(manifest))
    return ManifestPolicy(str(p))


def test_manifest_policy_refuses_malformed_or_missing_file(tmp_path):
    assert _policy_at(tmp_path, {"AR": "identity"}).decide(TARGET, call()).reason == POLICY_MALFORMED
    assert ManifestPolicy(str(tmp_path / "absent.json")).decide(TARGET, call()).reason == POLICY_INTERNAL


def test_manifest_policy_unknown_interaction_type(tmp_path):
    m = dict(load_manifest(), interaction_types={"read": {"AR": ["identity"], "R": ["session"], "high_impact": False}})
    d = _policy_at(tmp_path, m).decide(TARGET, call(interaction_type="nope"))
    assert d.reason == REQUIRED_SETS_UNRESOLVED


def test_manifest_policy_pin_follows_the_file(tmp_path):
    p = tmp_path / "manifest.json"
    shutil.copy("MANIFEST/manifest.json", p)
    policy = ManifestPolicy(str(p))
    before = policy.pin()
    assert before == {"policy_id": MANIFEST_POLICY_ID, "policy_sha256": SHA}
    m = load_manifest(); m["AR"] = m["AR"] + ["admin"]
    p.write_text(json.dumps(m))
    assert policy.pin()["policy_sha256"] != before["policy_sha256"]
    # The caller's old pin no longer matches, and the new required token is enforced.
    assert policy.decide(TARGET, call()).reason == AUTHORITY_MISSING


def test_manifest_policy_flags_high_impact(tmp_path):
    m = dict(load_manifest(), HIGH_IMPACT=["role"])
    policy = _policy_at(tmp_path, m)
    d = policy.decide(TARGET, call(expected_manifest_sha256=policy.pin()["policy_sha256"]))
    assert d.eligible and d.requires_approval is True


def test_manifest_policy_satisfies_the_protocol():
    assert isinstance(ManifestPolicy(), Policy)


# ---------------------------------------------------------------------------
# issue()
# ---------------------------------------------------------------------------

class FixedPolicy:
    """A non-manifest policy: whatever the integrator's engine says."""

    def __init__(self, decision, pin=None):
        self.decision = decision
        self._pin = pin or {"policy_id": "engine/1", "policy_sha256": "a" * 64}

    def pin(self):
        return self._pin

    def decide(self, target_url, interaction):
        if isinstance(self.decision, Exception):
            raise self.decision
        return self.decision


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def test_issue_eligible_receipt_verifies_end_to_end(key):
    now = datetime.now(timezone.utc)
    r = issue(ManifestPolicy(), TARGET, call(), signing_key=key, key_id="k1", now=now)
    assert r.decision.eligible and r.envelope is not None
    env = r.envelope
    assert env["policy"] == ManifestPolicy().pin()
    assert env["decision_id"]
    assert datetime.fromisoformat(env["not_after"]) == now + timedelta(seconds=DEFAULT_TTL_SECONDS)
    v = verify_envelope(env, bound(call()), TARGET, pinned_public_keys={"k1": key.public_key()})
    assert (v["accepted"], v["reason"]) == (True, ACCEPT_REASSERTED_AND_BOUND)
    assert set(env["request_context"]) == {"tool", "args_sha256", "principal"}


def test_issue_gives_each_receipt_its_own_decision_id(key):
    ids = {issue(ManifestPolicy(), TARGET, call(), signing_key=key, key_id="k1").envelope["decision_id"]
           for _ in range(5)}
    assert len(ids) == 5


def test_issue_refusal_carries_no_receipt(key):
    r = issue(ManifestPolicy(), TARGET, call(AP=["role"]), signing_key=key, key_id="k1")
    assert r.envelope is None and r.decision.reason == AUTHORITY_MISSING


def test_issue_from_a_custom_policy_and_pin_change_invalidates(key):
    policy = FixedPolicy(Decision(ELIGIBLE))
    r = issue(policy, TARGET, call(), signing_key=key, key_id="k1")
    assert r.envelope["policy"] == {"policy_id": "engine/1", "policy_sha256": "a" * 64}
    assert reassert(r.envelope, policy=policy)["outcome"] == REASSERTED
    policy._pin = {"policy_id": "engine/1", "policy_sha256": "b" * 64}   # the engine's bundle changed
    assert reassert(r.envelope, policy=policy)["outcome"] == RE_EVALUATE_REQUIRED


@pytest.mark.parametrize("policy,reason", [
    (FixedPolicy(RuntimeError("engine down")), POLICY_INTERNAL),
    (FixedPolicy("ELIGIBLE"), ISSUE_POLICY_ERROR),                               # not a Decision
    (FixedPolicy(Decision(ELIGIBLE), pin={"policy_id": "x"}), ISSUE_POLICY_ERROR),  # malformed pin
])
def test_issue_fails_closed_on_a_misbehaving_policy(key, policy, reason):
    r = issue(policy, TARGET, call(), signing_key=key, key_id="k1")
    assert r.envelope is None and r.decision.outcome == REFUSE and r.decision.reason == reason


@pytest.mark.parametrize("unbindable", [
    {"tool": "t"},                                      # no args, no principal
    {"tool": "t", "args": {}},                          # no principal
    {"tool": "t", "args": {}, "principal": ""},         # nobody
    {"tool": "", "args": {}, "principal": "agent-7"},   # no tool
    {"tool": "t", "args": object(), "principal": "agent-7"},  # unserializable args
])
def test_issue_refuses_an_eligible_call_it_cannot_bind(key, unbindable):
    r = issue(FixedPolicy(Decision(ELIGIBLE)), TARGET, unbindable, signing_key=key, key_id="k1")
    assert r.envelope is None and r.decision.reason == ISSUE_UNBINDABLE_CALL


def test_issue_surfaces_requires_approval(key):
    r = issue(FixedPolicy(Decision(ELIGIBLE, requires_approval=True)), TARGET, call(), signing_key=key, key_id="k1")
    assert r.decision.requires_approval is True and r.envelope is not None


@pytest.mark.parametrize("ttl", [0, -1, 1.5, True, None])
def test_issue_rejects_unbounded_or_bad_ttl(key, ttl):
    with pytest.raises(ValueError):
        issue(ManifestPolicy(), TARGET, call(), signing_key=key, key_id="k1", ttl_seconds=ttl)


def test_issue_requires_a_key():
    with pytest.raises(ValueError):
        issue(ManifestPolicy(), TARGET, call(), signing_key=None, key_id="k1")
