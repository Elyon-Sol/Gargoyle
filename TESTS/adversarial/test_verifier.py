"""
Canon-derived tests for IMPLEMENTATION/verifier.py.

The verifier (VL-037) is the first G4 build increment per
docs/restructure/08_enforcement_design.md section 8 step 1. These tests
derive from canon section 13 (revalidation; eligibility does not
persist) and canon section 11.1 (interaction identity I = (A, S, C, t)),
plus artifact 08 sections 4.2 (the Q5 authenticity-vs-binding split),
4.4 (the A1 floor), 7 (the reassert() replay/binding gap), and 8 (the
named test set). Each test docstring cites its source.

The verifier composes two existing pieces and adds one new check:
  - envelope.reassert() (canon section 13; artifact 05 reassertion
    protocol) for currency + integrity, and
  - a request_context-vs-live-interaction binding check (canon section
    11.1; artifact 08 sections 4.2 / 7) that reassert() does not perform.

Fixtures duplicate the build_envelope helpers from test_envelope.py /
test_ccs_canonical.py per the established self-contained adversarial
test-file precedent. _rehash_decision_sha256 is used by the
reassert-row tests that forge a non-decision_sha256 field, so the
forgery does not trip Row 2 (decision_sha256 verification) before
reaching the row under test.

Per VL-037 opener constraint (i): no hash-value pinning; the expected
manifest sha is computed live via manifest_sha256(), and envelopes are
built with a pinned timestamp_utc for determinism.

Ledger: VL-037 (target-side verifier; first G4 build increment).
"""

import hashlib

from IMPLEMENTATION.envelope import (
    INVALIDATED,
    REASSERTED,
    RE_EVALUATE_REQUIRED,
    build_envelope,
    canonical_json,
)
from IMPLEMENTATION.evaluator import load_manifest, manifest_sha256
from IMPLEMENTATION.verifier import (
    ACCEPT_REASSERTED_AND_BOUND,
    REF_VERIFY_BINDING_MISMATCH,
    REF_VERIFY_ENVELOPE_ABSENT,
    REF_VERIFY_REASSERT_INVALIDATED,
    REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED,
    verify_envelope,
)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

TARGET_URL = "http://127.0.0.1:9000/target"


def _normalized_interaction(ap=None, op=None, context=None):
    """
    A normalized_interaction matching validate_request()'s return shape.
    AP/OP default to the manifest-satisfying sets, already sorted (as
    validate_request would leave them). expected_manifest_sha256 is
    computed live.
    """
    return {
        "AP": ["identity", "role"] if ap is None else ap,
        "OP": ["session", "request"] if op is None else op,
        "context": {} if context is None else context,
        "expected_manifest_version": "1.0",
        "expected_manifest_sha256": manifest_sha256(),
    }


def _build_valid_envelope(interaction=None, target_url=TARGET_URL,
                          timestamp_utc="2026-05-21T00:00:00+00:00"):
    """Build an envelope against current repo state with all flags true."""
    if interaction is None:
        interaction = _normalized_interaction()
    return build_envelope(
        decision="ELIGIBLE",
        target_url=target_url,
        normalized_interaction=interaction,
        manifest=load_manifest(),
        ac3=True,
        t26=True,
        manifest_integrity=True,
        timestamp_utc=timestamp_utc,
    )


def _rehash_decision_sha256(envelope):
    """
    Re-compute decision_sha256 over the envelope minus decision_sha256
    and timestamp_utc (matching build_envelope's exclusions), so a
    forged non-decision_sha256 field stays internally consistent and the
    intended reassert() row fires instead of Row 2.
    """
    hashable = {
        k: v
        for k, v in envelope.items()
        if k not in ("decision_sha256", "timestamp_utc")
    }
    envelope["decision_sha256"] = hashlib.sha256(
        canonical_json(hashable).encode("utf-8")
    ).hexdigest()
    return envelope


# ---------------------------------------------------------------------------
# Accept path
# ---------------------------------------------------------------------------


def test_verify_accepts_valid_current_bound_envelope():
    """
    Canon section 13: "Eligibility does not persist across state
    transitions without revalidation." REASSERTED is the only state in
    which a past ELIGIBLE may be honored without re-evaluation; combined
    with the section 11.1 interaction-identity binding (the envelope is
    about this exact interaction), the verifier accepts.

    A valid envelope built against current state, presented with the
    matching live interaction and target_url, is accepted.
    """
    interaction = _normalized_interaction()
    env = _build_valid_envelope(interaction=interaction)
    result = verify_envelope(env, interaction, TARGET_URL)
    assert result["accepted"] is True
    assert result["reason"] == ACCEPT_REASSERTED_AND_BOUND


# ---------------------------------------------------------------------------
# reassert() currency/integrity rejects (closes A2 + state transitions)
# ---------------------------------------------------------------------------


def test_verify_rejects_forged_envelope_tamper():
    """
    Artifact 08 section 4.2: envelope authenticity is closed by the
    mechanism; a fabricated/mutated envelope fails decision_sha256 and
    reassert() Row 2 returns INVALIDATED (canon section 12.3/12.4
    fail-closed, operationalized via artifact-05-layer tamper
    detection). This is adversary A2 (forgery).

    Mutate a request_context field WITHOUT re-hashing decision_sha256:
    the stored hash no longer matches the body, so reassert() returns
    INVALIDATED and the verifier rejects.
    """
    env = _build_valid_envelope()
    env["request_context"]["AP"] = ["identity", "role", "admin"]
    result = verify_envelope(env, _normalized_interaction(), TARGET_URL)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_REASSERT_INVALIDATED


def test_verify_rejects_canon_change_invalidated():
    """
    Canon section 12.1 (a state transition is any change in the pinned
    state) + 12.4 (invalid transition without revalidation -> CCS = 0).
    A canon hash that no longer matches live canon means the envelope
    predates the current rules; reassert() Row 1 returns INVALIDATED.

    Forge canon_sha256 and re-hash decision_sha256 (so Row 2 does not
    fire first); the verifier rejects with the INVALIDATED reason.
    """
    env = _build_valid_envelope()
    env["canon"]["canon_sha256"] = "0" * 64
    _rehash_decision_sha256(env)
    result = verify_envelope(env, _normalized_interaction(), TARGET_URL)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_REASSERT_INVALIDATED


def test_verify_rejects_evaluator_change_re_evaluate():
    """
    Canon section 12.4: a changed evaluator hash is a decision-logic
    transition; reassert() Row 3 returns RE-EVALUATE-REQUIRED. The
    verifier surfaces it as REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED.

    Forge evaluator_sha256 and re-hash decision_sha256; the verifier
    rejects.
    """
    env = _build_valid_envelope()
    env["evaluator"]["evaluator_sha256"] = "0" * 64
    _rehash_decision_sha256(env)
    result = verify_envelope(env, _normalized_interaction(), TARGET_URL)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED


def test_verify_rejects_manifest_change_re_evaluate():
    """
    Canon section 11.9 (manifest is versioned + integrity-verifiable) +
    12.4 (governing manifest version change is an invalid transition).
    A changed manifest hash triggers reassert() Row 4
    RE-EVALUATE-REQUIRED.

    Forge evaluated_against.manifest_sha256 and re-hash decision_sha256;
    the verifier rejects.
    """
    env = _build_valid_envelope()
    env["evaluated_against"]["manifest_sha256"] = "0" * 64
    _rehash_decision_sha256(env)
    result = verify_envelope(env, _normalized_interaction(), TARGET_URL)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED


# ---------------------------------------------------------------------------
# Presence rejects (no usable decision artifact)
# ---------------------------------------------------------------------------


def test_verify_rejects_absent_envelope():
    """
    Artifact 08 section 8 (named test: "rejects an absent envelope").
    Canon section 13: with no decision artifact there is nothing to
    revalidate. A None envelope rejects with REF_VERIFY_ENVELOPE_ABSENT.
    This is the verifier-side face of adversary A1 (a call arriving with
    no attestation).
    """
    result = verify_envelope(None, _normalized_interaction(), TARGET_URL)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_ENVELOPE_ABSENT


def test_verify_rejects_malformed_envelope_without_raising():
    """
    Artifact 08 section 8 (named test: "rejects an absent envelope" -
    extended here to malformed). A dict missing the required structure
    must reject cleanly via the presence guard, NOT raise from inside
    reassert()'s key accesses.

    An empty dict and a partially-structured dict both reject with
    REF_VERIFY_ENVELOPE_ABSENT.
    """
    result_empty = verify_envelope({}, _normalized_interaction(), TARGET_URL)
    assert result_empty["accepted"] is False
    assert result_empty["reason"] == REF_VERIFY_ENVELOPE_ABSENT

    # request_context present but missing its sub-keys.
    partial = {
        "canon": {},
        "evaluator": {},
        "evaluated_against": {},
        "request_context": {"AP": ["identity"]},
        "decision_sha256": "0" * 64,
        "target_url": TARGET_URL,
    }
    result_partial = verify_envelope(partial, _normalized_interaction(), TARGET_URL)
    assert result_partial["accepted"] is False
    assert result_partial["reason"] == REF_VERIFY_ENVELOPE_ABSENT


# ---------------------------------------------------------------------------
# Binding rejects (closes A3 - replay across interactions / target)
# ---------------------------------------------------------------------------


def test_verify_rejects_replay_binding_mismatch():
    """
    THE load-bearing A3 case. Artifact 08 section 7: reassert() checks
    repository-state currency, not interaction binding, so a genuine,
    current envelope for interaction X REASSERTS even when presented
    alongside a different interaction Y. Canon section 13's
    per-interaction non-persistence is broader than reassert()'s
    hash-based transition detection; the binding check (canon section
    11.1 interaction identity) is what closes the gap.

    Build a genuine envelope for interaction X (AP = identity, role),
    then verify it against live interaction Y (AP additionally includes
    admin). reassert() would REASSERT (no state change), but the binding
    check rejects with REF_VERIFY_BINDING_MISMATCH.
    """
    interaction_x = _normalized_interaction(ap=["identity", "role"])
    env = _build_valid_envelope(interaction=interaction_x)
    interaction_y = _normalized_interaction(ap=["identity", "role", "admin"])
    result = verify_envelope(env, interaction_y, TARGET_URL)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_BINDING_MISMATCH


def test_verify_rejects_target_url_mismatch():
    """
    Artifact 08 section 4.2: target_url is inside the signed region and
    part of the binding obligation. A genuine, current envelope issued
    for target_url X, presented for a forward to target_url Y, REASSERTS
    but fails the binding check.

    Same interaction, mismatched target_url -> REF_VERIFY_BINDING_MISMATCH.
    """
    interaction = _normalized_interaction()
    env = _build_valid_envelope(interaction=interaction, target_url=TARGET_URL)
    result = verify_envelope(env, interaction, "http://127.0.0.1:9000/other")
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_BINDING_MISMATCH


def test_verify_accepts_under_ap_op_normalization():
    """
    Normalization parity (artifact 08 gap candidate 2 / VL-037 opener
    constraint (f)). request_validator._normalize_set_field sorts and
    deduplicates AP/OP; build_envelope records the normalized lists. The
    verifier must normalize the live interaction the same way so a caller
    presenting an unsorted or duplicated AP/OP does not cause a false
    reject.

    The envelope is built from the normalized interaction; the live
    interaction passes the same sets unsorted and with a duplicate. The
    verifier accepts.
    """
    env_interaction = _normalized_interaction(
        ap=["identity", "role"], op=["request", "session"]
    )
    env = _build_valid_envelope(interaction=env_interaction)
    # Live interaction: same sets, unsorted, with a duplicate.
    live = _normalized_interaction(
        ap=["role", "identity", "role"], op=["session", "request"]
    )
    result = verify_envelope(env, live, TARGET_URL)
    assert result["accepted"] is True
    assert result["reason"] == ACCEPT_REASSERTED_AND_BOUND


def test_verify_context_binding():
    """
    Canon section 11.1 C (context) is part of the interaction identity;
    artifact 08 section 4.2 includes context in the binding obligation.
    The verifier compares context by canonical_json equality (artifact
    08 gap candidate 1 [INFERENCE]).

    Equal context accepts; differing context rejects with
    REF_VERIFY_BINDING_MISMATCH (the envelope admitted a different
    interaction).
    """
    ctx = {"purpose": "demo", "tier": 1}
    interaction = _normalized_interaction(context=ctx)
    env = _build_valid_envelope(interaction=interaction)

    # Same context value (different key insertion order) accepts.
    same_ctx_other_order = _normalized_interaction(context={"tier": 1, "purpose": "demo"})
    accepted = verify_envelope(env, same_ctx_other_order, TARGET_URL)
    assert accepted["accepted"] is True
    assert accepted["reason"] == ACCEPT_REASSERTED_AND_BOUND

    # Different context value rejects.
    different_ctx = _normalized_interaction(context={"purpose": "demo", "tier": 2})
    rejected = verify_envelope(env, different_ctx, TARGET_URL)
    assert rejected["accepted"] is False
    assert rejected["reason"] == REF_VERIFY_BINDING_MISMATCH
