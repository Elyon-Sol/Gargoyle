"""
Canon-derived tests for IMPLEMENTATION/envelope.py.

Each test cites a specific clause of CANON/canon.md (whitepaper
v0.9.8.4) in its docstring and verifies envelope.py's behavior
against that clause. Companion file
TESTS/adversarial/test_envelope.py is spec-derived (cites
docs/restructure/05_admissibility_envelope_spec.md).

This file is the G7 partial-closure signal for the envelope domain:
tests derived from the canon, not from the code. A reader of
canon section 12 can verify that envelope.py honors the canonical
CCS invariant by reading this file's docstrings against
CANON/canon.md, without having to read envelope.py itself.

Per VL-028 session opener constraint (e): "Each test's docstring
quotes or paraphrases a specific canon section 12 clause (or, for
Row 2 per Decision B, the post-VL-026 spec's Row 2 Canon basis
wording). The Bundle B verifier-runs' per-branch citations
[recorded in EVIDENCE/verification_ledger.md VL-025 follow-up] are
the authoritative starting point but each test docstring must
still cite the canon clause directly, not the verifier-run by
reference."

Canon-citation set (Lesson 5 set-exhaustiveness, enumerated
against the VL-025 follow-up Bundle B verifier-runs and verified
against CANON/canon.md):

  - canon 12.1 "state transition S_t -> S_{t+1}" -> test 1
  - canon 12.3 "continuity constraint; d_{t+1} = u_{t+1} AND
    c_{t+1}" -> test 2 (first-issuance None); xfail tests 1 and 2
    (forward-looking derivation rule on REASSERTED)
  - canon 12.4 "failure condition; if any condition is violated:
    CCS = 0; governing manifest version change / role or authority
    schema change as invalid transitions" -> test 3 (evaluator
    change); xfail tests 2 and 3 (forward-looking derivation rule
    on INVALIDATED / RE-EVALUATE-REQUIRED)
  - canon 11.9 "the manifest must be deterministic, versioned, and
    integrity-verifiable" -> test 4 (manifest change), jointly with
    canon 12.4
  - canon 13 "Eligibility does not persist across state transitions
    without revalidation" -> test 5

Row 2 (decision_sha256 verification -> INVALIDATED) is included
per VL-028 opener Decision B with an explicit artifact-05-layer
acknowledgment in the docstring -- canon section 12.3/12.4
authorize the fail-closed semantics; the specific tamper-detection
mechanism is artifact-05-layer per post-VL-026 Edit 4.

xfail-history (resolved at VL-029): three tests were xfail-marked
at VL-028 (per the then-VL-028 opener Decision A and constraint (k))
awaiting envelope.py's implementation of the post-VL-026 spec's
forward-looking ccs-derivation rule (Open question 1 resolution).
At VL-028, reassert() returned a bare string outcome; the xfail
tests asserted against a then-provisional dict-shaped return
{"outcome": ..., "ccs": ...}. VL-029 locked the dict shape per
Decision A; the xfail markers were removed in the same commit.

Ledger: VL-028 (canon-derived half of G7 envelope-domain partial
closure); VL-029 (envelope.py ccs-derivation rule implementation +
xfail-marker removal).
"""

import hashlib

import pytest

from IMPLEMENTATION.envelope import (
    INVALIDATED,
    REASSERTED,
    RE_EVALUATE_REQUIRED,
    build_envelope,
    canonical_json,
    reassert,
)
from IMPLEMENTATION.evaluator import load_manifest, manifest_sha256


# ---------------------------------------------------------------------------
# Fixture builders (duplicated from test_envelope.py per the established
# precedent of self-contained adversarial test files; see
# test_request_schema.py for the same pattern)
# ---------------------------------------------------------------------------


def _normalized_interaction():
    """A valid normalized_interaction matching validate_request()'s return."""
    return {
        "AP": ["identity", "role"],
        "OP": ["session", "request"],
        "context": {},
        "expected_manifest_version": "1.0",
        "expected_manifest_sha256": manifest_sha256(),
    }


def _build_valid_envelope(timestamp_utc="2026-05-21T00:00:00+00:00"):
    """Build an envelope against current repo state with all flags true."""
    return build_envelope(
        decision="ELIGIBLE",
        target_url="http://127.0.0.1:9000/target",
        normalized_interaction=_normalized_interaction(),
        manifest=load_manifest(),
        ac3=True,
        t26=True,
        manifest_integrity=True,
        timestamp_utc=timestamp_utc,
    )


def _rehash_decision_sha256(envelope):
    """
    Re-compute decision_sha256 over the envelope minus decision_sha256
    and timestamp_utc, matching build_envelope's exclusion list. Used
    when forging a non-decision_sha256 field so the forgery does not
    trip the Row 2 (decision_sha256 verification) branch before
    reaching the row under test.
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
# Canon-derived tests (non-xfail)
# ---------------------------------------------------------------------------


def test_canon_12_1_state_transition_detected_via_hash_change():
    """
    Canon section 12.1: "S_t -> S_{t+1}. A transition occurs on any
    change in interaction context, authority, coverage, or system
    state."

    The envelope pins the system-state-defining hashes (canon, manifest,
    evaluator) so a hash mismatch IS a section-12.1 transition. Verified
    by forging canon_sha256 (a section-12.1 system-state change) and
    confirming reassert() detects the transition and refuses to reassert
    -- specifically, returning INVALIDATED per artifact 05's
    reassertion-protocol Row 1.

    Per VL-025 follow-up Bundle B verifier-run convergence: Row 1
    (canon hash mismatch) is a section-12.1 transition jointly with
    section 12.4 (invalid transition without revalidation).
    """
    env = _build_valid_envelope()
    env["canon"]["canon_sha256"] = "0" * 64
    _rehash_decision_sha256(env)
    assert reassert(env)["outcome"] == INVALIDATED


def test_canon_12_3_d_consistency_first_issuance_null():
    """
    Canon section 12.3: "CCS(S_t, S_{t+1}, I) = 1 iff: authority
    transitions are justified by AC^3(I); coverage transitions are
    justified by T^26(I); decision consistency holds:
    d_{t+1} = u_{t+1} AND c_{t+1}."

    Section 12.3 defines CCS as a transition relation over S_t and
    S_{t+1}; on first issuance there is no prior S_t to transition
    from, so section 12.3 is inapplicable rather than violated. Per
    VL-025 follow-up Bundle B verifier-run convergence on the
    first-issuance treatment, and per post-VL-026 Open question 1
    resolution naming Python None (JSON null) as the explicit
    first-issuance sentinel, build_envelope() records
    condition_results.ccs as None on first issuance.
    """
    env = _build_valid_envelope()
    assert env["condition_results"]["ccs"] is None


def test_canon_12_4_evaluator_change_invalidates_continuity():
    """
    Canon section 12.4: "If any condition is violated: CCS = 0. Any
    transition that alters authority, coverage, or decision state
    without valid re-evaluation constitutes a continuity violation.
    Examples of invalid transitions include: governing manifest
    version change, role or authority schema change, identity or
    mapping inconsistency."

    The evaluator code is the locus of decision logic; a changed
    evaluator hash represents a section-12.4-class transition (the
    decision logic itself moved). Per artifact 05 reassertion-protocol
    Row 3, this triggers RE-EVALUATE-REQUIRED rather than silent
    fallthrough to REASSERTED.

    VL-024 Implication 2 (the evaluator-versioning fail-closed
    posture) was carried as inference at VL-023 follow-up; VL-025
    converted the inference to direct citation in code at reassert()
    Row 3; VL-025 follow-up Bundle B verifier-run convergence
    confirmed the canon section-12.4 authorization is direct, not
    inferred. This test instantiates the converted citation.
    """
    env = _build_valid_envelope()
    env["evaluator"]["evaluator_sha256"] = "0" * 64
    _rehash_decision_sha256(env)
    assert reassert(env)["outcome"] == RE_EVALUATE_REQUIRED


def test_canon_11_9_manifest_change_invalidates_continuity():
    """
    Canon section 11.9: "The manifest must be deterministic, versioned,
    and integrity-verifiable." Canon section 12.4 lists "governing
    manifest version change" as an explicit example of an invalid
    transition.

    A changed manifest hash represents a joint section-11.9 / section-
    12.4 transition: the manifest's integrity-verifiability is what
    makes the hash-comparison meaningful (11.9), and a hash change
    instantiates the canonical example of an invalid transition
    (12.4). Per artifact 05 reassertion-protocol Row 4, the envelope
    returns RE-EVALUATE-REQUIRED.

    Per VL-025 follow-up Bundle B verifier-run: section 11.9 was
    added by OpenAI to the Row 4 citation as a refinement; the
    joint section-11.9 + section-12.4 reading is the converged
    citation across both Bundle B verifiers.
    """
    env = _build_valid_envelope()
    env["evaluated_against"]["manifest_sha256"] = "0" * 64
    _rehash_decision_sha256(env)
    assert reassert(env)["outcome"] == RE_EVALUATE_REQUIRED


def test_canon_13_eligibility_does_not_persist():
    """
    Canon section 13: "Eligibility does not persist across state
    transitions without revalidation."

    The envelope's reassertion protocol operationalizes section 13:
    REASSERTED is the only outcome under which a past ELIGIBLE may
    be honored without re-evaluation, and REASSERTED is returned
    only when every hash-pinned state component (canon, manifest,
    evaluator) is unchanged AND the envelope's own integrity
    (decision_sha256) verifies. Any state transition (canon /
    manifest / evaluator change) or any tamper (decision_sha256
    verification failure) produces a non-REASSERTED outcome,
    forcing revalidation per section 13.

    Verified by building an unmodified envelope against current
    state and confirming reassert() returns REASSERTED -- the only
    state in which section 13's "without revalidation" exception
    applies.
    """
    env = _build_valid_envelope()
    assert reassert(env)["outcome"] == REASSERTED


def test_row_2_tamper_detection_via_artifact_05_mechanism():
    """
    Post-VL-026 artifact 05 reassertion-protocol table Row 2 Canon
    basis: "sections 12.3/12.4 fail-closed semantics, operationalized
    via artifact-05-layer tamper detection."

    Per VL-028 opener Decision B: Row 2 is included in this canon-
    derived test file with explicit artifact-05-layer acknowledgment
    in the docstring because the decision_sha256 verification
    mechanism is artifact-05-layer rather than directly named in
    canon. Per VL-025 follow-up Bundle B finding 5: Row 2 is
    canon-undetermined as a direct mechanism but operationally
    compatible with canon sections 12.3 (continuity requires internal
    consistency) and 12.4 (fail-closed on violation).

    Verified by mutating a body field without re-hashing
    decision_sha256, so the envelope's stored hash no longer matches
    the canonicalization of its body. reassert() detects the
    inconsistency at Row 2 and returns INVALIDATED.
    """
    env = _build_valid_envelope()
    # Mutate a body field WITHOUT re-hashing. This is the tamper
    # case: the envelope's bytes change but decision_sha256 still
    # records the pre-tamper canonicalization.
    env["request_context"]["AP"] = ["identity", "role", "admin"]
    assert reassert(env)["outcome"] == INVALIDATED


# ---------------------------------------------------------------------------
# Tests for the post-VL-026 forward-looking ccs-derivation rule
# (formerly xfail at VL-028; xpassed and marker-removed at VL-029)
#
# These three tests verify that reassert() derives condition_results.ccs
# per post-VL-026 artifact 05 Open question 1 resolution: True on
# REASSERTED, False on INVALIDATED or RE-EVALUATE-REQUIRED. The dict
# shape {"outcome": <str>, "ccs": <bool>} is locked by VL-028 Decision A
# and implemented at VL-029. xfail history per VL-028 ledger entry.
# ---------------------------------------------------------------------------


def test_canon_12_3_ccs_derived_true_on_REASSERTED():
    """
    Canon section 12.3: "decision consistency holds:
    d_{t+1} = u_{t+1} AND c_{t+1}." Per post-VL-026 artifact 05 Open
    question 1 resolution: at reassertion, reassert() derives
    condition_results.ccs as True on REASSERTED (the canon's
    d_{t+1} = u_{t+1} AND c_{t+1} holds because all hashes match
    and decision_sha256 verifies, per artifact 05 row 5).

    Implemented at VL-029 per Decision A (formerly xfail at VL-028
    awaiting envelope.py's implementation of the post-VL-026 Open
    question 1 resolution).
    """
    env = _build_valid_envelope()
    result = reassert(env)
    assert result["outcome"] == REASSERTED
    assert result["ccs"] is True


def test_canon_12_4_ccs_derived_false_on_INVALIDATED():
    """
    Canon section 12.4: "if any condition is violated: CCS = 0."
    Per post-VL-026 artifact 05 Open question 1 resolution: at
    reassertion, reassert() derives condition_results.ccs as False
    on INVALIDATED (continuity does not hold; the envelope's
    rules-of-the-game have changed or the envelope is tampered).

    Implemented at VL-029 per Decision A (formerly xfail at VL-028
    awaiting envelope.py's implementation of the post-VL-026 Open
    question 1 resolution).
    """
    env = _build_valid_envelope()
    env["canon"]["canon_sha256"] = "0" * 64
    _rehash_decision_sha256(env)
    result = reassert(env)
    assert result["outcome"] == INVALIDATED
    assert result["ccs"] is False


def test_canon_12_4_ccs_derived_false_on_RE_EVALUATE_REQUIRED():
    """
    Canon section 12.4: "if any condition is violated: CCS = 0."
    Per post-VL-026 artifact 05 Open question 1 resolution: at
    reassertion, reassert() derives condition_results.ccs as False
    on RE-EVALUATE-REQUIRED (continuity does not hold; the
    decision logic or the governing manifest has moved and
    re-evaluation is required).

    Implemented at VL-029 per Decision A (formerly xfail at VL-028
    awaiting envelope.py's implementation of the post-VL-026 Open
    question 1 resolution).
    """
    env = _build_valid_envelope()
    env["evaluator"]["evaluator_sha256"] = "0" * 64
    _rehash_decision_sha256(env)
    result = reassert(env)
    assert result["outcome"] == RE_EVALUATE_REQUIRED
    assert result["ccs"] is False
