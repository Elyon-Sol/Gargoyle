"""
Adversarial tests for IMPLEMENTATION/envelope.py.

Derived from docs/restructure/05_admissibility_envelope_spec.md (post-
VL-026, 11309 bytes). Spec-derived: each test cites a specific passage
of artifact 05. Per VL-028 session opener constraint (b), the
docstring's citation is the test's reason for existing.

Companion file TESTS/adversarial/test_ccs_canonical.py is canon-derived
(cites canon section 12 directly). The two files overlap behaviorally
on the reassertion-protocol rows but cite different sources, per the
opener's distinction: this file's tests exercise envelope.py against
artifact 05; test_ccs_canonical.py exercises envelope.py against
CANON/canon.md.

Set-exhaustiveness check (Lesson 5):
  - Envelope-structure top-level keys (enumerated against artifact 05's
    JSON block): envelope_version, decision, target_url, canon,
    evaluated_against, request_context, evaluator, condition_results,
    decision_sha256, timestamp_utc -- 10 keys. Test 1.
  - request_context sub-block keys (enumerated against artifact 05's
    JSON block): AP, OP, context, expected_manifest_version,
    expected_manifest_sha256 -- 5 keys. Test 2.
  - Reassertion-protocol table rows (enumerated against artifact 05):
    Row 1 (canon mismatch -> INVALIDATED), Row 2 (decision_sha256
    verification -> INVALIDATED), Row 3 (evaluator mismatch ->
    RE-EVALUATE-REQUIRED), Row 4 (manifest mismatch ->
    RE-EVALUATE-REQUIRED), Row 5 (all match -> REASSERTED) -- 5 rows.
    Rows 1, 3, 4, 5 covered here as tests 9, 10, 11, 8 respectively;
    Row 2 (tamper detection) is in test_ccs_canonical.py per VL-028
    opener Decision B.

Ledger: VL-028 (proposed; spec-derived half of G7 envelope-domain
partial closure).

Per VL-008 procedure adapted for tests:
  (a) Scope-bound to artifact 05 (post-VL-026) + envelope.py at HEAD.
  (b) Each test's docstring names the artifact-05 passage it cites.
  (c) Tests verify properties, not specific hash values (constraint
      (i) of VL-028 opener: no decision_sha256 value pinning).

Lesson 6 mode-discipline applied: each docstring is a claim about
what the test exercises; the test does no more than the docstring
claims and no less.
"""

import hashlib
import json

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
# Fixture builders
# ---------------------------------------------------------------------------

# Per VL-028 opener constraint (i): no hash-value pinning across
# machines. We compute the live manifest_sha256 at test setup so the
# value-tracking matches whatever MANIFEST/manifest.json is on disk.
# This mirrors the discipline in test_adversarial_evaluator.py's
# ELIGIBLE case, which pins SHA only because the evaluator's
# manifest_integrity check requires the caller to pin a value; here
# the value goes into the envelope as audit data, not into a verified
# check.


def _normalized_interaction():
    """
    A valid normalized_interaction dict matching
    IMPLEMENTATION/request_validator.py's validate_request() return
    shape (AP, OP, context, expected_manifest_version,
    expected_manifest_sha256). The expected_manifest_sha256 is computed
    live so the build_envelope() output round-trips against the on-disk
    manifest.
    """
    return {
        "AP": ["identity", "role"],
        "OP": ["session", "request"],
        "context": {},
        "expected_manifest_version": "1.0",
        "expected_manifest_sha256": manifest_sha256(),
    }


def _build_valid_envelope(timestamp_utc="2026-05-21T00:00:00+00:00"):
    """
    Build an envelope that all condition-result flags pass, against
    the live repo state. timestamp_utc is pinned by default so
    determinism tests have a stable input; tests that exercise
    timestamp_invariance pass two different values.
    """
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
    Re-compute decision_sha256 over the (possibly forged) envelope's
    fields, excluding decision_sha256 itself and timestamp_utc per
    artifact 05's decision_sha256 field rationale.

    Used by Row 1/3/4 reassertion tests, where a non-decision_sha256
    field is forged to test that the specific row fires. Without
    re-hashing, Row 2 (decision_sha256 verification) would catch the
    forgery first and the test would assert on the wrong row.
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
# Envelope structure (artifact 05 "Envelope structure" JSON block)
# ---------------------------------------------------------------------------


EXPECTED_TOP_KEYS = {
    "envelope_version",
    "decision",
    "target_url",
    "canon",
    "evaluated_against",
    "request_context",
    "evaluator",
    "condition_results",
    "decision_sha256",
    "timestamp_utc",
}

EXPECTED_REQUEST_CONTEXT_KEYS = {
    "AP",
    "OP",
    "context",
    "expected_manifest_version",
    "expected_manifest_sha256",
}


def test_build_envelope_returns_canonical_top_keys():
    """
    Per artifact 05 "Envelope structure" JSON block: the envelope dict
    has exactly the named top-level keys. The set is enumerated from
    artifact 05 directly (Lesson 5 set-exhaustiveness). 10 keys.
    """
    env = _build_valid_envelope()
    assert set(env.keys()) == EXPECTED_TOP_KEYS, (
        f"top-level key set diverges; "
        f"missing={EXPECTED_TOP_KEYS - set(env.keys())}, "
        f"extra={set(env.keys()) - EXPECTED_TOP_KEYS}"
    )


def test_build_envelope_request_context_shape():
    """
    Per artifact 05 "Envelope structure" JSON block's request_context
    sub-block: the request_context dict has exactly five keys (AP, OP,
    context, expected_manifest_version, expected_manifest_sha256). The
    `context` field absorption is per VL-020's freshness pass; the
    five-key shape is the post-VL-020 / post-VL-026 spec.
    """
    env = _build_valid_envelope()
    rc = env["request_context"]
    assert set(rc.keys()) == EXPECTED_REQUEST_CONTEXT_KEYS, (
        f"request_context key set diverges; "
        f"missing={EXPECTED_REQUEST_CONTEXT_KEYS - set(rc.keys())}, "
        f"extra={set(rc.keys()) - EXPECTED_REQUEST_CONTEXT_KEYS}"
    )


def test_build_envelope_ccs_null_on_first_issuance():
    """
    Per artifact 05 Open question 1 resolution (post-VL-026):
    "build_envelope() records condition_results.ccs as Python None
    (JSON null) on first issuance." The forward-looking ccs-derivation
    rule fires at reassertion time, not at build time; see xfail tests
    in test_ccs_canonical.py.
    """
    env = _build_valid_envelope()
    assert env["condition_results"]["ccs"] is None


def test_build_envelope_decision_sha256_format():
    """
    Per artifact 05 decision_sha256 field rationale: "tamper-evidence.
    Canonical JSON (sorted keys, no whitespace, ensure_ascii=True per
    VL-009 ASCII-safe standard)." The hash is a SHA-256 hex digest,
    which by sha256.hexdigest()'s contract is exactly 64 lowercase
    hex characters. Test verifies length and character class;
    constraint (i) of VL-028 opener forbids pinning the specific
    value.
    """
    env = _build_valid_envelope()
    digest = env["decision_sha256"]
    assert isinstance(digest, str)
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_build_envelope_canonical_json_ensure_ascii():
    """
    Per artifact 05 Edit 1 (post-VL-026): the canonical_json helper
    uses ensure_ascii=True. A canonical JSON serialization of an
    object containing a non-ASCII character must escape that
    character as \\uXXXX rather than embedding the raw UTF-8 bytes.
    Verified via the canonical_json helper directly because
    envelope.py exposes the function at module scope (the helper is
    used by both build_envelope's decision_sha256 computation and
    reassert's verification).
    """
    payload = {"non_ascii": "caf\u00e9"}
    canonicalized = canonical_json(payload)
    assert "\\u00e9" in canonicalized, (
        f"ensure_ascii=True should escape non-ASCII as \\uXXXX; "
        f"got: {canonicalized!r}"
    )
    # And the raw UTF-8 byte sequence for the e-acute character
    # (0xc3 0xa9; written here as "\u00e9" to keep this source file
    # ASCII-safe per VL-009) must NOT appear in the serialization.
    assert "\u00e9" not in canonicalized


def test_build_envelope_determinism():
    """
    Per artifact 05 Canon-mapping row "section 9 reproducibility:
    identical inputs + same manifest -> identical results" and the
    field rationale "canonical JSON serialization -> deterministic
    decision_sha256." Two envelopes built with identical inputs
    (including a pinned timestamp_utc) must be byte-identical.
    """
    env1 = _build_valid_envelope(timestamp_utc="2026-05-21T00:00:00+00:00")
    env2 = _build_valid_envelope(timestamp_utc="2026-05-21T00:00:00+00:00")
    # JSON-serialize both with the same canonicalization the envelope
    # itself uses; byte-equality of the serializations is the strict
    # form of "identical."
    assert canonical_json(env1) == canonical_json(env2)
    assert env1["decision_sha256"] == env2["decision_sha256"]


def test_build_envelope_timestamp_invariance():
    """
    Per artifact 05 timestamp_utc field rationale: "excluded from
    decision_sha256 so the same decision is bit-identical regardless
    of issue time; preserves section 9 reproducibility." Two envelopes
    built with the same inputs but different timestamps must have the
    same decision_sha256.
    """
    env1 = _build_valid_envelope(timestamp_utc="2026-05-21T00:00:00+00:00")
    env2 = _build_valid_envelope(timestamp_utc="2026-05-22T12:34:56+00:00")
    assert env1["timestamp_utc"] != env2["timestamp_utc"]
    assert env1["decision_sha256"] == env2["decision_sha256"]


# ---------------------------------------------------------------------------
# Reassertion protocol (artifact 05 reassertion-protocol table)
#
# Row 2 (decision_sha256 verification -> INVALIDATED) lives in
# test_ccs_canonical.py per VL-028 opener Decision B.
# ---------------------------------------------------------------------------


def test_reassert_row_5_REASSERTED():
    """
    Per artifact 05 reassertion-protocol table Row 5: "all hashes
    match AND decision_sha256 verifies -> REASSERTED" with canon basis
    "section 12.3 - continuity holds; d_{t+1} = d_t provably." An
    unmodified envelope built against current state must reassert to
    REASSERTED.
    """
    env = _build_valid_envelope()
    assert reassert(env)["outcome"] == REASSERTED


def test_reassert_row_1_INVALIDATED_on_canon_forge():
    """
    Per artifact 05 reassertion-protocol table Row 1: "canon_sha256
    != live canon hash -> INVALIDATED" with canon basis "canon
    changed; envelope predates current rules." Forge the envelope's
    canon.canon_sha256 to a non-live value, re-hash decision_sha256
    so the forgery is internally consistent (otherwise Row 2 would
    catch it first), then reassert.
    """
    env = _build_valid_envelope()
    env["canon"]["canon_sha256"] = "0" * 64
    _rehash_decision_sha256(env)
    assert reassert(env)["outcome"] == INVALIDATED


def test_reassert_row_3_RE_EVALUATE_REQUIRED_on_evaluator_mismatch():
    """
    Per artifact 05 reassertion-protocol table Row 3: "evaluator_sha256
    != live evaluator hash -> RE-EVALUATE-REQUIRED" with canon basis
    "section 12.4 - decision logic transition." Forge the envelope's
    evaluator.evaluator_sha256 to a non-live value, re-hash
    decision_sha256, reassert. Row 1 (canon) and Row 2 (verification)
    must not fire because canon hash is unchanged and the rehash
    makes the envelope verify cleanly.
    """
    env = _build_valid_envelope()
    env["evaluator"]["evaluator_sha256"] = "0" * 64
    _rehash_decision_sha256(env)
    assert reassert(env)["outcome"] == RE_EVALUATE_REQUIRED


def test_reassert_row_4_RE_EVALUATE_REQUIRED_on_manifest_mismatch():
    """
    Per artifact 05 reassertion-protocol table Row 4: "manifest_sha256
    != live manifest hash -> RE-EVALUATE-REQUIRED" with canon basis
    "section 7/section 12.4 - manifest version/schema transition."
    Forge the envelope's evaluated_against.manifest_sha256 to a non-
    live value, re-hash decision_sha256, reassert.
    """
    env = _build_valid_envelope()
    env["evaluated_against"]["manifest_sha256"] = "0" * 64
    _rehash_decision_sha256(env)
    assert reassert(env)["outcome"] == RE_EVALUATE_REQUIRED


def test_reassert_purity():
    """
    Per artifact 05 (post-VL-026 Edit 2): "reassert() is pure with
    respect to the envelope: it reads live file hashes (canon.lock,
    IMPLEMENTATION/evaluator.py, the live manifest) but does not
    modify its input envelope. Callers may pass a persisted envelope
    to reassert() and rely on the envelope's bytes remaining
    unchanged."

    Verified by serializing the envelope before and after a reassert()
    call and asserting byte-equality of the canonical JSON.
    """
    env = _build_valid_envelope()
    before = canonical_json(env)
    _ = reassert(env)
    after = canonical_json(env)
    assert before == after, (
        "reassert() mutated its input envelope; "
        "post-VL-026 Edit 2 purity contract violated"
    )


def test_canonical_json_sort_keys_and_no_whitespace():
    """
    Per artifact 05 decision_sha256 field rationale: "Canonical JSON
    (sorted keys, no whitespace, ensure_ascii=True per VL-009 ASCII-
    safe standard)." Two structurally-equivalent dicts with different
    key insertion orders must canonicalize to the same bytes. Verified
    by constructing two dicts with the same keys/values in different
    insertion orders and asserting canonical_json output is identical.
    The "no whitespace" half is verified by checking the output
    contains no spaces and no newlines.
    """
    d1 = {"b": 2, "a": 1, "c": {"y": 20, "x": 10}}
    d2 = {"a": 1, "c": {"x": 10, "y": 20}, "b": 2}
    s1 = canonical_json(d1)
    s2 = canonical_json(d2)
    assert s1 == s2
    assert " " not in s1
    assert "\n" not in s1
    # Sanity: the serialization is valid JSON.
    assert json.loads(s1) == {"a": 1, "b": 2, "c": {"x": 10, "y": 20}}
