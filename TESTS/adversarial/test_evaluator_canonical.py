"""
Canon-derived tests for IMPLEMENTATION/evaluator.py (evaluator domain).

Each test cites a specific clause of CANON/canon.md (whitepaper
v0.9.8.4) in its docstring and verifies evaluator.py's behavior
against that clause. This is the evaluator-domain companion to
TESTS/adversarial/test_ccs_canonical.py (which is the canon-derived
half of G7 for the envelope/continuity domain, canon section 12).

This file closes G7 completely: with the envelope domain covered by
test_ccs_canonical.py and the evaluator domain covered here, the
project's canonical invariants (AC^3, T^26, and the manifest layer)
each have tests whose lineage runs from the canon to the assertion,
not from the code. A reader of canon section 11 can verify that
evaluator.py honors the canonical authority, coverage, and manifest
invariants by reading this file's docstrings against CANON/canon.md,
without having to read evaluator.py itself.

These tests exercise the predicate functions directly
(ac3_valid, t26_valid, manifest_integrity_valid) rather than the
end-to-end evaluate() pipeline. This is deliberate and is the
different-shape complement to the 23 code-derived tests in
TESTS/test_adversarial_evaluator.py (which drive evaluate()
end-to-end): canon section 11 defines AC^3 (11.7), T^26 (11.8), and
the governing manifest (11.9) as separate clauses, so the
canon-derived tests isolate one predicate per assertion to mirror
that per-clause structure. Per VL-034 Decision D, the code-derived
suite is augmented, not replaced.

Canon-citation set (Lesson 5 set-exhaustiveness, enumerated against
CANON/canon.md sections 11 and 9 at session start, source-first):

  AC^3 -- canon 11.7 "AC^3(I) = 1 <=> AP(I) superset-or-equal AR(I)"
    (with canon 11.5 "Present Authorities AP(I)", canon 11.3
    "Required Authorities AR(I)", canon section 3 "all required
    authority must be present"):
      - equality case of superset-or-equal        -> test_ac3_ap_equals_ar_accepts
      - proper-superset case                       -> test_ac3_ap_proper_superset_accepts
      - not-a-superset                             -> test_ac3_ap_missing_required_rejects
      - empty AP against non-empty AR              -> test_ac3_empty_ap_nonempty_ar_rejects
      - order independence of the set relation     -> test_ac3_order_independence
      - vacuous superset of the empty AR           -> test_ac3_empty_ar_accepts_any_ap
      - set membership ignores duplicates          -> test_ac3_duplicate_ap_members_ignored
      - fail-closed on malformed AP (canon 9)      -> test_ac3_type_violation_fails_closed

  T^26 -- canon 11.8 "T^26(I) = 1 <=> OP(I) superset-or-equal R(I)"
    (with canon 11.6 "Observed Coverage OP(I)", canon 11.4 "Coverage
    Requirements R(I)", canon section 3 "all required participants,
    roles, and evidence must be present"): same eight shapes over
    OP/R -> test_t26_* (mirrors the AC^3 enumeration).

  Manifest integrity -- canon 11.9 "the manifest must be
    deterministic, versioned, and integrity-verifiable", with canon
    12.4 "governing manifest version change" as an explicit invalid
    transition, and canon section 9 "fail closed under any missing or
    invalid input conditions":
      - both pins match (versioned)                -> test_manifest_version_pin_match_passes
      - version pin mismatch (12.4)                -> test_manifest_version_pin_mismatch_rejects
      - version pin missing (canon 9)              -> test_manifest_version_pin_missing_fails_closed
      - both pins match (integrity-verifiable)     -> test_manifest_sha256_pin_match_passes
      - sha256 pin mismatch (11.9 + 12.4)          -> test_manifest_sha256_pin_mismatch_rejects
      - sha256 pin missing (canon 9)               -> test_manifest_sha256_pin_missing_fails_closed

Artifact-05-layer acknowledgment (VL-034 Decision C, per VL-028
Decision B precedent): canon section 11 defines AC^3/T^26 as pure set
relations and defines the manifest's required PROPERTIES (11.9), but
does not specify the wire-level coercion or the caller-pinning
mechanism. Three test groups therefore carry an explicit
artifact-05-layer acknowledgment in their docstrings rather than a
bare canon citation:

  - test_ac3_duplicate_ap_members_ignored and
    test_t26_duplicate_op_members_ignored: canon 11.5/11.6 name AP/OP
    as SETS (so duplicates are not a canonical concept); the
    list-to-set coercion that realizes this is safe_set() in code --
    artifact-05-layer mechanism, canon set-semantics basis.
  - test_ac3_type_violation_fails_closed and
    test_t26_type_violation_fails_closed: canon section 9 directly
    authorizes fail-closed behavior; the SPECIFIC coercion
    (safe_set() returning None on a non-list-of-str, which the
    predicate maps to False) is artifact-05-layer.
  - the entire manifest-integrity group: canon 11.9 specifies the
    manifest's properties; the caller-pinning check
    (expected_manifest_version / expected_manifest_sha256 asserted by
    the caller and compared against the loaded manifest) is the
    artifact-05-layer mechanism described in
    docs/restructure/05_admissibility_envelope_spec.md. Citation is
    therefore canon-11.9-via-artifact-05.

G11 note (closed at VL-053): manifest_sha256() hashes the on-disk
MANIFEST_PATH. Before VL-053, manifest_integrity_valid() read the
version from its `manifest` argument but the sha256 from disk -- a
manifest-source asymmetry (G11, surfaced VL-012) that let a divergent
passed manifest yield a split-source integrity verdict. VL-053 adds a
divergence guard (the passed manifest must BE the on-disk source, else
fail closed); the characterization is
test_manifest_integrity_rejects_divergent_manifest below. The positive
manifest tests below pass the on-disk manifest (load_manifest()), so the
guard is a no-op for them. Per constraint (i), no test pins a literal
hash VALUE: the expected sha is derived live from manifest_sha256() so
the suite survives a GR-1 canon/manifest-version event without edits.

Ledger: VL-034 (canon-derived tests for the evaluator domain; G7
complete).
"""

from IMPLEMENTATION.evaluator import (
    ac3_valid,
    t26_valid,
    manifest_integrity_valid,
    manifest_sha256,
    load_manifest,
)


# ---------------------------------------------------------------------------
# AC^3 -- Authority Construct (canon 11.7)
#
# canon 11.7: "AC^3(I) = 1 <=> AP(I) superset-or-equal AR(I)"
# In code, ac3_valid(ctx, AR) builds AP_set from ctx["AP"] and AR_set
# from AR (both via safe_set) and returns AP_set >= AR_set, or False if
# either coercion fails. AR here is the manifest's required-authority
# set; AP is the caller's present-authority set.
# ---------------------------------------------------------------------------


def test_ac3_ap_equals_ar_accepts():
    """
    Canon 11.7: "AC^3(I) = 1 <=> AP(I) superset-or-equal AR(I)."

    The equality case of superset-or-equal: when the present-authority
    set AP exactly equals the required-authority set AR, every required
    authority is present and AC^3 holds. This is the boundary of the
    superset-or-equal relation (a set is superset-or-equal to itself).
    """
    assert ac3_valid({"AP": ["identity", "role"]}, ["identity", "role"]) is True


def test_ac3_ap_proper_superset_accepts():
    """
    Canon 11.7: "AC^3(I) = 1 <=> AP(I) superset-or-equal AR(I)", read
    together with canon section 3: "all required authority must be
    present, identifiable, and properly scoped."

    The proper-superset case: AP carries authorities beyond those
    required. Canon 11.7 requires only that AP be a superset-or-equal
    of AR; surplus present authority does not defeat completeness, so
    AC^3 holds.
    """
    assert (
        ac3_valid(
            {"AP": ["identity", "role", "admin", "root"]},
            ["identity", "role"],
        )
        is True
    )


def test_ac3_ap_missing_required_rejects():
    """
    Canon 11.7: "AC^3(I) = 1 <=> AP(I) superset-or-equal AR(I)."

    When AP omits a required authority ("role"), AP is not a
    superset-or-equal of AR, so the biconditional fails and AC^3 = 0.
    Canon section 3 frames this directly: a required authority that is
    not present defeats authority completeness.
    """
    assert ac3_valid({"AP": ["identity"]}, ["identity", "role"]) is False


def test_ac3_empty_ap_nonempty_ar_rejects():
    """
    Canon 11.7: "AC^3(I) = 1 <=> AP(I) superset-or-equal AR(I)", with
    canon section 3 "all required authority must be present."

    An empty present-authority set cannot be a superset of a non-empty
    required-authority set, so AC^3 = 0. (Distinct from a missing AP
    key: here AP is well-formed but empty.)
    """
    assert ac3_valid({"AP": []}, ["identity", "role"]) is False


def test_ac3_order_independence():
    """
    Canon 11.7: "AC^3(I) = 1 <=> AP(I) superset-or-equal AR(I)."

    Canon 11.7 defines AC^3 in terms of the superset-or-equal relation
    over SETS (canon 11.5 "Present Authorities AP(I)" names AP a set).
    A set relation is order-independent, so presenting the same
    authorities in a different order yields the identical AC^3 verdict.
    """
    assert ac3_valid({"AP": ["role", "identity"]}, ["identity", "role"]) is True


def test_ac3_empty_ar_accepts_any_ap():
    """
    Canon 11.7: "AC^3(I) = 1 <=> AP(I) superset-or-equal AR(I)."

    The vacuous-superset edge: when AR is empty, there are no required
    authorities, and every set (including any non-empty AP) is a
    superset-or-equal of the empty set. AC^3 therefore holds. This is
    the canonical boundary of the superset-or-equal relation, not an
    implementation artifact.
    """
    assert ac3_valid({"AP": ["identity", "role"]}, []) is True


def test_ac3_duplicate_ap_members_ignored():
    """
    Canon 11.5 names AP(I) a SET ("Present Authorities AP(I)"); canon
    11.7 evaluates AC^3 over that set. A set has no concept of
    duplicate members, so repeated entries in the caller-supplied AP do
    not change set membership and do not change the AC^3 verdict.

    Artifact-05-layer acknowledgment (VL-034 Decision C): the canonical
    basis is the set semantics of canon 11.5/11.7. The list-to-set
    coercion that realizes "duplicates collapse" is safe_set() in
    IMPLEMENTATION/evaluator.py -- an artifact-05-layer mechanism, not a
    clause named in canon. The canon authorizes the set semantics; the
    coercion implements it.
    """
    assert (
        ac3_valid({"AP": ["identity", "identity", "role"]}, ["identity", "role"])
        is True
    )


def test_ac3_type_violation_fails_closed():
    """
    Canon section 9 (Reproducibility): a valid implementation must
    "fail closed under any missing or invalid input conditions." Canon
    11.7 presupposes AP is a well-formed set; a malformed AP is an
    invalid input.

    Artifact-05-layer acknowledgment (VL-034 Decision C): the
    fail-closed REQUIREMENT is direct canon (section 9). The SPECIFIC
    mechanism -- safe_set() returning None on anything that is not a
    list-of-strings, which ac3_valid maps to False -- is
    artifact-05-layer. Representative malformed shapes (a string, an
    integer, and a nested list of unhashables) each fail closed.
    """
    assert ac3_valid({"AP": "identity,role"}, ["identity", "role"]) is False
    assert ac3_valid({"AP": 42}, ["identity", "role"]) is False
    assert ac3_valid({"AP": [["identity"], ["role"]]}, ["identity", "role"]) is False


# ---------------------------------------------------------------------------
# T^26 -- Coverage Model (canon 11.8)
#
# canon 11.8: "T^26(I) = 1 <=> OP(I) superset-or-equal R(I)"
# In code, t26_valid(ctx, R) builds OP_set from ctx["OP"] and R_set from
# R (both via safe_set) and returns OP_set >= R_set, or False if either
# coercion fails. R is the manifest's required-coverage set; OP is the
# caller's observed-coverage set. Mirrors the AC^3 enumeration above.
# ---------------------------------------------------------------------------


def test_t26_op_equals_r_accepts():
    """
    Canon 11.8: "T^26(I) = 1 <=> OP(I) superset-or-equal R(I)."

    The equality case: when observed coverage OP exactly equals
    required coverage R, all required coverage is present and T^26
    holds (a set is superset-or-equal to itself).
    """
    assert t26_valid({"OP": ["session", "request"]}, ["session", "request"]) is True


def test_t26_op_proper_superset_accepts():
    """
    Canon 11.8: "T^26(I) = 1 <=> OP(I) superset-or-equal R(I)", with
    canon section 3 "all required participants, roles, and evidence
    must be present."

    The proper-superset case: surplus observed coverage beyond what is
    required does not defeat coverage completeness, so T^26 holds.
    """
    assert (
        t26_valid(
            {"OP": ["session", "request", "trace", "audit"]},
            ["session", "request"],
        )
        is True
    )


def test_t26_op_missing_required_rejects():
    """
    Canon 11.8: "T^26(I) = 1 <=> OP(I) superset-or-equal R(I)."

    When OP omits a required coverage element ("request"), OP is not a
    superset-or-equal of R, so T^26 = 0. Canon section 3: required
    coverage that is not present defeats coverage completeness.
    """
    assert t26_valid({"OP": ["session"]}, ["session", "request"]) is False


def test_t26_empty_op_nonempty_r_rejects():
    """
    Canon 11.8: "T^26(I) = 1 <=> OP(I) superset-or-equal R(I)", with
    canon section 3 "all required ... must be present."

    An empty observed-coverage set cannot be a superset of a non-empty
    required-coverage set, so T^26 = 0.
    """
    assert t26_valid({"OP": []}, ["session", "request"]) is False


def test_t26_order_independence():
    """
    Canon 11.8: "T^26(I) = 1 <=> OP(I) superset-or-equal R(I)."

    T^26 is defined over the superset-or-equal relation on SETS (canon
    11.6 "Observed Coverage OP(I)"). The relation is order-independent,
    so reordering the observed coverage yields the identical verdict.
    """
    assert t26_valid({"OP": ["request", "session"]}, ["session", "request"]) is True


def test_t26_empty_r_accepts_any_op():
    """
    Canon 11.8: "T^26(I) = 1 <=> OP(I) superset-or-equal R(I)."

    The vacuous-superset edge: when R is empty there is no required
    coverage, and every set is a superset-or-equal of the empty set, so
    T^26 holds. Canonical boundary of the relation, not an
    implementation artifact.
    """
    assert t26_valid({"OP": ["session", "request"]}, []) is True


def test_t26_duplicate_op_members_ignored():
    """
    Canon 11.6 names OP(I) a SET ("Observed Coverage OP(I)"); canon
    11.8 evaluates T^26 over that set. Duplicate entries in the
    caller-supplied OP do not change set membership and do not change
    the T^26 verdict.

    Artifact-05-layer acknowledgment (VL-034 Decision C): the canonical
    basis is the set semantics of canon 11.6/11.8; the list-to-set
    coercion realizing it is safe_set(), an artifact-05-layer
    mechanism.
    """
    assert (
        t26_valid({"OP": ["session", "session", "request"]}, ["session", "request"])
        is True
    )


def test_t26_type_violation_fails_closed():
    """
    Canon section 9 (Reproducibility): "fail closed under any missing
    or invalid input conditions." A malformed OP is an invalid input;
    canon 11.8 presupposes OP is a well-formed set.

    Artifact-05-layer acknowledgment (VL-034 Decision C): the
    fail-closed requirement is direct canon (section 9); the specific
    safe_set()-returns-None-maps-to-False mechanism is
    artifact-05-layer. Representative malformed shapes each fail
    closed.
    """
    assert t26_valid({"OP": "session,request"}, ["session", "request"]) is False
    assert t26_valid({"OP": 42}, ["session", "request"]) is False
    assert t26_valid({"OP": [["session"], ["request"]]}, ["session", "request"]) is False


# ---------------------------------------------------------------------------
# Manifest integrity -- canon 11.9 via artifact-05 (VL-034 Decision C)
#
# canon 11.9: "the manifest must be deterministic, versioned, and
# integrity-verifiable." The caller-pinning check
# (manifest_integrity_valid) is the artifact-05-layer mechanism that
# operationalizes 11.9 at the wire boundary: the caller asserts which
# manifest version + sha256 it expects, and the evaluator refuses if the
# loaded manifest does not match. This is NOT canonical CCS (canon
# section 12); see test_ccs_canonical.py and the manifest-integrity
# disambiguation in VL-012.
#
# Per VL-034 constraint (i): the expected sha is derived LIVE from
# manifest_sha256() in each test, never pinned as a literal value, so
# this suite survives a GR-1 canon/manifest-version event without edits.
#
# G11 (closed VL-053): the manifest-source asymmetry (manifest_integrity_valid
# read version from the argument, sha from disk) is closed by a divergence
# guard; test_manifest_integrity_rejects_divergent_manifest characterizes it.
# ---------------------------------------------------------------------------


def test_manifest_version_pin_match_passes():
    """
    Canon 11.9: "the manifest must be ... versioned ..."
    Artifact-05-layer (VL-034 Decision C): manifest_integrity_valid()
    operationalizes "versioned" by comparing the caller's
    expected_manifest_version against the loaded manifest's version.

    When the caller pins the correct version (and the correct live
    sha256), the check passes. The version dimension is the focus of
    this positive case.
    """
    manifest = load_manifest()
    ctx = {
        "expected_manifest_version": manifest["version"],
        "expected_manifest_sha256": manifest_sha256(),
    }
    assert manifest_integrity_valid(ctx, manifest) is True


def test_manifest_version_pin_mismatch_rejects():
    """
    Canon 12.4 lists "governing manifest version change" as an explicit
    example of an invalid transition.
    Artifact-05-layer (VL-034 Decision C): manifest_integrity_valid()
    detects a version transition by comparing the caller's pinned
    version against the loaded manifest's version.

    When the caller pins a version the loaded manifest does not match
    ("2.0" vs "1.0"), the check refuses -- the caller's expected
    manifest is not the one in force.
    """
    manifest = load_manifest()
    ctx = {
        "expected_manifest_version": "2.0",
        "expected_manifest_sha256": manifest_sha256(),
    }
    assert manifest_integrity_valid(ctx, manifest) is False


def test_manifest_version_pin_missing_fails_closed():
    """
    Canon section 9: "fail closed under any missing or invalid input
    conditions." Canon 11.9 requires the manifest be versioned; a
    caller that supplies no version pin provides an invalid (absent)
    input to the integrity check.
    Artifact-05-layer (VL-034 Decision C): with no
    expected_manifest_version in ctx, the value is None, which is not a
    string, so manifest_integrity_valid() fails closed.
    """
    manifest = load_manifest()
    ctx = {"expected_manifest_sha256": manifest_sha256()}
    assert manifest_integrity_valid(ctx, manifest) is False


def test_manifest_sha256_pin_match_passes():
    """
    Canon 11.9: "the manifest must be ... integrity-verifiable."
    Artifact-05-layer (VL-034 Decision C): manifest_integrity_valid()
    operationalizes "integrity-verifiable" by comparing the caller's
    expected_manifest_sha256 against the live hash of the on-disk
    manifest (manifest_sha256()).

    When the caller pins the correct live sha256 (and the correct
    version), the check passes. Per constraint (i) the expected sha is
    derived live, not hardcoded. The integrity dimension is the focus
    of this positive case.
    """
    manifest = load_manifest()
    ctx = {
        "expected_manifest_version": manifest["version"],
        "expected_manifest_sha256": manifest_sha256(),
    }
    assert manifest_integrity_valid(ctx, manifest) is True


def test_manifest_sha256_pin_mismatch_rejects():
    """
    Canon 11.9 "integrity-verifiable" together with canon 12.4 (an
    integrity-violating change is an invalid transition).
    Artifact-05-layer (VL-034 Decision C): when the caller's pinned
    sha256 does not match the live manifest hash, the integrity check
    refuses.

    A sha pin of all-zeros (a value the real manifest cannot hash to)
    is the canonical integrity-mismatch case. Using an obviously-invalid
    sentinel rather than a real alternate hash keeps the test free of
    hash-value pinning per constraint (i).
    """
    manifest = load_manifest()
    ctx = {
        "expected_manifest_version": manifest["version"],
        "expected_manifest_sha256": "0" * 64,
    }
    assert manifest_integrity_valid(ctx, manifest) is False


def test_manifest_sha256_pin_missing_fails_closed():
    """
    Canon section 9: "fail closed under any missing or invalid input
    conditions." A caller that supplies a correct version pin but no
    sha256 pin provides an incomplete integrity assertion.
    Artifact-05-layer (VL-034 Decision C): with no
    expected_manifest_sha256 in ctx the value is None, not a string, so
    manifest_integrity_valid() fails closed even though the version pin
    is correct -- both pins are load-bearing.
    """
    manifest = load_manifest()
    ctx = {"expected_manifest_version": manifest["version"]}
    assert manifest_integrity_valid(ctx, manifest) is False


def test_manifest_integrity_rejects_divergent_manifest():
    """
    Canon section 9 (Reproducibility): "fail closed under any missing or
    invalid input conditions"; canon 11.9 "the manifest must be ...
    integrity-verifiable."

    G11 characterization (VL-053). Before VL-053,
    manifest_integrity_valid() read the version from its `manifest`
    argument but the sha256 from the on-disk MANIFEST/manifest.json via
    manifest_sha256(), ignoring the argument. A caller passing a manifest
    that DIVERGES from the on-disk source -- different AR/R, same version,
    with the caller pinning the on-disk sha -- passed the version check
    (argument) and the sha check (disk) and returned True, even though
    AC^3/T^26 were evaluated against the divergent argument: a split-source
    integrity verdict (the asymmetry tracked as G11, surfaced VL-012).

    Per constraint (i) no literal hash is pinned: the caller pins the LIVE
    on-disk sha via manifest_sha256() and the LIVE on-disk version via
    load_manifest(); only the manifest CONTENT (AR/R) diverges. On the
    pre-VL-053 behavior this returned True (the masked verdict); on the
    VL-053 divergence guard it returns False (fail closed). This test
    asserts the fixed behavior.
    """
    on_disk = load_manifest()
    divergent = dict(on_disk)
    divergent["AR"] = on_disk["AR"] + ["doctor_authorized"]
    divergent["R"] = on_disk["R"] + ["patient_access"]
    ctx = {
        "expected_manifest_version": on_disk["version"],
        "expected_manifest_sha256": manifest_sha256(),
    }
    assert manifest_integrity_valid(ctx, divergent) is False
