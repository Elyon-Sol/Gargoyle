"""
Issuer-signing tests for Elyon-Sol (VL-040, T-signing).

Closes the VL-039 follow-up 2 forgery finding on the signed path: a party who
knows the published record and recomputes an unkeyed decision_sha256 can mint a
from-scratch envelope the unsigned verify_envelope accepts. Issuer signing
(Ed25519) authenticates the gate; the target verifies the signature against a
pinned public key before reassert().

Derivation (each test docstring cites its source):
  - canon section 8.2 (PoE: an optional, implementation-dependent integrity
    anchor that "does not affect admissibility logic")
  - canon section 11.9 (integrity-verifiable)
  - canon section 9 (fail-closed)
  - canon section 14 (identity-agnostic: the key proves who ISSUED the
    attestation, not who the actors are)
  - docs/restructure/05_admissibility_envelope_spec.md "Issuer signature
    (opt-in)" (the schema + the signed region + the no-new-reassertion-row
    layering + the two reason codes)

Opt-in boundary (honest scope): forgery is closed ONLY on the signed path
(pinned_public_keys supplied). With pinned_public_keys=None the unsigned path
is byte-behavior-unchanged and STILL forgeable; that is pinned explicitly
below (test_verifier_unsigned_mode_accepts_forge_non_default; renamed from the
retired canary test_unsigned_path_unchanged_forge_still_accepted at the VL-047
cutover), the same honesty as TESTS/adversarial/test_findings_001.py.

Per VL-040 constraint (i): no hash-value pinning; the manifest sha is computed
live and envelopes use a pinned timestamp_utc for determinism. The keypair is
generated live; the private key is never written to disk.

Ledger: VL-040 (issuer signing; opt-in).
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from IMPLEMENTATION.envelope import (
    REASSERTED,
    build_envelope,
    canonical_json,
    reassert,
    sign_envelope,
    _HASH_EXCLUDED_KEYS,
    _SIGNATURE_EXCLUDED_KEYS,
    _sha256_text,
)
from IMPLEMENTATION.evaluator import load_manifest, manifest_sha256
from IMPLEMENTATION.verifier import (
    ACCEPT_REASSERTED_AND_BOUND,
    REF_VERIFY_SIGNATURE_INVALID,
    REF_VERIFY_SIGNATURE_UNKNOWN_KEY,
    verify_envelope,
)


TARGET_URL = "http://127.0.0.1:9000/target"
GATE_KEY_ID = "gate-ed25519-001"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _normalized_interaction(context=None):
    return {
        "AP": ["identity", "role"],
        "OP": ["session", "request"],
        "context": {} if context is None else context,
        "expected_manifest_version": "1.0",
        "expected_manifest_sha256": manifest_sha256(),
    }


def _build_unsigned_envelope(interaction=None,
                             timestamp_utc="2026-05-31T00:00:00+00:00"):
    if interaction is None:
        interaction = _normalized_interaction()
    return build_envelope(
        decision="ELIGIBLE",
        target_url=TARGET_URL,
        normalized_interaction=interaction,
        manifest=load_manifest(),
        ac3=True,
        t26=True,
        manifest_integrity=True,
        timestamp_utc=timestamp_utc,
    )


def _gate_keypair():
    """A live-generated gate keypair; the private key is never persisted."""
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def _construct_forge(interaction):
    """
    The verbatim VL-039 follow-up 2 three-model construction: a from-scratch
    envelope built from PUBLIC knowledge only (the published record's hashes +
    the envelope shape), with a correctly recomputed unkeyed decision_sha256
    and NO issuer signature. This is exactly what the unsigned path accepts.
    """
    forge = {
        "envelope_version": "1.0",
        "decision": "ELIGIBLE",
        "target_url": TARGET_URL,
        "canon": {"version": "0.9.8.4", "canon_sha256": _live_canon_sha256()},
        "evaluated_against": {
            "manifest_version": "1.0",
            "manifest_sha256": manifest_sha256(),
        },
        "request_context": {
            "AP": interaction["AP"],
            "OP": interaction["OP"],
            "context": interaction["context"],
            "expected_manifest_version": "1.0",
            "expected_manifest_sha256": manifest_sha256(),
        },
        "evaluator": {"version": "0.9.8.4", "evaluator_sha256": _live_evaluator_sha256()},
        "condition_results": {"ac3": True, "t26": True,
                              "manifest_integrity": True, "ccs": None},
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
    }
    hashable = {k: v for k, v in forge.items() if k not in _HASH_EXCLUDED_KEYS}
    forge["decision_sha256"] = _sha256_text(canonical_json(hashable))
    return forge


def _live_canon_sha256():
    from IMPLEMENTATION.envelope import _read_canon_lock
    return _read_canon_lock()


def _live_evaluator_sha256():
    from IMPLEMENTATION.envelope import _evaluator_sha256
    return _evaluator_sha256()


# ---------------------------------------------------------------------------
# sign_envelope() behavior
# ---------------------------------------------------------------------------


def test_sign_envelope_adds_issuer_fields_and_is_pure():
    """
    Artifact 05 "Issuer signature (opt-in)": sign_envelope adds issuer_key_id
    and issuer_signature and returns a NEW dict (purity, matching reassert()).
    The input unsigned envelope is unchanged.
    """
    priv, _ = _gate_keypair()
    env = _build_unsigned_envelope()
    before = canonical_json(env)
    signed = sign_envelope(env, priv, GATE_KEY_ID)

    assert signed["issuer_key_id"] == GATE_KEY_ID
    assert isinstance(signed["issuer_signature"], str)
    assert len(bytes.fromhex(signed["issuer_signature"])) == 64  # Ed25519 sig
    assert "issuer_signature" not in env
    assert canonical_json(env) == before, "sign_envelope mutated its input"


def test_decision_sha256_identical_signed_vs_unsigned():
    """
    Artifact 05 decision_sha256 rationale (VL-040): the issuer fields are
    excluded from decision_sha256's region, so signing does not change
    decision_sha256. This is what lets a signed envelope pass reassert() Row 2
    unchanged and keeps the unsigned suite byte-stable.
    """
    priv, _ = _gate_keypair()
    env = _build_unsigned_envelope()
    signed = sign_envelope(env, priv, GATE_KEY_ID)
    assert signed["decision_sha256"] == env["decision_sha256"]


def test_signed_envelope_reasserts_unchanged():
    """
    Artifact 05 layering: signing is not a reassert()/CCS concern. A signed
    envelope built against current state still reasserts REASSERTED (Row 2
    verifies because the issuer fields are in _HASH_EXCLUDED_KEYS).
    """
    priv, _ = _gate_keypair()
    signed = sign_envelope(_build_unsigned_envelope(), priv, GATE_KEY_ID)
    assert reassert(signed)["outcome"] == REASSERTED


# ---------------------------------------------------------------------------
# Signed-path verification: honor genuine, refuse forge (the killer property)
# ---------------------------------------------------------------------------


def test_signed_envelope_honored_on_signed_path():
    """
    Canon section 8.2 / 11.9 + artifact 05: a target holding the gate's pinned
    public key honors a genuinely gate-signed, current, bound envelope.
    """
    priv, pub = _gate_keypair()
    interaction = _normalized_interaction()
    signed = sign_envelope(_build_unsigned_envelope(interaction=interaction),
                           priv, GATE_KEY_ID)
    result = verify_envelope(signed, interaction, TARGET_URL,
                             pinned_public_keys={GATE_KEY_ID: pub})
    assert result["accepted"] is True
    assert result["reason"] == ACCEPT_REASSERTED_AND_BOUND


def test_three_model_forge_refused_on_signed_path():
    """
    THE killer property (VL-040 goal). The verbatim VL-039 follow-up 2
    construction - a from-scratch envelope, no key, correct unkeyed
    decision_sha256 - is REFUSED on the signed path with
    REF_VERIFY_SIGNATURE_INVALID (no issuer_signature present). Canon section 9
    fail-closed. This directly falsifies the prior finding's attack.
    """
    priv, pub = _gate_keypair()
    interaction = _normalized_interaction(context={"exfil": "yes"})
    forge = _construct_forge(interaction)
    assert "issuer_signature" not in forge  # the adversary holds no key
    result = verify_envelope(forge, interaction, TARGET_URL,
                             pinned_public_keys={GATE_KEY_ID: pub})
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_SIGNATURE_INVALID


def test_forge_with_unknown_key_id_refused():
    """
    Canon section 9 fail-closed + artifact 05: a forge that fabricates an
    issuer_key_id not in the target's pinned set (even with some bytes in
    issuer_signature) is refused with REF_VERIFY_SIGNATURE_UNKNOWN_KEY before
    any signature math.
    """
    _, pub = _gate_keypair()
    interaction = _normalized_interaction()
    forge = _construct_forge(interaction)
    forge["issuer_key_id"] = "attacker-key-999"
    forge["issuer_signature"] = "00" * 64
    result = verify_envelope(forge, interaction, TARGET_URL,
                             pinned_public_keys={GATE_KEY_ID: pub})
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_SIGNATURE_UNKNOWN_KEY


def test_forge_signed_with_wrong_key_refused():
    """
    Canon section 9 + 8.2: an adversary who signs with their OWN Ed25519 key
    but claims the gate's pinned key_id is refused - the signature does not
    verify against the pinned public key. REF_VERIFY_SIGNATURE_INVALID.
    """
    _, gate_pub = _gate_keypair()
    attacker_priv = Ed25519PrivateKey.generate()
    interaction = _normalized_interaction()
    forge = _construct_forge(interaction)
    # Adversary signs the real region with their own key, under the gate's key_id.
    forge["issuer_key_id"] = GATE_KEY_ID
    region = {k: v for k, v in forge.items() if k not in _SIGNATURE_EXCLUDED_KEYS}
    forge["issuer_signature"] = attacker_priv.sign(
        canonical_json(region).encode("utf-8")
    ).hex()
    result = verify_envelope(forge, interaction, TARGET_URL,
                             pinned_public_keys={GATE_KEY_ID: gate_pub})
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_SIGNATURE_INVALID


def test_tampered_signed_envelope_refused_on_signature():
    """
    Canon section 9: tampering a signed envelope's request_context without
    re-signing breaks the signature. Because the signature is checked before
    reassert(), the verifier refuses with REF_VERIFY_SIGNATURE_INVALID (the
    tamper also breaks decision_sha256/Row 2, but provenance is checked first).
    """
    priv, pub = _gate_keypair()
    interaction = _normalized_interaction()
    signed = sign_envelope(_build_unsigned_envelope(interaction=interaction),
                           priv, GATE_KEY_ID)
    signed["request_context"]["AP"] = ["identity", "role", "admin"]  # tamper
    result = verify_envelope(signed, interaction, TARGET_URL,
                             pinned_public_keys={GATE_KEY_ID: pub})
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_SIGNATURE_INVALID


# ---------------------------------------------------------------------------
# Opt-in boundary: the unsigned path is unchanged (and still forgeable)
# ---------------------------------------------------------------------------


def test_verifier_unsigned_mode_accepts_forge_non_default():
    """
    VL-047 characterization (NOT the gate's default behavior). The verifier's
    UNSIGNED mode (verify_envelope with pinned_public_keys=None) still accepts a
    from-scratch forge - that mode legitimately remains for the target-side
    enforcement and A1-bypass demonstrations
    (TESTS/adversarial/test_enforcement.py, TESTS/adversarial/test_bypass.py)
    that use the unsigned verifier. It is no longer the GATE's default path: as
    of the VL-047 cutover pep.py's default forward signs
    (TESTS/test_pep.py::test_default_path_is_signed_and_forge_refused). This is
    the renamed successor to the retired canary
    test_unsigned_path_unchanged_forge_still_accepted; the fact it pins is
    unchanged - only its framing (a non-default verifier mode, not the gate).
    """
    interaction = _normalized_interaction()
    forge = _construct_forge(interaction)
    result = verify_envelope(forge, interaction, TARGET_URL)  # no pinned keys
    assert result["accepted"] is True
    assert result["reason"] == ACCEPT_REASSERTED_AND_BOUND


def test_genuine_signed_envelope_unsigned_path_still_honored():
    """
    A genuinely signed envelope verified on the UNSIGNED path
    (pinned_public_keys=None) is still honored: the extra issuer fields do not
    disturb reassert() (they are in _HASH_EXCLUDED_KEYS) or the binding check.
    Signing is additive; it never breaks an existing unsigned verifier.
    """
    priv, _ = _gate_keypair()
    interaction = _normalized_interaction()
    signed = sign_envelope(_build_unsigned_envelope(interaction=interaction),
                           priv, GATE_KEY_ID)
    result = verify_envelope(signed, interaction, TARGET_URL)
    assert result["accepted"] is True
    assert result["reason"] == ACCEPT_REASSERTED_AND_BOUND
