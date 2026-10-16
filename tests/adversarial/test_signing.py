"""
Issuer-signing tests.

Without a signature, anyone who knows the published policy pin can build a
receipt from scratch with a correct decision_sha256 (it is an unkeyed hash).
Ed25519 issuer signatures close that: the target checks the signature against
a pinned public key before anything else.

This holds only when the verifier is given pinned_public_keys. With
pinned_public_keys=None the verifier runs in unsigned mode, which still
accepts a from-scratch forgery; test_verifier_unsigned_mode_accepts_forge_non_default
pins that fact so nobody mistakes unsigned mode for protection.

The keypair is generated per test and never written to disk.
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.policy import ManifestPolicy
from gargoyle.envelope import (
    REASSERTED,
    args_sha256,
    build_envelope,
    canonical_json,
    reassert,
    sign_envelope,
    ENVELOPE_VERSION,
    _HASH_EXCLUDED_KEYS,
    _SIGNATURE_EXCLUDED_KEYS,
    _sha256_text,
)
from gargoyle.verifier import (
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


def _normalized_interaction(args=None):
    return {
        "tool": "transfer",
        "args": {"amount": 5} if args is None else args,
        "principal": "agent-7",
    }


def _build_unsigned_envelope(interaction=None,
                             timestamp_utc="2026-05-31T00:00:00+00:00"):
    if interaction is None:
        interaction = _normalized_interaction()
    return build_envelope(
        policy_pin=ManifestPolicy().pin(),
        decision="ELIGIBLE",
        target_url=TARGET_URL,
        call=interaction,
        timestamp_utc=timestamp_utc,
    )


def _gate_keypair():
    """A live-generated gate keypair; the private key is never persisted."""
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def _construct_forge(interaction):
    """
    A from-scratch receipt built only from public knowledge (the policy pin and
    the receipt format), with a correctly computed decision_sha256 and no issuer
    signature. Unsigned mode accepts exactly this.
    """
    forge = {
        "envelope_version": ENVELOPE_VERSION,
        "decision": "ELIGIBLE",
        "target_url": TARGET_URL,
        "policy": ManifestPolicy().pin(),
        "request_context": {
            "tool": interaction["tool"],
            "args_sha256": args_sha256(interaction["args"]),
            "principal": interaction["principal"],
        },
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
    }
    hashable = {k: v for k, v in forge.items() if k not in _HASH_EXCLUDED_KEYS}
    forge["decision_sha256"] = _sha256_text(canonical_json(hashable))
    return forge


# ---------------------------------------------------------------------------
# sign_envelope() behavior
# ---------------------------------------------------------------------------


def test_sign_envelope_adds_issuer_fields_and_is_pure():
    """
    sign_envelope adds issuer_key_id and a 64-byte Ed25519 issuer_signature and
    returns a new dict, leaving the unsigned input untouched.
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
    The issuer fields are outside decision_sha256's hashed region, so signing does
    not change decision_sha256 and a signed receipt still passes the integrity check.
    """
    priv, _ = _gate_keypair()
    env = _build_unsigned_envelope()
    signed = sign_envelope(env, priv, GATE_KEY_ID)
    assert signed["decision_sha256"] == env["decision_sha256"]


def test_signed_envelope_reasserts_unchanged():
    """
    A signed receipt issued under the current policy reasserts as REASSERTED:
    signing does not affect the integrity or policy-pin checks.
    """
    priv, _ = _gate_keypair()
    signed = sign_envelope(_build_unsigned_envelope(), priv, GATE_KEY_ID)
    assert reassert(signed)["outcome"] == REASSERTED


# ---------------------------------------------------------------------------
# Signed path: honor a genuine receipt, refuse forgeries
# ---------------------------------------------------------------------------


def test_signed_envelope_honored_on_signed_path():
    """
    A target holding the issuer's pinned public key honors a genuinely signed,
    current receipt bound to the call it is executing.
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
    The from-scratch forgery (no key, correct unkeyed decision_sha256) is refused
    on the signed path with REF_VERIFY_SIGNATURE_INVALID, because it carries no
    issuer signature.
    """
    priv, pub = _gate_keypair()
    interaction = _normalized_interaction(args={"exfil": "yes"})
    forge = _construct_forge(interaction)
    assert "issuer_signature" not in forge  # the adversary holds no key
    result = verify_envelope(forge, interaction, TARGET_URL,
                             pinned_public_keys={GATE_KEY_ID: pub})
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_SIGNATURE_INVALID


def test_forge_with_unknown_key_id_refused():
    """
    A forgery naming an issuer_key_id the target has not pinned is refused with
    REF_VERIFY_SIGNATURE_UNKNOWN_KEY before any signature is checked.
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
    An attacker who signs with their own Ed25519 key while claiming the issuer's
    key id is refused: the signature does not verify against the pinned key.
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
    Changing a signed receipt's request_context without re-signing breaks the
    signature. The signature is checked first, so the refusal is
    REF_VERIFY_SIGNATURE_INVALID rather than the integrity-check failure the
    tamper would also cause.
    """
    priv, pub = _gate_keypair()
    interaction = _normalized_interaction()
    signed = sign_envelope(_build_unsigned_envelope(interaction=interaction),
                           priv, GATE_KEY_ID)
    signed["request_context"]["tool"] = "delete_database"  # tamper
    result = verify_envelope(signed, interaction, TARGET_URL,
                             pinned_public_keys={GATE_KEY_ID: pub})
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_SIGNATURE_INVALID


# ---------------------------------------------------------------------------
# Unsigned mode: no key pinning, still forgeable
# ---------------------------------------------------------------------------


def test_verifier_unsigned_mode_accepts_forge_non_default():
    """
    Characterizes unsigned mode, which is not protection: verify_envelope with
    pinned_public_keys=None accepts a from-scratch forgery. Unsigned mode exists
    for demonstrating what a target sees without key pinning (test_bypass.py).
    The issuer always signs (gargoyle.issuer.issue), so a deployed target must
    pin keys.
    """
    interaction = _normalized_interaction()
    forge = _construct_forge(interaction)
    result = verify_envelope(forge, interaction, TARGET_URL)  # no pinned keys
    assert result["accepted"] is True
    assert result["reason"] == ACCEPT_REASSERTED_AND_BOUND


def test_genuine_signed_envelope_unsigned_path_still_honored():
    """
    A signed receipt checked in unsigned mode is still honored: the issuer fields
    disturb neither the integrity check nor the binding check.
    """
    priv, _ = _gate_keypair()
    interaction = _normalized_interaction()
    signed = sign_envelope(_build_unsigned_envelope(interaction=interaction),
                           priv, GATE_KEY_ID)
    result = verify_envelope(signed, interaction, TARGET_URL)
    assert result["accepted"] is True
    assert result["reason"] == ACCEPT_REASSERTED_AND_BOUND
