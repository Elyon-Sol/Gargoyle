"""
Canon/spec-derived tests for the B-prime-2 published key record (VL-042).
Repo path: TESTS/adversarial/test_key_record.py.

Covers the reader (IMPLEMENTATION/key_record_source.py) and the verifier
consultation (IMPLEMENTATION/verifier.py::verify_envelope key_record_view path)
against 09_key_record_spec.md sections 5-9 and canon sections 8.2 / 9 / 11.9 /
13 / 14. Run from the repo root (build_envelope reads CANON/canon.lock,
MANIFEST/manifest.json, IMPLEMENTATION/evaluator.py from disk), per
constraint (m) sandbox discipline: pytest in the author's real environment.

Records are built inline (not via EVIDENCE/published_keys_gen.py) so the suite
does not depend on whether EVIDENCE/ is an importable package; the inline
construction is byte-identical in structure to build_key_record's output
(same signed region: canonical_json(record minus publisher_signature)).
"""

import base64
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from IMPLEMENTATION.envelope import build_envelope, sign_envelope, canonical_json
from IMPLEMENTATION.key_record_source import load_key_record_from_bytes
from IMPLEMENTATION.verifier import (
    verify_envelope,
    ACCEPT_REASSERTED_AND_BOUND,
    REF_VERIFY_KEY_RECORD_INVALID,
    REF_VERIFY_KEY_RECORD_STALE,
    REF_VERIFY_KEY_UNKNOWN,
    REF_VERIFY_KEY_REVOKED,
    REF_VERIFY_KEY_OUT_OF_WINDOW,
    REF_VERIFY_KEY_ROLE_NOT_ISSUER,
    REF_VERIFY_SIGNATURE_INVALID,
)

NOW = datetime(2026, 6, 2, 12, 0, 0, tzinfo=timezone.utc)
ROOT_ID = "root-test-1"
TARGET_URL = "https://example.test/hook"


def _pub_b64(public_key):
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _interaction():
    # The same dict feeds build_envelope (request_context) and verify_envelope
    # (live interaction), so the binding check passes by construction.
    return {
        "AP": ["auth.read", "auth.write"],
        "OP": ["op.forward"],
        "context": {"tenant": "t1"},
        "expected_manifest_version": "1",
        "expected_manifest_sha256": "pinned-manifest-sha-placeholder",
    }


def _signed_envelope(issuer_private, key_id, not_after=None):
    interaction = _interaction()
    env = build_envelope(
        decision="ELIGIBLE",
        target_url=TARGET_URL,
        normalized_interaction=interaction,
        manifest={"version": "0.9.8.4"},
        ac3=True,
        t26=True,
        manifest_integrity=True,
    )
    signed = sign_envelope(env, issuer_private, key_id, not_after=not_after)
    return signed, interaction


def _key_entry(key_id, public_key, not_before, not_after, revoked=False):
    entry = {
        "key_id": key_id,
        "public_key": _pub_b64(public_key),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "revoked": revoked,
    }
    if revoked:
        entry["revoked_at"] = not_before.isoformat()
        entry["reason"] = "test: compromised"
    return entry


def _record_bytes(root_private, key_entries, serial=1, record_not_after=None):
    if record_not_after is None:
        record_not_after = NOW + timedelta(hours=24)
    record = {
        "format": "elyon-sol-key-record",
        "version": 1,
        "root_key_id": ROOT_ID,
        "serial": serial,
        "issued_at": NOW.isoformat(),
        "not_after": record_not_after.isoformat(),
        "keys": list(key_entries),
    }
    message = canonical_json(record).encode("utf-8")
    record["publisher_signature"] = root_private.sign(message).hex()
    return json.dumps(record).encode("utf-8")


def _trust_view(root_private, key_entries, serial=1, record_not_after=None,
                last_seen_serial=None):
    pinned = {ROOT_ID: root_private.public_key()}
    raw = _record_bytes(root_private, key_entries, serial=serial,
                        record_not_after=record_not_after)
    return load_key_record_from_bytes(raw, pinned, now=NOW,
                                      last_seen_serial=last_seen_serial)


def _valid_window():
    return (NOW - timedelta(days=1), NOW + timedelta(days=365))


# --------------------------------------------------------------------------
# Accept path
# --------------------------------------------------------------------------

def test_valid_current_key_accepted():
    root = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    nb, na = _valid_window()
    loaded = _trust_view(root, [_key_entry("issuer-1", issuer.public_key(), nb, na)])
    assert loaded["reason"] is None
    signed, interaction = _signed_envelope(issuer, "issuer-1")
    result = verify_envelope(signed, interaction, TARGET_URL,
                            key_record_view=loaded["trust_view"], now=NOW)
    assert result["accepted"] is True
    assert result["reason"] == ACCEPT_REASSERTED_AND_BOUND


# --------------------------------------------------------------------------
# Reader-layer refusals (RECORD_INVALID / RECORD_STALE)
# --------------------------------------------------------------------------

def test_bad_publisher_signature_refused():
    root = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    nb, na = _valid_window()
    raw = _record_bytes(root, [_key_entry("issuer-1", issuer.public_key(), nb, na)])
    record = json.loads(raw)
    # flip the last hex nibble of the publisher signature
    sig = record["publisher_signature"]
    record["publisher_signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    tampered = json.dumps(record).encode("utf-8")
    loaded = load_key_record_from_bytes(tampered, {ROOT_ID: root.public_key()},
                                        now=NOW)
    assert loaded["reason"] == REF_VERIFY_KEY_RECORD_INVALID


def test_unknown_root_refused():
    root = Ed25519PrivateKey.generate()
    other_root = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    nb, na = _valid_window()
    raw = _record_bytes(root, [_key_entry("issuer-1", issuer.public_key(), nb, na)])
    # pinned map does not contain ROOT_ID -> cannot validate the record
    loaded = load_key_record_from_bytes(raw, {"some-other-root": other_root.public_key()},
                                        now=NOW)
    assert loaded["reason"] == REF_VERIFY_KEY_RECORD_INVALID


def test_malformed_record_refused():
    root = Ed25519PrivateKey.generate()
    loaded = load_key_record_from_bytes(b"not valid json",
                                        {ROOT_ID: root.public_key()}, now=NOW)
    assert loaded["reason"] == REF_VERIFY_KEY_RECORD_INVALID


def test_stale_record_by_not_after_refused():
    root = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    nb, na = _valid_window()
    # record not_after one hour in the PAST relative to NOW -> stale
    loaded = _trust_view(root, [_key_entry("issuer-1", issuer.public_key(), nb, na)],
                        record_not_after=NOW - timedelta(hours=1))
    assert loaded["reason"] == REF_VERIFY_KEY_RECORD_STALE


def test_serial_rollback_refused():
    root = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    nb, na = _valid_window()
    # record serial 1 but verifier has already seen serial 5 -> rollback
    loaded = _trust_view(root, [_key_entry("issuer-1", issuer.public_key(), nb, na)],
                        serial=1, last_seen_serial=5)
    assert loaded["reason"] == REF_VERIFY_KEY_RECORD_STALE


def test_equal_serial_accepted():
    # serial == last_seen is fine: the signed serial guarantees an identical
    # record (spec section 5).
    root = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    nb, na = _valid_window()
    loaded = _trust_view(root, [_key_entry("issuer-1", issuer.public_key(), nb, na)],
                        serial=3, last_seen_serial=3)
    assert loaded["reason"] is None


# --------------------------------------------------------------------------
# Verifier-layer key-status refusals (UNKNOWN / REVOKED / OUT_OF_WINDOW)
# --------------------------------------------------------------------------

def test_revoked_key_refused():
    root = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    nb, na = _valid_window()
    loaded = _trust_view(root, [_key_entry("issuer-1", issuer.public_key(), nb, na,
                                            revoked=True)])
    assert loaded["reason"] is None  # record itself is valid and fresh
    signed, interaction = _signed_envelope(issuer, "issuer-1")
    result = verify_envelope(signed, interaction, TARGET_URL,
                            key_record_view=loaded["trust_view"], now=NOW)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_KEY_REVOKED


def test_unknown_key_refused():
    root = Ed25519PrivateKey.generate()
    issuer_in = Ed25519PrivateKey.generate()
    issuer_out = Ed25519PrivateKey.generate()
    nb, na = _valid_window()
    # record lists issuer-1 only; envelope is signed under key_id issuer-2
    loaded = _trust_view(root, [_key_entry("issuer-1", issuer_in.public_key(), nb, na)])
    signed, interaction = _signed_envelope(issuer_out, "issuer-2")
    result = verify_envelope(signed, interaction, TARGET_URL,
                            key_record_view=loaded["trust_view"], now=NOW)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_KEY_UNKNOWN


def test_out_of_window_key_refused():
    root = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    # window entirely in the past relative to NOW
    nb = NOW - timedelta(days=10)
    na = NOW - timedelta(days=1)
    loaded = _trust_view(root, [_key_entry("issuer-1", issuer.public_key(), nb, na)])
    signed, interaction = _signed_envelope(issuer, "issuer-1")
    result = verify_envelope(signed, interaction, TARGET_URL,
                            key_record_view=loaded["trust_view"], now=NOW)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_KEY_OUT_OF_WINDOW


def test_window_boundary_now_equals_not_after_refused():
    # half-open [not_before, not_after): now == not_after is OUT of window
    root = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    nb = NOW - timedelta(days=1)
    na = NOW
    loaded = _trust_view(root, [_key_entry("issuer-1", issuer.public_key(), nb, na)])
    signed, interaction = _signed_envelope(issuer, "issuer-1")
    result = verify_envelope(signed, interaction, TARGET_URL,
                            key_record_view=loaded["trust_view"], now=NOW)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_KEY_OUT_OF_WINDOW


def test_tampered_signature_with_valid_record_refused():
    # key is valid in the record, but the ENVELOPE's issuer_signature is broken:
    # the record vouches for the key, the envelope must still be signed by it.
    root = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    nb, na = _valid_window()
    loaded = _trust_view(root, [_key_entry("issuer-1", issuer.public_key(), nb, na)])
    signed, interaction = _signed_envelope(issuer, "issuer-1")
    sig = signed["issuer_signature"]
    signed["issuer_signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    result = verify_envelope(signed, interaction, TARGET_URL,
                            key_record_view=loaded["trust_view"], now=NOW)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_SIGNATURE_INVALID


# --------------------------------------------------------------------------
# Precedence and byte-behavior preservation
# --------------------------------------------------------------------------

def test_record_exclusive_precedence_revocation_wins():
    # the key is REVOKED in the record but would be accepted by the static map;
    # record-exclusive means the static map is ignored -> REVOKED (decision 3).
    root = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    nb, na = _valid_window()
    loaded = _trust_view(root, [_key_entry("issuer-1", issuer.public_key(), nb, na,
                                            revoked=True)])
    signed, interaction = _signed_envelope(issuer, "issuer-1")
    result = verify_envelope(
        signed, interaction, TARGET_URL,
        pinned_public_keys={"issuer-1": issuer.public_key()},
        key_record_view=loaded["trust_view"], now=NOW,
    )
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_KEY_REVOKED


def test_static_map_path_unchanged():
    # VL-040 byte-behavior: no record, static map supplied -> accepts.
    issuer = Ed25519PrivateKey.generate()
    signed, interaction = _signed_envelope(issuer, "issuer-1")
    result = verify_envelope(signed, interaction, TARGET_URL,
                            pinned_public_keys={"issuer-1": issuer.public_key()})
    assert result["accepted"] is True
    assert result["reason"] == ACCEPT_REASSERTED_AND_BOUND


def test_unsigned_path_unchanged():
    # VL-040 byte-behavior: neither trust source supplied -> unsigned path,
    # reassert + binding pass on a freshly built envelope -> accepts.
    interaction = _interaction()
    env = build_envelope(
        decision="ELIGIBLE",
        target_url=TARGET_URL,
        normalized_interaction=interaction,
        manifest={"version": "0.9.8.4"},
        ac3=True,
        t26=True,
        manifest_integrity=True,
    )
    result = verify_envelope(env, interaction, TARGET_URL)
    assert result["accepted"] is True
    assert result["reason"] == ACCEPT_REASSERTED_AND_BOUND


# --------------------------------------------------------------------------
# Role separation (2026-10-07 review): an approver-role key never issues
# --------------------------------------------------------------------------

def test_approver_role_key_cannot_sign_envelopes():
    """A key the signed record designates role=approver (the R1 approver key) is
    REFUSED as an envelope issuer, even though it is present, unrevoked, in
    window and its signature is valid. Fails if the verifier's role check is
    reverted (the approver holder could then mint gate envelopes)."""
    root = Ed25519PrivateKey.generate()
    gate_key = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    nb, na = _valid_window()
    ap_entry = _key_entry("ap", approver.public_key(), nb, na)
    ap_entry["role"] = "approver"
    loaded = _trust_view(root, [_key_entry("gate", gate_key.public_key(), nb, na),
                                ap_entry])
    assert loaded["reason"] is None
    signed, interaction = _signed_envelope(approver, "ap")
    result = verify_envelope(signed, interaction, TARGET_URL,
                            key_record_view=loaded["trust_view"], now=NOW)
    assert result["accepted"] is False
    assert result["reason"] == REF_VERIFY_KEY_ROLE_NOT_ISSUER


def test_issuer_role_key_accepted():
    """An explicit role=issuer key signs exactly as a role-less key does."""
    root = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    nb, na = _valid_window()
    entry = _key_entry("issuer-1", issuer.public_key(), nb, na)
    entry["role"] = "issuer"
    loaded = _trust_view(root, [entry])
    signed, interaction = _signed_envelope(issuer, "issuer-1")
    result = verify_envelope(signed, interaction, TARGET_URL,
                            key_record_view=loaded["trust_view"], now=NOW)
    assert result["accepted"] is True
