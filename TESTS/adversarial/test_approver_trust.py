"""
Canon/spec-derived tests for approver provenance + role (Feature 1, residual R1).
Repo path: TESTS/adversarial/test_approver_trust.py.

Covers IMPLEMENTATION/approver_trust.py (the [FIX H5] LOAD-BEARING half) against
docs/design/governance_layer_design.md section 1.4 [FIX H5]. The resolver turns a
VALIDATED signed key-record trust view into the {key_id: public_key} approver map
verify_grant() consumes, enforcing SoD as ROLE-DISTINCTNESS in the SIGNED record
(only role=="approver", non-revoked, in-window, key_id != gate_key_id).

Records are built inline (the same construction test_key_record.py uses) so the
signed region is canonical_json(record minus publisher_signature): the per-key
`role` is therefore signature-covered. Each test drives the REAL chain
(load_key_record_from_bytes) and, where end-to-end, the REAL grant verifier
(verify_grant) - never a stub. Run from the repo root, per sandbox discipline.
"""

import base64
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from IMPLEMENTATION.envelope import canonical_json
from IMPLEMENTATION.key_record_source import load_key_record_from_bytes
from IMPLEMENTATION.approver_trust import resolve_approver_keys, APPROVER_ROLE
from IMPLEMENTATION.approval import (
    build_grant,
    sign_grant,
    verify_grant,
    ACCEPT_GRANT_VALID,
    REF_APPROVAL_KEY_UNKNOWN,
)

NOW = datetime(2026, 6, 2, 12, 0, 0, tzinfo=timezone.utc)
ROOT_ID = "root-test-1"
GATE_KEY_ID = "issuer-1"
DECISION = "decision-sha-256-fixture"
REQ_ID = "approval-request-fixture"


def _pub_b64(public_key):
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _key_entry(key_id, public_key, not_before, not_after, revoked=False, role=None):
    entry = {
        "key_id": key_id,
        "public_key": _pub_b64(public_key),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "revoked": revoked,
    }
    if role is not None:
        entry["role"] = role
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


def _trust_view(root_private, key_entries):
    pinned = {ROOT_ID: root_private.public_key()}
    raw = _record_bytes(root_private, key_entries)
    loaded = load_key_record_from_bytes(raw, pinned, now=NOW)
    assert loaded["reason"] is None, loaded["reason"]
    return loaded["trust_view"]


def _window():
    return (NOW - timedelta(days=1), NOW + timedelta(days=365))


def _signed_grant(approver_private, key_id, decision=DECISION, req_id=REQ_ID):
    grant = build_grant(
        decision_sha256=decision,
        approval_request_id=req_id,
        grant_id="grant-" + key_id,
        not_after=NOW + timedelta(minutes=5),
    )
    return sign_grant(grant, approver_private, key_id)


# --------------------------------------------------------------------------
# Role surfacing through the signed chain (provenance)
# --------------------------------------------------------------------------

def test_role_surfaced_into_trust_view():
    root = Ed25519PrivateKey.generate()
    appr = Ed25519PrivateKey.generate()
    nb, na = _window()
    tv = _trust_view(root, [_key_entry("appr-1", appr.public_key(), nb, na,
                                       role="approver")])
    assert tv["appr-1"]["role"] == "approver"


def test_roleless_key_surfaces_role_none():
    # A pre-VL-119 record (no role field) loads with role None -> never approver.
    root = Ed25519PrivateKey.generate()
    appr = Ed25519PrivateKey.generate()
    nb, na = _window()
    tv = _trust_view(root, [_key_entry("appr-1", appr.public_key(), nb, na)])
    assert tv["appr-1"]["role"] is None
    assert resolve_approver_keys(tv, gate_key_id=GATE_KEY_ID, now=NOW) == {}


# --------------------------------------------------------------------------
# Selection: only an active, in-window, signed "approver" key is eligible
# --------------------------------------------------------------------------

def test_selects_only_approver_role():
    root = Ed25519PrivateKey.generate()
    appr = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    revoked = Ed25519PrivateKey.generate()
    expired = Ed25519PrivateKey.generate()
    roleless = Ed25519PrivateKey.generate()
    nb, na = _window()
    entries = [
        _key_entry("appr-1", appr.public_key(), nb, na, role="approver"),
        _key_entry(GATE_KEY_ID, issuer.public_key(), nb, na, role="issuer"),
        _key_entry("appr-revoked", revoked.public_key(), nb, na, revoked=True,
                   role="approver"),
        _key_entry("appr-expired", expired.public_key(),
                   NOW - timedelta(days=10), NOW - timedelta(days=1),
                   role="approver"),
        _key_entry("roleless", roleless.public_key(), nb, na),
    ]
    tv = _trust_view(root, entries)
    resolved = resolve_approver_keys(tv, gate_key_id=GATE_KEY_ID, now=NOW)
    assert set(resolved.keys()) == {"appr-1"}


def test_revoked_approver_excluded():
    root = Ed25519PrivateKey.generate()
    appr = Ed25519PrivateKey.generate()
    nb, na = _window()
    tv = _trust_view(root, [_key_entry("appr-1", appr.public_key(), nb, na,
                                       revoked=True, role="approver")])
    assert resolve_approver_keys(tv, gate_key_id=GATE_KEY_ID, now=NOW) == {}


def test_expired_approver_excluded():
    root = Ed25519PrivateKey.generate()
    appr = Ed25519PrivateKey.generate()
    tv = _trust_view(root, [_key_entry("appr-1", appr.public_key(),
                                       NOW - timedelta(days=10),
                                       NOW - timedelta(days=1), role="approver")])
    assert resolve_approver_keys(tv, gate_key_id=GATE_KEY_ID, now=NOW) == {}


def test_not_yet_valid_approver_excluded():
    root = Ed25519PrivateKey.generate()
    appr = Ed25519PrivateKey.generate()
    tv = _trust_view(root, [_key_entry("appr-1", appr.public_key(),
                                       NOW + timedelta(days=1),
                                       NOW + timedelta(days=365), role="approver")])
    assert resolve_approver_keys(tv, gate_key_id=GATE_KEY_ID, now=NOW) == {}


def test_gate_key_id_belt_and_braces():
    # Even a well-formed approver-role key is excluded if it shares the gate id.
    root = Ed25519PrivateKey.generate()
    appr = Ed25519PrivateKey.generate()
    nb, na = _window()
    tv = _trust_view(root, [_key_entry(GATE_KEY_ID, appr.public_key(), nb, na,
                                       role="approver")])
    assert resolve_approver_keys(tv, gate_key_id=GATE_KEY_ID, now=NOW) == {}


# --------------------------------------------------------------------------
# Revert-catcher (the design's core for R1): an ISSUER-role key, presented as
# the approver, must NOT release a held decision. With role-distinctness it is
# excluded -> verify_grant -> REF_APPROVAL_KEY_UNKNOWN. If the resolver ignored
# role (the revert), the issuer key would be in the map and the grant would be
# GRANT_VALID - a gate-minted self-approval. That contrast is asserted here.
# --------------------------------------------------------------------------

def test_issuer_role_cannot_authorize_revert_catcher():
    root = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()  # the gate's own key
    nb, na = _window()
    # The issuer key carries role "issuer"; the gate signs a grant with it.
    tv = _trust_view(root, [_key_entry("gate-issuer", issuer.public_key(), nb, na,
                                       role="issuer")])
    grant = _signed_grant(issuer, "gate-issuer")

    # Role-distinctness (the build): issuer key is not an approver -> excluded.
    resolved = resolve_approver_keys(tv, gate_key_id=GATE_KEY_ID, now=NOW)
    assert resolved == {}
    verdict = verify_grant(
        grant,
        expected_decision_sha256=DECISION,
        expected_approval_request_id=REQ_ID,
        approver_public_keys=resolved,
        gate_key_id=GATE_KEY_ID,
        now=NOW,
    )
    assert verdict["accepted"] is False
    assert verdict["reason"] == REF_APPROVAL_KEY_UNKNOWN

    # The revert (ignore role) WOULD honor the gate's self-minted approval:
    reverted = {kid: info["public_key"] for kid, info in tv.items()}
    bad = verify_grant(
        grant,
        expected_decision_sha256=DECISION,
        expected_approval_request_id=REQ_ID,
        approver_public_keys=reverted,
        gate_key_id=GATE_KEY_ID,
        now=NOW,
    )
    assert bad["accepted"] is True  # proves role-distinctness is load-bearing


# --------------------------------------------------------------------------
# Provenance: trust flows ONLY from the validated signed chain
# --------------------------------------------------------------------------

def test_tampered_record_yields_no_approver():
    # A record whose publisher signature is broken never validates -> no view ->
    # no approver key, so an attacker cannot inject an approver by editing bytes.
    root = Ed25519PrivateKey.generate()
    appr = Ed25519PrivateKey.generate()
    nb, na = _window()
    raw = _record_bytes(root, [_key_entry("appr-1", appr.public_key(), nb, na,
                                          role="approver")])
    rec = json.loads(raw)
    sig = rec["publisher_signature"]
    rec["publisher_signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    tampered = json.dumps(rec).encode("utf-8")
    loaded = load_key_record_from_bytes(tampered, {ROOT_ID: root.public_key()},
                                        now=NOW)
    assert loaded["trust_view"] is None
    assert resolve_approver_keys(loaded["trust_view"], gate_key_id=GATE_KEY_ID,
                                 now=NOW) == {}


def test_key_not_in_signed_record_is_unknown():
    # An approver key the publisher never signed is simply absent from the view.
    root = Ed25519PrivateKey.generate()
    appr = Ed25519PrivateKey.generate()
    outsider = Ed25519PrivateKey.generate()
    nb, na = _window()
    tv = _trust_view(root, [_key_entry("appr-1", appr.public_key(), nb, na,
                                       role="approver")])
    grant = _signed_grant(outsider, "outsider-1")
    resolved = resolve_approver_keys(tv, gate_key_id=GATE_KEY_ID, now=NOW)
    verdict = verify_grant(
        grant,
        expected_decision_sha256=DECISION,
        expected_approval_request_id=REQ_ID,
        approver_public_keys=resolved,
        gate_key_id=GATE_KEY_ID,
        now=NOW,
    )
    assert verdict["accepted"] is False
    assert verdict["reason"] == REF_APPROVAL_KEY_UNKNOWN


# --------------------------------------------------------------------------
# Positive composition proof: signed chain -> resolve -> verify_grant GREEN
# --------------------------------------------------------------------------

def test_end_to_end_approver_grant_accepted():
    root = Ed25519PrivateKey.generate()
    appr = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    nb, na = _window()
    tv = _trust_view(root, [
        _key_entry("appr-1", appr.public_key(), nb, na, role="approver"),
        _key_entry(GATE_KEY_ID, issuer.public_key(), nb, na, role="issuer"),
    ])
    resolved = resolve_approver_keys(tv, gate_key_id=GATE_KEY_ID, now=NOW)
    assert set(resolved.keys()) == {"appr-1"}
    grant = _signed_grant(appr, "appr-1")
    verdict = verify_grant(
        grant,
        expected_decision_sha256=DECISION,
        expected_approval_request_id=REQ_ID,
        approver_public_keys=resolved,
        gate_key_id=GATE_KEY_ID,
        now=NOW,
    )
    assert verdict["accepted"] is True
    assert verdict["reason"] == ACCEPT_GRANT_VALID


# --------------------------------------------------------------------------
# Pure-resolver hardening
# --------------------------------------------------------------------------

def test_non_dict_view_returns_empty():
    assert resolve_approver_keys(None, gate_key_id=GATE_KEY_ID) == {}
    assert resolve_approver_keys([], gate_key_id=GATE_KEY_ID) == {}


def test_malformed_entry_skipped_not_raised():
    view = {"appr-1": "not-a-dict", 42: {"role": "approver"}}
    assert resolve_approver_keys(view, gate_key_id=GATE_KEY_ID, now=NOW) == {}


def test_negative_clock_skew_rejected():
    try:
        resolve_approver_keys({}, gate_key_id=GATE_KEY_ID,
                              clock_skew=-timedelta(seconds=1))
    except ValueError:
        return
    assert False, "negative clock_skew must raise ValueError"


def test_clock_skew_widens_window():
    # An approver key that expired 10s ago is honored within a 30s skew window,
    # mirroring verify_envelope's VL-075 issuer-key widening.
    root = Ed25519PrivateKey.generate()
    appr = Ed25519PrivateKey.generate()
    tv = _trust_view(root, [_key_entry("appr-1", appr.public_key(),
                                       NOW - timedelta(days=1),
                                       NOW - timedelta(seconds=10),
                                       role="approver")])
    assert resolve_approver_keys(tv, gate_key_id=GATE_KEY_ID, now=NOW) == {}
    widened = resolve_approver_keys(tv, gate_key_id=GATE_KEY_ID, now=NOW,
                                    clock_skew=timedelta(seconds=30))
    assert set(widened.keys()) == {"appr-1"}
