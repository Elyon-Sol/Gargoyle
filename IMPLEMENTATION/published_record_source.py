"""
B-prime-1 SIGNED published-record reader for Elyon-Sol (VL-074, B1; the
A3b sub-case (b) record-freshness increment). Repo path:
IMPLEMENTATION/published_record_source.py.

MIRRORS IMPLEMENTATION/key_record_source.py (the B-prime-2 key-record reader)
as a SIBLING, applying the same signed-record trust model to the published
HASH record that published_source.py serves under the byte-anchor model:

  - B-prime-1 ORIGINAL (published_source.py) pins the sha256 of the record
    BYTES (anchor_sha256). That has NO temporal dimension: a stale-but-anchor-
    matching record is honored arbitrarily later (A3b sub-case (b), artifact 04
    G5 / A3b). It is left BYTE-UNCHANGED here (build-then-wire; its runners and
    tests are untouched).
  - B-prime-1 SIGNED (this module) pins a PUBLISHER PUBLIC KEY and verifies a
    publisher SIGNATURE over a record that carries serial + not_after, so the
    record may be reissued under a STABLE pin AND a stale record fails closed
    (REF_VERIFY_PUBLISHED_RECORD_STALE). This is the freshness B1 adds.

Like key_record_source.py it imports cryptography (to reconstruct the publisher
public key) and reuses canonical_json from envelope.py so the gen-side and
reader-side canonicalization match exactly. The pinned publisher key, like the
B-prime-1 anchor and the B-prime-2 root, is held OUT-OF-BAND and is NEVER
fetched alongside the record (that would be circular).

REF_VERIFY_PUBLISHED_RECORD_* codes: verifier.py is the canonical home of the
REF_VERIFY_* namespace. This reader EMITS the two
(REF_VERIFY_PUBLISHED_RECORD_INVALID, REF_VERIFY_PUBLISHED_RECORD_STALE) and
IMPORTS them from verifier.py for a single source of truth. No import cycle:
verifier imports envelope, not this module.

Return contract (parity with key_record_source.py's discriminating reader):
  {"record": <currency dict>, "reason": None}             on success
  {"record": None, "reason": <REF_VERIFY_PUBLISHED_RECORD_*>}  on any fault
On success "record" is the validated record dict, which carries the three
currency pins (canon_sha256 / evaluator_sha256 / manifest_sha256) that
envelope.reassert(record_source=...) consults, so it is a drop-in record_source
once a caller chooses to use it (the wiring step, a later increment).
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature

from IMPLEMENTATION.transport import get_published

from IMPLEMENTATION.verifier import (
    REF_VERIFY_PUBLISHED_RECORD_INVALID,
    REF_VERIFY_PUBLISHED_RECORD_STALE,
)

# canonical_json REUSED from envelope.py so reader-side canonicalization matches
# the gen/sign side exactly (prefix-ful import per VL-027).
from IMPLEMENTATION.envelope import canonical_json

PUBLISHED_RECORD_FORMAT = "elyon-sol-published-record"
_SIGNATURE_FIELD = "publisher_signature"

# Structural envelope keys the signed record must carry.
_REQUIRED_RECORD_KEYS = (
    "format", "version", "publisher_key_id", "serial",
    "issued_at", "not_after", _SIGNATURE_FIELD,
)
# The three currency pins the record must carry (parity with
# EVIDENCE/published_hashes_gen.py and build_envelope's pins).
_REQUIRED_PIN_KEYS = (
    "canon_sha256",
    "evaluator_sha256",
    "manifest_sha256",
)


def _reject(reason: str) -> Dict[str, Any]:
    return {"record": None, "reason": reason}


def _parse_aware(value: Any) -> datetime:
    """ISO-8601 -> tz-AWARE datetime; raises ValueError on non-string,
    unparseable, or tz-naive. Accepts a trailing Z."""
    if not isinstance(value, str):
        raise ValueError("timestamp not a string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError("timestamp is tz-naive")
    return dt


def _structurally_valid(record: Any) -> bool:
    if not isinstance(record, dict):
        return False
    for key in _REQUIRED_RECORD_KEYS:
        if key not in record:
            return False
    if record.get("format") != PUBLISHED_RECORD_FORMAT:
        return False
    if not isinstance(record.get("publisher_key_id"), str):
        return False
    if not isinstance(record.get("serial"), int) or isinstance(
        record.get("serial"), bool
    ):
        return False
    if not isinstance(record.get(_SIGNATURE_FIELD), str):
        return False
    for key in _REQUIRED_PIN_KEYS:
        if not isinstance(record.get(key), str):
            return False
    return True


def load_signed_record_from_bytes(
    record_bytes: bytes,
    pinned_publisher_keys: Dict[str, Any],
    now: Optional[datetime] = None,
    last_seen_serial: Optional[int] = None,
    clock_skew: timedelta = timedelta(0),
) -> Dict[str, Any]:
    """
    The pure, network-free trust check (mirror of
    key_record_source.load_key_record_from_bytes). Order, each step fail-closed:

      1. parse JSON + structural validation        -> PUBLISHED_RECORD_INVALID
      2. select pinned publisher key by id          -> PUBLISHED_RECORD_INVALID
      3. verify publisher_signature vs pinned key    -> PUBLISHED_RECORD_INVALID
      4. freshness: now < not_after + clock_skew;
         serial monotonic if last_seen given         -> PUBLISHED_RECORD_STALE
      5. return the validated record dict (carries the three currency pins).

    A tz-naive / unparseable not_after fails closed to STALE (it cannot be
    safely compared and the freshness field owns the field, parity with the
    key reader). now defaults to datetime.now(timezone.utc).

    clock_skew (VL-075, B2; spec 15_clock_skew_tolerance_spec.md): a non-negative
    tolerance for cross-host clock divergence. The record-level freshness check
    becomes now < not_after + clock_skew (default timedelta(0) -> the strict
    pre-VL-075 check, byte-behavior-identical). A negative value narrows the
    window (a config error) and raises ValueError.
    """
    if clock_skew < timedelta(0):
        raise ValueError("clock_skew must be non-negative")
    if now is None:
        now = datetime.now(timezone.utc)
    if not isinstance(pinned_publisher_keys, dict) or not pinned_publisher_keys:
        return _reject(REF_VERIFY_PUBLISHED_RECORD_INVALID)

    # 1. parse + structure
    try:
        record = json.loads(record_bytes)
    except (json.JSONDecodeError, ValueError):
        return _reject(REF_VERIFY_PUBLISHED_RECORD_INVALID)
    if not _structurally_valid(record):
        return _reject(REF_VERIFY_PUBLISHED_RECORD_INVALID)

    # 2. select the signing publisher key by id
    publisher_key = pinned_publisher_keys.get(record["publisher_key_id"])
    if publisher_key is None:
        return _reject(REF_VERIFY_PUBLISHED_RECORD_INVALID)

    # 3. publisher signature over canonical_json(record minus signature)
    unsigned = {k: v for k, v in record.items() if k != _SIGNATURE_FIELD}
    try:
        signature = bytes.fromhex(record[_SIGNATURE_FIELD])
    except (ValueError, TypeError):
        return _reject(REF_VERIFY_PUBLISHED_RECORD_INVALID)
    message = canonical_json(unsigned).encode("utf-8")
    try:
        publisher_key.verify(signature, message)
    except InvalidSignature:
        return _reject(REF_VERIFY_PUBLISHED_RECORD_INVALID)
    except Exception:
        return _reject(REF_VERIFY_PUBLISHED_RECORD_INVALID)

    # 4. freshness: record not_after, then serial rollback if state persisted
    try:
        record_not_after = _parse_aware(record["not_after"])
    except ValueError:
        return _reject(REF_VERIFY_PUBLISHED_RECORD_STALE)
    if not (now < record_not_after + clock_skew):
        return _reject(REF_VERIFY_PUBLISHED_RECORD_STALE)
    if last_seen_serial is not None and record["serial"] < last_seen_serial:
        return _reject(REF_VERIFY_PUBLISHED_RECORD_STALE)

    # 5. success: the validated record (carries the three currency pins)
    return {"record": record, "reason": None}


def fetch_signed_record(
    publisher_url: str,
    pinned_publisher_keys: Dict[str, Any],
    now: Optional[datetime] = None,
    last_seen_serial: Optional[int] = None,
    timeout: int = 10,
    clock_skew: timedelta = timedelta(0),
) -> Dict[str, Any]:
    """
    Fetch the signed published record over HTTP, then run the pure trust check.
    Cross-host is modeled with loopback (the B-prime-1/2 transport model; true
    multi-machine + TLS is G5 / deployment). Any transport failure (connection,
    non-200, timeout) fails closed to PUBLISHED_RECORD_INVALID - the target
    refuses rather than proceeding without a validated record (canon section 9).
    """
    try:
        # TLS-aware transport seam (VL-039): resolves ELYON_TLS_CA_BUNDLE fail-closed, so
        # signed mode works over the real cross-host TLS deployment (parity with the
        # byte-anchor fetch_published_record).
        response = get_published(publisher_url, timeout=timeout)
    except Exception:
        return _reject(REF_VERIFY_PUBLISHED_RECORD_INVALID)
    if response.status_code != 200:
        return _reject(REF_VERIFY_PUBLISHED_RECORD_INVALID)
    return load_signed_record_from_bytes(
        response.content, pinned_publisher_keys, now=now,
        last_seen_serial=last_seen_serial, clock_skew=clock_skew,
    )
