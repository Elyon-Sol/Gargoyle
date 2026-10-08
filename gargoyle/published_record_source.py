"""Signed published-record reader: a record that can be reissued and goes stale.

published_source pins the SHA-256 of a record's bytes. That pin has no time
dimension: an old record that still matches the anchor is honored forever,
and every reissue needs a new anchor on every target. This reader pins a
publisher public key instead and verifies a publisher signature over a
record carrying a serial and a not_after, so the publisher can reissue under
a stable pin and a stale or rolled-back record is refused
(REF_VERIFY_PUBLISHED_RECORD_STALE).

The pinned publisher key is held out-of-band and is never fetched alongside
the record, which would be circular. canonical_json is shared with the
signing side so both sign and verify the same bytes. The refusal codes are
defined in verifier.py and imported here.

Returns {"record": <dict>, "reason": None} on success, or
{"record": None, "reason": REF_VERIFY_PUBLISHED_RECORD_*}. A successful
record carries policy_id / policy_sha256 and can be passed straight to
envelope.reassert(record_source=...).
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature

from gargoyle.transport import get_published

from gargoyle.verifier import (
    REF_VERIFY_PUBLISHED_RECORD_INVALID,
    REF_VERIFY_PUBLISHED_RECORD_STALE,
)

# Shared with the signing side so both canonicalize identically.
from gargoyle.envelope import canonical_json

PUBLISHED_RECORD_FORMAT = "gargoyle-published-record"
_SIGNATURE_FIELD = "publisher_signature"

# Structural keys the signed record must carry.
_REQUIRED_RECORD_KEYS = (
    "format", "version", "publisher_key_id", "serial",
    "issued_at", "not_after", _SIGNATURE_FIELD,
)
# The policy pin the record must carry, matching a receipt's policy block.
_REQUIRED_PIN_KEYS = (
    "policy_id",
    "policy_sha256",
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
    """The network-free trust check. Each step fails closed, in order:

      1. parse JSON and check structure            -> PUBLISHED_RECORD_INVALID
      2. select the pinned publisher key by id      -> PUBLISHED_RECORD_INVALID
      3. verify publisher_signature                 -> PUBLISHED_RECORD_INVALID
      4. now < not_after + clock_skew, and serial
         not below last_seen_serial when given      -> PUBLISHED_RECORD_STALE

    The signature is checked before freshness, so nothing in an unsigned
    record is believed. A tz-naive or unparseable not_after is STALE, since it
    cannot be compared safely. `clock_skew` tolerates cross-host clock drift;
    it must be non-negative (a negative value would be a config error and
    raises ValueError). `now` defaults to the current UTC time.
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

    # 4. freshness: not_after, then serial rollback when the caller keeps state
    try:
        record_not_after = _parse_aware(record["not_after"])
    except ValueError:
        return _reject(REF_VERIFY_PUBLISHED_RECORD_STALE)
    if not (now < record_not_after + clock_skew):
        return _reject(REF_VERIFY_PUBLISHED_RECORD_STALE)
    if last_seen_serial is not None and record["serial"] < last_seen_serial:
        return _reject(REF_VERIFY_PUBLISHED_RECORD_STALE)

    # 5. success: the validated record, carrying the policy pin
    return {"record": record, "reason": None}


def fetch_signed_record(
    publisher_url: str,
    pinned_publisher_keys: Dict[str, Any],
    now: Optional[datetime] = None,
    last_seen_serial: Optional[int] = None,
    timeout: int = 10,
    clock_skew: timedelta = timedelta(0),
) -> Dict[str, Any]:
    """Fetch the signed record over HTTP(S), then run the trust check. Any
    transport failure (connection error, timeout, non-200) is
    PUBLISHED_RECORD_INVALID: the target refuses rather than proceeding
    without a validated record."""
    try:
        # TLS settings come from gargoyle.transport (GARGOYLE_TLS_CA_BUNDLE).
        response = get_published(publisher_url, timeout=timeout)
    except Exception:
        return _reject(REF_VERIFY_PUBLISHED_RECORD_INVALID)
    if response.status_code != 200:
        return _reject(REF_VERIFY_PUBLISHED_RECORD_INVALID)
    return load_signed_record_from_bytes(
        response.content, pinned_publisher_keys, now=now,
        last_seen_serial=last_seen_serial, clock_skew=clock_skew,
    )
