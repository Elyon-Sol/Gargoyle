"""Key records: a root-signed list of issuer (and approver) keys.

A target pins one root PUBLIC key out of band. The publisher signs a record
listing keys with their validity windows, revocation flags and optional
roles. Because trust rests on the root's signature rather than on the
record's bytes, the record can change (revoke a key, add one, bump the
serial) without re-pinning every target. The root key is never fetched with
the record; that would be circular.

  load_key_record_from_bytes() - the pure trust check: signature, freshness,
      then the per-key trust view. `now` is injectable for tests.
  fetch_key_record()           - HTTP GET, then the trust check. Any transport
      failure refuses.

This reader emits REF_VERIFY_KEY_RECORD_INVALID / _STALE and the root-status
refusals. Whether a particular key is unknown, revoked or out of window is
decided later, in verifier.verify_envelope, from the trust view.
"""

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import requests

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Refusal codes live in verifier.py. No import cycle: verifier imports
# envelope, not this module.
from gargoyle.verifier import (
    REF_VERIFY_KEY_RECORD_INVALID,
    REF_VERIFY_KEY_RECORD_STALE,
    REF_VERIFY_ROOT_REVOKED,
    REF_VERIFY_ROOT_RETIRED,
    REF_VERIFY_ROOT_OUT_OF_WINDOW,
)

KEY_RECORD_FORMAT = "gargoyle-key-record"
_SIGNATURE_FIELD = "publisher_signature"
_REQUIRED_RECORD_KEYS = (
    "format", "version", "root_key_id", "serial",
    "issued_at", "not_after", "keys", _SIGNATURE_FIELD,
)
_REQUIRED_KEY_FIELDS = ("key_id", "public_key", "not_before", "not_after",
                        "revoked")

# The same serializer the publisher signs with, so signatures verify byte for byte.
from gargoyle.envelope import canonical_json


def _reject(reason: str) -> Dict[str, Any]:
    return {"trust_view": None, "reason": reason}


def _parse_aware(value: Any) -> datetime:
    """ISO-8601 to a timezone-aware datetime. Raises ValueError on a
    non-string, an unparseable string or a naive result. Accepts a trailing Z."""
    if not isinstance(value, str):
        raise ValueError("timestamp not a string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    dt = datetime.fromisoformat(text)  # raises ValueError on bad format
    if dt.tzinfo is None:
        raise ValueError("timestamp is tz-naive")
    return dt


def _structurally_valid(record: Any) -> bool:
    if not isinstance(record, dict):
        return False
    for key in _REQUIRED_RECORD_KEYS:
        if key not in record:
            return False
    if record.get("format") != KEY_RECORD_FORMAT:
        return False
    if not isinstance(record.get("root_key_id"), str):
        return False
    if not isinstance(record.get("serial"), int) or isinstance(
        record.get("serial"), bool
    ):
        return False
    if not isinstance(record.get("publisher_signature"), str):
        return False
    if not isinstance(record.get("keys"), list):
        return False
    return True


def load_key_record_from_bytes(
    record_bytes: bytes,
    pinned_root_keys: Dict[str, Any],
    now: Optional[datetime] = None,
    last_seen_serial: Optional[int] = None,
    root_status_view: Optional[Dict[str, Any]] = None,
    clock_skew: timedelta = timedelta(0),
) -> Dict[str, Any]:
    """The pure trust check. Returns {"trust_view": dict, "reason": None,
    "serial": int} on success, or {"trust_view": None, "reason": code}.

    Order, each step failing closed:
      1. parse JSON and check structure             -> RECORD_INVALID
      2. select the signing root by root_key_id      -> RECORD_INVALID if unknown
      3. verify publisher_signature with that root   -> RECORD_INVALID
      4. freshness: now < not_after + clock_skew, and
         serial >= last_seen_serial when given       -> RECORD_STALE
      5. build the per-key trust view                -> RECORD_INVALID on bad
         key material or an unparseable window

    clock_skew (non-negative; negative raises ValueError) widens the record's
    freshness check. Per-key windows are stored as parsed and checked, with
    the same skew, by the verifier.

    root_status_view, when given, is authoritative for roots it lists: a
    revoked root refuses (ROOT_REVOKED); a retired root refuses records issued
    at or after its retirement (ROOT_RETIRED) while older ones age out through
    freshness; and both `now` and the record's issued_at must fall inside the
    root's own skew-widened validity window (ROOT_OUT_OF_WINDOW), because a
    root has no authority before its window opens and nothing it signed is
    trusted after it closes.

    Trust view shape, one entry per key:
        {key_id: {"public_key", "revoked", "not_before", "not_after", "role"}}
    """
    if clock_skew < timedelta(0):
        raise ValueError("clock_skew must be non-negative")
    if now is None:
        now = datetime.now(timezone.utc)
    if not isinstance(pinned_root_keys, dict) or not pinned_root_keys:
        return _reject(REF_VERIFY_KEY_RECORD_INVALID)

    # 1. parse + structure
    try:
        record = json.loads(record_bytes)
    except (json.JSONDecodeError, ValueError):
        return _reject(REF_VERIFY_KEY_RECORD_INVALID)
    if not _structurally_valid(record):
        return _reject(REF_VERIFY_KEY_RECORD_INVALID)

    # 2. select the signing root. A root listed in root_status_view is governed
    # by the view, not the bare pin, so a stale pin cannot override a root
    # revocation. A root not in the view but pinned is trusted as pinned. A
    # root in neither is unknown: RECORD_INVALID.
    if root_status_view is not None and record["root_key_id"] in root_status_view:
        rinfo = root_status_view[record["root_key_id"]]
        rstatus = rinfo.get("status")
        if rstatus == "revoked":
            return _reject(REF_VERIFY_ROOT_REVOKED)
        if rstatus == "retired":
            retired_at = rinfo.get("retired_at")
            try:
                issued_at = _parse_aware(record["issued_at"])
            except (ValueError, TypeError, KeyError):
                return _reject(REF_VERIFY_ROOT_RETIRED)
            if retired_at is None or not (issued_at < retired_at):
                return _reject(REF_VERIFY_ROOT_RETIRED)
        elif rstatus != "active":
            return _reject(REF_VERIFY_KEY_RECORD_INVALID)
        # The root's own validity window: both `now` and the record's issued_at
        # must be inside it. Missing bounds refuse.
        root_not_before = rinfo.get("not_before")
        root_not_after = rinfo.get("not_after")
        if root_not_before is None or root_not_after is None:
            return _reject(REF_VERIFY_ROOT_OUT_OF_WINDOW)
        try:
            issued_at = _parse_aware(record["issued_at"])
        except (ValueError, TypeError, KeyError):
            return _reject(REF_VERIFY_KEY_RECORD_INVALID)
        window_open = root_not_before - clock_skew
        window_close = root_not_after + clock_skew
        for moment in (now, issued_at):
            if not (window_open <= moment < window_close):
                return _reject(REF_VERIFY_ROOT_OUT_OF_WINDOW)
        root_key = rinfo.get("public_key")
        if root_key is None:
            return _reject(REF_VERIFY_KEY_RECORD_INVALID)
    else:
        root_key = pinned_root_keys.get(record["root_key_id"])
        if root_key is None:
            return _reject(REF_VERIFY_KEY_RECORD_INVALID)

    # 3. publisher signature over canonical_json(record minus signature)
    unsigned = {k: v for k, v in record.items() if k != _SIGNATURE_FIELD}
    try:
        signature = bytes.fromhex(record[_SIGNATURE_FIELD])
    except (ValueError, TypeError):
        return _reject(REF_VERIFY_KEY_RECORD_INVALID)
    message = canonical_json(unsigned).encode("utf-8")
    try:
        root_key.verify(signature, message)
    except InvalidSignature:
        return _reject(REF_VERIFY_KEY_RECORD_INVALID)
    except Exception:
        return _reject(REF_VERIFY_KEY_RECORD_INVALID)

    # 4. freshness: record not_after, then serial rollback if state persisted
    try:
        record_not_after = _parse_aware(record["not_after"])
    except ValueError:
        # A naive or unparseable not_after cannot be compared safely: refuse
        # as STALE.
        return _reject(REF_VERIFY_KEY_RECORD_STALE)
    if not (now < record_not_after + clock_skew):
        return _reject(REF_VERIFY_KEY_RECORD_STALE)
    if last_seen_serial is not None and record["serial"] < last_seen_serial:
        return _reject(REF_VERIFY_KEY_RECORD_STALE)

    # 5. build the per-key trust view
    trust_view: Dict[str, Dict[str, Any]] = {}
    for entry in record["keys"]:
        if not isinstance(entry, dict):
            return _reject(REF_VERIFY_KEY_RECORD_INVALID)
        for field in _REQUIRED_KEY_FIELDS:
            if field not in entry:
                return _reject(REF_VERIFY_KEY_RECORD_INVALID)
        if not isinstance(entry["key_id"], str):
            return _reject(REF_VERIFY_KEY_RECORD_INVALID)
        if not isinstance(entry["revoked"], bool):
            return _reject(REF_VERIFY_KEY_RECORD_INVALID)
        try:
            raw = base64.b64decode(entry["public_key"], validate=True)
            public_key = Ed25519PublicKey.from_public_bytes(raw)
            not_before = _parse_aware(entry["not_before"])
            key_not_after = _parse_aware(entry["not_after"])
        except (ValueError, TypeError, base64.binascii.Error):
            return _reject(REF_VERIFY_KEY_RECORD_INVALID)
        except Exception:
            return _reject(REF_VERIFY_KEY_RECORD_INVALID)
        trust_view[entry["key_id"]] = {
            "public_key": public_key,
            "revoked": entry["revoked"],
            "not_before": not_before,
            "not_after": key_not_after,
            # Optional role, covered by the record signature, so approver and
            # issuer keys can be kept apart. A key with no role is never
            # accepted as an approver (approver_trust) and is treated as an
            # issuer key (verifier).
            "role": entry.get("role"),
        }

    # Return the signed serial so a consumer can keep a high-water mark across
    # fetches and refuse a rolled-back record. Refusals carry no serial.
    return {"trust_view": trust_view, "reason": None, "serial": record["serial"]}


def fetch_key_record(
    publisher_url: str,
    pinned_root_keys: Dict[str, Any],
    now: Optional[datetime] = None,
    last_seen_serial: Optional[int] = None,
    root_status_view: Optional[Dict[str, Any]] = None,
    timeout: int = 10,
    clock_skew: timedelta = timedelta(0),
) -> Dict[str, Any]:
    """Fetch the key record over HTTP, then run load_key_record_from_bytes.

    Any transport failure (connection error, non-200, timeout) refuses with
    RECORD_INVALID. The bytes are untrusted until the signature verifies
    against the pinned root. root_status_view is passed through, so a target
    that fetched the root record first can follow a root rotation.
    """
    try:
        response = requests.get(publisher_url, timeout=timeout)
    except Exception:
        return _reject(REF_VERIFY_KEY_RECORD_INVALID)
    if response.status_code != 200:
        return _reject(REF_VERIFY_KEY_RECORD_INVALID)
    return load_key_record_from_bytes(
        response.content, pinned_root_keys, now=now,
        last_seen_serial=last_seen_serial,
        root_status_view=root_status_view,
        clock_skew=clock_skew,
    )
