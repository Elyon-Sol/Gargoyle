"""
B-prime-2 key-record reader for Elyon-Sol (VL-042, T-key-record). Repo path:
IMPLEMENTATION/key_record_source.py.

MIRRORS IMPLEMENTATION/published_source.py (the B-prime-1 hash-record reader)
as a SIBLING module, not an extension (09_key_record_spec.md sections 7, 15).
The two share a three-layer SHAPE but not a trust primitive:

  - B-prime-1 pins the sha256 of the record BYTES (anchor_sha256). That cannot
    serve a record that CHANGES, because every revocation would force
    re-pinning out-of-band - back to the N-pin redistribution this increment
    exists to escape.
  - B-prime-2 pins a root PUBLIC KEY and verifies a publisher SIGNATURE, so the
    record may change (revoke, bump serial, reissue) under a STABLE pin.

It also differs in import profile (published_source.py is cryptography-free;
this reader must reconstruct public keys, so it imports cryptography here -
keeping verifier.py / envelope.py import-clean, decision 2) and in return
contract (published_source.py returns dict-or-None; this reader discriminates
RECORD_INVALID from RECORD_STALE, decisions 2 and 5).

Three layers, mirroring published_source.py:
  load_key_record_from_bytes() - the pure, network-free trust check (verify
      publisher signature -> freshness -> build the per-key trust view). The
      load-bearing, deterministically testable layer (now is injectable).
  fetch_key_record()           - the transport: requests.get over loopback,
      then load_key_record_from_bytes. The only network-touching layer;
      fail-closed on any connection / non-200 / timeout.

The pinned root, like B-prime-1's pinned anchor, is held OUT-OF-BAND and is
NEVER fetched alongside the record (that would be circular).

REF_VERIFY_KEY_* codes: verifier.py is the canonical home of the full
REF_VERIFY_* namespace. This reader EMITS two of them
(REF_VERIFY_KEY_RECORD_INVALID, REF_VERIFY_KEY_RECORD_STALE) and IMPORTS them
from verifier.py for a single source of truth. The other three (UNKNOWN /
REVOKED / OUT_OF_WINDOW) are decided in verify_envelope at trust-view lookup,
not here.
"""

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import requests

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# REF_VERIFY_KEY_RECORD_* are defined canonically in verifier.py (the
# REF_VERIFY_* home, mirroring how request_validator.py owns REF_SCHEMA_* even
# for the code pep.py emits). The reader EMITS these two and imports them so
# there is a single source of truth. No cycle: verifier imports envelope, not
# this module. INTEGRATION ORDER: apply the verifier.py VL-042 edits (which add
# these codes) before placing this reader.
from IMPLEMENTATION.verifier import (
    REF_VERIFY_KEY_RECORD_INVALID,
    REF_VERIFY_KEY_RECORD_STALE,
    REF_VERIFY_ROOT_REVOKED,
    REF_VERIFY_ROOT_RETIRED,
    REF_VERIFY_ROOT_OUT_OF_WINDOW,
)

KEY_RECORD_FORMAT = "elyon-sol-key-record"
_SIGNATURE_FIELD = "publisher_signature"
_REQUIRED_RECORD_KEYS = (
    "format", "version", "root_key_id", "serial",
    "issued_at", "not_after", "keys", _SIGNATURE_FIELD,
)
_REQUIRED_KEY_FIELDS = ("key_id", "public_key", "not_before", "not_after",
                        "revoked")

# canonical_json is REUSED from envelope.py so reader-side canonicalization
# matches the gen/sign side exactly (prefix-ful import per VL-027). INTEGRATION
# CHECK: verify this import resolves in the real environment before trusting
# the module (VL-027 - an unseen import surfaces only at runtime).
from IMPLEMENTATION.envelope import canonical_json


def _reject(reason: str) -> Dict[str, Any]:
    return {"trust_view": None, "reason": reason}


def _parse_aware(value: Any) -> datetime:
    """
    Parse an ISO-8601 timestamp to a tz-AWARE datetime. Raises ValueError on a
    non-string, an unparseable string, or a tz-naive result. Accepts a trailing
    Z by normalizing to +00:00.
    """
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
    """
    The pure, network-free trust check. Returns
    {"trust_view": <dict>, "reason": None} on success, or
    {"trust_view": None, "reason": <REF_VERIFY_KEY_RECORD_*>} on any fault.

    Order (each step fail-closed, 09_key_record_spec.md sections 5-7):
      1. parse JSON + structural validation        -> RECORD_INVALID
      2. select pinned root by root_key_id          -> RECORD_INVALID (unknown)
      3. verify publisher_signature vs pinned root  -> RECORD_INVALID
      4. freshness: now < not_after + clock_skew;
         serial monotonic if last_seen given        -> RECORD_STALE
      5. build per-key trust view (reconstruct keys) -> RECORD_INVALID on bad
         key material / naive or unparseable window

    clock_skew (VL-075, B2; spec 15_clock_skew_tolerance_spec.md): a non-negative
    tolerance for cross-host clock divergence. The RECORD-level freshness check
    becomes now < not_after + clock_skew (default timedelta(0) -> the strict
    pre-VL-075 check). The per-key validity windows in the trust view are stored
    raw and time-checked (skew-adjusted) at the verifier consume side. A negative
    value narrows the window (a config error) and raises ValueError.

    When root_status_view (VL-044) is supplied, step 2 also gates the SIGNING
    root's status: a revoked root refuses (REF_VERIFY_ROOT_REVOKED), a retired
    root refuses a NEW record (REF_VERIFY_ROOT_RETIRED; issued_at >= retired_at)
    while past records age via freshness, and a designated-active successor's key
    comes from the view. The signing root's own validity WINDOW from the view is
    enforced too (REF_VERIFY_ROOT_OUT_OF_WINDOW): `now` and the key record's
    issued_at must both fall inside [not_before - clock_skew, not_after +
    clock_skew) - a root signs nothing before its window opens, and nothing it
    signed is trusted once the window has closed (the X.509 chain rule; the
    per-key KEY_OUT_OF_WINDOW analog one layer up). root_status_view=None is
    VL-042 byte-behavior.

    The trust view carries STATUS per key (decision 2: richer view) so
    verify_envelope can later discriminate UNKNOWN / REVOKED / OUT_OF_WINDOW:
        {key_id: {"public_key": <obj>, "revoked": <bool>,
                  "not_before": <aware dt>, "not_after": <aware dt>,
                  "role": <str or None>}}   # role: VL-119 R1, optional, signed
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

    # 2. select the signing root. When a validated root_status_view is supplied
    # (VL-044), it is AUTHORITATIVE and supersedes a bare pin (so a pin cannot
    # silently defeat a root revocation - the artifact 09 decision-3 precedence,
    # one layer up). A root present in the view is gated by its status: revoked
    # refuses, retired refuses a NEW record (issued_at >= retired_at) while
    # honoring past ones, active proceeds with the view's key. A root absent from
    # the view but pinned is active-by-pinning (the bootstrap default). Neither ->
    # unknown signing root, folded to RECORD_INVALID. With root_status_view=None
    # this is byte-identical to the VL-042 pinned-only selection.
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
        # Per-root validity window (VL-154 open item; 11_root_record_spec.md
        # sections 6.1 / 8 / 9). The view parsed the window; this is the
        # consuming layer that compares it. Both `now` and the record's
        # issued_at must be inside the (skew-widened) window: before
        # not_before the root had no authority to sign; after not_after
        # nothing it signed is trusted any longer. Missing or unparseable
        # bounds fail closed.
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
        # tz-naive not_after fails closed to STALE (cannot safely compare);
        # a non-parseable not_after is structural -> but treated here uniformly
        # as STALE per spec section 5 freshness ownership of the field.
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
            # VL-119 (R1, [FIX H5] provenance+role): surface the signed key
            # entry's OPTIONAL role so the approver-trust resolver can enforce
            # role-distinctness from the SIGNED record. The publisher signs the
            # whole record (this entry included), so the role is signature-
            # provenanced. Absent -> None (role-less, pre-VL-119 behavior); a
            # role-less key is never an approver (fail-closed at the resolver).
            "role": entry.get("role"),
        }

    # SES-9a: surface the validated record's SERIAL (additive; the signed
    # region includes it, verified above) so a consumer can keep a monotonic
    # high-water mark across fetches - the SES-8 rollback defense the signed
    # HASH record path already has. Absent from the _reject shape; consumers
    # read it with .get(). trust_view/reason contract unchanged.
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
    """
    Fetch the key record over HTTP, then run the pure trust check.

    Cross-host is modeled with loopback (the B-prime-1 transport model; true
    multi-machine + TLS is G5 / deployment). Any transport failure (connection,
    non-200, timeout) fails closed to RECORD_INVALID - the target refuses
    rather than proceeding without a validated record (canon section 9). The
    bytes are not trusted until the publisher signature verifies against the
    pinned root the target holds out-of-band.

    root_status_view (VL-049, additive; default None = VL-042 byte-behavior) is
    threaded to load_key_record_from_bytes so a target can validate a fetched
    key record against a root-status view obtained by fetching the root record
    first (the planned-rotation chain): a key record signed by a designated-
    active successor is honored, a revoked/retired signing root is refused. The
    validation logic in load_key_record_from_bytes is unchanged; only this
    transport wrapper threads the view.
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
