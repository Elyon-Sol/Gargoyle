"""Fetch a published policy record and verify it against a pinned anchor.

A target on another host cannot trust its own disk for the live policy pin.
Instead it fetches a published record {policy_id, policy_sha256} and checks
receipts against that (envelope.reassert(record_source=...)). The record is
trusted only if the SHA-256 of its raw bytes equals an anchor the target was
given out-of-band. The anchor is never fetched alongside the record, which
would be circular.

This reduces the target's trust to one pinned anchor plus the channel; it
does not remove trust. Still outside this module: distributing the anchor
securely, and record freshness (a stale record that still matches the anchor
is accepted here; the signed reader in published_record_source handles
freshness and rollback).

anchor_sha256()          SHA-256 of the record bytes.
load_record_from_bytes() verify the anchor, then parse; network-free.
fetch_published_record() HTTP GET, then load_record_from_bytes.
"""

import hashlib
import json
from typing import Any, Dict, Optional

from gargoyle.transport import get_published


# The pin keys a record must carry, matching a receipt's policy block.
_REQUIRED_RECORD_KEYS = (
    "policy_id",
    "policy_sha256",
)


def anchor_sha256(record_bytes: bytes) -> str:
    """SHA-256 hex digest of a record's raw bytes. Compute the target's
    pinned value from the actual published bytes, never by hand."""
    return hashlib.sha256(record_bytes).hexdigest()


def load_record_from_bytes(
    record_bytes: bytes,
    pinned_root_sha256: str,
) -> Optional[Dict[str, Any]]:
    """Return the record dict, or None to refuse.

    The anchor is checked before parsing: bytes that do not hash to the
    pinned anchor are never parsed or trusted. A record that does not parse
    or lacks a string policy_id / policy_sha256 is also None.
    """
    if not isinstance(pinned_root_sha256, str):
        return None
    if anchor_sha256(record_bytes) != pinned_root_sha256:
        return None
    try:
        record = json.loads(record_bytes)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(record, dict):
        return None
    for key in _REQUIRED_RECORD_KEYS:
        if key not in record or not isinstance(record[key], str):
            return None
    return record


def fetch_published_record(
    publisher_url: str,
    pinned_root_sha256: str,
    timeout: int = 10,
) -> Optional[Dict[str, Any]]:
    """Fetch a record over HTTP(S) and verify it against the pinned anchor.

    Any transport failure (connection error, timeout, non-200) returns None,
    so the target refuses rather than proceeding without an anchored record.
    """
    try:
        response = get_published(publisher_url, timeout=timeout)
    except Exception:
        return None
    if response.status_code != 200:
        return None
    return load_record_from_bytes(response.content, pinned_root_sha256)
