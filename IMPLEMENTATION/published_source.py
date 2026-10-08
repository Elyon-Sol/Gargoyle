"""
Cross-host published-record transport for Elyon-Sol (VL-039, T-G5-transport).

This module is the G5 increment: it lets a target on a different process or
host obtain Elyon-Sol's published hash record from a publisher and verify it
against a single pinned trust anchor, so the target's currency check (the
envelope's pinned canon / evaluator / manifest hashes) can be performed
against the FETCHED record rather than the target's own local disk
(Decision C). It is the cross-host counterpart of the test-scope
published-source reader VL-038 carried inside
TESTS/adversarial/test_enforcement.py; promotion to IMPLEMENTATION/ is the
G5 transport step that VL-038 named, not built (artifact 08 section 6;
04_current_vs_claimed.md G5 row).

==============================================================
The trust bootstrap (Decision B-prime-1: pinned root hash)
==============================================================

G5 does NOT make verification trustless. Trust does not vanish; it
bootstraps. What this buys is reducing and making explicit the trust
surface: from "the target trusts its entire local working tree" down to
"the target trusts ONE pinned published-record anchor, distributed
out-of-band, plus transport integrity." The pinned anchor is the sha256 of
EVIDENCE/published_hashes.json, configured on the target out-of-band (it is
NOT fetched alongside the record - that would be circular). The hash chain
extends: CANON/canon.lock -> EVIDENCE/published_hashes.json -> the pinned
root the target holds.

What remains the G5 FLOOR, named not built (Decision F), parallel to the A1
floor (artifact 08 section 4.4): secure distribution of the pinned anchor
itself; record freshness / revocation (a stale-but-anchor-matching record is
a distinct threat); signing / PKI (which would remove per-target pinning);
TLS and true multi-machine networking (modeled here by loopback). Do not
overclaim "the target needs no trust"; claim "the target's trust is reduced
to one pinned anchor plus the channel."

==============================================================
Canon basis (no new invariant - canon section 14)
==============================================================

Fetching a record is verification I/O. The target still only verifies and
acts / refuses; it does not execute. This operationalizes canon section 11.9
("the manifest must be deterministic, versioned, and integrity-verifiable",
extended to the canon and evaluator hashes), canon section 13 (revalidation),
and canon section 8.2 ("the choice of anchoring system is
implementation-dependent and does not affect admissibility logic" - the
pinned-root anchor is exactly such an implementation-dependent choice). No
new canonical invariant is introduced (artifact 08 section 5).

==============================================================
Separation of concerns
==============================================================

anchor_sha256()          - the pinned-anchor primitive (pure over bytes).
load_record_from_bytes() - anchor-verify then parse (pure over bytes; the
                           load-bearing, network-free trust check; testable
                           deterministically).
fetch_published_record() - the transport: requests.get over loopback, then
                           load_record_from_bytes. The only part that touches
                           the network.

The currency check itself is NOT here: under Decision D-b it lives in
envelope.reassert(envelope, record_source=<fetched record>) and
verifier.verify_envelope(..., record_source=<fetched record>), reused as-is.
This module's job ends at handing back an anchor-verified record dict.
"""

import hashlib
import json
from typing import Any, Dict, Optional

from IMPLEMENTATION.transport import get_published


# The three pin keys the record carries (parity with
# EVIDENCE/published_hashes_gen.py's output and build_envelope's pins).
_REQUIRED_RECORD_KEYS = (
    "canon_sha256",
    "evaluator_sha256",
    "manifest_sha256",
)


def anchor_sha256(record_bytes: bytes) -> str:
    """
    The pinned-anchor primitive: SHA-256 hex digest of the published
    record's raw bytes. The target holds a pinned value of this for the
    authentic record (configured out-of-band, constraint (i): derived live
    from the actual EVIDENCE/published_hashes.json bytes, never hand-copied).
    """
    return hashlib.sha256(record_bytes).hexdigest()


def load_record_from_bytes(
    record_bytes: bytes,
    pinned_root_sha256: str,
) -> Optional[Dict[str, Any]]:
    """
    Anchor-verify a fetched published record, then parse it.

    This is the load-bearing, network-free trust check (Decision B-prime-1):

      1. Compute anchor_sha256(record_bytes) and compare to the pinned root.
         A mismatch means the fetched bytes are not the record the target
         was configured to trust -> return None (refuse; do NOT parse or
         trust an unanchored record).
      2. Parse JSON. A parse failure or a record missing a required pin key
         is unusable -> return None.
      3. Return the record dict (canon / evaluator / manifest version + sha).

    Returns the record dict on success, or None on anchor mismatch / parse
    failure / missing key. None is the caller's signal to refuse before
    trusting any currency claim.
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
    """
    Fetch the published record from a publisher over HTTP, then
    anchor-verify it against the pinned root.

    The transport models cross-host with loopback (127.0.0.1) per VL-039
    Decision B; true multi-machine and TLS are deployment (Decision F). Any
    transport failure (connection, non-200, timeout) returns None - the
    target refuses rather than proceeding without an anchored record
    (fail-closed, canon section 9).

    The anchor verification (load_record_from_bytes) is what makes the
    fetched bytes trustworthy; the bytes arriving over the wire are not
    trusted until their sha256 equals the pinned root the target holds
    out-of-band.
    """
    try:
        response = get_published(publisher_url, timeout=timeout)
    except Exception:
        return None
    if response.status_code != 200:
        return None
    return load_record_from_bytes(response.content, pinned_root_sha256)
