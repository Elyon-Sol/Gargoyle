"""Approver CLI: the human side of an approval hold.

A grant only separates duties if a human produces it out of band, with a key
the issuing service cannot reach. This is that tool, kept minimal: it shows
the human exactly which held decision they are releasing and, on
confirmation, emits a signed grant.

Run it as a separate process that holds the approver private key; the
issuing service holds only the approver public key. make_grant() is the
testable core and main() the thin CLI around it. Grants are built and signed
by gargoyle.approval, so what this emits is exactly what verify_grant
accepts.
"""

import argparse
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from gargoyle.approval import build_grant, sign_grant


def make_grant(
    *,
    approver_private_hex: str,
    approver_key_id: str,
    decision_sha256: str,
    approval_request_id: str,
    not_after_seconds: int = 300,
    grant_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build and sign an approval grant for a held decision. The private key
    is raw Ed25519 bytes in hex, used only here and never returned or logged.
    grant_id defaults to a fresh uuid; it is the grant's single-use key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(approver_private_hex))
    base = now if now is not None else datetime.now(timezone.utc)
    grant = build_grant(
        decision_sha256=decision_sha256,
        approval_request_id=approval_request_id,
        grant_id=grant_id or uuid.uuid4().hex,
        not_after=base + timedelta(seconds=not_after_seconds),
    )
    return sign_grant(grant, signing_key, approver_key_id)


def main(argv=None) -> int:
    """Read a pending-approval hold (JSON with approval_request_id and
    decision_sha256) from --pending or stdin, show the human what they are
    releasing, and on confirmation print the signed grant JSON to stdout.

    The approver key comes from the environment (GARGOYLE_APPROVER_KEY_HEX +
    GARGOYLE_APPROVER_KEY_ID) so it is never passed on the command line. --yes
    skips the interactive confirm (for scripted approver workflows)."""
    import os

    parser = argparse.ArgumentParser(
        prog="approver_cli",
        description="Emit a signed approval grant for a gate-held decision.",
    )
    parser.add_argument("--pending", help="file with the 202 JSON; default stdin")
    parser.add_argument("--ttl", type=int, default=300, help="grant lifetime (s)")
    parser.add_argument("--yes", action="store_true", help="skip the confirm prompt")
    args = parser.parse_args(argv)

    raw = open(args.pending).read() if args.pending else sys.stdin.read()
    pending = json.loads(raw)
    decision_sha256 = pending["decision_sha256"]
    approval_request_id = pending["approval_request_id"]

    key_hex = os.environ.get("GARGOYLE_APPROVER_KEY_HEX")
    key_id = os.environ.get("GARGOYLE_APPROVER_KEY_ID")
    if not key_hex or not key_id:
        print("GARGOYLE_APPROVER_KEY_HEX and GARGOYLE_APPROVER_KEY_ID must be set",
              file=sys.stderr)
        return 2

    # Show the human exactly what they are releasing.
    sys.stderr.write(
        "About to APPROVE a held high-impact decision:\n"
        "  decision_sha256     : %s\n"
        "  approval_request_id : %s\n" % (decision_sha256, approval_request_id)
    )
    if not args.yes:
        sys.stderr.write("Type 'approve' to sign a grant: ")
        sys.stderr.flush()
        if sys.stdin.readline().strip() != "approve":
            print("aborted (no grant emitted)", file=sys.stderr)
            return 1

    grant = make_grant(
        approver_private_hex=key_hex,
        approver_key_id=key_id,
        decision_sha256=decision_sha256,
        approval_request_id=approval_request_id,
        not_after_seconds=args.ttl,
    )
    print(json.dumps(grant))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
