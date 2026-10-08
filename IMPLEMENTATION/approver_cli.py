"""
Approver CLI - the minimal human surface for governance Feature 1 ([FIX H5]).

The whole point of the approval grant is that it is produced OUT-OF-BAND, by a
human, with a key the gate cannot reach. This is that surface, deliberately
minimal: it shows the human exactly what they are releasing (the decision the
gate held) and, on their action, emits a signed grant the gate will verify.

It is a SEPARATE process holding the approver PRIVATE key (never the gate's, and
never in the repo). The gate holds only the approver public key. make_grant() is
the testable core; main() is the thin CLI around it.

reuse, not re-implement: the grant is built and signed by IMPLEMENTATION.approval
(the same Ed25519 + binding the gate verifies), so a grant this CLI emits is
exactly what verify_grant accepts.
"""

import argparse
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from IMPLEMENTATION.approval import build_grant, sign_grant


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
    """Build + sign an approval grant for a held decision. The private key is
    supplied as hex (Ed25519 raw private bytes) and used only here; it is never
    returned or logged. grant_id defaults to a fresh uuid (mandatory single-use
    key, [FIX H3])."""
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
    """Read a gate 202 PENDING_APPROVAL response (JSON: approval_request_id +
    decision_sha256) from --pending (a file) or stdin, show the human what they
    are releasing, and on confirmation emit the signed grant JSON to stdout.

    The approver key comes from the environment (ELYON_APPROVER_KEY_HEX +
    ELYON_APPROVER_KEY_ID) so it is never passed on the command line. --yes
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

    key_hex = os.environ.get("ELYON_APPROVER_KEY_HEX")
    key_id = os.environ.get("ELYON_APPROVER_KEY_ID")
    if not key_hex or not key_id:
        print("ELYON_APPROVER_KEY_HEX and ELYON_APPROVER_KEY_ID must be set",
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
