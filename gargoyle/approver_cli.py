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

Two ways in. From a file or stdin: the flagged receipt (or a bare hold)
is shown and, on confirmation, the grant is printed. Against an issuing
service (--issuer URL, with GARGOYLE_APPROVER_TOKEN for the Bearer): every
pending flagged receipt is fetched, shown one by one, and each confirmed
grant is posted back, so the middleware waiting on it proceeds.
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
    """Read the flagged receipt itself, or a bare hold (JSON with
    approval_request_id and decision_sha256), from --pending or stdin, show
    the human what they are releasing, and on confirmation print the signed
    grant JSON to stdout. A receipt is preferred: it lets the human see the
    tool, the argument hash, the principal and the target they are
    releasing, all of which are inside the issuer's signature.

    The approver key comes from the environment (GARGOYLE_APPROVER_KEY_HEX +
    GARGOYLE_APPROVER_KEY_ID) so it is never passed on the command line. --yes
    skips the interactive confirm (for scripted approver workflows)."""
    import os

    parser = argparse.ArgumentParser(
        prog="approver_cli",
        description="Emit a signed approval grant for a held decision.",
    )
    parser.add_argument("--pending", help="file with the flagged receipt or hold JSON; default stdin")
    parser.add_argument("--issuer", help="issuing service URL: fetch its pending holds and post grants back")
    parser.add_argument("--ttl", type=int, default=300, help="grant lifetime (s)")
    parser.add_argument("--yes", action="store_true", help="skip the confirm prompt")
    args = parser.parse_args(argv)

    key_hex = os.environ.get("GARGOYLE_APPROVER_KEY_HEX")
    key_id = os.environ.get("GARGOYLE_APPROVER_KEY_ID")
    if not key_hex or not key_id:
        print("GARGOYLE_APPROVER_KEY_HEX and GARGOYLE_APPROVER_KEY_ID must be set",
              file=sys.stderr)
        return 2

    if args.issuer:
        token = os.environ.get("GARGOYLE_APPROVER_TOKEN")
        if not token:
            print("GARGOYLE_APPROVER_TOKEN must be set to talk to the issuer", file=sys.stderr)
            return 2
        return approve_at_issuer(args.issuer, token, key_hex=key_hex, key_id=key_id,
                                 ttl=args.ttl, yes=args.yes)

    raw = open(args.pending).read() if args.pending else sys.stdin.read()
    pending = json.loads(raw)
    decision_sha256 = pending["decision_sha256"]
    approval_request_id = pending["approval_request_id"]

    describe(pending)
    if not args.yes and not confirm():
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


def describe(pending: Dict[str, Any]) -> None:
    """Show the human exactly what they are releasing: everything inside the
    issuer's signature that identifies the call."""
    lines = ["About to APPROVE a held high-impact decision:",
             "  decision_sha256     : %s" % pending.get("decision_sha256"),
             "  approval_request_id : %s" % pending.get("approval_request_id")]
    rc = pending.get("request_context")
    if isinstance(rc, dict):
        lines += ["  tool                : %s" % rc.get("tool"),
                  "  args_sha256         : %s" % rc.get("args_sha256"),
                  "  principal           : %s" % rc.get("principal")]
        if rc.get("on_behalf_of"):
            lines.append("  on_behalf_of        : %s" % rc.get("on_behalf_of"))
        lines += ["  target_url          : %s" % pending.get("target_url"),
                  "  policy              : %s" % pending.get("policy"),
                  "  not_after           : %s" % pending.get("not_after")]
    sys.stderr.write("\n".join(lines) + "\n")


def confirm() -> bool:
    sys.stderr.write("Type 'approve' to sign a grant: ")
    sys.stderr.flush()
    return sys.stdin.readline().strip() == "approve"


def approve_at_issuer(issuer_url: str, token: str, *, key_hex: str, key_id: str, ttl: int = 300,
                      yes: bool = False, http: Any = None) -> int:
    """Fetch the issuer's pending holds, confirm each, sign and post the
    grant. Exit 0 when every grant posted was accepted, 1 when one was
    declined or refused, 2 when the issuer could not be reached."""
    import requests

    http = http if http is not None else requests.Session()
    headers = {"Authorization": "Bearer " + token}
    base = issuer_url.rstrip("/")
    try:
        r = http.get(base + "/pending", headers=headers, timeout=10)
        if r.status_code != 200:
            print("issuer refused: %s" % r.text[:200], file=sys.stderr)
            return 2
        pending = r.json().get("pending", [])
    except Exception as exc:
        print("issuer unreachable: %s" % exc, file=sys.stderr)
        return 2
    if not pending:
        print("nothing pending", file=sys.stderr)
        return 0
    status = 0
    for env in pending:
        describe(env)
        if not yes and not confirm():
            print("skipped", file=sys.stderr)
            status = 1
            continue
        grant = make_grant(approver_private_hex=key_hex, approver_key_id=key_id,
                           decision_sha256=env["decision_sha256"],
                           approval_request_id=env["approval_request_id"], not_after_seconds=ttl)
        try:
            r = http.post(base + "/grants", json=grant, headers=headers, timeout=10)
            body = r.json() if r.status_code == 200 else {"accepted": False, "reason": r.text[:200]}
        except Exception as exc:
            body = {"accepted": False, "reason": str(exc)}
        if body.get("accepted"):
            print("granted %s" % env["approval_request_id"], file=sys.stderr)
        else:
            print("refused %s: %s" % (env["approval_request_id"], body.get("reason")), file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
