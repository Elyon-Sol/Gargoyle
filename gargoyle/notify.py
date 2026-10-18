"""Approval transport (roadmap step 6): tell a human where the hold is.

The approval itself never travels here. A grant is a signature made with a
key on the approver's device, in the browser console or the CLI, and only
that releases a call. This module only posts a notice of a new hold to a
webhook so the approver hears about it in Slack, Teams, or whatever accepts
an HTTP POST, with a link to the console. The notice carries the hold's
summary (tool, principal, target, expiry, how many approvers) and the
receipt; it carries no key and cannot approve anything. A failing webhook
is logged and otherwise ignored: the hold still exists and the console
still shows it.

    GARGOYLE_HOLD_WEBHOOK_URL   where to POST (a Slack incoming webhook works as is)
    GARGOYLE_APPROVE_URL        the console link to include (default: <issuer>/approve)
"""

import json
import sys
import threading
from typing import Any, Callable, Dict, Optional

ENV_HOLD_WEBHOOK_URL = "GARGOYLE_HOLD_WEBHOOK_URL"
ENV_APPROVE_URL = "GARGOYLE_APPROVE_URL"


def hold_notice(envelope: Dict[str, Any], args: Any, approve_url: Optional[str]) -> Dict[str, Any]:
    """The JSON a webhook receives: a one-line `text` (what Slack renders)
    and the structured hold beside it."""
    rc = envelope.get("request_context", {})
    terms = envelope.get("approval") or {}
    required = terms.get("required", 1)
    who = rc.get("principal", "?")
    if rc.get("on_behalf_of"):
        who += " on behalf of " + rc["on_behalf_of"]
    text = "Gargoyle hold: %s by %s on %s (expires %s%s)%s" % (
        rc.get("tool", "?"), who, envelope.get("target_url", "?"), envelope.get("not_after", "?"),
        (", %d approvals needed" % required) if required > 1 else "",
        (" -> " + approve_url) if approve_url else "")
    return {"text": text, "hold": {"approval_request_id": envelope.get("approval_request_id"),
                                   "decision_sha256": envelope.get("decision_sha256"),
                                   "tool": rc.get("tool"), "principal": rc.get("principal"),
                                   "on_behalf_of": rc.get("on_behalf_of"), "target_url": envelope.get("target_url"),
                                   "not_after": envelope.get("not_after"), "approvals_required": required,
                                   "approvers": terms.get("approvers"), "args": args, "approve_url": approve_url},
            "envelope": envelope}


def webhook_notifier(url: str, approve_url: Optional[str] = None, *, http: Any = None,
                     timeout: float = 5.0, background: bool = True) -> Callable[[Dict[str, Any], Any], None]:
    """on_hold(envelope, args): POST the notice to `url`. `http` is any object
    with a requests-style post (a requests.Session by default). With
    `background`, the POST runs in a thread so issuing never waits on Slack."""
    def post(envelope: Dict[str, Any], args: Any) -> None:
        session = http
        if session is None:
            import requests
            session = requests.Session()
        try:
            r = session.post(url, json=hold_notice(envelope, args, approve_url), timeout=timeout)
            status = getattr(r, "status_code", None)
            if status is not None and status >= 300:
                sys.stderr.write("gargoyle: hold webhook answered %s\n" % status)
        except Exception as exc:
            sys.stderr.write("gargoyle: hold webhook failed: %s: %s\n" % (type(exc).__name__, str(exc)[:200]))

    def on_hold(envelope: Dict[str, Any], args: Any) -> None:
        if background:
            threading.Thread(target=post, args=(envelope, args), daemon=True).start()
        else:
            post(envelope, args)
    return on_hold


def notifier_from_env(environ: Dict[str, str], issuer_url: Optional[str] = None):
    """The configured notifier, or None when no webhook is set."""
    url = environ.get(ENV_HOLD_WEBHOOK_URL)
    if not url:
        return None
    approve = environ.get(ENV_APPROVE_URL) or ((issuer_url.rstrip("/") + "/approve") if issuer_url else None)
    return webhook_notifier(url, approve)
