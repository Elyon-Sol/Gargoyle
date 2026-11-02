"""Reconciliation: the client's evidence against the issuer's witness, and
the gated folder against the evidence.

Findings, never silently fixed:
  PREDATES_WITNESS      evidence from before the witness began; it can be vouched for neither way (information)
  UNWITNESSED_RECEIPT   evidence honors a decision the issuer never issued (forged or foreign)
  UNWITNESSED_RELEASE   a held call was honored but the issuer saw no grant for its hold (or plan)
  MISSING_EVIDENCE      the issuer issued a receipt to this principal and the client recorded nothing
  PREDATES_EVIDENCE     issued more than the window before this log's genesis entry; the log cannot be asked about it (information)
  EVIDENCE_BEFORE_ISSUE the client's entry predates the issuer's issuance
  CHANGED_OUTSIDE_GATE  a file under the gated folder is not in the state the last gated write left it
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from gargoyle.state import describe, state_sha256


def _parse(ts: Any) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None


def reconcile(evidence: Iterable[Any], witness: Iterable[Any], *, principal: Optional[str] = None,
              target_url: Optional[str] = None, window_seconds: float = 5.0) -> Dict[str, Any]:
    """Compare verified evidence entries with verified witness entries.
    `principal` limits MISSING_EVIDENCE to receipts issued to that
    principal (the evidence log is one executor's); None means every
    principal in the witness. `target_url` likewise limits it to receipts
    the issuer issued for that target: one issuer may serve several gates,
    each with its own evidence log, and a witness entry that names another
    target is another gate's business (counted in "issued_elsewhere").
    Entries from an issuer too old to name the target are still reported."""
    issued: Dict[str, Dict[str, Any]] = {}
    granted: Dict[str, List[Dict[str, Any]]] = {}
    plan_granted: Dict[str, List[Dict[str, Any]]] = {}
    horizon: Optional[datetime] = None
    for w in witness:
        if not isinstance(w, dict):
            continue
        if horizon is None:
            horizon = _parse(w.get("at"))
        if w.get("event") == "issued" and isinstance(w.get("decision_id"), str):
            issued[w["decision_id"]] = w
        elif w.get("event") == "granted" and isinstance(w.get("approval_request_id"), str):
            (plan_granted if w.get("hold_kind") == "plan" else granted).setdefault(w["approval_request_id"], []).append(w)

    findings: List[Dict[str, Any]] = []
    seen_decisions = set()
    honored_at: Dict[Any, Any] = {}          # decision_id -> seq of the entry that first honored it
    # The evidence log's own beginning: an issuance older than its first entry
    # is one this log was never in a position to record (a fresh install, a
    # rotated log). Reported, counted, and kept apart from MISSING_EVIDENCE.
    evidence = list(evidence)
    log_start: Optional[datetime] = None
    first = next((e for e in evidence if isinstance(e, dict)), None)
    if first is not None and first.get("seq") == 1 and first.get("prev_sha256") == "0" * 64:
        # Only a log that begins at its genesis entry can say when it began;
        # a log missing its head is a chain failure, and what the head would
        # have held stays MISSING_EVIDENCE.
        log_start = _parse(first.get("at"))
    for e in evidence:
        if not isinstance(e, dict):
            continue
        receipt = e.get("receipt") if isinstance(e.get("receipt"), dict) else None
        if receipt is None:
            continue
        did = receipt.get("decision_id")
        seen_decisions.add(did)
        w = issued.get(did)
        if e.get("kind") == "honored":
            # The issuer issued each decision id once; the evidence honoring
            # it twice is a replay the executor's cache did not catch.
            if did in honored_at:
                findings.append({"finding": "REPLAYED_RECEIPT", "seq": e.get("seq"), "decision_id": did, "tool": e.get("tool"),
                                 "first_seq": honored_at[did]})
                continue
            honored_at[did] = e.get("seq")
            if w is None:
                at_e = _parse(e.get("at"))
                if horizon is not None and at_e is not None and at_e < horizon:
                    findings.append({"finding": "PREDATES_WITNESS", "seq": e.get("seq"), "decision_id": did, "tool": e.get("tool")})
                else:
                    findings.append({"finding": "UNWITNESSED_RECEIPT", "seq": e.get("seq"), "decision_id": did, "tool": e.get("tool")})
                continue
            if w.get("decision_sha256") != receipt.get("decision_sha256") or w.get("principal") != receipt.get("request_context", {}).get("principal"):
                findings.append({"finding": "UNWITNESSED_RECEIPT", "seq": e.get("seq"), "decision_id": did, "tool": e.get("tool")})
                continue
            if receipt.get("requires_approval"):
                g = e.get("grant")
                arid = receipt.get("approval_request_id")
                if isinstance(g, dict) and "plan" in g:
                    pid = (g.get("plan") or {}).get("approval_request_id")
                    if pid not in plan_granted:
                        findings.append({"finding": "UNWITNESSED_RELEASE", "seq": e.get("seq"), "decision_id": did, "tool": e.get("tool"), "plan": True})
                elif arid not in granted:
                    findings.append({"finding": "UNWITNESSED_RELEASE", "seq": e.get("seq"), "decision_id": did, "tool": e.get("tool")})
            at_e, at_w = _parse(e.get("at")), _parse(w.get("at"))
            if at_e and at_w and (at_w - at_e).total_seconds() > window_seconds:
                findings.append({"finding": "EVIDENCE_BEFORE_ISSUE", "seq": e.get("seq"), "decision_id": did})
    elsewhere = 0
    for did, w in issued.items():
        if did in seen_decisions:
            continue
        if principal is not None and w.get("principal") != principal:
            continue
        if target_url is not None and isinstance(w.get("target_url"), str) and w["target_url"] != target_url:
            elsewhere += 1
            continue
        at_w = _parse(w.get("at"))
        # Every issuance precedes its own evidence entry by a little; only one
        # older than the log's first entry by more than the window predates it.
        kind = ("PREDATES_EVIDENCE" if (log_start is not None and at_w is not None
                                        and (log_start - at_w).total_seconds() > window_seconds) else "MISSING_EVIDENCE")
        findings.append({"finding": kind, "decision_id": did, "tool": w.get("tool"), "principal": w.get("principal"),
                         "held": bool(w.get("held")), "at": w.get("at")})
    hard = [f for f in findings if f["finding"] not in ("PREDATES_WITNESS", "PREDATES_EVIDENCE")]
    return {"accepted": not hard, "findings": findings, "horizon": horizon.isoformat() if horizon else None,
            "log_start": log_start.isoformat() if log_start else None,
            "issued": len(issued), "evidence_with_receipt": len(seen_decisions), "issued_elsewhere": elsewhere}


def check_tree(evidence: Iterable[Any], root: str) -> Dict[str, Any]:
    """Every file under `root` that the evidence has a post-state for must
    be in that state now; files the gate never touched are counted, not
    judged. A file whose last recorded state says it existed but which is
    gone is reported too."""
    last: Dict[str, Dict[str, Any]] = {}
    for e in evidence:
        if not isinstance(e, dict) or e.get("kind") != "honored":
            continue
        ex = e.get("execution") if isinstance(e.get("execution"), dict) else None
        rc = (e.get("receipt") or {}).get("request_context") if isinstance(e.get("receipt"), dict) else None
        if ex is None or not ex.get("post_state_sha256") or not rc:
            continue
        ref = None
        meta = e.get("grant") if isinstance(e.get("grant"), dict) else None
        # The ref is the path the call changed: from the plan release's args, or
        # the snapshot sidecar is not in evidence, so recover it from the
        # arguments the executor recorded when it could, else skip.
        args = (meta or {}).get("args") if meta and "plan" in meta else None
        if isinstance(args, dict):
            ref = args.get("path") or args.get("source")
        if ref is None:
            ref = e.get("ref")
        if ref is None:
            continue
        last[ref] = {"post": ex["post_state_sha256"], "seq": e.get("seq")}
    findings, checked, untouched = [], 0, 0
    for dirpath, _, files in os.walk(root):
        for name in files:
            p = os.path.join(dirpath, name)
            rec = last.get(p)
            if rec is None:
                untouched += 1
                continue
            checked += 1
            try:
                data = open(p, "rb").read()
            except OSError:
                data = None
            now = state_sha256(describe(p, data, with_text=False))
            if now != rec["post"]:
                findings.append({"finding": "CHANGED_OUTSIDE_GATE", "path": p, "last_gated_seq": rec["seq"]})
    for p, rec in last.items():
        if str(Path(p)).startswith(str(Path(root))) and not os.path.exists(p):
            findings.append({"finding": "CHANGED_OUTSIDE_GATE", "path": p, "last_gated_seq": rec["seq"], "missing": True})
    return {"accepted": not findings, "findings": findings, "checked": checked, "untouched": untouched}
