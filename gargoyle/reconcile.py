"""Reconciliation: the client's evidence against the issuer's witness, and
the gated folder against the evidence.

Findings, never silently fixed:
  UNWITNESSED_RECEIPT   evidence honors a decision the issuer never issued (forged or foreign)
  UNWITNESSED_RELEASE   a held call was honored but the issuer saw no grant for its hold (or plan)
  MISSING_EVIDENCE      the issuer issued a receipt to this principal and the client recorded nothing
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
              window_seconds: float = 5.0) -> Dict[str, Any]:
    """Compare verified evidence entries with verified witness entries.
    `principal` limits MISSING_EVIDENCE to receipts issued to that
    principal (the evidence log is one executor's); None means every
    principal in the witness."""
    issued: Dict[str, Dict[str, Any]] = {}
    granted: Dict[str, List[Dict[str, Any]]] = {}
    plan_granted: Dict[str, List[Dict[str, Any]]] = {}
    for w in witness:
        if not isinstance(w, dict):
            continue
        if w.get("event") == "issued" and isinstance(w.get("decision_id"), str):
            issued[w["decision_id"]] = w
        elif w.get("event") == "granted" and isinstance(w.get("approval_request_id"), str):
            (plan_granted if w.get("hold_kind") == "plan" else granted).setdefault(w["approval_request_id"], []).append(w)

    findings: List[Dict[str, Any]] = []
    seen_decisions = set()
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
            if w is None:
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
    for did, w in issued.items():
        if did in seen_decisions:
            continue
        if principal is not None and w.get("principal") != principal:
            continue
        findings.append({"finding": "MISSING_EVIDENCE", "decision_id": did, "tool": w.get("tool"), "principal": w.get("principal"),
                         "held": bool(w.get("held")), "at": w.get("at")})
    return {"accepted": not findings, "findings": findings,
            "issued": len(issued), "evidence_with_receipt": len(seen_decisions)}


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
