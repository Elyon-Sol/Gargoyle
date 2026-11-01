"""The issuer's witness log: an independent record to check the client's evidence against.

The evidence log (gargoyle.evidence) is the executor's own statement, and
the executor is the workstation, where the user administers the machine
and holds the executor key. The issuer is a different party on a server
the operator controls. It records, signed with the issuer key and
hash-chained, every receipt it issued, every grant it accepted, every
decline and every plan. Reconciling the two (gargoyle.reconcile) turns the
client's evidence from a self-report into a report checked against a
witness: evidence for a decision the issuer never issued is a forgery, a
held call honored without a grant the issuer saw is a bypass, a receipt
issued with no evidence at all is a gap.

    entry = {
      "witness_version": "gargoyle-witness/1",
      "seq": n, "prev_sha256": ..., "at": ...,
      "event": "issued" | "refused" | "granted" | "declined" | "plan" | "plan_granted",
      <fields per event>,
      "entry_sha256": sha256(canonical_json(entry minus entry_sha256, issuer_key_id, issuer_signature)),
      "issuer_key_id": ..., "issuer_signature": ed25519 over canonical_json(entry minus issuer_signature)
    }
"""

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from gargoyle.envelope import canonical_json

WITNESS_VERSION = "gargoyle-witness/1"
GENESIS = "0" * 64
_HASH_EXCLUDED = ("entry_sha256", "issuer_key_id", "issuer_signature")

REF_WITNESS_MALFORMED = "REF_WITNESS_MALFORMED"
REF_WITNESS_HASH_MISMATCH = "REF_WITNESS_HASH_MISMATCH"
REF_WITNESS_CHAIN_BROKEN = "REF_WITNESS_CHAIN_BROKEN"
REF_WITNESS_KEY_UNKNOWN = "REF_WITNESS_KEY_UNKNOWN"
REF_WITNESS_SIGNATURE_INVALID = "REF_WITNESS_SIGNATURE_INVALID"
ACCEPT_WITNESS_VERIFIED = "WITNESS_VERIFIED"


def entry_sha256(entry: Dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k not in _HASH_EXCLUDED}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


class WitnessLog:
    """Append-only, one JSON line per event, each signed by the issuer."""

    def __init__(self, path: Optional[str], signing_key: Any, key_id: str) -> None:
        self.path = Path(path) if path else None
        self._key, self._kid = signing_key, key_id
        self._lock = threading.Lock()
        self._seq = 0
        self._tail = GENESIS
        self.entries: List[Dict[str, Any]] = []          # kept in memory too, for tests and GET /witness
        if self.path is not None and self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    e = json.loads(line)
                    self.entries.append(e)
                    self._seq, self._tail = int(e["seq"]), e["entry_sha256"]
        elif self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch()
        # Every start is on record: the first "started" entry is the witness's
        # horizon (evidence older than it cannot be vouched for either way),
        # and later ones mark restarts for the operator.
        self.record("started", resumed=bool(self.entries))

    def record(self, event: str, **fields: Any) -> Dict[str, Any]:
        with self._lock:
            entry: Dict[str, Any] = {"witness_version": WITNESS_VERSION, "seq": self._seq + 1, "prev_sha256": self._tail,
                                     "at": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
            entry["entry_sha256"] = entry_sha256(entry)
            entry["issuer_key_id"] = self._kid
            region = {k: v for k, v in entry.items() if k != "issuer_signature"}
            entry["issuer_signature"] = self._key.sign(canonical_json(region).encode("utf-8")).hex()
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, sort_keys=True) + "\n")
            self.entries.append(entry)
            self._seq, self._tail = entry["seq"], entry["entry_sha256"]
            return entry


def verify_witness(entries: Iterable[Any], *, issuer_public_keys: Dict[str, Any]) -> Dict[str, Any]:
    """Every entry hashes, links and carries a valid issuer signature.
    Returns {"accepted", "reason", "count", "tail_sha256", "entries": [...]}."""
    report, prev, expect, tail, ok_all = [], GENESIS, 1, GENESIS, True
    for raw in entries:
        if not isinstance(raw, dict) or raw.get("witness_version") != WITNESS_VERSION or "entry_sha256" not in raw \
                or not isinstance(raw.get("seq"), int) or "event" not in raw:
            report.append({"seq": None, "accepted": False, "reason": REF_WITNESS_MALFORMED}); ok_all = False
            continue
        ok, reason = True, ACCEPT_WITNESS_VERIFIED
        if entry_sha256(raw) != raw["entry_sha256"]:
            ok, reason = False, REF_WITNESS_HASH_MISMATCH
        elif raw["seq"] != expect or raw.get("prev_sha256") != prev:
            ok, reason = False, REF_WITNESS_CHAIN_BROKEN
        else:
            key = issuer_public_keys.get(raw.get("issuer_key_id"))
            if key is None:
                ok, reason = False, REF_WITNESS_KEY_UNKNOWN
            else:
                region = {k: v for k, v in raw.items() if k != "issuer_signature"}
                try:
                    key.verify(bytes.fromhex(raw.get("issuer_signature", "")), canonical_json(region).encode("utf-8"))
                except Exception:
                    ok, reason = False, REF_WITNESS_SIGNATURE_INVALID
        report.append({"seq": raw["seq"], "event": raw["event"], "accepted": ok, "reason": reason})
        ok_all = ok_all and ok
        expect, prev, tail = raw["seq"] + 1, raw["entry_sha256"], raw["entry_sha256"]
    return {"accepted": ok_all, "reason": ACCEPT_WITNESS_VERIFIED if ok_all else next(r["reason"] for r in report if not r["accepted"]),
            "count": len(report), "tail_sha256": tail, "entries": report}


def describe(entry: Any) -> Dict[str, str]:
    """One witness entry as the columns an operator reads: when, what
    happened, who, which tool, and the outcome in words. The same reading
    the approval console shows; `gargoyle witness` prints it."""
    if not isinstance(entry, dict):
        return {"at": "", "event": "malformed", "who": "", "tool": "", "outcome": "not a witness entry", "ref": ""}
    ev = str(entry.get("event", "?"))
    who = str(entry.get("principal") or entry.get("approver") or entry.get("by") or "")
    tool = str(entry.get("tool") or ("plan (%s steps)" % entry.get("steps") if ev == "plan" else ""))
    short = lambda k, n=12: (str(entry.get(k) or "")[:n])
    if ev == "issued":
        outcome = "covered by an approved plan" if entry.get("covered") else ("held for approval" if entry.get("held") else "allowed")
        if entry.get("state_bound"):
            outcome += " (state-bound)"
        elif "state_bound" in entry and entry.get("held"):
            outcome += " (unbound)"
        ref = short("decision_id", 40) or short("decision_sha256")
    elif ev == "refused":
        outcome, ref = "refused: %s" % entry.get("reason", "?"), ""
    elif ev == "granted":
        n, k = entry.get("collected"), entry.get("required")
        outcome = "released" + (" (%s of %s)" % (n, k) if isinstance(k, int) and k > 1 else "")
        if isinstance(entry.get("roles"), list) and entry["roles"]:
            outcome += " as " + "/".join(str(r) for r in entry["roles"])
        ref = short("approval_request_id", 40)
    elif ev == "grant_refused":
        outcome, ref = "release refused: %s" % entry.get("reason", "?"), short("approval_request_id", 40)
    elif ev == "declined":
        outcome, ref = "declined" + (": %s" % entry["why"] if isinstance(entry.get("why"), str) and entry["why"] else ""), short("approval_request_id", 40)
    elif ev == "plan":
        outcome, ref = "held for approval" if entry.get("held") else "allowed", short("plan_id", 40)
    elif ev == "started":
        outcome, ref = "issuer restarted" if entry.get("resumed") else "witness began", ""
    elif ev == "enrolled":
        outcome, ref = "approver key replaced" if entry.get("replaced") else "approver key enrolled", ""
    elif ev == "enroll_refused":
        outcome, ref = "enrolment refused: %s" % entry.get("reason", "?"), ""
    elif ev == "revoked":
        outcome, ref = "approver key revoked by %s" % (entry.get("by") or "the operator"), ""
    elif ev == "sidedoors":
        n = entry.get("count")
        kinds = entry.get("kinds") if isinstance(entry.get("kinds"), dict) else {}
        outcome = ("%s side door%s found" % (n, "" if n == 1 else "s")) if isinstance(n, int) and n else "no side doors found"
        if kinds:
            outcome += " (" + ", ".join("%d %s" % (v, k) for k, v in sorted(kinds.items())) + ")"
        ref = str(entry.get("target_url") or "")[:40]
    else:
        outcome, ref = ev, ""
    return {"at": str(entry.get("at", "")), "event": ev, "who": who, "tool": tool, "outcome": outcome, "ref": ref}


def read_witness(path: str) -> List[Any]:
    out: List[Any] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append(None)
    return out
