"""The evidence log: an append-only hash chain of what the gate decided.

An execution receipt (gargoyle.execution) proves one honored call. It says
nothing about the calls that were refused, and nothing about whether the
file of receipts an auditor is handed is complete. The evidence log is the
executor's record of every decision it made, honored or refused, each entry
hashed over the one before it:

    entry = {
        "evidence_version": "gargoyle-evidence/2",
        "seq":           1, 2, 3 ...            (dense, from 1)
        "prev_sha256":   <entry_sha256 of seq-1; 64 zeros for seq 1>,
        "at":            <when the executor decided, ISO 8601, UTC>,
        "kind":          "honored" | "refused",
        "tool":          <tool name>,
        "args_sha256":   <sha256 of the canonical arguments>,
        "principal":     <the principal the executor serves>,
        "reason":        <the verdict code: CHAIN-side ACCEPT_* or REF_*>,
        "receipt":       <authorization receipt or null>,
        "grant":         <approval grant or null>,
        "execution":     <execution receipt or null>,
        "entry_sha256":  sha256(canonical_json(entry minus entry_sha256))
    }

A refused entry records what was asked and why it did not run: a policy
refusal carries no receipt, a declined or timed-out hold carries the flagged
receipt the human did not release. An honored entry carries the full chain
verify_chain checks.

What the chain proves to an auditor who holds the file and the trust keys:
every honored entry is a verified authorization/approval/execution chain;
no entry in the middle was altered, removed or inserted after the fact
(the hashes would not link); the refusals are the ones the executor wrote
when it wrote them, in order. What it does not prove: that the file is not
truncated at the tail. An auditor who notes the last entry_sha256 at each
audit (printed by `gargoyle audit`) can tell a later copy that lost its
tail from one that only grew. That is the whole mechanism: a log, not a
ledger, and no rules about amending it, because it is not amended.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from gargoyle.envelope import args_sha256, canonical_json, canonical_json_legacy
from gargoyle.execution import verify_chain
from gargoyle.verifier import verify_provenance

EVIDENCE_VERSION = "gargoyle-evidence/4"          # 3 added `client`, 4 adds `ref`; hashes over RFC 8785 canonical JSON
EVIDENCE_VERSIONS = {"gargoyle-evidence/1": canonical_json_legacy, "gargoyle-evidence/2": canonical_json,
                     "gargoyle-evidence/3": canonical_json, EVIDENCE_VERSION: canonical_json}
GENESIS = "0" * 64

HONORED = "honored"
REFUSED = "refused"

ACCEPT_EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"          # the whole file checks
ACCEPT_ENTRY_VERIFIED = "ENTRY_VERIFIED"                # a refused entry that hashes and links
REF_EVIDENCE_MALFORMED = "REF_EVIDENCE_MALFORMED"       # not an entry
REF_EVIDENCE_HASH_MISMATCH = "REF_EVIDENCE_HASH_MISMATCH"  # entry_sha256 does not match the entry
REF_EVIDENCE_CHAIN_BROKEN = "REF_EVIDENCE_CHAIN_BROKEN"    # seq or prev_sha256 does not follow
REF_EVIDENCE_RECEIPT_MISSING = "REF_EVIDENCE_RECEIPT_MISSING"  # honored without receipt or execution
REF_EVIDENCE_UNCHAINED = "REF_EVIDENCE_UNCHAINED"       # a pre-chain {receipt, grant, execution} line
REF_EVIDENCE_REPLAY = "REF_EVIDENCE_REPLAY"             # a decision id (or plan step) honored twice in one log

# Verdicts an honored entry carries when the admitted call did not succeed
# downstream: the receipt was claimed, so the entry must exist, and the
# verdict says the change most likely did not happen (the execution receipt's
# outputs carry the error). Any other verdict on an honored entry is the
# verifier's accept reason.
TOOL_ERROR = "TOOL_ERROR"                       # the upstream answered with isError: true
UPSTREAM_ERROR = "UPSTREAM_ERROR"               # the upstream answered with a JSON-RPC error
UPSTREAM_UNAVAILABLE = "UPSTREAM_UNAVAILABLE"   # the upstream could not be reached after the claim
FAILED_VERDICTS = frozenset((TOOL_ERROR, UPSTREAM_ERROR, UPSTREAM_UNAVAILABLE))

_FIELDS = ("evidence_version", "seq", "prev_sha256", "at", "kind", "tool", "args_sha256",
           "principal", "reason", "receipt", "grant", "execution", "entry_sha256")
# Version 3 names the MCP client that made the call ("Claude Desktop 1.2", "ChatGPT"),
# from the initialize handshake; null when the client did not say. The
# receipt stays model-agnostic: this is evidence about the session, not a
# bound field of the decision.
_FIELDS_V3 = _FIELDS + ("client",)
# Version 4 adds `ref`: what the adapter examined for a state-bound call (a
# file path, "mailRule:<id>"), or null. With it a folder can be checked
# against the evidence without any plaintext (gargoyle.reconcile.check_tree).
_FIELDS_V4 = _FIELDS_V3 + ("ref",)
_FIELDS_BY_VERSION = {"gargoyle-evidence/3": _FIELDS_V3, "gargoyle-evidence/4": _FIELDS_V4}


def entry_sha256(entry: Dict[str, Any]) -> str:
    """The hash an entry carries: over its canonical JSON without the hash
    itself, under the serializer of the entry's own evidence_version, so a
    log that spans a format change still verifies end to end."""
    body = {k: v for k, v in entry.items() if k != "entry_sha256"}
    serialize = EVIDENCE_VERSIONS.get(entry.get("evidence_version"), canonical_json)
    return hashlib.sha256(serialize(body).encode("utf-8")).hexdigest()


def build_entry(*, seq: int, prev_sha256: str, kind: str, tool: str, args: Any, principal: str,
                reason: str, receipt: Any = None, grant: Any = None, execution: Any = None,
                at: Optional[datetime] = None, client: Optional[str] = None, ref: Optional[str] = None) -> Dict[str, Any]:
    if kind not in (HONORED, REFUSED):
        raise ValueError("kind must be honored or refused")
    if client is not None and not isinstance(client, str):
        raise ValueError("client must be a string or None")
    if ref is not None and not isinstance(ref, str):
        raise ValueError("ref must be a string or None")
    entry = {
        "evidence_version": EVIDENCE_VERSION,
        "seq": seq,
        "prev_sha256": prev_sha256,
        "at": (at or datetime.now(timezone.utc)).isoformat(),
        "kind": kind,
        "tool": tool,
        "args_sha256": args_sha256(args),
        "principal": principal,
        "reason": reason,
        "receipt": receipt,
        "grant": grant,
        "execution": execution,
        "client": client,
        "ref": ref,
    }
    entry["entry_sha256"] = entry_sha256(entry)
    return entry


class EvidenceLog:
    """Appends entries to a JSON Lines file, continuing the chain found at
    its tail. The file is read once, when the first entry is appended; a
    file nobody else writes to is the operating assumption (one middleware
    process, one log), as for any append-only log."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._seq: Optional[int] = None
        self._tail: str = GENESIS

    def _load_tail(self) -> None:
        self._seq, self._tail = 0, GENESIS
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = json.loads(line)
                if last.get("evidence_version") in EVIDENCE_VERSIONS:
                    self._seq, self._tail = int(last["seq"]), str(last["entry_sha256"])

    def append(self, kind: str, tool: str, args: Any, principal: str, reason: str, *,
               receipt: Any = None, grant: Any = None, execution: Any = None,
               client: Optional[str] = None, ref: Optional[str] = None) -> Dict[str, Any]:
        """Write one entry and return it. Raises OSError if the file cannot
        be written; the caller decides whether that stops the call."""
        if self._seq is None:
            self._load_tail()
        entry = build_entry(seq=self._seq + 1, prev_sha256=self._tail, kind=kind, tool=tool, args=args,
                            principal=principal, reason=reason, receipt=receipt, grant=grant, execution=execution,
                            client=client, ref=ref)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        self._seq, self._tail = entry["seq"], entry["entry_sha256"]
        return entry


def _well_formed(entry: Any) -> bool:
    expected = _FIELDS_BY_VERSION.get(entry.get("evidence_version"), _FIELDS) if isinstance(entry, dict) else _FIELDS
    return (isinstance(entry, dict) and set(entry) == set(expected)
            and entry["evidence_version"] in EVIDENCE_VERSIONS
            and (entry.get("client") is None or isinstance(entry.get("client"), str))
            and (entry.get("ref") is None or isinstance(entry.get("ref"), str))
            and isinstance(entry["seq"], int) and entry["seq"] >= 1
            and isinstance(entry["prev_sha256"], str) and len(entry["prev_sha256"]) == 64
            and isinstance(entry["at"], str) and entry["kind"] in (HONORED, REFUSED)
            and isinstance(entry["tool"], str) and isinstance(entry["principal"], str)
            and isinstance(entry["args_sha256"], str) and len(entry["args_sha256"]) == 64
            and isinstance(entry["reason"], str) and isinstance(entry["entry_sha256"], str))


def verify_log(
    entries: Iterable[Any],
    *,
    issuer_public_keys: Dict[str, Any],
    executor_public_keys: Dict[str, Any],
    approver_public_keys: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Offline check of a whole log: each entry hashes to its entry_sha256
    and links to the one before; each honored entry's receipt, grant and
    execution receipt verify as a chain (gargoyle.execution.verify_chain)
    and describe the call the entry names; a refused entry that carries a
    receipt has it checked for issuer provenance. Returns
    {"accepted", "reason", "tail_sha256", "count", "honored", "refused",
     "entries": [{"seq", "kind", "tool", "principal", "accepted", "reason", "verdict", "released_by"}, ...]},
    `reason` the verification outcome, `verdict` what the executor recorded,
    `released_by` the approver key ids of the grants an honored held call carried,
    `state` {"pre", "post"} the target's state hashes when the call was state-bound.
    Verification continues past a bad entry so the report names every one."""
    trust = dict(issuer_public_keys=issuer_public_keys, executor_public_keys=executor_public_keys,
                 approver_public_keys=approver_public_keys)
    report: List[Dict[str, Any]] = []
    expect_seq, prev, tail = 1, GENESIS, GENESIS
    counts = {HONORED: 0, REFUSED: 0}
    all_ok = True
    claimed: Dict[str, int] = {}      # decision_id / plan step -> seq of the honored entry that spent it

    for raw in entries:
        if not _well_formed(raw):
            # A line the middleware wrote before the chain existed is named
            # as such, so an upgrade is told apart from tampering.
            legacy = isinstance(raw, dict) and set(raw) == {"receipt", "grant", "execution"}
            rc = (raw.get("receipt") or {}).get("request_context") if legacy else None
            rc = rc if isinstance(rc, dict) else {}
            report.append({"seq": None, "kind": None, "tool": rc.get("tool"), "principal": rc.get("principal"),
                           "accepted": False, "reason": REF_EVIDENCE_UNCHAINED if legacy else REF_EVIDENCE_MALFORMED,
                           "verdict": None, "released_by": [], "state": None, "client": None, "plan": None, "ref": None})
            all_ok = False
            continue
        e = raw
        ok, reason = True, None
        if entry_sha256(e) != e["entry_sha256"]:
            ok, reason = False, REF_EVIDENCE_HASH_MISMATCH
        elif e["seq"] != expect_seq or e["prev_sha256"] != prev:
            ok, reason = False, REF_EVIDENCE_CHAIN_BROKEN
        elif e["kind"] == HONORED:
            if e["receipt"] is None or e["execution"] is None:
                ok, reason = False, REF_EVIDENCE_RECEIPT_MISSING
            else:
                r = verify_chain(e["receipt"], e["execution"], grant=e["grant"], **trust)
                ok, reason = r["accepted"], r["reason"]
                rc = e["receipt"].get("request_context") or {}
                if ok and (rc.get("tool") != e["tool"] or rc.get("args_sha256") != e["args_sha256"]
                           or rc.get("principal") != e["principal"]):
                    ok, reason = False, REF_EVIDENCE_RECEIPT_MISSING
                if ok:
                    # Single use, checked after the fact: a decision id, or a
                    # plan step, honored twice in one log is a replay the
                    # executor's cache missed (a second process, a lost cache).
                    keys = [str(e["receipt"].get("decision_id"))]
                    gs = e["grant"]
                    if isinstance(gs, dict) and "plan" in gs and "step" in gs:
                        keys.append("plan:%s:%s" % ((gs["plan"] or {}).get("plan_id"), gs["step"]))
                    if any(k in claimed for k in keys):
                        ok, reason = False, REF_EVIDENCE_REPLAY
                    else:
                        for k in keys:
                            claimed[k] = e["seq"]
        else:
            reason = ACCEPT_ENTRY_VERIFIED
            if e["receipt"] is not None:
                p = verify_provenance(e["receipt"], pinned_public_keys=issuer_public_keys,
                                      now=_parse_at(e["at"]), historical=True)
                ok, reason = p["accepted"], (ACCEPT_ENTRY_VERIFIED if p["accepted"] else p["reason"])
        counts[e["kind"]] += 1
        plan_ref = None
        grant_set = e["grant"]
        if isinstance(grant_set, dict) and "plan" in grant_set and "step" in grant_set:
            plan_ref = {"plan_id": (grant_set["plan"] or {}).get("plan_id"), "step": grant_set["step"]}
            grant_set = grant_set.get("grants")
        released_by = [g.get("approver_key_id") for g in (grant_set if isinstance(grant_set, list) else [grant_set])
                       if isinstance(g, dict)] if grant_set is not None else []
        ex = e["execution"] if isinstance(e["execution"], dict) else {}
        state = ({"pre": ex.get("pre_state_sha256"), "post": ex.get("post_state_sha256")}
                 if ex.get("pre_state_sha256") or ex.get("post_state_sha256") else None)
        report.append({"seq": e["seq"], "kind": e["kind"], "tool": e["tool"], "principal": e["principal"],
                       "accepted": ok, "reason": reason, "verdict": e["reason"], "released_by": released_by,
                       "state": state, "client": e.get("client"), "plan": plan_ref, "ref": e.get("ref")})
        all_ok = all_ok and ok
        # The chain continues from what the file says, so one bad entry is
        # reported once rather than cascading into every later one.
        expect_seq, prev, tail = e["seq"] + 1, e["entry_sha256"], e["entry_sha256"]

    # A revert is recognisable without any annotation: its pre-state is an
    # earlier honored entry's post-state and its post-state that entry's pre-state.
    for i, r in enumerate(report):
        r["reverts"] = None
        st = r.get("state")
        if r["accepted"] and st and st.get("pre") and st.get("post"):
            for prev in reversed(report[:i]):
                ps = prev.get("state")
                if prev["accepted"] and ps and ps.get("post") == st["pre"] and ps.get("pre") == st["post"]:
                    r["reverts"] = prev["seq"]
                    break
    return {"accepted": all_ok, "reason": ACCEPT_EVIDENCE_VERIFIED if all_ok else _first_failure(report),
            "tail_sha256": tail, "count": len(report), "honored": counts[HONORED], "refused": counts[REFUSED],
            "entries": report}


def _first_failure(report: List[Dict[str, Any]]) -> str:
    return next(r["reason"] for r in report if not r["accepted"])


def _parse_at(text: str) -> datetime:
    try:
        at = datetime.fromisoformat(text)
        return at if at.tzinfo is not None else at.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def read_log(path: str) -> List[Any]:
    """The entries of a JSON Lines file, blank lines skipped; a line that is
    not JSON becomes None so verify_log reports it as malformed."""
    out: List[Any] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            out.append(None)
    return out
