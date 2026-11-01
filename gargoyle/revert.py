"""Undo for an approved change: a revert is another state-bound write.

Before a held, state-bound call runs, the executor keeps the target's
bytes in a snapshot store beside the audit log, keyed by the state hash
the receipt bound, with a sidecar naming the decision, the target and,
after the run, the state the call left. `gargoyle_revert` is a tool the
middleware adds to the upstream's list: given a decision id (or "last"),
it builds the write that restores the snapshot and sends it through the
gate like any other write. So an undo is held, shown to the approver as a
diff from the current content back to the snapshot, bound to the current
state, signed, executed once, and recorded. The chain proves the
relationship without trusting any annotation: the revert's pre-state is
the original's post-state and its post-state is the original's pre-state;
`gargoyle audit` prints "reverts #N" when it sees that.

Refused before a card is ever raised (each with its own sentence, `revert_text`,
because one code for every cause left a tester unable to tell "undo is off"
from "that write was never held", soak test 2026-11-01):
  REF_REVERT_DISABLED         no snapshot store on this gate
  REF_REVERT_NOTHING_HELD     "last" with no held change on record: calls allowed by rule leave no snapshot
  REF_REVERT_NOT_ATTESTED     the change has no recorded after-state (no executor key, or it did not finish)
  REF_REVERT_UNKNOWN          no change with that decision id
  REF_REVERT_SNAPSHOT_MISSING the sidecar exists but its bytes are gone from the store
  REF_REVERT_STATE_CHANGED    the target is no longer as the original call left it
  REF_REVERT_NEEDS_DELETE     the target did not exist before; undoing would delete
  REF_REVERT_NOT_TEXT         the snapshot is not UTF-8 text the write tool can carry

Text files only, and only files a write can restore. A revert of a create
would be a delete, which the gate refuses; a revert of a move would be a
move back, not built here.
"""

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from gargoyle.state import state_sha256
from gargoyle.adapters import (REF_REVERT_IRREVERSIBLE, REF_REVERT_NEEDS_DELETE, REF_REVERT_NOT_TEXT, REF_REVERT_UNKNOWN,
                               REF_REVERT_UNSUPPORTED)

REVERT_TOOL = "gargoyle_revert"
REVERT_TOOL_DEF = {
    "name": REVERT_TOOL,
    "description": ("Undo a file change a person released through this gate: restores the file to its content "
                    "before that change. Held for approval like any write; refused if the file changed since. "
                    "Only held changes can be undone; a write allowed by rule leaves no snapshot. "
                    "decision_id: the change to undo, or \"last\" for the most recent released change; "
                    "path: with \"last\", the most recent released change to that file."),
    "inputSchema": {"type": "object", "properties": {"decision_id": {"type": "string", "default": "last"},
                                                     "path": {"type": "string"}}},
}

REF_REVERT_STATE_CHANGED = "REF_REVERT_STATE_CHANGED"
REF_REVERT_DISABLED = "REF_REVERT_DISABLED"
REF_REVERT_NOTHING_HELD = "REF_REVERT_NOTHING_HELD"
REF_REVERT_NOT_ATTESTED = "REF_REVERT_NOT_ATTESTED"
REF_REVERT_SNAPSHOT_MISSING = "REF_REVERT_SNAPSHOT_MISSING"

REVERT_TEXT = {
    REF_REVERT_DISABLED: "undo is not enabled on this gate (no snapshot store)",
    REF_REVERT_NOTHING_HELD: "no held change is on record: calls allowed by rule leave no snapshot, so only a change a person released can be undone",
    REF_REVERT_NOT_ATTESTED: "that change has no recorded after-state (the gate has no executor key, or the call did not finish), so there is nothing proven to undo",
    REF_REVERT_UNKNOWN: "no change with that decision id is on record",
    REF_REVERT_SNAPSHOT_MISSING: "the snapshot for that change is missing from the store",
    REF_REVERT_STATE_CHANGED: "the file is no longer as that change left it; undo would overwrite someone else's work",
    REF_REVERT_NEEDS_DELETE: "the file did not exist before that change; undoing it would be a delete, which the gate refuses",
    REF_REVERT_NOT_TEXT: "the snapshot is not UTF-8 text the write tool can carry",
    REF_REVERT_IRREVERSIBLE: "that change cannot be reversed",
    REF_REVERT_UNSUPPORTED: "this gate's adapter cannot compose an undo",
}


def revert_text(reason: str) -> str:
    """The one line the model reads for a refused undo: the code and why."""
    why = REVERT_TEXT.get(reason)
    return "refused: %s%s" % (reason, (" (%s)" % why) if why else "")


class SnapshotStore:
    """Content by state hash, plus a sidecar per decision."""

    def __init__(self, directory: str) -> None:
        self.dir = Path(directory)

    def _ensure(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)

    def put(self, decision_id: str, description: Dict[str, Any], data: Optional[bytes], tool: str,
            args: Any = None) -> Dict[str, Any]:
        """Keep the pre-state of `decision_id`: the bytes (None when the target
        did not exist) and a sidecar naming the call, so the same probe can be
        repeated later to ask whether the target is still as the call left it.
        Returns the sidecar."""
        self._ensure()
        key = state_sha256(description)
        if data is not None:
            blob = self.dir / (key + ".bin")
            if not blob.exists():
                blob.write_bytes(data)
                try:
                    os.chmod(blob, stat.S_IRUSR | stat.S_IWUSR)
                except OSError:
                    pass
        meta = {"decision_id": decision_id, "tool": tool, "args": args, "ref": description["ref"], "pre_state_sha256": key,
                "existed": data is not None, "post_state_sha256": None, "at": datetime.now(timezone.utc).isoformat()}
        (self.dir / (decision_id + ".json")).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        return meta

    def record_post(self, decision_id: str, post_state_sha256: Optional[str], data: Optional[bytes] = None) -> None:
        """The state the call left: its hash in the sidecar, its bytes under
        that hash (an adapter may need both snapshots to compose the undo)."""
        p = self.dir / (decision_id + ".json")
        if p.exists():
            meta = json.loads(p.read_text(encoding="utf-8"))
            meta["post_state_sha256"] = post_state_sha256
            p.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        if data is not None and post_state_sha256:
            blob = self.dir / (post_state_sha256 + ".bin")
            if not blob.exists():
                blob.write_bytes(data)

    def sidecars(self) -> List[Dict[str, Any]]:
        if not self.dir.exists():
            return []
        out = [json.loads(p.read_text(encoding="utf-8")) for p in self.dir.glob("*.json")]
        return sorted(out, key=lambda m: m.get("at", ""))

    def sidecars_for(self, ref: Optional[str]) -> List[Dict[str, Any]]:
        """Sidecars, narrowed to one target when `ref` is given."""
        if not ref:
            return self.sidecars()
        from gargoyle.globs import normalize_path
        n = normalize_path(ref)
        return [m for m in self.sidecars() if normalize_path(str(m.get("ref", ""))) == n]

    def find(self, decision_id: str, ref: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if decision_id == "last":
            done = [m for m in self.sidecars_for(ref) if m.get("post_state_sha256")]
            return done[-1] if done else None
        p = self.dir / (decision_id + ".json")
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def content(self, pre_state_sha256: str) -> Optional[bytes]:
        p = self.dir / (pre_state_sha256 + ".bin")
        return p.read_bytes() if p.exists() else None


def plan_revert(store: SnapshotStore, decision_id: str, adapter, ref: Optional[str] = None) -> Dict[str, Any]:
    """The call that undoes `decision_id`, or a refusal:
    {"params": {"name", "arguments"}, "reverts": id} | {"reason": REF_REVERT_*}.
    The adapter composes the inverse from the two snapshots and confirms the
    target is still as that call left it. `ref` narrows "last" to one file."""
    key = decision_id or "last"
    meta = store.find(key, ref)
    if meta is None:
        if key == "last":
            return {"reason": REF_REVERT_NOT_ATTESTED if store.sidecars_for(ref) else REF_REVERT_NOTHING_HELD}
        return {"reason": REF_REVERT_UNKNOWN}
    if not meta.get("post_state_sha256"):
        return {"reason": REF_REVERT_NOT_ATTESTED}
    if adapter is None:
        return {"reason": REF_REVERT_UNSUPPORTED}
    pre = store.content(meta["pre_state_sha256"]) if meta.get("existed") else None
    if meta.get("existed") and pre is None:
        return {"reason": REF_REVERT_SNAPSHOT_MISSING}
    post = store.content(meta["post_state_sha256"])
    plan = adapter.restore(meta, pre, post)
    if "reason" in plan:
        return plan
    # Still as the original call left it? Repeat the original call's probe
    # now and compare with the state recorded after it ran.
    probe = adapter.probe(meta["tool"], meta.get("args") if meta.get("args") is not None else {"path": meta["ref"]})
    if probe is None or state_sha256(probe[0]) != meta["post_state_sha256"]:
        return {"reason": REF_REVERT_STATE_CHANGED}
    return {"params": plan["params"], "reverts": meta["decision_id"]}
