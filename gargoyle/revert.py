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

Refused before a card is ever raised:
  REF_REVERT_UNKNOWN          no snapshot for that decision (or nothing to revert)
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

REVERT_TOOL = "gargoyle_revert"
REVERT_TOOL_DEF = {
    "name": REVERT_TOOL,
    "description": ("Undo an approved file change made through this gate: restores the file to its content "
                    "before that change. Held for approval like any write; refused if the file changed since. "
                    "decision_id: the change to undo, or \"last\" for the most recent approved change."),
    "inputSchema": {"type": "object", "properties": {"decision_id": {"type": "string", "default": "last"}}},
}

REF_REVERT_UNKNOWN = "REF_REVERT_UNKNOWN"
REF_REVERT_STATE_CHANGED = "REF_REVERT_STATE_CHANGED"
REF_REVERT_NEEDS_DELETE = "REF_REVERT_NEEDS_DELETE"
REF_REVERT_NOT_TEXT = "REF_REVERT_NOT_TEXT"


class SnapshotStore:
    """Content by state hash, plus a sidecar per decision."""

    def __init__(self, directory: str) -> None:
        self.dir = Path(directory)

    def _ensure(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)

    def put(self, decision_id: str, description: Dict[str, Any], data: Optional[bytes], tool: str) -> Dict[str, Any]:
        """Keep the pre-state of `decision_id`: the bytes (None when the target
        did not exist) and a sidecar. Returns the sidecar."""
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
        meta = {"decision_id": decision_id, "tool": tool, "ref": description["ref"], "pre_state_sha256": key,
                "existed": data is not None, "post_state_sha256": None, "at": datetime.now(timezone.utc).isoformat()}
        (self.dir / (decision_id + ".json")).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        return meta

    def record_post(self, decision_id: str, post_state_sha256: Optional[str]) -> None:
        p = self.dir / (decision_id + ".json")
        if p.exists():
            meta = json.loads(p.read_text(encoding="utf-8"))
            meta["post_state_sha256"] = post_state_sha256
            p.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    def sidecars(self) -> List[Dict[str, Any]]:
        if not self.dir.exists():
            return []
        out = [json.loads(p.read_text(encoding="utf-8")) for p in self.dir.glob("*.json")]
        return sorted(out, key=lambda m: m.get("at", ""))

    def find(self, decision_id: str) -> Optional[Dict[str, Any]]:
        if decision_id == "last":
            done = [m for m in self.sidecars() if m.get("post_state_sha256")]
            return done[-1] if done else None
        p = self.dir / (decision_id + ".json")
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def content(self, pre_state_sha256: str) -> Optional[bytes]:
        p = self.dir / (pre_state_sha256 + ".bin")
        return p.read_bytes() if p.exists() else None


def plan_revert(store: SnapshotStore, decision_id: str, probe) -> Dict[str, Any]:
    """The write that undoes `decision_id`, or a refusal:
    {"params": {"name": "write_file", "arguments": {...}}, "reverts": id} |
    {"reason": REF_REVERT_*}. `probe` is the state probe, used to confirm the
    target is still as that call left it."""
    meta = store.find(decision_id or "last")
    if meta is None or not meta.get("post_state_sha256"):
        return {"reason": REF_REVERT_UNKNOWN}
    if not meta.get("existed"):
        return {"reason": REF_REVERT_NEEDS_DELETE}
    data = store.content(meta["pre_state_sha256"])
    if data is None:
        return {"reason": REF_REVERT_UNKNOWN}
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return {"reason": REF_REVERT_NOT_TEXT}
    args = {"path": meta["ref"], "content": text}
    now = probe("write_file", args) if probe is not None else None
    if now is None or state_sha256(now) != meta["post_state_sha256"]:
        return {"reason": REF_REVERT_STATE_CHANGED}
    return {"params": {"name": "write_file", "arguments": args}, "reverts": meta["decision_id"]}
