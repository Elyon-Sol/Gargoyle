"""State-bound approval: the world the human saw is the world the call runs in.

A held call is approved against what the approver was shown. Without this
module that is the arguments alone; the target could change between the
card and the run, and the executor would not notice. With it, the executor
describes the target's current state before asking for the receipt, the
issuer puts the state's hash into the receipt's signed request context,
the approver's grant covers it, and at execution the executor describes
the state again and refuses if it moved (REF_VERIFY_STATE_MISMATCH). The
execution receipt then carries the pre-state and post-state hashes, so an
auditor can see not only that the call ran but what it changed.

The state description is the executor's own statement, as the execution
receipt is; it binds the executor to one state, it does not make the
executor honest. Its canonical form:

    {"ref": <what was examined, e.g. the file path>,
     "sha256": <hex of the bytes> | null when absent,
     "size": <byte count> | null}

and state_sha256 = sha256(canonical_json(description)). A `text` member
(the bytes as UTF-8, when small enough) may travel beside the description
to the issuer so the console can show a diff; it is not part of the hash,
which already covers the bytes.

The reference probe knows filesystem tools: for a tool that takes a path,
the state is that file. Any executor can supply its own probe.
"""

import hashlib
from typing import Any, Callable, Dict, Optional

from gargoyle.envelope import canonical_json

PROBE_TOOLS = ("write_file", "edit_file", "create_directory", "move_file", "delete_file")
PATH_ARGS = ("path", "source")
TEXT_LIMIT = 65536


def describe(ref: str, data: Optional[bytes], *, with_text: bool = True) -> Dict[str, Any]:
    """The state description for `ref` holding `data` (None when absent)."""
    desc: Dict[str, Any] = {"ref": ref, "sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
                            "size": len(data) if data is not None else None}
    if with_text and data is not None and len(data) <= TEXT_LIMIT:
        try:
            desc["text"] = data.decode("utf-8")
        except UnicodeDecodeError:
            pass
    return desc


def state_sha256(description: Dict[str, Any]) -> str:
    """The hash the receipt binds: over ref, sha256 and size only."""
    core = {"ref": description["ref"], "sha256": description.get("sha256"), "size": description.get("size")}
    return hashlib.sha256(canonical_json(core).encode("utf-8")).hexdigest()


def text_consistent(description: Dict[str, Any]) -> bool:
    """A description's `text`, when present, must be the very bytes its
    `sha256` and `size` name, so what an approver reads as the current
    content is what the receipt binds. Without that the diff on the card
    would be the executor's word alone (second review, finding 6)."""
    if "text" not in description:
        return True
    if description.get("sha256") is None:
        return False
    try:
        data = description["text"].encode("utf-8")
    except (UnicodeEncodeError, AttributeError):
        return False
    return (hashlib.sha256(data).hexdigest() == description["sha256"]
            and (description.get("size") is None or description["size"] == len(data)))


def valid_description(d: Any) -> bool:
    return (isinstance(d, dict) and isinstance(d.get("ref"), str) and bool(d["ref"])
            and (d.get("sha256") is None or (isinstance(d["sha256"], str) and len(d["sha256"]) == 64))
            and (d.get("size") is None or (isinstance(d["size"], int) and not isinstance(d["size"], bool) and d["size"] >= 0))
            and (d.get("sha256") is None) == (d.get("size") is None)
            and ("text" not in d or isinstance(d["text"], str))
            and ("summary" not in d or isinstance(d["summary"], str))
            and ("irreversible" not in d or isinstance(d["irreversible"], bool))
            and set(d) <= {"ref", "sha256", "size", "text", "summary", "irreversible"})


def filesystem_probe(tool: str, args: Any) -> Optional[Dict[str, Any]]:
    """The reference probe: for a filesystem tool with a path, the file's
    current bytes (or absence). None for tools it does not know, so the
    call is not state-bound."""
    if tool not in PROBE_TOOLS or not isinstance(args, dict):
        return None
    path = next((args[k] for k in PATH_ARGS if isinstance(args.get(k), str) and args[k]), None)
    if path is None:
        return None
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        data = None
    except IsADirectoryError:
        return describe(path, b"", with_text=False)
    except OSError:
        return None
    return describe(path, data)


def read_target(description: Dict[str, Any]) -> Optional[bytes]:
    """The bytes behind a filesystem state description, or None when absent."""
    if description.get("sha256") is None:
        return None
    try:
        with open(description["ref"], "rb") as f:
            return f.read()
    except OSError:
        return None


def probe_from_name(name: Optional[str]) -> Optional[Callable[[str, Any], Optional[Dict[str, Any]]]]:
    """GARGOYLE_MCP_STATE_PROBE: "filesystem" (default) or "none"."""
    if name in (None, "", "filesystem"):
        return filesystem_probe
    if name == "none":
        return None
    raise ValueError("unknown state probe: %s" % name)
