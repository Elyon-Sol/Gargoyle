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
import ntpath
import os
import posixpath
import re
from typing import Any, Callable, Dict, Optional

from gargoyle.envelope import canonical_json

PROBE_TOOLS = ("write_file", "edit_file", "create_directory", "move_file", "delete_file")
PATH_ARGS = ("path", "source")
RESOLVED_ARGS = ("path", "source", "destination")
REF_TARGET_RELATIVE_PATH = "REF_TARGET_RELATIVE_PATH"   # a state-bound tool named a relative path and no root is configured
REF_TARGET_PATH_NOT_CANONICAL = "REF_TARGET_PATH_NOT_CANONICAL"  # Windows would rewrite the name (trailing dot/space, stream suffix, device name)
REF_TARGET_STATE_UNREADABLE = "REF_TARGET_STATE_UNREADABLE"      # the target exists but could not be read: the call must not run unbound


class StateUnreadable(Exception):
    """The target exists but its bytes could not be read (a sharing violation,
    a permission error). Before 2026-11-01 the probe returned None here and
    the call went on unbound: no state on the card, no state check at
    execution, no line in any log. A security property must not vanish
    silently; the gate refuses instead."""


def is_absolute_path(value: str) -> bool:
    """POSIX absolute, a Windows drive path, or a UNC path. Anything else
    is relative to something, and that something must be the root."""
    return value.startswith("/") or value.startswith("\\\\") or bool(re.match(r"^[A-Za-z]:[\\/]", value))


def resolve_path_args(tool: str, args: Any, root: Optional[str]):
    """Return (args, reason). A relative path argument is made absolute
    against `root` before anything looks at it, so the state the receipt
    binds, the rules that match the path, the gate-folder check and the
    upstream all see the same file. The upstream resolves relative paths
    against its own root; the gate has to agree with it, not with its own
    working directory (found 2026-10-30: a client sent "hello.txt", the
    gate bound an absent file beside itself while the upstream overwrote
    the real one). Without a root, a relative path on a state-bound tool is
    refused with REF_TARGET_RELATIVE_PATH; other tools pass through as before."""
    if not isinstance(args, dict):
        return args, None
    from gargoyle.globs import is_windows_path, path_rewrite_reason
    out = None
    for key in RESOLVED_ARGS:
        value = args.get(key)
        if not isinstance(value, str) or not value:
            continue
        if not is_absolute_path(value):
            if root is None:
                if tool in PROBE_TOOLS:
                    return args, REF_TARGET_RELATIVE_PATH
                continue
            if out is None:
                out = dict(args)
            value = out[key] = _join_under(root, value)
        # A name Windows would rewrite is refused before the rules see it, so
        # the name judged, the name bound and the name on disk are one name
        # (soak test 2026-11-01: `x.ps1.`, `x.ps1 ` and `x.ps1::$DATA` slipped
        # a hold on `*.ps1` and landed as x.ps1).
        if (is_windows_path(value) or (root is not None and not root.startswith("/"))) and path_rewrite_reason(value):
            return args, REF_TARGET_PATH_NOT_CANONICAL
    return (out if out is not None else args), None


def resolve_steps(steps: Any, root: Optional[str]):
    """Plan steps resolved the way calls are: exact arguments through
    `resolve_path_args`, relative `match` globs joined under the root. Until
    2026-11-01 steps went to the issuer as written while calls were
    resolved first, so a relative step was judged by the wrong rules and
    never matched the call it was meant to release. Returns (steps, reason)."""
    if not isinstance(steps, list):
        return steps, None
    out = []
    for s in steps:
        if isinstance(s, dict) and isinstance(s.get("args"), dict):
            a, why = resolve_path_args(str(s.get("tool")), s["args"], root)
            if why is not None:
                return steps, why
            s = dict(s, args=a)
        elif isinstance(s, dict) and isinstance(s.get("match"), dict) and root:
            m = dict(s["match"])
            for k in RESOLVED_ARGS:
                v = m.get(k)
                if isinstance(v, str) and v and not is_absolute_path(v):
                    m[k] = _join_under(root, v)
            s = dict(s, match=m)
        out.append(s)
    return out, None


def _join_under(root: str, value: str) -> str:
    """root + value in the root's own flavour: a POSIX root gives a POSIX
    path and a Windows root a Windows one, whatever platform the gate runs
    on, because the root describes the upstream, not the gate."""
    if root.startswith("/"):
        return posixpath.normpath(posixpath.join(root, value.replace("\\", "/")))
    return ntpath.normpath(ntpath.join(root, value))
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
    if os.path.isdir(path):
        # The same on every platform: Windows raises PermissionError for a
        # directory, which used to leave create_directory unbound there.
        return describe(path, b"", with_text=False)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        data = None
    except IsADirectoryError:
        return describe(path, b"", with_text=False)
    except OSError as exc:
        raise StateUnreadable("%s: %s" % (path, exc))
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
