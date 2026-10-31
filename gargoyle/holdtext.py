"""One sentence per hold, for the approver who is not an engineer.

The approver signs the receipt's args_sha256 and state_sha256; what the
console shows is a rendering of those same bytes. This module is the
rendering for the non-technical views: a deterministic function of the
tool, the arguments the issuer holds and the executor's pre-state
description, computed in the issuer so the console and `gargoyle approve`
say the same thing. It is never authored text and never a model's
summary: when no template fits, `readable` is False and the hold is for
the technical view only.

    describe_hold("write_file", {"path": "/srv/clients/acme/plan.md", "content": ...}, state)
    -> {"sentence": "Replace the contents of plan.md in /srv/clients/acme (412 -> 530 bytes; +4/-1 lines)",
        "readable": True, "irreversible": False, "verb": "replace"}

An executor may hand the issuer its own `summary` (and `irreversible`) in
the state description (gargoyle.state); that is the adapter's template and
wins over the ones here.
"""

import difflib
import ntpath
import posixpath
from typing import Any, Dict, Optional, Tuple

READ_TOOLS = ("read_file", "read_multiple_files", "list_directory", "list_allowed_directories", "get_file_info",
              "search_files", "directory_tree", "read_text_file", "read_media_file", "list_directory_with_sizes")


def _is_windows(path: str) -> bool:
    return "\\" in path or (len(path) > 1 and path[1] == ":")


def split_path(path: Any) -> Tuple[str, str]:
    """(folder, name) for a POSIX or Windows path; ("", path) when there is no folder."""
    if not isinstance(path, str) or not path:
        return "", ""
    mod = ntpath if _is_windows(path) else posixpath
    folder, name = mod.split(path.rstrip("/\\") or path)
    return folder, name or path


def human_bytes(n: Any) -> str:
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        return "unknown size"
    if n < 1024:
        return "%d bytes" % n
    if n < 1024 * 1024:
        return "%.1f KB" % (n / 1024)
    return "%.1f MB" % (n / (1024 * 1024))


def line_delta(old: str, new: str) -> Tuple[int, int]:
    """(added, removed) line counts between two texts."""
    added = removed = 0
    for line in difflib.ndiff(old.splitlines(), new.splitlines()):
        if line.startswith("+ "):
            added += 1
        elif line.startswith("- "):
            removed += 1
    return added, removed


def _where(folder: str) -> str:
    return (" in " + folder) if folder else ""


def _out(sentence: str, *, readable: bool = True, irreversible: bool = False, verb: str = "") -> Dict[str, Any]:
    return {"sentence": sentence, "readable": readable, "irreversible": irreversible, "verb": verb}


def describe_hold(tool: Any, args: Any, state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The plain-language line for one held call. `state` is the executor's
    description of the target before the call ({"ref", "sha256", "size",
    "text"?, "summary"?, "irreversible"?}) or None."""
    args = args if isinstance(args, dict) else {}
    state = state if isinstance(state, dict) else {}
    tool = tool if isinstance(tool, str) else ""
    irreversible = bool(state.get("irreversible"))
    if isinstance(state.get("summary"), str) and state["summary"]:
        # The adapter's own words for its own tool (graph's send_mail says
        # who the mail goes to); the file templates below are the fallback.
        return _out(state["summary"], irreversible=irreversible, verb=tool)
    exists = state.get("sha256") is not None if "sha256" in state else None
    folder, name = split_path(args.get("path"))
    if tool == "write_file":
        content = args.get("content")
        new_size = len(content.encode("utf-8")) if isinstance(content, str) else None
        if exists is False:
            s = "Create %s (%s)%s" % (name or "a file", human_bytes(new_size), _where(folder))
            return _out(s, verb="create") if name else _out(s, readable=False, verb="create")
        if not state:
            # No pre-state was described: the file may or may not exist.
            s = "Write %s (%s)%s" % (name or "a file", human_bytes(new_size), _where(folder))
            return _out(s, verb="write") if name else _out(s, readable=False, verb="write")
        s = "Replace the contents of %s%s (%s -> %s" % (name, _where(folder), human_bytes(state.get("size")), human_bytes(new_size))
        if isinstance(state.get("text"), str) and isinstance(content, str):
            add, rem = line_delta(state["text"], content)
            s += "; +%d/-%d lines" % (add, rem)
        return _out(s + ")", irreversible=irreversible, verb="replace")
    if tool == "edit_file":
        edits = args.get("edits")
        n = len(edits) if isinstance(edits, list) else None
        s = "Change %s in %s%s" % ("%d passage%s" % (n, "" if n == 1 else "s") if n is not None else "text", name, _where(folder))
        if isinstance(state.get("size"), int):
            s += " (%s now)" % human_bytes(state["size"])
        return _out(s, irreversible=irreversible, verb="edit")
    if tool == "create_directory":
        return _out("Create folder %s%s" % (name, _where(folder)), verb="create")
    if tool == "move_file":
        sf, sn = split_path(args.get("source"))
        df, dn = split_path(args.get("destination"))
        if not sn or not dn:
            return _out("move with incomplete arguments", readable=False, verb="move")
        if sf == df:
            return _out("Rename %s to %s%s" % (sn, dn, _where(sf)), irreversible=irreversible, verb="rename")
        return _out("Move %s from %s to %s" % (sn, sf or "the root", df or "the root"), irreversible=irreversible, verb="move")
    if tool.startswith("delete_") or tool in ("rm", "remove_file", "unlink"):
        target = name or str(args.get("path") or args.get("source") or "")
        size = " (%s)" % human_bytes(state["size"]) if isinstance(state.get("size"), int) else ""
        return _out("Delete %s%s%s" % (target or "a file", size, (" from " + folder) if folder else ""),
                    readable=bool(target), irreversible=True, verb="delete")
    if tool in READ_TOOLS:
        what = name or str(args.get("path") or "")
        return _out("Read %s%s" % (what, _where(folder)) if what else "Read from the target", verb="read")
    if tool == "send_mail":
        to = args.get("to") or args.get("recipients") or args.get("toRecipients")
        subject = args.get("subject")
        attachments = args.get("attachments")
        if isinstance(to, list) and to and all(isinstance(t, str) for t in to) and isinstance(subject, str):
            n = len(attachments) if isinstance(attachments, list) else 0
            s = "Send an email to %s with subject '%s'" % (", ".join(to), subject)
            if n:
                s += " (%d attachment%s)" % (n, "" if n == 1 else "s")
            return _out(s, irreversible=True, verb="send")
        return _out("send_mail with arguments this view cannot read", readable=False, irreversible=True, verb="send")
    n = len(args)
    return _out("%s with %d argument%s" % (tool or "an unnamed tool", n, "" if n == 1 else "s"),
                readable=False, irreversible=irreversible, verb=tool)


def describe_plan(plan: Any) -> Dict[str, Any]:
    """The line for a scoped grant (gargoyle.plans): the plan's own note and
    what its steps are made of."""
    if not isinstance(plan, dict) or not isinstance(plan.get("steps"), list):
        return _out("a plan this view cannot read", readable=False, verb="plan")
    counts: Dict[str, int] = {}
    for s in plan["steps"]:
        t = s.get("tool") if isinstance(s, dict) else None
        counts[t if isinstance(t, str) else "?"] = counts.get(t if isinstance(t, str) else "?", 0) + 1
    parts = ", ".join("%d %s" % (n, t) for t, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
    note = plan.get("note") if isinstance(plan.get("note"), str) and plan.get("note") else "(no note)"
    total = len(plan["steps"])
    return _out("Plan of %d step%s: %s (%s)" % (total, "" if total == 1 else "s", note, parts),
                readable=bool(parts) and "?" not in counts, verb="plan")
