"""Adapters: what a held call changes, in a form the gate can bind, show,
and undo. The gate itself knows only tool names and arguments. An adapter
knows the target: it describes the target's state before and after a call
(gargoyle.state), tells the approver what the call means, and composes the
call that restores the earlier state (gargoyle.revert).

    probe(tool, args)   -> (description, bytes) | None
        description: {"ref", "sha256", "size", "text"?, "summary"?, "irreversible"?}
        bytes: the state's canonical bytes (the hash's preimage), kept as the
        snapshot; None when the target does not exist
    restore(meta, pre_bytes, post_bytes) -> {"params": {"name", "arguments"}} | {"reason": REF_REVERT_*}
        the inverse call, given the sidecar and the two snapshots

FilesystemAdapter: a tool with a path changes that file. GraphAdapter: a
Microsoft Graph MCP server's tools change mail rules, events, contacts,
Teams objects; which tool is which is a JSON spec (gargoyle/specs/
graph-reference.json is the reference naming; map your server's names).
The Graph adapter reads state through the upstream server itself, with
the same credential the write will use, so the gate needs no Graph access
of its own.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from gargoyle.envelope import canonical_json
from gargoyle.state import describe, filesystem_probe, read_target

REF_REVERT_UNKNOWN = "REF_REVERT_UNKNOWN"
REF_REVERT_NEEDS_DELETE = "REF_REVERT_NEEDS_DELETE"
REF_REVERT_NOT_TEXT = "REF_REVERT_NOT_TEXT"
REF_REVERT_IRREVERSIBLE = "REF_REVERT_IRREVERSIBLE"
REF_REVERT_UNSUPPORTED = "REF_REVERT_UNSUPPORTED"

Probe = Optional[Tuple[Dict[str, Any], Optional[bytes]]]


class FilesystemAdapter:
    """Files on the executor's host (the stdio middleware's own case)."""

    name = "filesystem"

    def probe(self, tool: str, args: Any) -> Probe:
        desc = filesystem_probe(tool, args)
        if desc is None:
            return None
        return desc, read_target(desc)

    def restore(self, meta: Dict[str, Any], pre: Optional[bytes], post: Optional[bytes]) -> Dict[str, Any]:
        if pre is None:
            return {"reason": REF_REVERT_NEEDS_DELETE}      # undoing a create is a delete, which the gate refuses
        try:
            text = pre.decode("utf-8")
        except UnicodeDecodeError:
            return {"reason": REF_REVERT_NOT_TEXT}
        return {"params": {"name": "write_file", "arguments": {"path": meta["ref"], "content": text}}}


def _tool_json(reply: Any) -> Any:
    """The JSON a Graph MCP tool returned, from its text content."""
    if not isinstance(reply, dict) or "result" not in reply:
        return None
    result = reply["result"]
    if isinstance(result, dict) and result.get("isError"):
        return None
    if isinstance(result, dict) and isinstance(result.get("structuredContent"), (dict, list)):
        return result["structuredContent"]
    for item in (result.get("content") or []) if isinstance(result, dict) else []:
        if isinstance(item, dict) and item.get("type") == "text":
            try:
                return json.loads(item["text"])
            except (ValueError, TypeError):
                return None
    return None


class GraphAdapter:
    """A Microsoft Graph MCP server, by spec.

    spec = {
      "internal_domains": ["contoso.com"],
      "kinds": {
        "<kind>": {"label": "inbox rule", "name_field": "displayName", "id_field": "id",
                   "list_tool": "...", "list_args": {}, "items_path": "value",
                   "get_tool": "...", "id_arg": "id",
                   "create_tool": "...", "create_arg": "rule",
                   "update_tool": "...", "update_arg": "rule",
                   "delete_tool": "...",
                   "writable_fields": ["displayName", "sequence", "conditions", "actions", "isEnabled"]}
      },
      "tools": {
        "<tool name>": {"kind": "<kind>", "op": "create" | "update" | "delete"},
        "<tool name>": {"op": "irreversible", "label": "send mail", "summary": "sends mail to {toRecipients}: {subject}"}
      }
    }"""

    name = "graph"

    def __init__(self, upstream: Any, spec: Dict[str, Any]) -> None:
        self.upstream = upstream
        self.spec = spec
        self._next_id = 0

    @classmethod
    def from_file(cls, upstream: Any, path: str) -> "GraphAdapter":
        return cls(upstream, json.loads(Path(path).read_text(encoding="utf-8")))

    # ---- talking to the upstream ----
    def _call(self, tool: str, args: Dict[str, Any]) -> Any:
        self._next_id += 1
        reply = self.upstream.send({"jsonrpc": "2.0", "id": "gargoyle-probe-%d" % self._next_id, "method": "tools/call",
                                    "params": {"name": tool, "arguments": args}})
        return _tool_json(reply)

    def _items(self, kind: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        doc = self._call(kind["list_tool"], dict(kind.get("list_args") or {}))
        if doc is None:
            return None
        items = doc
        for key in (kind.get("items_path") or "").split("."):
            if key:
                items = items.get(key) if isinstance(items, dict) else None
        if not isinstance(items, list):
            return None
        idf = kind.get("id_field", "id")
        return sorted((i for i in items if isinstance(i, dict) and idf in i), key=lambda i: str(i[idf]))

    def _item(self, kind: Dict[str, Any], item_id: str) -> Optional[Dict[str, Any]]:
        doc = self._call(kind["get_tool"], {kind.get("id_arg", "id"): item_id})
        return doc if isinstance(doc, dict) else None

    # ---- descriptions ----
    @staticmethod
    def _desc(ref: str, obj: Any, summary: str, irreversible: bool = False) -> Tuple[Dict[str, Any], Optional[bytes]]:
        data = canonical_json(obj).encode("utf-8") if obj is not None else None
        # The text is the hashed bytes themselves (canonical JSON), so the
        # console can verify it against the bound state before showing it;
        # it pretty-prints JSON for display.
        desc = describe(ref, data, with_text=True)
        desc["summary"] = summary
        if irreversible:
            desc["irreversible"] = True
        return desc, data

    def _external(self, value: Any) -> List[str]:
        """Addresses in `value` outside the internal domains."""
        internal = [d.lower() for d in self.spec.get("internal_domains", [])]
        found: List[str] = []

        def walk(v):
            if isinstance(v, str) and "@" in v:
                dom = v.rsplit("@", 1)[1].strip(">").lower()
                if internal and dom not in internal:
                    found.append(v)
            elif isinstance(v, dict):
                for x in v.values():
                    walk(x)
            elif isinstance(v, list):
                for x in v:
                    walk(x)
        walk(value)
        return found

    def probe(self, tool: str, args: Any) -> Probe:
        rule = (self.spec.get("tools") or {}).get(tool)
        if rule is None or not isinstance(args, dict):
            return None
        op = rule.get("op")
        if op == "irreversible":
            text = rule.get("summary", "{tool}").replace("{tool}", tool)
            for k, v in args.items():
                text = text.replace("{" + k + "}", v if isinstance(v, str) else json.dumps(v))
            ext = self._external(args)
            if ext:
                text += " (to an outside address: %s)" % ", ".join(ext[:3])
            return self._desc("%s:%s" % (tool, rule.get("label", tool)), None, text + ". Cannot be undone.", irreversible=True)
        kind = (self.spec.get("kinds") or {}).get(rule.get("kind"))
        if kind is None:
            return None
        label = kind.get("label", rule.get("kind"))
        name_field = kind.get("name_field")
        if op == "create":
            items = self._items(kind)
            if items is None:
                return None
            payload = args.get(kind.get("create_arg", "item"), args)
            name = payload.get(name_field) if isinstance(payload, dict) and name_field else None
            summary = "creates %s%s" % (label, (" '%s'" % name) if name else "")
            ext = self._external(payload)
            if ext:
                summary += " (to an outside address: %s)" % ", ".join(ext[:3])
            return self._desc("%s:all" % rule["kind"], items, summary + "; %d %s(s) exist now" % (len(items), label))
        item_id = args.get(kind.get("id_arg", "id"))
        if not isinstance(item_id, str) or not item_id:
            return None
        item = self._item(kind, item_id)
        name = item.get(name_field) if isinstance(item, dict) and name_field else None
        verb = "updates" if op == "update" else "deletes" if op == "delete" else op
        summary = "%s %s%s" % (verb, label, (" '%s'" % name) if name else " " + item_id)
        if op == "update":
            ext = self._external(args.get(kind.get("update_arg", "item"), args))
            if ext:
                summary += " (to an outside address: %s)" % ", ".join(ext[:3])
        if item is None:
            summary += " (does not exist now)"
        return self._desc("%s:%s" % (rule["kind"], item_id), item, summary)

    # ---- undo ----
    def restore(self, meta: Dict[str, Any], pre: Optional[bytes], post: Optional[bytes]) -> Dict[str, Any]:
        rule = (self.spec.get("tools") or {}).get(meta.get("tool"))
        if rule is None:
            return {"reason": REF_REVERT_UNSUPPORTED}
        if rule.get("op") == "irreversible":
            return {"reason": REF_REVERT_IRREVERSIBLE}
        kind = (self.spec.get("kinds") or {}).get(rule.get("kind")) or {}
        idf = kind.get("id_field", "id")
        load = lambda b: json.loads(b.decode("utf-8")) if b is not None else None
        before, after = load(pre), load(post)
        if rule["op"] == "create":
            # The created object is the one in the post set that was not in the pre set.
            if not isinstance(before, list) or not isinstance(after, list) or not kind.get("delete_tool"):
                return {"reason": REF_REVERT_UNSUPPORTED}
            old = {str(i.get(idf)) for i in before}
            new = [i for i in after if str(i.get(idf)) not in old]
            if len(new) != 1:
                return {"reason": REF_REVERT_UNKNOWN}
            return {"params": {"name": kind["delete_tool"], "arguments": {kind.get("id_arg", "id"): str(new[0][idf])}}}
        if rule["op"] == "update":
            if not isinstance(before, dict) or not kind.get("update_tool"):
                return {"reason": REF_REVERT_UNSUPPORTED}
            fields = kind.get("writable_fields")
            body = {k: v for k, v in before.items() if (fields is None or k in fields) and k != idf}
            return {"params": {"name": kind["update_tool"], "arguments": {kind.get("id_arg", "id"): str(before[idf]),
                                                                           kind.get("update_arg", "item"): body}}}
        if rule["op"] == "delete":
            if not isinstance(before, dict) or not kind.get("create_tool"):
                return {"reason": REF_REVERT_UNSUPPORTED}
            fields = kind.get("writable_fields")
            body = {k: v for k, v in before.items() if (fields is None or k in fields) and k != idf}
            return {"params": {"name": kind["create_tool"], "arguments": {kind.get("create_arg", "item"): body}}}
        return {"reason": REF_REVERT_UNSUPPORTED}


def adapter_from_name(name: Any, upstream: Any = None, spec_path: Optional[str] = None) -> Any:
    """GARGOYLE_MCP_STATE_PROBE: "filesystem" (default), "none", or "graph"
    with GARGOYLE_MCP_ADAPTER_SPEC naming the tool mapping (default: the
    reference naming shipped in gargoyle/specs/graph-reference.json)."""
    if name is None or name == "" or name == "filesystem":
        return FilesystemAdapter()
    if name == "none":
        return None
    if name == "graph":
        if upstream is None:
            raise ValueError("the graph adapter needs the upstream server")
        path = spec_path or str(Path(__file__).parent / "specs" / "graph-reference.json")
        return GraphAdapter.from_file(upstream, path)
    if hasattr(name, "probe"):
        return name
    if callable(name):
        return _LegacyProbeAdapter(name)
    raise ValueError("unknown state probe: %s" % name)


class _LegacyProbeAdapter:
    """A bare probe function (tool, args) -> description, for tests and
    integrators who wrote one before adapters existed."""

    name = "custom"

    def __init__(self, fn) -> None:
        self.fn = fn

    def probe(self, tool: str, args: Any) -> Probe:
        desc = self.fn(tool, args)
        return None if desc is None else (desc, read_target(desc))

    def restore(self, meta, pre, post):
        return FilesystemAdapter().restore(meta, pre, post)
