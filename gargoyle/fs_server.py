"""A small filesystem MCP server over stdio, in Python, for deployments that
have no Node: list, read, write, create directories, move and delete under
one root. It exists so the gated workflow can be shown with nothing but
the package installed; it is not a replacement for the official server.

    python -m gargoyle.fs_server <root>

Every path argument must resolve inside <root>; anything else is an error
result. The tool names match the official filesystem server's where the
behaviour is the same, so one rules file governs either.
"""

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict

PROTOCOL_VERSION = "2025-06-18"
TOOLS = [
    {"name": "list_directory", "description": "List entries under a directory.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "read_file", "description": "Read a UTF-8 text file.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "write_file", "description": "Create or overwrite a UTF-8 text file.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                     "required": ["path", "content"]}},
    {"name": "create_directory", "description": "Create a directory (and parents).",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "move_file", "description": "Move or rename a file or directory.",
     "inputSchema": {"type": "object", "properties": {"source": {"type": "string"}, "destination": {"type": "string"}},
                     "required": ["source", "destination"]}},
    {"name": "delete_file", "description": "Delete a file.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "list_allowed_directories", "description": "The root this server serves.",
     "inputSchema": {"type": "object", "properties": {}}},
]


from gargoyle.globs import path_rewrite_reason

# On Windows a name the filesystem would rewrite (trailing dot or space, a
# stream suffix, a device name) is refused outright, so the file created is
# the file named. Tests set this on any platform.
STRICT_NAMES = os.name == "nt"


class Root:
    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise SystemExit("fs_server: not a directory: %s" % root)

    def inside(self, p: str) -> Path:
        if STRICT_NAMES:
            reason = path_rewrite_reason(p)
            if reason:
                raise ValueError("path is not canonical: %s (%s)" % (p, reason))
        q = (self.root / p).resolve() if not Path(p).is_absolute() else Path(p).resolve()
        if q != self.root and self.root not in q.parents:
            raise ValueError("path is outside the allowed root: %s" % p)
        return q

    def call(self, name: str, args: Dict[str, Any]) -> str:
        if name == "list_allowed_directories":
            return str(self.root)
        if name == "list_directory":
            d = self.inside(args["path"])
            return "\n".join(("[DIR]  " if e.is_dir() else "[FILE] ") + e.name for e in sorted(d.iterdir())) or "(empty)"
        if name == "read_file":
            # Bytes as they are: no newline translation, so what the assistant
            # reads is what the state probe hashes.
            return self.inside(args["path"]).read_bytes().decode("utf-8")
        if name == "write_file":
            # Bytes as given: on Windows, text mode would turn every "\n" into
            # "\r\n", and a restored snapshot would no longer match its hash.
            p = self.inside(args["path"]); p.parent.mkdir(parents=True, exist_ok=True)
            data = args["content"].encode("utf-8")
            p.write_bytes(data)
            return "wrote %d bytes to %s" % (len(data), p)
        if name == "create_directory":
            p = self.inside(args["path"]); existed = p.is_dir(); p.mkdir(parents=True, exist_ok=True)
            return ("already existed %s" if existed else "created %s") % p
        if name == "move_file":
            s, d = self.inside(args["source"]), self.inside(args["destination"])
            shutil.move(str(s), str(d))
            return "moved %s -> %s" % (s, d)
        if name == "delete_file":
            p = self.inside(args["path"])
            if p.is_dir():
                raise ValueError("delete_file refuses directories")
            p.unlink()
            return "deleted %s" % p
        raise ValueError("unknown tool: %s" % name)


def serve(root: Root, stdin=None, stdout=None) -> None:
    from gargoyle.mcp_server import utf8_stdio
    stdin, stdout = utf8_stdio(stdin, stdout)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        method, msg_id = msg.get("method"), msg.get("id")
        if method == "initialize":
            result = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                      "serverInfo": {"name": "gargoyle-fs", "version": "0.1"}}
        elif method == "notifications/initialized":
            continue
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = msg.get("params") or {}
            try:
                text = root.call(params.get("name"), params.get("arguments") or {})
                result = {"content": [{"type": "text", "text": text}], "isError": False}
            except Exception as exc:
                result = {"content": [{"type": "text", "text": "error: %s" % exc}], "isError": True}
        else:
            if msg_id is None:
                continue
            stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id,
                                     "error": {"code": -32601, "message": "method not found: %s" % method}}) + "\n")
            stdout.flush()
            continue
        if msg_id is not None:
            stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
            stdout.flush()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m gargoyle.fs_server <root>")
    serve(Root(sys.argv[1]))
