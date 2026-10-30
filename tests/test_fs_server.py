"""gargoyle.fs_server: the Python filesystem MCP server stays inside its root
and works behind the gate end to end."""

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.fs_server import Root
from gargoyle.issuer import issue
from gargoyle.mcp_server import ENVELOPE_META_KEY, ServerState, StdioUpstream, call_for, handle_message
from reference import reference_pin, reference_policy


def test_root_confines_every_path(tmp_path):
    root = Root(str(tmp_path)); (tmp_path / "a.txt").write_text("hi")
    assert root.call("list_allowed_directories", {}) == str(tmp_path.resolve())
    assert "[FILE] a.txt" in root.call("list_directory", {"path": "."})
    assert root.call("read_file", {"path": "a.txt"}) == "hi"
    root.call("write_file", {"path": "sub/b.txt", "content": "x"}); assert (tmp_path / "sub" / "b.txt").read_text() == "x"
    root.call("move_file", {"source": "sub/b.txt", "destination": "c.txt"}); assert (tmp_path / "c.txt").exists()
    root.call("delete_file", {"path": "c.txt"}); assert not (tmp_path / "c.txt").exists()
    for bad in ({"path": "../outside"}, {"path": "/etc/passwd"}):
        try:
            root.call("read_file", bad); assert False, bad
        except ValueError as e:
            assert "outside" in str(e)
    try:
        root.call("delete_file", {"path": "sub"}); assert False
    except ValueError:
        pass


def test_behind_the_gate_over_stdio(tmp_path):
    key = Ed25519PrivateKey.generate()
    up = StdioUpstream([sys.executable, "-m", "gargoyle.fs_server", str(tmp_path)])
    try:
        # The gate resolves relative paths against the upstream's root before
        # anything looks at them, so a receipt the client brings is for the
        # resolved call, and the state it binds is the real file's.
        state = ServerState({"pinned_public_keys": {"k1": key.public_key()}, "record": reference_pin(),
                             "target_id": "mcp://fs", "principal": "agent-7"}, upstream=up, state_root=str(tmp_path))
        init = handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert init["result"]["serverInfo"]["name"] == "gargoyle-fs"
        handle_message(state, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        names = [t["name"] for t in handle_message(state, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]]
        assert "write_file" in names and "delete_file" in names
        args = {"path": "hello.txt", "content": "written under a receipt"}
        resolved = {"path": str(tmp_path / "hello.txt"), "content": "written under a receipt"}
        env = issue(reference_policy(), "mcp://fs", call_for("write_file", resolved, "agent-7"), signing_key=key, key_id="k1").envelope
        r = handle_message(state, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                   "params": {"name": "write_file", "arguments": args, "_meta": {ENVELOPE_META_KEY: env}}})
        assert r["result"]["isError"] is False and (tmp_path / "hello.txt").read_text() == "written under a receipt"
        bare = handle_message(state, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "hello.txt"}}})
        assert bare["result"]["isError"] is True            # no receipt, no read
    finally:
        up.close()


def test_relative_path_without_a_root_is_refused_not_misbound(tmp_path):
    """No root to resolve against: a state-bound tool with a relative path
    is refused before any receipt, instead of binding a file beside the
    gate while the upstream writes a different one."""
    from gargoyle.mcp_server import REASON_META_KEY
    from gargoyle.state import REF_TARGET_RELATIVE_PATH
    key = Ed25519PrivateKey.generate()
    up = StdioUpstream([sys.executable, "-m", "gargoyle.fs_server", str(tmp_path)])
    try:
        state = ServerState({"pinned_public_keys": {"k1": key.public_key()}, "record": reference_pin(),
                             "target_id": "mcp://fs", "principal": "agent-7"}, upstream=up)
        assert state.state_root is None
        handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        handle_message(state, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        args = {"path": "hello.txt", "content": "x"}
        env = issue(reference_policy(), "mcp://fs", call_for("write_file", args, "agent-7"), signing_key=key, key_id="k1").envelope
        r = handle_message(state, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                   "params": {"name": "write_file", "arguments": args, "_meta": {ENVELOPE_META_KEY: env}}})
        assert r["result"]["isError"] is True and r["result"]["_meta"][REASON_META_KEY] == REF_TARGET_RELATIVE_PATH
        assert not (tmp_path / "hello.txt").exists()
    finally:
        up.close()


def test_root_comes_from_a_filesystem_target_id(tmp_path):
    key = Ed25519PrivateKey.generate()
    state = ServerState({"pinned_public_keys": {"k1": key.public_key()}, "record": reference_pin(),
                         "target_id": "mcp://filesystem/" + str(tmp_path), "principal": "agent-7"})
    assert state.state_root == str(tmp_path)
    assert ServerState({"pinned_public_keys": {"k1": key.public_key()}, "record": reference_pin(),
                        "target_id": "claude-code:///x", "principal": "agent-7"}).state_root is None


def test_write_and_read_are_byte_exact_whatever_the_platform_newline(tmp_path):
    """A restored snapshot must hash to what it hashed before: no newline
    translation on write (Windows would double every line ending) or read."""
    from gargoyle.fs_server import Root
    root = Root(str(tmp_path))
    content = "a\r\nb\nc"
    root.call("write_file", {"path": str(tmp_path / "x.md"), "content": content})
    assert (tmp_path / "x.md").read_bytes() == content.encode("utf-8")
    assert root.call("read_file", {"path": str(tmp_path / "x.md")}) == content
