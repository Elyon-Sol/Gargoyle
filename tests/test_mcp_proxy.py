"""The MCP server as middleware: in front of an upstream stdio MCP server it
relays everything except tools/call, which it forwards only once a receipt
has been honored, with Gargoyle's own _meta keys stripped."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from gargoyle.consumer import REF_TARGET_NOT_CONFIGURED
from gargoyle.issuer import issue
from gargoyle.mcp_server import (
    ENVELOPE_META_KEY, EXECUTED_META_KEY, REASON_META_KEY, ServerState, StdioUpstream,
    call_for, handle_message, upstream_from_argv,
)
from gargoyle.policy import manifest_sha256
from gargoyle.published_source import anchor_sha256
from gargoyle.verifier import REF_VERIFY_ENVELOPE_ABSENT, REF_VERIFY_REPLAY
from reference import MANIFEST_PATH, reference_policy, reference_record_bytes

FIXTURE = str(Path(__file__).parent / "fixtures" / "echo_mcp_server.py")
UPSTREAM_CMD = [sys.executable, "-I", FIXTURE]
TARGET_ID = "mcp://tools.example.com"
PRINCIPAL = "agent-7"


@pytest.fixture
def upstream():
    up = StdioUpstream(UPSTREAM_CMD)
    try:
        yield up
    finally:
        up.close()


def _config(key):
    record_bytes = reference_record_bytes()
    return {"pinned_public_keys": {"k1": key.public_key()}, "record_bytes": record_bytes,
            "pinned_root": anchor_sha256(record_bytes), "target_id": TARGET_ID, "principal": PRINCIPAL}


def _receipt(key, args):
    interaction = {**call_for("echo", args, PRINCIPAL), "AP": ["identity", "role"], "OP": ["session", "request"],
                   "expected_manifest_version": "1.0", "expected_manifest_sha256": manifest_sha256(MANIFEST_PATH)}
    return issue(reference_policy(), TARGET_ID, interaction, signing_key=key, key_id="k1").envelope


def _calls(upstream):
    return upstream.send({"jsonrpc": "2.0", "id": "f", "method": "fixture/calls"})["result"]["calls"]


def test_proxy_relays_handshake_and_tool_list_from_the_upstream(upstream):
    state = ServerState(_config(Ed25519PrivateKey.generate()), upstream=upstream)
    init = handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init["result"]["serverInfo"]["name"] == "echo-upstream"      # the upstream's, not ours
    assert handle_message(state, {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    tools = handle_message(state, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert [t["name"] for t in tools["result"]["tools"]] == ["echo"]
    # An unknown method goes to the upstream too, and its error comes back.
    assert handle_message(state, {"jsonrpc": "2.0", "id": 3, "method": "resources/list"})["error"]["code"] == -32601


def test_proxy_forwards_only_honored_calls_and_strips_its_meta(upstream):
    key = Ed25519PrivateKey.generate()
    state = ServerState(_config(key), upstream=upstream)
    handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    handle_message(state, {"jsonrpc": "2.0", "method": "notifications/initialized"})

    bare = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": {"x": 1}}}
    refused = handle_message(state, bare)
    assert refused["result"]["isError"] is True
    assert refused["result"]["_meta"][REASON_META_KEY] == REF_VERIFY_ENVELOPE_ABSENT
    assert _calls(upstream) == []                                          # never reached the upstream

    env = _receipt(key, {"x": 1})
    attested = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"x": 1},
                           "_meta": {ENVELOPE_META_KEY: env, "progressToken": "p-1"}}}
    reply = handle_message(state, attested)
    assert reply["id"] == 3 and reply["result"]["isError"] is False
    assert reply["result"]["content"][0]["text"] == 'echo:{"x": 1}'
    assert reply["result"]["_meta"] == {"upstream": "seen", EXECUTED_META_KEY: True,
                                        REASON_META_KEY: "REASSERTED_AND_BOUND"}
    forwarded = _calls(upstream)
    assert forwarded == [{"name": "echo", "arguments": {"x": 1}, "_meta": {"progressToken": "p-1"}}]

    replay = handle_message(state, dict(attested, id=4))
    assert replay["result"]["isError"] is True
    assert replay["result"]["_meta"][REASON_META_KEY] == REF_VERIFY_REPLAY
    other_args = {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                  "params": {"name": "echo", "arguments": {"x": 2}, "_meta": {ENVELOPE_META_KEY: env}}}
    assert handle_message(state, other_args)["result"]["isError"] is True
    assert len(_calls(upstream)) == 1
    assert state.executed == [{"tool": "echo", "args": {"x": 1}}]


def test_unconfigured_proxy_relays_nothing_gated(upstream):
    state = ServerState(None, upstream=upstream)
    handle_message(state, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    handle_message(state, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    r = handle_message(state, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": {}}})
    assert r["result"]["_meta"][REASON_META_KEY] == REF_TARGET_NOT_CONFIGURED
    assert _calls(upstream) == []


def test_upstream_from_argv():
    assert upstream_from_argv([]) is None and upstream_from_argv(["--"]) is None
    up = upstream_from_argv(["--", *UPSTREAM_CMD])
    try:
        assert up.command == UPSTREAM_CMD
    finally:
        up.close()


def test_end_to_end_over_stdio(tmp_path):
    """The real entry point: `python -m gargoyle.mcp_server -- <upstream>`
    with configuration from the environment, driven over its stdio."""
    key = Ed25519PrivateKey.generate()
    record = tmp_path / "record.json"; record.write_bytes(reference_record_bytes())
    env = dict(os.environ,
               GARGOYLE_MCP_GATE_KEY_ID="k1",
               GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX=key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
               GARGOYLE_MCP_TARGET_ID=TARGET_ID, GARGOYLE_MCP_PRINCIPAL=PRINCIPAL,
               GARGOYLE_MCP_RECORD_PATH=str(record))
    receipt = _receipt(key, {"x": 1})
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": {"x": 1}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "echo", "arguments": {"x": 1}, "_meta": {ENVELOPE_META_KEY: receipt}}},
        {"jsonrpc": "2.0", "id": 4, "method": "gargoyle/executed_count"},
    ]
    proc = subprocess.run([sys.executable, "-m", "gargoyle.mcp_server", "--", *UPSTREAM_CMD],
                          input="".join(json.dumps(l) + "\n" for l in lines), capture_output=True,
                          text=True, env=env, timeout=60, cwd=str(Path(__file__).parent.parent))
    replies = {r["id"]: r for r in (json.loads(l) for l in proc.stdout.splitlines() if l.strip())}
    assert replies[1]["result"]["serverInfo"]["name"] == "echo-upstream"
    assert replies[2]["result"]["isError"] is True
    assert replies[3]["result"]["isError"] is False and replies[3]["result"]["content"][0]["text"] == 'echo:{"x": 1}'
    assert replies[4]["result"] == {"count": 1}
