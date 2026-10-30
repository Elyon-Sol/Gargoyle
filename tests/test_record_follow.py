"""Operability: a rule change on the issuer reaches every gate without a
file copy or a restart. The issuer publishes its pin as a signed record
(SPEC 9); the middleware follows it, cached a minute, and asks again at
once when a receipt names a pin the cache does not know."""

import json
import os
import time
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import encode
from gargoyle.mcp_server import EXECUTED_META_KEY, REASON_META_KEY, IssuerClient, RecordFollower, ServerState, handle_message
from gargoyle.published_record_source import load_signed_record_from_bytes
from gargoyle.rules import RulesPolicy
from gargoyle.verifier import REF_VERIFY_PUBLISHED_RECORD_STALE, REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED

issuer, idp, executor = (Ed25519PrivateKey.generate() for _ in range(3))
TARGET = "mcp://fs"
PRINCIPAL = "agent@contoso.com"
RULES_A = {"version": "a", "default": "allow", "rules": []}
RULES_B = {"version": "b", "default": "allow", "rules": [{"tools": ["delete_*"], "action": "deny", "reason": "DESTRUCTIVE_TOOL"}]}


def _write_rules(path, doc, bump):
    path.write_text(json.dumps(doc))
    os.utime(path, (time.time() + bump, time.time() + bump))      # a new mtime, so the policy reloads


def _token():
    return encode({"sub": PRINCIPAL, "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")


class Shim:
    def __init__(self, c): self.c = c
    def post(self, url, json=None, headers=None, timeout=None): return self.c.post(url.replace("http://i", ""), json=json, headers=headers)
    def get(self, url, headers=None, timeout=None): return self.c.get(url.replace("http://i", ""), headers=headers)


def test_the_issuer_publishes_a_signed_record_whose_serial_rises_with_the_pin(tmp_path):
    rules = tmp_path / "rules.json"; _write_rules(rules, RULES_A, 0)
    pol = RulesPolicy(str(rules))
    clock = [datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)]
    c = TestClient(build_issuer_app(policy=pol, signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()}, now=lambda: clock[0]))
    first = c.get("/record")
    res = load_signed_record_from_bytes(first.content, {"issuer-1": issuer.public_key()}, now=clock[0])
    assert res["reason"] is None and res["record"]["policy_sha256"] == pol.pin()["policy_sha256"]
    serial = res["record"]["serial"]
    clock[0] += timedelta(seconds=30)
    assert c.get("/record").json()["serial"] == serial                      # same pin, same serial
    _write_rules(rules, RULES_B, 10)
    second = c.get("/record").json()
    assert second["policy_sha256"] == pol.pin()["policy_sha256"] != res["record"]["policy_sha256"] and second["serial"] > serial
    # A record rolled back to the earlier serial is stale once the higher one was seen; the wrong key is invalid.
    assert load_signed_record_from_bytes(first.content, {"issuer-1": issuer.public_key()}, now=clock[0], last_seen_serial=second["serial"])["reason"] == REF_VERIFY_PUBLISHED_RECORD_STALE
    assert load_signed_record_from_bytes(first.content, {"issuer-1": Ed25519PrivateKey.generate().public_key()}, now=clock[0])["record"] is None


def test_a_gate_following_the_record_survives_a_rule_change_without_a_copy_or_restart(tmp_path):
    rules = tmp_path / "rules.json"; _write_rules(rules, RULES_A, 0)
    pol = RulesPolicy(str(rules))
    c = TestClient(build_issuer_app(policy=pol, signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()}))
    ic = IssuerClient("http://i", _token(), http=Shim(c))
    config = {"pinned_public_keys": {"issuer-1": issuer.public_key()}, "record": None, "record_url": "http://i/record",
              "target_id": TARGET, "principal": PRINCIPAL, "executor_signing_key": executor, "executor_key_id": "executor-1"}
    live = ServerState(config, issuer_client=ic, audit_log=str(tmp_path / "audit.jsonl"), state_root="/gargoyle-test-root"); live.initialized = True
    stale = ServerState(dict(config, record=pol.pin(), record_url=None), issuer_client=ic, state_root="/gargoyle-test-root"); stale.initialized = True   # a static copy of today's pin
    call = lambda i: {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "a"}}}
    assert handle_message(live, call(1))["result"]["_meta"][EXECUTED_META_KEY] is True
    assert handle_message(stale, call(2))["result"]["_meta"][EXECUTED_META_KEY] is True
    assert live.record_follower.fetches == 1
    # The operator tightens the rules. The issuer applies them at once.
    _write_rules(rules, RULES_B, 10)
    r = handle_message(live, call(3))
    assert r["result"]["_meta"][EXECUTED_META_KEY] is True                 # the cached pin disagreed; the gate asked again
    assert live.record_follower.fetches == 2
    assert handle_message(live, call(4))["result"]["_meta"][EXECUTED_META_KEY] is True and live.record_follower.fetches == 2
    denied = handle_message(live, {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "delete_file", "arguments": {"path": "a"}}})
    assert denied["result"]["_meta"][REASON_META_KEY] == "DESTRUCTIVE_TOOL"
    # The gate on a static copy of the old pin refuses until someone copies the new file.
    s = handle_message(stale, call(6))
    assert s["result"]["_meta"][EXECUTED_META_KEY] is False and s["result"]["_meta"][REASON_META_KEY] == REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED


def test_follower_does_not_cache_a_failure(tmp_path):
    class Down:
        def get(self, url, timeout=None): raise ConnectionError("down")
    f = RecordFollower("http://i/record", {"issuer-1": issuer.public_key()}, http=Down())
    assert f(None)["record"] is None and f(None)["record"] is None and f.fetches == 2
