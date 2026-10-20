"""State-bound approval: a held call is approved against the target's state
and runs only in that state. The middleware probes the file before asking,
the issuer binds the hash into the receipt, the approver sees the change,
the middleware probes again before running and refuses if the file moved,
and the execution receipt records the state before and after."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gargoyle.approval import build_grant, sign_grant
from gargoyle.consumer import Consumer
from gargoyle.envelope import build_envelope
from gargoyle.execution import (ACCEPT_CHAIN_VERIFIED, REF_EXEC_BINDING_MISMATCH, build_execution_receipt,
                                sign_execution_receipt, verify_chain, verify_execution_receipt)
from gargoyle.issuer import issue
from gargoyle.issuer_service import build_issuer_app
from gargoyle.jws import encode
from gargoyle.policy import ELIGIBLE, Decision
from gargoyle.state import describe, filesystem_probe, probe_from_name, state_sha256, valid_description
from gargoyle.verifier import REF_VERIFY_ENVELOPE_ABSENT, REF_VERIFY_STATE_MISMATCH, verify_envelope

TARGET = "mcp://fs"
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
issuer, executor, approver, idp = (Ed25519PrivateKey.generate() for _ in range(4))
ISSUER_KEYS = {"issuer-1": issuer.public_key()}


class Hold:
    def pin(self): return PIN
    def decide(self, target_url, interaction): return Decision(ELIGIBLE, None, True)


class Allow:
    def pin(self): return PIN
    def decide(self, target_url, interaction): return Decision(ELIGIBLE)


def test_state_description_and_hash_cover_bytes_not_text():
    d = describe("C:\\x\\notes.md", b"hello")
    assert d["sha256"] and d["size"] == 5 and d["text"] == "hello"
    assert state_sha256(d) == state_sha256({k: v for k, v in d.items() if k != "text"})
    assert state_sha256(describe("p", b"hello")) != state_sha256(describe("p", b"hellO"))
    absent = describe("p", None)
    assert absent["sha256"] is None and absent["size"] is None and "text" not in absent
    assert state_sha256(absent) != state_sha256(describe("p", b""))
    assert valid_description(d) and valid_description(absent)
    for bad in ({"ref": ""}, {"ref": "p", "sha256": "x", "size": 1}, {"ref": "p", "sha256": "a" * 64}, {"ref": "p", "extra": 1}):
        assert not valid_description(bad), bad


def test_filesystem_probe_reads_the_target_or_its_absence(tmp_path):
    f = tmp_path / "n.md"; f.write_bytes(b"one\n")
    d = filesystem_probe("write_file", {"path": str(f), "content": "two"})
    assert d["ref"] == str(f) and d["size"] == 4 and d["text"] == "one\n"
    gone = filesystem_probe("write_file", {"path": str(tmp_path / "new.md"), "content": "x"})
    assert gone["sha256"] is None
    assert filesystem_probe("read_file", {"path": str(f)}) is None           # not a state-changing tool
    assert filesystem_probe("write_file", {"content": "x"}) is None          # nothing to probe
    assert filesystem_probe("move_file", {"source": str(f), "destination": str(tmp_path / "m")})["size"] == 4
    assert probe_from_name("none") is None and probe_from_name(None) is filesystem_probe
    with pytest.raises(ValueError):
        probe_from_name("magic")


def test_receipt_binds_the_state_and_the_verifier_enforces_it():
    pre = state_sha256(describe("p", b"one"))
    call = {"tool": "write_file", "args": {"path": "p", "content": "two"}, "principal": "agent-7", "state_sha256": pre}
    env = issue(Hold(), TARGET, call, signing_key=issuer, key_id="issuer-1", now=NOW).envelope
    assert env["request_context"]["state_sha256"] == pre
    live = {"tool": "write_file", "args": {"path": "p", "content": "two"}, "principal": "agent-7"}
    kw = dict(record_source=PIN, pinned_public_keys=ISSUER_KEYS, now=NOW)
    assert verify_envelope(env, dict(live, state_sha256=pre), TARGET, **kw)["accepted"]
    assert verify_envelope(env, live, TARGET, **kw)["reason"] == REF_VERIFY_STATE_MISMATCH          # executor saw nothing
    moved = state_sha256(describe("p", b"one and more"))
    assert verify_envelope(env, dict(live, state_sha256=moved), TARGET, **kw)["reason"] == REF_VERIFY_STATE_MISMATCH
    # Lowering the binding breaks the signature; a malformed hash is unusable; an unbound receipt ignores a live hash.
    assert not verify_envelope(dict(env, request_context={**env["request_context"], "state_sha256": moved}),
                               dict(live, state_sha256=moved), TARGET, **kw)["accepted"]
    bad = dict(env, request_context={**env["request_context"], "state_sha256": "zz"})
    assert verify_envelope(bad, live, TARGET, **kw)["reason"] == REF_VERIFY_ENVELOPE_ABSENT
    free = issue(Allow(), TARGET, live, signing_key=issuer, key_id="issuer-1", now=NOW).envelope
    assert verify_envelope(free, dict(live, state_sha256=pre), TARGET, **kw)["accepted"]
    with pytest.raises(ValueError):
        build_envelope(decision=ELIGIBLE, target_url=TARGET, call=dict(live, state_sha256="short"), policy_pin=PIN)


def test_execution_receipt_records_pre_and_post_state():
    pre = state_sha256(describe("p", b"one")); post = state_sha256(describe("p", b"two"))
    call = {"tool": "write_file", "args": {"path": "p", "content": "two"}, "principal": "agent-7", "state_sha256": pre}
    env = issue(Hold(), TARGET, call, signing_key=issuer, key_id="issuer-1", now=NOW).envelope
    ex = sign_execution_receipt(build_execution_receipt(envelope=env, outputs={"ok": 1}, executed_at=NOW, post_state_sha256=post),
                                executor, "executor-1")
    assert ex["pre_state_sha256"] == pre and ex["post_state_sha256"] == post
    keys = {"executor-1": executor.public_key()}
    assert verify_execution_receipt(ex, env, keys)["accepted"]
    grant = sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                   grant_id="g", not_after=NOW + timedelta(minutes=5)), approver, "approver-1")
    chain = verify_chain(env, ex, grant=grant, issuer_public_keys=ISSUER_KEYS, executor_public_keys=keys,
                         approver_public_keys={"approver-1": approver.public_key()})
    assert chain["reason"] == ACCEPT_CHAIN_VERIFIED
    # An execution receipt that drops or alters the pre-state does not describe this authorization.
    forged = sign_execution_receipt({k: v for k, v in ex.items() if k not in ("pre_state_sha256", "executor_signature", "executor_key_id")},
                                    executor, "executor-1")
    assert verify_execution_receipt(forged, env, keys)["reason"] == REF_EXEC_BINDING_MISMATCH
    with pytest.raises(ValueError):
        build_execution_receipt(envelope=env, outputs={}, executed_at=NOW, post_state_sha256="nope")


def _token(sub="agent-7"):
    return encode({"sub": sub, "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}, idp, "idp-1")


def test_middleware_refuses_when_the_file_moved_between_card_and_run(tmp_path):
    """End to end: hold on a real file, the human approves, but the file was
    edited meanwhile. The call does not run. Unchanged, it runs and the
    execution receipt carries pre and post state."""
    from gargoyle.mcp_server import IssuerClient, ServerState, _audit_meta, _gate
    app = build_issuer_app(policy=Hold(), signing_key=issuer, key_id="issuer-1", idp_public_keys={"idp-1": idp.public_key()},
                           approver_public_keys={"approver-1": approver.public_key()})
    c = TestClient(app); h = {"Authorization": "Bearer " + _token()}

    class Shim:
        def post(self, url, json=None, headers=None, timeout=None): return c.post(url.replace("http://i", ""), json=json, headers=headers)
        def get(self, url, headers=None, timeout=None): return c.get(url.replace("http://i", ""), headers=headers)

    target = tmp_path / "notes.md"; target.write_text("one\n", encoding="utf-8", newline="\n")
    params = {"name": "write_file", "arguments": {"path": str(target), "content": "two\n"}}
    seen = {}

    def approve_after_edit(seconds):
        hold = c.get("/pending", headers=h).json()["pending"][0]
        seen["state"] = hold["state"]
        if seen.get("edit"):
            target.write_text("someone else wrote this\n", encoding="utf-8", newline="\n")    # the world moved
        env = hold["envelope"]
        g = sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                   grant_id="g-" + env["approval_request_id"], not_after=datetime.now(timezone.utc) + timedelta(minutes=5)),
                       approver, "approver-1")
        c.post("/grants", json=g, headers=h)

    def mw():
        return ServerState({"pinned_public_keys": ISSUER_KEYS, "record": PIN, "target_id": TARGET, "principal": "agent-7",
                            "approver_public_keys": {"approver-1": approver.public_key()},
                            "executor_signing_key": executor, "executor_key_id": "executor-1"},
                           issuer_client=IssuerClient("http://i", _token(), http=Shim(), approval_timeout=30, poll_seconds=0.01,
                                                      sleep=approve_after_edit))

    seen["edit"] = True
    gate = _gate(mw(), params)
    assert not gate["executed"] and gate["reason"] == REF_VERIFY_STATE_MISMATCH
    assert seen["state"]["text"] == "one\n" and seen["state"]["size"] == 4         # what the approver was shown
    assert target.read_text(encoding="utf-8") == "someone else wrote this\n"       # untouched by the gate

    seen["edit"] = False
    target.write_text("one\n", encoding="utf-8", newline="\n")
    state = mw()
    gate = _gate(state, params)
    assert gate["executed"], gate["reason"]
    target.write_text("two\n", encoding="utf-8", newline="\n")                                   # the upstream's effect, simulated
    meta = _audit_meta(state, gate, {"ok": True}, params)
    ex = meta["gargoyle/execution"]
    assert ex["pre_state_sha256"] == state_sha256(describe(str(target), b"one\n"))
    assert ex["post_state_sha256"] == state_sha256(describe(str(target), b"two\n"))
    chain = verify_chain(gate["envelope"], ex, grant=gate["grant"], issuer_public_keys=ISSUER_KEYS,
                         executor_public_keys={"executor-1": executor.public_key()}, approver_public_keys={"approver-1": approver.public_key()})
    assert chain["reason"] == ACCEPT_CHAIN_VERIFIED
    # The audit names the state transition.
    from gargoyle.evidence import verify_log
    entry = {"evidence_version": "gargoyle-evidence/2", "seq": 1, "prev_sha256": "0" * 64, "at": NOW.isoformat(), "kind": "honored",
             "tool": "write_file", "args_sha256": gate["envelope"]["request_context"]["args_sha256"], "principal": "agent-7",
             "reason": gate["reason"], "receipt": gate["envelope"], "grant": gate["grant"], "execution": ex}
    from gargoyle.evidence import entry_sha256
    entry["entry_sha256"] = entry_sha256(entry)
    v = verify_log([entry], issuer_public_keys=ISSUER_KEYS, executor_public_keys={"executor-1": executor.public_key()},
                   approver_public_keys={"approver-1": approver.public_key()})
    assert v["accepted"] and v["entries"][0]["state"] == {"pre": ex["pre_state_sha256"], "post": ex["post_state_sha256"]}
