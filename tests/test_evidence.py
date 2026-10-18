"""The evidence log: every decision in one hash chain, checkable offline.

Honored entries carry a full receipt chain; refused entries carry what was
asked and why not. Editing, removing or inserting an entry breaks the chain
at that point; the auditor is told where."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.envelope import args_sha256
from gargoyle.evidence import (ACCEPT_ENTRY_VERIFIED, ACCEPT_EVIDENCE_VERIFIED, GENESIS, HONORED, REFUSED,
                               REF_EVIDENCE_CHAIN_BROKEN, REF_EVIDENCE_HASH_MISMATCH, REF_EVIDENCE_MALFORMED,
                               REF_EVIDENCE_RECEIPT_MISSING, EvidenceLog, build_entry, entry_sha256, read_log,
                               verify_log)
from gargoyle.execution import (ACCEPT_CHAIN_VERIFIED, REF_EXEC_SIGNATURE_INVALID, build_execution_receipt,
                                sign_execution_receipt)
from gargoyle.issuer import issue as _issue
from gargoyle.policy import ELIGIBLE, Decision

TARGET = "mcp://filesystem/x"
PRINCIPAL = "spiffe://gargoyle.local/agent/a"
PIN = {"policy_id": "engine/1", "policy_sha256": "a" * 64}
NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
RAN = NOW + timedelta(seconds=30)
issuer = Ed25519PrivateKey.generate(); executor = Ed25519PrivateKey.generate()
ISSUER_KEYS = {"issuer-1": issuer.public_key()}
EXEC_KEYS = {"executor-1": executor.public_key()}
TRUST = dict(issuer_public_keys=ISSUER_KEYS, executor_public_keys=EXEC_KEYS)


class AllowAll:
    def pin(self): return PIN
    def decide(self, target_url, interaction): return Decision(ELIGIBLE)


def issue(tool, args):
    return _issue(AllowAll(), TARGET, {"tool": tool, "args": args, "principal": PRINCIPAL},
                  signing_key=issuer, key_id="issuer-1", now=NOW).envelope


def honored(tool, args):
    """A receipt and its execution receipt, as the middleware would hold them."""
    env = issue(tool, args)
    ex = sign_execution_receipt(build_execution_receipt(envelope=env, outputs={"ok": True}, executed_at=RAN),
                                executor, "executor-1")
    return env, ex, ACCEPT_CHAIN_VERIFIED


def test_entries_chain_and_verify(tmp_path):
    log = EvidenceLog(str(tmp_path / "evidence.jsonl"))
    env, ex, reason = honored("read_file", {"path": "a"})
    e1 = log.append(HONORED, "read_file", {"path": "a"}, PRINCIPAL, reason, receipt=env, execution=ex)
    e2 = log.append(REFUSED, "delete_file", {"path": "a"}, PRINCIPAL, "DESTRUCTIVE_TOOL")
    env3, ex3, reason3 = honored("write_file", {"path": "b", "content": "x"})
    e3 = log.append(HONORED, "write_file", {"path": "b", "content": "x"}, PRINCIPAL, reason3, receipt=env3, execution=ex3)

    assert e1["seq"] == 1 and e1["prev_sha256"] == GENESIS
    assert e2["prev_sha256"] == e1["entry_sha256"] and e3["prev_sha256"] == e2["entry_sha256"]
    assert e2["args_sha256"] == args_sha256({"path": "a"}) and e2["receipt"] is None
    for e in (e1, e2, e3):
        assert entry_sha256(e) == e["entry_sha256"]

    v = verify_log(read_log(str(log.path)), **TRUST)
    assert v["accepted"] and v["reason"] == ACCEPT_EVIDENCE_VERIFIED
    assert (v["count"], v["honored"], v["refused"]) == (3, 2, 1)
    assert [r["reason"] for r in v["entries"]] == [ACCEPT_CHAIN_VERIFIED, ACCEPT_ENTRY_VERIFIED, ACCEPT_CHAIN_VERIFIED]
    assert v["tail_sha256"] == e3["entry_sha256"]


def test_a_new_process_continues_the_chain(tmp_path):
    path = str(tmp_path / "evidence.jsonl")
    a = EvidenceLog(path).append(REFUSED, "t", {}, PRINCIPAL, "R1")
    b = EvidenceLog(path).append(REFUSED, "t", {}, PRINCIPAL, "R2")   # a fresh object, as after a restart
    assert b["seq"] == 2 and b["prev_sha256"] == a["entry_sha256"]
    assert verify_log(read_log(path), **TRUST)["accepted"]


def test_edit_removal_insertion_and_garbage_are_each_named(tmp_path):
    path = tmp_path / "evidence.jsonl"
    log = EvidenceLog(str(path))
    for i in range(4):
        env, ex, reason = honored("read_file", {"path": str(i)})
        log.append(HONORED, "read_file", {"path": str(i)}, PRINCIPAL, reason, receipt=env, execution=ex)
    lines = path.read_text().splitlines()
    entries = [json.loads(x) for x in lines]

    # Edit: the reason of entry 2 is changed, hash no longer matches.
    edited = dict(entries[1], reason="whatever")
    v = verify_log([entries[0], edited] + entries[2:], **TRUST)
    assert not v["accepted"] and v["reason"] == REF_EVIDENCE_HASH_MISMATCH
    assert [r["accepted"] for r in v["entries"]] == [True, False, True, True]

    # Edit with the hash recomputed: entry 3 no longer links to it.
    edited["entry_sha256"] = entry_sha256(edited)
    v = verify_log([entries[0], edited] + entries[2:], **TRUST)
    assert [r["reason"] for r in v["entries"]][1:3] == [ACCEPT_CHAIN_VERIFIED, REF_EVIDENCE_CHAIN_BROKEN]

    # Removal of entry 2: entry 3 has the wrong seq and the wrong prev.
    v = verify_log(entries[:1] + entries[2:], **TRUST)
    assert [r["reason"] for r in v["entries"]] == [ACCEPT_CHAIN_VERIFIED, REF_EVIDENCE_CHAIN_BROKEN, ACCEPT_CHAIN_VERIFIED]

    # Insertion of a refused entry that was never in the chain.
    forged = build_entry(seq=3, prev_sha256=entries[1]["entry_sha256"], kind=REFUSED, tool="delete_file",
                         args={}, principal=PRINCIPAL, reason="DESTRUCTIVE_TOOL")
    v = verify_log(entries[:2] + [forged] + entries[2:], **TRUST)
    assert [r["accepted"] for r in v["entries"]] == [True, True, True, False, True]

    # A line that is not an entry at all.
    v = verify_log([entries[0], None, {"receipt": {}, "execution": {}}], **TRUST)
    assert [r["reason"] for r in v["entries"]][1:] == [REF_EVIDENCE_MALFORMED, REF_EVIDENCE_MALFORMED]

    # Truncation is the one thing the chain cannot see; the tail hash is for that.
    v = verify_log(entries[:3], **TRUST)
    assert v["accepted"] and v["tail_sha256"] == entries[2]["entry_sha256"]


def test_honored_entries_need_a_real_chain_that_matches_the_entry():
    env, ex, reason = honored("read_file", {"path": "a"})

    bare = build_entry(seq=1, prev_sha256=GENESIS, kind=HONORED, tool="read_file", args={"path": "a"},
                       principal=PRINCIPAL, reason=reason)
    assert verify_log([bare], **TRUST)["reason"] == REF_EVIDENCE_RECEIPT_MISSING

    bad_sig = dict(ex, executor_signature="00" * 64)
    e = build_entry(seq=1, prev_sha256=GENESIS, kind=HONORED, tool="read_file", args={"path": "a"},
                    principal=PRINCIPAL, reason=reason, receipt=env, execution=bad_sig)
    assert verify_log([e], **TRUST)["reason"] == REF_EXEC_SIGNATURE_INVALID

    # A valid chain pasted under the wrong tool name does not vouch for that name.
    e = build_entry(seq=1, prev_sha256=GENESIS, kind=HONORED, tool="delete_file", args={"path": "a"},
                    principal=PRINCIPAL, reason=reason, receipt=env, execution=ex)
    assert verify_log([e], **TRUST)["reason"] == REF_EVIDENCE_RECEIPT_MISSING


def test_a_declined_hold_keeps_its_receipt_and_the_receipt_is_checked():
    env = issue("write_file", {"path": "p", "content": "c"})
    e = build_entry(seq=1, prev_sha256=GENESIS, kind=REFUSED, tool="write_file", args={"path": "p", "content": "c"},
                    principal=PRINCIPAL, reason="REF_TARGET_APPROVAL_DECLINED", receipt=env, at=RAN)
    assert verify_log([e], **TRUST)["entries"][0]["reason"] == ACCEPT_ENTRY_VERIFIED
    forged = dict(env, issuer_signature="00" * 64)
    e = build_entry(seq=1, prev_sha256=GENESIS, kind=REFUSED, tool="write_file", args={"path": "p", "content": "c"},
                    principal=PRINCIPAL, reason="REF_TARGET_APPROVAL_DECLINED", receipt=forged, at=RAN)
    assert not verify_log([e], **TRUST)["accepted"]


def test_build_entry_rejects_unknown_kind():
    with pytest.raises(ValueError):
        build_entry(seq=1, prev_sha256=GENESIS, kind="maybe", tool="t", args={}, principal=PRINCIPAL, reason="x")
