"""Evidence outlives format changes. A gargoyle/2 receipt (the fixture
frozen before the move to RFC 8785) is refused at admission but verifies in
an audit under the serializer it was signed with, grants and execution
receipt included; an evidence log that spans the change verifies end to end."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.consumer import Consumer
from gargoyle.envelope import ENVELOPE_VERSION, canonical_json_legacy, decision_sha256_of, serializer_for
from gargoyle.evidence import EVIDENCE_VERSION, HONORED, REFUSED, EvidenceLog, entry_sha256, verify_log
from gargoyle.execution import ACCEPT_CHAIN_VERIFIED, verify_chain
from gargoyle.verifier import ACCEPT_PROVENANCE, REF_VERIFY_SIGNATURE_INVALID, REF_VERIFY_VERSION_UNSUPPORTED, verify_provenance

V2 = json.loads((Path(__file__).parent / "fixtures" / "wire_vectors_v2.json").read_text(encoding="utf-8"))
NOW = datetime(2026, 10, 16, 12, 1, tzinfo=timezone.utc)


def _key(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def _keys():
    issuer, approver, bob, executor = (_key(V2[k] if k in V2 else V2["threshold"][k])
                                       for k in ("issuer_seed_label", "approver_seed_label", "approver_2_seed_label", "executor_seed_label"))
    return (issuer, {V2["signed"]["issuer_key_id"]: issuer.public_key()},
            {"approver-alice": approver.public_key(), "approver-bob": bob.public_key()},
            {V2["execution"]["executor_key_id"]: executor.public_key()})


def test_the_fixture_is_the_old_format_and_hashes_under_the_old_serializer():
    assert V2["signed"]["envelope_version"] == "gargoyle/2" != ENVELOPE_VERSION
    assert serializer_for("gargoyle/2") is canonical_json_legacy and serializer_for("gargoyle/9") is None
    assert decision_sha256_of(V2["signed"]) == V2["signed"]["decision_sha256"]


def test_admission_refuses_but_an_audit_verifies_the_whole_old_chain():
    _, issuer_keys, approvers, exec_keys = _keys()
    # Admission: the format is not current.
    assert verify_provenance(V2["signed"], pinned_public_keys=issuer_keys, now=NOW)["reason"] == REF_VERIFY_VERSION_UNSUPPORTED
    c = Consumer(target_id=V2["signed"]["target_url"], record=V2["signed"]["policy"], pinned_public_keys=issuer_keys, approver_public_keys=approvers)
    assert c.check(V2["signed"], V2["call"], grant=V2["grant"], now=NOW).reason == REF_VERIFY_VERSION_UNSUPPORTED
    # Audit: historical verification under the gargoyle/2 serializer.
    assert verify_provenance(V2["signed"], pinned_public_keys=issuer_keys, now=NOW, historical=True)["reason"] == ACCEPT_PROVENANCE
    chain = verify_chain(V2["signed"], V2["execution"], grant=V2["grant"], issuer_public_keys=issuer_keys,
                         executor_public_keys=exec_keys, approver_public_keys=approvers, outputs=V2["outputs"], check_outputs=True)
    assert chain["reason"] == ACCEPT_CHAIN_VERIFIED
    T = V2["threshold"]
    chain2 = verify_chain(T["signed"], T["execution"], grant=T["grants"], issuer_public_keys=issuer_keys,
                          executor_public_keys=exec_keys, approver_public_keys=approvers)
    assert chain2["reason"] == ACCEPT_CHAIN_VERIFIED
    # Historical does not mean lenient: a tampered old receipt still fails.
    tampered = dict(V2["signed"], target_url="https://elsewhere.example/")
    assert verify_provenance(tampered, pinned_public_keys=issuer_keys, now=NOW, historical=True)["reason"] == REF_VERIFY_SIGNATURE_INVALID


def test_an_evidence_log_spanning_the_format_change_verifies(tmp_path):
    _, issuer_keys, approvers, exec_keys = _keys()
    path = tmp_path / "audit.jsonl"
    # Two entries as a gargoyle-evidence/1 writer produced them: hashed with the legacy serializer.
    def v1_entry(seq, prev, kind, tool, reason, receipt=None, grant=None, execution=None, principal="agent-7"):
        e = {"evidence_version": "gargoyle-evidence/1", "seq": seq, "prev_sha256": prev, "at": "2026-10-16T12:01:00+00:00",
             "kind": kind, "tool": tool, "args_sha256": V2["args_sha256"], "principal": principal, "reason": reason,
             "receipt": receipt, "grant": grant, "execution": execution}
        body = dict(e)
        e["entry_sha256"] = hashlib.sha256(canonical_json_legacy(body).encode("utf-8")).hexdigest()
        return e
    e1 = v1_entry(1, "0" * 64, HONORED, "transfer_funds", "CHAIN_VERIFIED", V2["signed"], V2["grant"], V2["execution"])
    e2 = v1_entry(2, e1["entry_sha256"], REFUSED, "delete_file", "DESTRUCTIVE_TOOL")
    assert entry_sha256(e1) == e1["entry_sha256"]            # recomputed under the entry's own version
    path.write_text(json.dumps(e1) + "\n" + json.dumps(e2) + "\n", encoding="utf-8")
    # A current writer continues the chain with a version-2 entry.
    e3 = EvidenceLog(str(path)).append(REFUSED, "delete_file", {"path": "x"}, "agent-7", "DESTRUCTIVE_TOOL")
    assert e3["evidence_version"] == EVIDENCE_VERSION and e3["seq"] == 3 and e3["prev_sha256"] == e2["entry_sha256"]
    entries = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]
    v = verify_log(entries, issuer_public_keys=issuer_keys, executor_public_keys=exec_keys, approver_public_keys=approvers)
    assert v["accepted"], [r["reason"] for r in v["entries"]]
    assert [r["reason"] for r in v["entries"]][0] == ACCEPT_CHAIN_VERIFIED
