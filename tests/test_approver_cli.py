"""The approver CLI releases a flagged receipt: it shows the human what is
inside the issuer's signature and emits a grant the consumer honors."""

import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from gargoyle.approver_cli import main, make_grant
from gargoyle.consumer import Consumer
from gargoyle.issuer import issue
from gargoyle.policy import ELIGIBLE, Decision

TARGET = "https://target.example/act"
PIN = {"policy_id": "engine/1", "policy_sha256": "a" * 64}


class FlagAll:
    def pin(self): return PIN
    def decide(self, target_url, interaction): return Decision(ELIGIBLE, requires_approval=True)


def test_cli_reads_a_receipt_shows_the_call_and_emits_an_honored_grant(monkeypatch, tmp_path, capsys):
    issuer = Ed25519PrivateKey.generate(); approver = Ed25519PrivateKey.generate()
    call = {"tool": "transfer", "args": {"amount": 5}, "principal": "agent-7"}
    env = issue(FlagAll(), TARGET, call, signing_key=issuer, key_id="issuer-1").envelope
    receipt_file = tmp_path / "receipt.json"; receipt_file.write_text(json.dumps(env))
    monkeypatch.setenv("GARGOYLE_APPROVER_KEY_HEX",
                       approver.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    monkeypatch.setenv("GARGOYLE_APPROVER_KEY_ID", "approver-alice")
    assert main(["--pending", str(receipt_file), "--yes"]) == 0
    out, err = capsys.readouterr()
    for shown in ("tool                : transfer", "principal           : agent-7",
                  "target_url          : " + TARGET, env["decision_sha256"], env["approval_request_id"]):
        assert shown in err
    grant = json.loads(out)
    consumer = Consumer(target_id=TARGET, record=PIN, pinned_public_keys={"issuer-1": issuer.public_key()},
                        approver_public_keys={"approver-alice": approver.public_key()})
    assert consumer.check(env, call, grant=grant).honored is True


def test_cli_refuses_without_key_material_and_without_confirmation(monkeypatch, tmp_path, capsys):
    hold = tmp_path / "hold.json"
    hold.write_text(json.dumps({"decision_sha256": "0" * 64, "approval_request_id": "req-1"}))
    monkeypatch.delenv("GARGOYLE_APPROVER_KEY_HEX", raising=False)
    monkeypatch.delenv("GARGOYLE_APPROVER_KEY_ID", raising=False)
    assert main(["--pending", str(hold), "--yes"]) == 2
    approver = Ed25519PrivateKey.generate()
    monkeypatch.setenv("GARGOYLE_APPROVER_KEY_HEX",
                       approver.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    monkeypatch.setenv("GARGOYLE_APPROVER_KEY_ID", "approver-alice")
    import io, sys
    monkeypatch.setattr(sys, "stdin", io.StringIO("no\n"))
    assert main(["--pending", str(hold)]) == 1
    assert capsys.readouterr().out == ""
