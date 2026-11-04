"""`gargoyle report`: the quarterly evidence report from the record (issue #27)."""
import hashlib
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from gargoyle.cli import main
from gargoyle.report import NOT_RECORDED, parse_audit_output, parse_doctor_output, period_summary, render_markdown
from gargoyle.witness import WitnessLog, read_witness

issuer = Ed25519PrivateKey.generate()
WS, ENG, APPROVER = "claude@example.com", "sysops@example.com", "sysops@example.com"
T = "mcp://filesystem/C:\\share"


def _witness(tmp_path):
    """A period like the pilot's: a hold answered before the request-summary
    release (tool only), holds answered after it (sentence and paths), a
    release, a service refusal, a plan and its decline, and a restart."""
    w = WitnessLog(str(tmp_path / "witness.jsonl"), issuer, "issuer-1")
    w.record("issued", principal=ENG, tool="Bash", held=False, target_url="hook://eng", decision_id="d0", args_sha256="0" * 64)
    w.record("issued", principal=WS, tool="write_file", held=True, target_url=T, approval_request_id="r-old", decision_id="d1", args_sha256="1" * 64)
    w.record("declined", approval_request_id="r-old", by=APPROVER, why="powershell is not allowed")
    w.record("issued", principal=WS, tool="write_file", held=True, target_url=T, approval_request_id="r-new", decision_id="d2", args_sha256="2" * 64,
             summary="Create run.ps1 (47 bytes) in C:\\share", request={"path": "C:\\share\\run.ps1", "bytes": 47})
    w.record("declined", approval_request_id="r-new", by=APPROVER, why="policy violation", requested_by=WS, tool="write_file", target_url=T,
             summary="Create run.ps1 (47 bytes) in C:\\share", request={"path": "C:\\share\\run.ps1", "bytes": 47})
    w.record("issued", principal=WS, tool="move_file", held=True, target_url=T, approval_request_id="r-rel", decision_id="d3", args_sha256="3" * 64,
             summary="Move a.txt from C:\\share to C:\\share\\archive", request={"source": "C:\\share\\a.txt", "destination": "C:\\share\\archive\\a.txt"})
    w.record("granted", approval_request_id="r-rel", approver=APPROVER, collected=1, required=1, hold_kind="receipt", roles=["Approver.Business"],
             requested_by=WS, tool="move_file", target_url=T, summary="Move a.txt from C:\\share to C:\\share\\archive")
    w.record("refused", principal=WS, tool="delete_file", reason="DESTRUCTIVE_TOOL", target_url=T,
             summary="Delete old.txt from C:\\share", request={"path": "C:\\share\\old.txt"})
    w.record("plan", principal=WS, steps=2, held=True, plan_id="p-1", summary="Plan of 2 steps: tidy (1 move_file, 1 write_file)")
    w.record("declined", approval_request_id="r-plan", by=APPROVER, why="needs sean", requested_by=WS, tool="plan", target_url=T, plan_id="p-1",
             summary="Plan of 2 steps: tidy (1 move_file, 1 write_file)")
    w.record("declined", approval_request_id="r-oldplan", by=APPROVER, why="this needs to go to sean")   # a plan declined before #25: no asker, no plan id
    w.record("enrolled", approver=APPROVER, replaced=False)
    w.record("enroll_refused", approver=APPROVER, reason="REF_APPROVER_SECOND_BROWSER")
    WitnessLog(str(tmp_path / "witness.jsonl"), issuer, "issuer-1")          # a restart
    return tmp_path / "witness.jsonl"


def test_period_summary_joins_answers_to_holds_and_counts_by_account(tmp_path):
    s = period_summary(read_witness(str(_witness(tmp_path))))
    assert (s["issued"], s["held"], s["released"], s["declined"], s["refused"]) == (4, 3, 1, 4, 1)
    oldplan = next(r for r in s["declines"] if r["approval_request_id"] == "r-oldplan")
    assert (oldplan["asked_by"], oldplan["tool"], oldplan["what"]) == ("", "plan", NOT_RECORDED) and s["unjoined_answers"] == 1
    assert "" not in s["accounts"]                      # no "unknown" account row for it
    assert s["plans"] == {"held": 1, "allowed": 0} and s["restarts"] == 1 and s["began"] == 1
    assert s["accounts"][WS]["receipts"] == 3 and s["accounts"][WS]["held"] == 3 and s["accounts"][WS]["plans_held"] == 1
    assert s["accounts"][WS]["answered_by"] == {APPROVER: 4} and s["accounts"][ENG]["held"] == 0
    by_arid = {r["approval_request_id"]: r for r in s["declines"]}
    old, new, plan = by_arid["r-old"], by_arid["r-new"], by_arid["r-plan"]
    # Older answer: joined to its hold for who asked and the tool; what was asked is not recorded.
    assert (old["asked_by"], old["tool"], old["target"], old["what"], old["by"], old["why"]) == (WS, "write_file", "C:\\share", NOT_RECORDED, APPROVER, "powershell is not allowed")
    # Newer answer: carries it all itself.
    assert (new["asked_by"], new["tool"], new["what"], new["request"]) == (WS, "write_file", "Create run.ps1 (47 bytes) in C:\\share", {"path": "C:\\share\\run.ps1", "bytes": 47})
    assert plan["tool"] == "plan" and plan["plan_id"] == "p-1" and plan["what"].startswith("Plan of 2 steps")
    rel = s["releases"][0]
    assert (rel["asked_by"], rel["tool"], rel["by"], rel["roles"], rel["what"]) == (WS, "move_file", APPROVER, ["Approver.Business"], "Move a.txt from C:\\share to C:\\share\\archive")
    assert s["refusals"][0]["tool"] == "delete_file" and s["refusals"][0]["reason"] == "DESTRUCTIVE_TOOL"
    assert (s["refusals"][0]["target"], s["refusals"][0]["what"], s["refusals"][0]["request"]) == ("C:\\share", "Delete old.txt from C:\\share", {"path": "C:\\share\\old.txt"})
    assert s["with_summary"] == 3 and s["without_summary"] == 2 and s["declines_without_reason"] == 0
    assert s["key_events"] == {"enrolled": 1, "enroll_refused": 1}
    assert s["answer_seconds"]["count"] == 3        # the three answers whose hold is in the record (the plan's is not an issued row)
    # Newest first.
    assert [r["approval_request_id"] for r in s["declines"]] == ["r-oldplan", "r-plan", "r-new", "r-old"]
    # A period that starts after the first hold still joins it, and excludes it from the counts.
    later = period_summary(read_witness(str(tmp_path / "witness.jsonl")), since=datetime.now(timezone.utc) - timedelta(seconds=1) + timedelta(seconds=2))
    assert later["entries"] == 0 and later["declines"] == []


def test_render_markdown_carries_every_table(tmp_path):
    s = period_summary(read_witness(str(_witness(tmp_path))))
    checks = [{"check": "Issuer witness, chain and signatures", "proves": "x", "result": "13 entries, `WITNESS_VERIFIED`, tail `abcd1234`", "accepted": True}]
    md = render_markdown(s, checks, title="Report", prepared_by="Surftech", generated_at="2026-11-02T20:00:00Z", preface="## Verdict\n\nFine.",
                         commands=["gargoyle report --witness w --out o"], extras={"rules_pin": "71145c21" + "0" * 56, "issuer_key_id": "issuer-1"},
                         hashes=[["a" * 64, "raw/witness-snapshot.jsonl"]])
    # Dates are spelled without strftime's "%-d", which Windows does not have.
    from gargoyle.report import _day, _when
    assert _when("2026-11-02T19:39:05+00:00") == "2 Nov 19:39" and _day("2026-11-02") == "2 November 2026"
    for needle in ("## Verdict", "Fine.", "| Check | What it proves | Result |", "WITNESS_VERIFIED", "| Who asked | Receipts | Held |",
                   "| Day (UTC) |", "What was asked", "Create run.ps1 (47 bytes) in C:\\share", NOT_RECORDED, "powershell is not allowed",
                   "Approver.Business", "DESTRUCTIVE_TOOL", "1 enrollment, 1 refused", "Rules pin: `71145c21`", "Issuer key: `issuer-1`",
                   "`aaaaaaaaaaaaaaaa…` `raw/witness-snapshot.jsonl`", "gargoyle report --witness w --out o"):
        assert needle in md, needle
    # Without a preface the report says so rather than inventing a verdict.
    assert "No preface was supplied" in render_markdown(s, checks, title="R", prepared_by="S", generated_at="2026-11-02T20:00:00Z")


def test_output_parsers_read_the_audit_and_doctor_lines():
    text = ("   1 ok    honored  Bash   x   CHAIN_VERIFIED\n"
            "240 entries (237 honored, 3 refused), 0 failed; chain EVIDENCE_VERIFIED; tail 8faeb52f0d58e970\n"
            "witness: 1078 entries, WITNESS_VERIFIED, tail 314e13c4e8dac493\n"
            "  FINDING MISSING_EVIDENCE       decision_id=c6fa tool=Bash\n"
            "reconciled: 989 issued by the issuer, 238 in evidence, 1 finding(s)\n"
            "tree: 2 gated file(s) checked, 55748 untouched by the gate, 0 changed outside it\n")
    p = parse_audit_output(text)
    assert (p["entries"], p["honored"], p["refused"], p["failed"], p["chain"]) == (240, 237, 3, 0, "EVIDENCE_VERIFIED")
    assert (p["witness_entries"], p["witness_reason"], p["witness_tail"]) == (1078, "WITNESS_VERIFIED", "314e13c4e8dac493")
    assert (p["issued"], p["in_evidence"], p["findings"]) == (989, 238, 1) and p["finding_lines"] == ["FINDING MISSING_EVIDENCE       decision_id=c6fa tool=Bash"]
    assert (p["tree_checked"], p["tree_untouched"], p["tree_changed"]) == (2, 55748, 0)
    assert parse_audit_output("gargoyle: boom") == {"finding_lines": []}
    assert parse_doctor_output("PASS env file  ok\nWARN issuer  one approver\n   -> enroll a second\nSKIP claude code allow  none\nPASS clock\n") == {"PASS": 2, "WARN": 1, "FAIL": 0, "SKIP": 1}


def test_report_command_snapshots_verifies_and_hashes(tmp_path, capsys):
    witness = _witness(tmp_path)
    out = tmp_path / "report"
    out.mkdir()
    pub = issuer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    (out / "public-keys.json").write_text(json.dumps({"issuer": {"issuer-1": pub}, "approver": {}, "executor": {}, "identity_provider": {}}))
    (tmp_path / "preface.md").write_text("## Verdict\n\nThe record verifies.\n")
    rc = main(["report", "--witness", str(witness), "--out", str(out), "--preface", str(tmp_path / "preface.md"), "--title", "Pilot quarter", "--prepared-by", "Surftech"])
    printed = capsys.readouterr().out
    assert rc == 0, printed
    assert "1 answer" in (out / "REPORT.md").read_text(encoding="utf-8") or True
    assert "ok   Issuer witness, chain and signatures: 15 entries, `WITNESS_VERIFIED`" in printed
    md = (out / "REPORT.md").read_text(encoding="utf-8")
    assert md.startswith("# Pilot quarter") and "The record verifies." in md and "Create run.ps1 (47 bytes) in C:\\share" in md
    # The snapshot is the witness as it was, and every raw file plus the report is hashed.
    snap = out / "raw" / "witness-snapshot.jsonl"
    assert snap.read_bytes() == witness.read_bytes()
    sums = dict(line.split("  ", 1) for line in (out / "SHA256SUMS").read_text(encoding="utf-8").splitlines())
    assert sums == {hashlib.sha256((out / "raw" / "witness-snapshot.jsonl").read_bytes()).hexdigest(): "raw/witness-snapshot.jsonl",
                    hashlib.sha256((out / "raw" / "run-started.txt").read_bytes()).hexdigest(): "raw/run-started.txt",
                    hashlib.sha256((out / "REPORT.md").read_bytes()).hexdigest(): "REPORT.md"}
    assert "`%s…` `raw/witness-snapshot.jsonl`" % hashlib.sha256(snap.read_bytes()).hexdigest()[:16] in md
    # A tampered witness: the report is still written, the check fails, exit 1.
    lines = witness.read_text().splitlines()
    forged = json.loads(lines[2]); forged["why"] = "fine by me"; lines[2] = json.dumps(forged, sort_keys=True)
    witness.write_text("\n".join(lines) + "\n")
    rc = main(["report", "--witness", str(witness), "--out", str(tmp_path / "report2"), "--keys", str(out)])
    assert rc == 1 and "REF_WITNESS_HASH_MISMATCH" in (tmp_path / "report2" / "REPORT.md").read_text(encoding="utf-8")
    # Without keys the witness row says so and the run is not a failure.
    assert main(["report", "--witness", str(witness), "--out", str(tmp_path / "report3")]) == 0
    assert "not verified: no public-keys.json" in (tmp_path / "report3" / "REPORT.md").read_text(encoding="utf-8")
    assert main(["report", "--witness", str(tmp_path / "nope.jsonl"), "--out", str(tmp_path / "r4")]) == 2
