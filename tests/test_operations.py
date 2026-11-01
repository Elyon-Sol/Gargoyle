"""`gargoyle backup` / `gargoyle restore`: the issuer host's state comes back
whole, the hold store copied consistently, the witness verified on both
ends, nothing overwritten without --force, nothing written for a broken
chain or a tampered archive."""

import json
import os
import sqlite3
import tarfile

import pytest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from gargoyle.cli import main
from gargoyle.holdstore import HoldStore
from gargoyle.operations import INVENTORY, backup, format_inventory, inspect, restore, witness_head
from gargoyle.witness import WitnessLog


def _opt(tmp_path, name="opt"):
    """A small issuer host: keys, a real witness, a hold store with one open hold, one remote gate."""
    opt = tmp_path / name; dep = opt / "deploy"; dep.mkdir(parents=True)
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    (dep / "public-keys.json").write_text(json.dumps({"issuer": {"issuer-1": pub}, "approver": {}, "executor": {}}))
    (dep / "issuer.env").write_text("GARGOYLE_ISSUER_KEY_HEX=deadbeef\n"); (dep / "issuer.env").chmod(0o600)
    (dep / "rules.json").write_text('{"version": "t", "rules": []}\n')
    (dep / "approvers.json").write_text('{"approvers": {}}\n')
    w = WitnessLog(str(dep / "witness.jsonl"), key, "issuer-1")
    w.record("issued", tool="write_file", principal="a@b"); w.record("granted", approver="s@b")
    store = HoldStore(str(dep / "holds.sqlite"))
    store.dict("pending")["arid-1"] = {"approval_request_id": "arid-1", "not_after": "2099-01-01T00:00:00+00:00"}
    store.dict("grants")["arid-0"] = [{"grant_id": "g"}]
    gate = dep / "files"; gate.mkdir(); (gate / "gate.env").write_text("PORT=8444\n")
    (gate / "audit.jsonl").write_text('{"seq": 1}\n'); (gate / "audit.jsonl.lock").write_text("")
    (gate / "snapshots").mkdir(); (gate / "snapshots" / "x.bin").write_bytes(b"\x00\x01")
    c = sqlite3.connect(str(gate / "audit.replay.sqlite")); c.execute("create table t(x)"); c.execute("insert into t values (1)"); c.commit(); c.close()
    (opt / "tls").mkdir(); (opt / "tls" / "gate.crt").write_text("CERT"); (opt / "tls" / "gate.key").write_text("KEY")
    return opt, key, store


def test_backup_names_the_witness_head_and_copies_the_inventory(tmp_path):
    opt, _, store = _opt(tmp_path)
    dest = tmp_path / "backups"
    r = backup(opt, dest)
    assert r["archive"] and r["witness"]["accepted"] and r["witness_head"]["seq"] == 3
    name = Path(r["archive"]).name
    assert name.startswith("gargoyle-backup-") and "-w3-" in name and name.endswith(".tar.gz")
    assert oct(Path(r["archive"]).stat().st_mode & 0o777) == "0o600"
    m = inspect(Path(r["archive"]))
    files = set(m["files"])
    assert {"deploy/holds.sqlite", "deploy/witness.jsonl", "deploy/public-keys.json", "deploy/issuer.env", "tls/gate.key",
            "deploy/files/audit.jsonl", "deploy/files/audit.replay.sqlite", "deploy/files/snapshots/x.bin", "deploy/files/gate.env"} <= files
    assert not any(f.endswith(("-wal", "-shm", ".lock")) for f in files)
    assert m["holds"] == {"grants": 1, "pending": 1} and m["gates"] == ["files"]
    # the hold store copy is a consistent SQLite file, not the WAL-dependent original
    with tarfile.open(r["archive"]) as tar:
        tar.extract("gargoyle/deploy/holds.sqlite", str(tmp_path / "x"))
    c = sqlite3.connect(str(tmp_path / "x" / "gargoyle" / "deploy" / "holds.sqlite"))
    assert c.execute("pragma integrity_check").fetchone()[0] == "ok"
    assert json.loads(c.execute("select v from kv where ns='pending'").fetchone()[0])["approval_request_id"] == "arid-1"
    store.close()


def test_backup_refuses_a_broken_witness(tmp_path):
    opt, _, store = _opt(tmp_path)
    lines = (opt / "deploy" / "witness.jsonl").read_text().splitlines()
    lines[1] = lines[1].replace('"issued"', '"issued_"')
    (opt / "deploy" / "witness.jsonl").write_text("\n".join(lines) + "\n")
    r = backup(opt, tmp_path / "b")
    assert r["archive"] is None and "broken chain" in r["refused"] and not list((tmp_path / "b").glob("*.tar.gz"))
    store.close()


def test_restore_round_trip_moves_existing_aside_and_brings_the_hold_back(tmp_path):
    opt, key, store = _opt(tmp_path)
    r = backup(opt, tmp_path / "b"); archive = Path(r["archive"])
    # life goes on, then disaster: the witness grows, the hold store is lost
    WitnessLog(str(opt / "deploy" / "witness.jsonl"), key, "issuer-1").record("declined")
    store.close(); (opt / "deploy" / "holds.sqlite").unlink()
    for p in (opt / "deploy").glob("holds.sqlite-*"): p.unlink()
    refused = restore(archive, opt)
    assert refused["restored"] is False and "--force" in refused["refused"]
    ok = restore(archive, opt, force=True)
    assert ok["restored"] and ok["witness"]["accepted"] and ok["holds_integrity"] == "ok"
    assert ok["witness_head"]["seq"] == 3 and ok["holds"] == {"grants": 1, "pending": 1}
    aside = Path(ok["moved_aside"])
    assert (aside / "deploy" / "witness.jsonl").exists() and witness_head(aside / "deploy" / "witness.jsonl")["seq"] == 5
    assert (aside / "tls" / "gate.crt").exists() and (aside / "deploy" / "files" / "audit.jsonl").exists()
    # the restored store opens as the issuer would open it, and the hold is there
    back = HoldStore(str(opt / "deploy" / "holds.sqlite"))
    assert "arid-1" in back.dict("pending"); back.close()
    assert (opt / "deploy" / "files" / "snapshots" / "x.bin").read_bytes() == b"\x00\x01"
    assert oct((opt / "deploy" / "issuer.env").stat().st_mode & 0o777) == "0o600"


def test_restore_verify_only_writes_nothing_and_a_tampered_archive_is_refused(tmp_path):
    opt, _, store = _opt(tmp_path); store.close()
    archive = Path(backup(opt, tmp_path / "b")["archive"])
    empty = tmp_path / "empty"; empty.mkdir()
    r = restore(archive, empty, verify_only=True)
    assert not r.get("refused") and r["restored"] is False and list(empty.iterdir()) == []
    # tamper: rewrite one member
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(archive) as src, tarfile.open(bad, "w:gz") as dst:
        for m in src.getmembers():
            f = src.extractfile(m) if m.isfile() else None
            data = f.read() if f else None
            if m.name == "gargoyle/deploy/rules.json":
                data = b'{"version": "evil", "rules": []}\n'; m.size = len(data)
            dst.addfile(m, __import__("io").BytesIO(data) if data is not None else None)
    r = restore(bad, empty, force=True)
    assert r["restored"] is False and r["corrupt"] == ["deploy/rules.json"] and list(empty.iterdir()) == []


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="file modes; root reads everything")
def test_backup_refuses_when_a_secret_is_unreadable(tmp_path):
    opt, _, store = _opt(tmp_path); store.close()
    (opt / "deploy" / "issuer.env").chmod(0o000)
    try:
        r = backup(opt, tmp_path / "b")
    finally:
        (opt / "deploy" / "issuer.env").chmod(0o600)
    assert r["archive"] is None and r["unreadable"] == ["deploy/issuer.env"] and "root" in r["refused"]
    assert not list((tmp_path / "b").glob("*.tar.gz"))


def test_inventory_is_printed_and_covers_the_secrets(capsys):
    text = format_inventory()
    assert "deploy/issuer.env" in text and "deploy/holds.sqlite" in text and "deploy/<gate>/snapshots" in text
    assert all(kind in ("sqlite", "append", "secret", "config", "tree") for _, kind, _ in INVENTORY)
    assert main(["backup", "--inventory"]) == 0 and "lose this" in capsys.readouterr().out


def test_cli_backup_and_restore(tmp_path, capsys):
    opt, _, store = _opt(tmp_path); store.close()
    assert main(["backup", str(tmp_path / "b"), "--opt", str(opt)]) == 0
    out = capsys.readouterr().out
    assert "witness seq 3 WITNESS_VERIFIED" in out
    archive = next((tmp_path / "b").glob("*.tar.gz"))
    assert main(["restore", str(archive), "--opt", str(opt), "--verify-only"]) == 0
    assert "verified; nothing written" in capsys.readouterr().out
    assert main(["restore", str(archive), "--opt", str(opt)]) == 1
    assert "--force" in capsys.readouterr().err
    assert main(["restore", str(archive), "--opt", str(opt), "--force"]) == 0
    assert "previous state moved to" in capsys.readouterr().out
    assert main(["restore", str(archive), "--inspect"]) == 0 and json.loads(capsys.readouterr().out)["witness_head"]["seq"] == 3
