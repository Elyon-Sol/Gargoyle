"""Backup and restore of an issuer host's state: `gargoyle backup` and
`gargoyle restore`.

One box runs the issuer for a small tenant. What it holds that cannot be
regenerated is listed in INVENTORY with what its loss means; the backup
copies exactly that set, the hold store through SQLite's online backup
(a consistent copy while the issuer writes), the append-only files and
configuration as they are. The archive's name carries the witness head,
so an operator can see at a glance which chain tail a backup holds, and
the archive is not produced unless the copied witness verifies against
the copied issuer key: a backup of a broken chain is not a backup.

Restore reverses it, verifies every file against the manifest and the
witness against the key, moves anything already in place aside rather
than over it, and reports what came back (pending holds, witness head).
Stopping and starting the service is the wrapper script's job, so this
module is the same on a workstation test tree and on the host.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ARCHIVE_PREFIX = "gargoyle-backup-"
MANIFEST = "MANIFEST.json"

# (relative path under the opt dir, kind, what its loss means). Kinds:
#   sqlite  copied with the online backup API (the -wal and -shm files are never copied)
#   append  an append-only log, copied as is
#   secret  a private key or token file; the backup archive is mode 0600 because of these
#   config  regenerable from the installer, kept so a restore is one step
#   tree    a directory copied whole
INVENTORY = [
    ("deploy/issuer.env", "secret", "the issuer's signing key: every receipt and witness entry ever signed stops verifying as this issuer's; a new key is a new issuer"),
    ("deploy/holds.sqlite", "sqlite", "open holds, grants waiting to be collected, declines and their reasons, the decline cooldown, plans: approvers' pending work and the gate's uncollected grants"),
    ("deploy/witness.jsonl", "append", "the issuer's signed record of every decision: the chain clients reconcile their evidence against; its horizon moves to the restore"),
    ("deploy/approvers.json", "secret", "enrolled approvers' public keys, current and retired: grants signed under those keys stop verifying in audits, and every approver must enrol again"),
    ("deploy/public-keys.json", "config", "the trust roots a client copies: issuer, approver, executor, identity-provider keys"),
    ("deploy/approver.env", "secret", "the terminal approver's key (gargoyle approve)"),
    ("deploy/approver-web.json", "secret", "the browser approver file for sites without Entra"),
    ("deploy/rules.json", "config", "the policy: its hash is the pin every receipt carries"),
    ("deploy/record.json", "config", "the published pin (rewritten at start)"),
    ("deploy/mcp-config.json", "config", "the local gate's MCP entry"),
    ("deploy/middleware.env", "secret", "the local gate's executor key and settings"),
    ("tls", "tree", "the issuer's certificate and private key: clients pin gate.crt, so a new certificate must be redistributed"),
    ("secrets", "tree", "the OAuth broker's client secret and other service secrets (gargoyle-remote@*)"),
]
# Each remote gate under deploy/<name>/ (gargoyle-remote@<name>): its evidence
# log, replay claims, snapshots for undo, tokens and OAuth state.
GATE_FILES = [("gate.env", "config"), ("middleware.env", "secret"), ("audit.jsonl", "append"), ("audit.replay.sqlite", "sqlite"),
              ("remote-tokens.json", "secret"), ("oauth-state.json", "secret"), ("snapshots", "tree")]
GATE_LOSS = {"audit.jsonl": "the gate's evidence log: what it did, with receipts; without it the witness alone says what was decided, not what ran",
             "audit.replay.sqlite": "the single-use claims: a receipt honored before the loss could be honored again within its lifetime",
             "snapshots": "pre-change snapshots: undo of held changes before the loss"}
SKIP_SUFFIXES = ("-wal", "-shm", ".lock")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sqlite_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    s = sqlite3.connect("file:%s?mode=ro" % src.as_posix(), uri=True)
    d = sqlite3.connect(str(dst))
    try:
        s.backup(d)
    finally:
        d.close(); s.close()


def _copy_tree(src: Path, dst: Path) -> List[Path]:
    out: List[Path] = []
    for p in sorted(src.rglob("*")):
        if p.is_file() and not p.name.endswith(SKIP_SUFFIXES):
            rel = p.relative_to(src)
            if p.suffix == ".sqlite":
                _sqlite_copy(p, dst / rel)
            else:
                (dst / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, dst / rel)
            out.append(dst / rel)
    return out


def gate_dirs(opt: Path) -> List[Path]:
    dep = opt / "deploy"
    return sorted(p for p in dep.iterdir() if p.is_dir() and (p / "gate.env").exists()) if dep.is_dir() else []


def witness_head(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    last = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last = line
    if not last:
        return None
    e = json.loads(last)
    return {"seq": e.get("seq"), "entry_sha256": e.get("entry_sha256"), "at": e.get("at")}


def verify_witness_file(witness: Path, public_keys: Path) -> Dict[str, Any]:
    from gargoyle.approvers import keys_from_hex
    from gargoyle.witness import read_witness, verify_witness
    keys = json.loads(public_keys.read_text(encoding="utf-8"))
    r = verify_witness(read_witness(str(witness)), issuer_public_keys=keys_from_hex(keys.get("issuer", {})))
    return {k: v for k, v in r.items() if k != "entries"}


def hold_counts(holds: Path) -> Dict[str, int]:
    if not holds.exists():
        return {}
    c = sqlite3.connect("file:%s?mode=ro" % holds.as_posix(), uri=True)
    try:
        return {ns: n for ns, n in c.execute("select ns, count(*) from kv group by ns order by ns")}
    except sqlite3.Error:
        return {}
    finally:
        c.close()


class Unreadable(Exception):
    """Paths the backup could not read: run as the service user or root."""

    def __init__(self, paths: List[str]) -> None:
        super().__init__("%d path(s) not readable: %s" % (len(paths), ", ".join(paths[:6]) + ("…" if len(paths) > 6 else "")))
        self.paths = paths


def stage(opt: Path, into: Path, *, extra: Optional[List[Path]] = None) -> List[str]:
    """Copy the inventory from `opt` under `into`; return the relative paths
    copied. Raises Unreadable naming every path permissions kept out: a
    backup missing the issuer key or a gate's log is not a backup."""
    copied: List[str] = []
    unreadable: List[str] = []

    def one(src: Path, dst: Path, kind: str) -> None:
        try:
            if kind == "sqlite":
                _sqlite_copy(src, dst); copied.append(dst.relative_to(into).as_posix())
            elif kind == "tree":
                for p in _copy_tree(src, dst):
                    copied.append(p.relative_to(into).as_posix())
            else:
                dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src, dst); copied.append(dst.relative_to(into).as_posix())
        except (PermissionError, sqlite3.OperationalError):
            unreadable.append(src.relative_to(opt).as_posix() if src.is_relative_to(opt) else str(src))

    for rel, kind, _ in INVENTORY:
        if (opt / rel).exists():
            one(opt / rel, into / rel, kind)
    for gate in gate_dirs(opt):
        for name, kind in GATE_FILES:
            if (gate / name).exists():
                one(gate / name, into / (gate / name).relative_to(opt), kind)
    for p in extra or []:
        if p.exists() and p.is_file():
            one(p, into / "extra" / p.name, "config")
    if unreadable:
        raise Unreadable(unreadable)
    return copied


def backup(opt: Path, dest: Path, *, extra: Optional[List[Path]] = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Stage, verify, archive. Returns the report; `archive` is None when the
    witness did not verify (nothing is written then)."""
    opt, dest = Path(opt), Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    stamp = (now or _now()).strftime("%Y%m%dT%H%M%SZ")
    with tempfile.TemporaryDirectory(prefix="gargoyle-backup-") as tmp:
        root = Path(tmp) / "gargoyle"
        try:
            copied = stage(opt, root, extra=extra)
        except Unreadable as exc:
            return {"archive": None, "files": 0, "refused": str(exc) + " (run as the service user or root)", "unreadable": exc.paths}
        head = witness_head(root / "deploy" / "witness.jsonl")
        witness = None
        if (root / "deploy" / "witness.jsonl").exists() and (root / "deploy" / "public-keys.json").exists():
            witness = verify_witness_file(root / "deploy" / "witness.jsonl", root / "deploy" / "public-keys.json")
        manifest = {
            "format": "gargoyle-backup/1", "created": (now or _now()).isoformat(), "host": platform.node(), "opt": str(opt),
            "witness_head": head, "witness": witness, "holds": hold_counts(root / "deploy" / "holds.sqlite"),
            "gates": [g.name for g in gate_dirs(opt)],
            "files": {rel: _sha256(root / rel) for rel in copied},
        }
        (root / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        report: Dict[str, Any] = {"archive": None, "files": len(copied), "witness_head": head, "witness": witness, "holds": manifest["holds"]}
        if witness is not None and not witness.get("accepted"):
            report["refused"] = "witness does not verify (%s); not archiving a broken chain" % witness.get("reason")
            return report
        tag = "-w%s-%s" % (head["seq"], str(head["entry_sha256"])[:8]) if head else "-nowitness"
        archive = dest / ("%s%s%s.tar.gz" % (ARCHIVE_PREFIX, stamp, tag))
        fd = os.open(str(archive), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f, tarfile.open(fileobj=f, mode="w:gz") as tar:
            tar.add(str(root), arcname="gargoyle")
        report["archive"] = str(archive)
        report["bytes"] = archive.stat().st_size
    return report


def inspect(archive: Path) -> Dict[str, Any]:
    with tarfile.open(str(archive), "r:gz") as tar:
        member = tar.getmember("gargoyle/" + MANIFEST)
        f = tar.extractfile(member)
        return json.loads(f.read().decode("utf-8")) if f else {}


def _safe_members(tar: tarfile.TarFile, root: Path):
    base = root.resolve()
    for m in tar.getmembers():
        target = (root / m.name).resolve()
        if not str(target).startswith(str(base) + os.sep) and target != base:
            raise ValueError("archive member escapes the target directory: %s" % m.name)
        if m.issym() or m.islnk():
            raise ValueError("archive carries a link: %s" % m.name)
        yield m


def restore(archive: Path, opt: Path, *, force: bool = False, verify_only: bool = False,
            now: Optional[datetime] = None) -> Dict[str, Any]:
    """Extract into `opt` after verifying the manifest and the witness.
    Anything already at the inventory paths is moved to
    `<opt>/pre-restore-<stamp>/` first (only with `force`); without it a
    populated `<opt>/deploy` refuses. `verify_only` extracts to a
    temporary directory, checks, and writes nothing under `opt`."""
    archive, opt = Path(archive), Path(opt)
    stamp = (now or _now()).strftime("%Y%m%dT%H%M%SZ")
    with tempfile.TemporaryDirectory(prefix="gargoyle-restore-") as tmp:
        work = Path(tmp)
        with tarfile.open(str(archive), "r:gz") as tar:
            tar.extractall(str(work), members=_safe_members(tar, work))
        root = work / "gargoyle"
        manifest = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
        bad = [rel for rel, digest in manifest["files"].items() if not (root / rel).exists() or _sha256(root / rel) != digest]
        report: Dict[str, Any] = {"archive": str(archive), "manifest": {k: manifest.get(k) for k in ("created", "host", "witness_head", "holds", "gates")},
                                  "files": len(manifest["files"]), "corrupt": bad, "restored": False}
        if bad:
            report["refused"] = "%d file(s) differ from the manifest" % len(bad)
            return report
        if (root / "deploy" / "witness.jsonl").exists() and (root / "deploy" / "public-keys.json").exists():
            w = verify_witness_file(root / "deploy" / "witness.jsonl", root / "deploy" / "public-keys.json")
            report["witness"] = w
            if not w.get("accepted"):
                report["refused"] = "witness in the archive does not verify (%s)" % w.get("reason")
                return report
        if (root / "deploy" / "holds.sqlite").exists():
            c = sqlite3.connect(str(root / "deploy" / "holds.sqlite"))
            try:
                report["holds_integrity"] = c.execute("pragma integrity_check").fetchone()[0]
            finally:
                c.close()
            if report["holds_integrity"] != "ok":
                report["refused"] = "hold store in the archive fails integrity_check"
                return report
        if verify_only:
            return report
        existing = [opt / rel for rel, _, _ in INVENTORY if (opt / rel).exists()] + gate_dirs(opt)
        if existing and not force:
            report["refused"] = "%s already holds state (%d path(s)); pass --force to move it aside first" % (opt, len(existing))
            return report
        if existing:
            aside = opt / ("pre-restore-" + stamp)
            aside.mkdir(parents=True, exist_ok=True)
            for p in existing:
                target = aside / p.relative_to(opt)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(p), str(target))
            for leftover in (opt / "deploy").glob("holds.sqlite-*") if (opt / "deploy").exists() else []:
                shutil.move(str(leftover), str(aside / "deploy" / leftover.name))
            report["moved_aside"] = str(aside)
        for rel in manifest["files"]:
            if rel.startswith("extra/"):
                continue
            src, dst = root / rel, opt / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            if rel.endswith((".env", ".json")) and ("secret" in rel or rel.endswith(("issuer.env", "middleware.env", "approver.env", "approvers.json",
                                                                                     "approver-web.json", "remote-tokens.json", "oauth-state.json"))):
                os.chmod(dst, 0o600)
        report["restored"] = True
        report["witness_head"] = witness_head(opt / "deploy" / "witness.jsonl")
        report["holds"] = hold_counts(opt / "deploy" / "holds.sqlite")
    return report


def format_inventory() -> str:
    lines = ["%-28s %-7s %s" % ("path", "kind", "lose this and you lose")]
    for rel, kind, loss in INVENTORY:
        lines.append("%-28s %-7s %s" % (rel, kind, loss))
    for name, kind in GATE_FILES:
        lines.append("%-28s %-7s %s" % ("deploy/<gate>/" + name, kind, GATE_LOSS.get(name, "the gate's own settings and tokens")))
    return "\n".join(lines)
