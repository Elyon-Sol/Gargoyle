"""Soak review 2026-11-01: names Windows rewrites must not slip a rule; an
unreadable target must not run unbound; a refused undo must say why; plan
steps resolve like calls; a client's state inside the root is a side door."""

import json
import os
import shutil

import pytest

from gargoyle import fs_server
from gargoyle.globs import canonical_path, glob_match, is_windows_path, path_rewrite_reason
from gargoyle.mcp_server import _touches_gate_files
from gargoyle.plans import step_matches
from gargoyle.revert import (REF_REVERT_NOT_ATTESTED, REF_REVERT_NOTHING_HELD, REF_REVERT_SNAPSHOT_MISSING, REF_REVERT_UNKNOWN,
                             SnapshotStore, plan_revert, revert_text)
from gargoyle.rules import RulesPolicy
from gargoyle.state import (REF_TARGET_PATH_NOT_CANONICAL, StateUnreadable, describe, filesystem_probe, resolve_path_args,
                            resolve_steps, state_sha256)
from gargoyle.adapters import FilesystemAdapter
from gargoyle.witness import describe as describe_event

ESCAPES = ("C:\\share\\x.ps1.", "C:\\share\\x.ps1 ", "C:\\share\\x.ps1::$DATA", "C:\\share\\x.ps1. ")


def test_canonical_path_is_the_name_windows_uses():
    for v in ESCAPES:
        assert canonical_path(v) == "c:/share/x.ps1", v
    assert canonical_path("C:\\share\\ads.txt:hidden.ps1") == "c:/share/ads.txt"   # a stream of ads.txt
    assert canonical_path("C:\\share\\sub.\\x.md") == "c:/share/sub/x.md"
    assert canonical_path("C:\\share\\ok.ps1") == "c:/share/ok.ps1"
    assert canonical_path("\\\\srv\\share\\x.ps1.") == "//srv/share/x.ps1"
    assert path_rewrite_reason("C:\\share\\ok.ps1") is None
    assert "rewrite" in path_rewrite_reason("C:\\share\\x.ps1 ")
    assert "reserved" in path_rewrite_reason("C:\\share\\CON.txt") and "reserved" in path_rewrite_reason("C:\\share\\com1")
    assert path_rewrite_reason("C:\\share\\console.txt") is None                     # only the bare stem is reserved
    assert is_windows_path("C:\\x") and is_windows_path("\\\\srv\\s") and is_windows_path("sub\\x") and not is_windows_path("/srv/x")


def test_a_hold_on_ps1_covers_every_name_that_lands_as_ps1(tmp_path):
    for v in ESCAPES + ("c:/SHARE/X.PS1::$data",):
        assert glob_match("*.ps1", v), v
        assert step_matches({"tool": "write_file", "match": {"destination": "*.ps1"}}, "write_file", {"destination": v})
    assert not glob_match("*.ps1", "C:\\share\\x.ps1.txt")
    doc = {"version": "t", "default": "allow", "rules": [{"tools": ["write_file"], "args": {"path": "*.ps1"}, "action": "hold"}]}
    p = tmp_path / "rules.json"; p.write_text(json.dumps(doc)); pol = RulesPolicy(str(p))
    base = {"principal": "a@contoso.com", "groups": [], "roles": [], "tool": "write_file"}
    for v in ESCAPES:
        assert pol.decide("t", {**base, "args": {"path": v}}).requires_approval, v
    assert not pol.decide("t", {**base, "args": {"path": "C:\\share\\notes.txt"}}).requires_approval


def test_the_gate_refuses_a_name_windows_would_rewrite_before_the_rules_see_it():
    for v in ESCAPES + ("C:\\share\\CON.txt", "C:\\share\\ads.txt:hidden.ps1"):
        assert resolve_path_args("write_file", {"path": v}, "C:\\share") == ({"path": v}, REF_TARGET_PATH_NOT_CANONICAL), v
        assert resolve_path_args("read_file", {"path": v}, None)[1] == REF_TARGET_PATH_NOT_CANONICAL      # Windows-flavoured, no root needed
    # A relative name under a Windows root is judged after the join.
    assert resolve_path_args("write_file", {"path": "x.ps1."}, "C:\\share")[1] == REF_TARGET_PATH_NOT_CANONICAL
    assert resolve_path_args("move_file", {"source": "a.txt", "destination": "b.ps1 "}, "C:\\share")[1] == REF_TARGET_PATH_NOT_CANONICAL
    # Ordinary names pass, and POSIX names keep their legal dots and colons.
    assert resolve_path_args("write_file", {"path": "x.ps1"}, "C:\\share") == ({"path": "C:\\share\\x.ps1"}, None)
    assert resolve_path_args("write_file", {"path": "/srv/shared/odd."}, "/srv/shared") == ({"path": "/srv/shared/odd."}, None)
    assert resolve_path_args("write_file", {"path": "a:b.txt"}, "/srv/shared") == ({"path": "/srv/shared/a:b.txt"}, None)


def test_the_gate_folder_guard_sees_the_rewritten_name_too():
    gate = "c:/gargoyle"
    assert _touches_gate_files({"path": "C:\\gargoyle\\rules.json"}, gate)
    assert _touches_gate_files({"path": "C:\\gargoyle\\rules.json."}, gate)
    assert _touches_gate_files({"path": "C:\\gargoyle\\rules.json::$DATA"}, gate)
    assert not _touches_gate_files({"path": "C:\\gargoyle-share\\rules.json"}, gate)


def test_the_filesystem_server_refuses_such_names_when_strict(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_server, "STRICT_NAMES", True)
    root = fs_server.Root(str(tmp_path))
    for bad in ("x.ps1.", "x.ps1 ", "x.ps1::$DATA", "CON.txt", "sub.\\x"):
        with pytest.raises(ValueError, match="not canonical"):
            root.call("write_file", {"path": bad, "content": "x"})
    assert not list(tmp_path.iterdir())
    root.call("write_file", {"path": "ok.ps1", "content": "x"}); assert (tmp_path / "ok.ps1").read_text() == "x"
    monkeypatch.setattr(fs_server, "STRICT_NAMES", False)
    assert root.call("create_directory", {"path": "d"}).startswith("created ")
    assert root.call("create_directory", {"path": "d"}).startswith("already existed ")


def test_an_unreadable_target_refuses_instead_of_running_unbound(tmp_path, monkeypatch):
    d = tmp_path / "folder"; d.mkdir()
    desc = filesystem_probe("create_directory", {"path": str(d)})
    assert desc == describe(str(d), b"", with_text=False)                  # a directory binds as empty on every platform
    f = tmp_path / "locked.txt"; f.write_bytes(b"x")
    real_open = open

    def locked(path, *a, **k):
        if str(path) == str(f):
            raise PermissionError(13, "sharing violation")
        return real_open(path, *a, **k)
    monkeypatch.setattr("builtins.open", locked)
    with pytest.raises(StateUnreadable):
        filesystem_probe("write_file", {"path": str(f)})
    with pytest.raises(StateUnreadable):
        FilesystemAdapter().probe("write_file", {"path": str(f)})
    assert filesystem_probe("write_file", {"path": str(tmp_path / "absent.txt")})["sha256"] is None   # absent is a state, not an error


def test_a_refused_undo_says_which_of_the_causes_it_is(tmp_path):
    store = SnapshotStore(str(tmp_path / "snap")); a = FilesystemAdapter()
    assert plan_revert(store, "last", a)["reason"] == REF_REVERT_NOTHING_HELD               # nothing was ever held
    f = tmp_path / "n.md"; f.write_bytes(b"one\n")
    store.put("d-1", describe(str(f), b"one\n"), b"one\n", "write_file", {"path": str(f), "content": "two\n"})
    assert plan_revert(store, "last", a)["reason"] == REF_REVERT_NOT_ATTESTED             # held, but no after-state yet
    assert plan_revert(store, "d-1", a)["reason"] == REF_REVERT_NOT_ATTESTED
    assert plan_revert(store, "nope", a)["reason"] == REF_REVERT_UNKNOWN
    f.write_bytes(b"two\n"); store.record_post("d-1", state_sha256(describe(str(f), b"two\n")))
    assert plan_revert(store, "last", a)["reverts"] == "d-1"
    assert plan_revert(store, "last", a, ref=str(tmp_path / "other.md"))["reason"] == REF_REVERT_NOTHING_HELD   # narrowed to a file
    assert plan_revert(store, "last", a, ref=str(f).upper() if os.name == "nt" else str(f))["reverts"] == "d-1"
    for blob in (tmp_path / "snap").glob("*.bin"):
        blob.unlink()
    assert plan_revert(store, "d-1", a)["reason"] == REF_REVERT_SNAPSHOT_MISSING
    assert revert_text(REF_REVERT_NOTHING_HELD).startswith("refused: REF_REVERT_NOTHING_HELD (no held change")
    assert revert_text("REF_SOMETHING_ELSE") == "refused: REF_SOMETHING_ELSE"


def test_plan_steps_resolve_like_calls():
    root = "C:\\share"
    steps = [{"tool": "write_file", "args": {"path": "it-test\\a.txt", "content": "x"}},
             {"tool": "write_file", "match": {"path": "it-test\\*.md"}},
             {"tool": "move_file", "match": {"source": "C:\\share\\a", "destination": "b\\*"}},
             {"tool": "send_mail", "args": {"to": "x@y"}}]
    out, why = resolve_steps(steps, root)
    assert why is None
    assert out[0]["args"] == {"path": "C:\\share\\it-test\\a.txt", "content": "x"}
    assert out[1]["match"] == {"path": "C:\\share\\it-test\\*.md"}
    assert out[2]["match"] == {"source": "C:\\share\\a", "destination": "C:\\share\\b\\*"}
    assert out[3] == steps[3] and steps[0]["args"]["path"] == "it-test\\a.txt"      # input untouched
    assert resolve_steps([{"tool": "write_file", "args": {"path": "x.ps1."}}], root)[1] == REF_TARGET_PATH_NOT_CANONICAL
    assert resolve_steps("nonsense", root) == ("nonsense", None)


def test_the_witness_says_whether_a_receipt_bound_state():
    base = {"event": "issued", "principal": "p", "tool": "write_file", "decision_id": "d" * 36}
    assert describe_event({**base, "held": True, "state_bound": True})["outcome"] == "held for approval (state-bound)"
    assert describe_event({**base, "held": True, "state_bound": False})["outcome"] == "held for approval (unbound)"
    assert describe_event({**base, "held": False, "state_bound": False})["outcome"] == "allowed"          # reads are never bound; no noise
    assert describe_event({**base, "held": True})["outcome"] == "held for approval"                        # older entries unchanged


def test_client_state_inside_the_root_and_rewritten_script_names_are_side_doors(tmp_path):
    from test_sidedoors import discover, home_with
    import gargoyle.sidedoors as sd
    root = tmp_path / "share"; root.mkdir(); (root / ".claude").mkdir(); (root / ".claude" / "scheduled_tasks.lock").write_text("")
    home, managed = home_with(tmp_path, managed_settings={"permissions": {"deny": ["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"]}})
    ev = [{"kind": "honored", "tool": "write_file", "ref": "C:\\share\\TICKET-1016-trailing-dot.ps1.", "at": "2026-11-01T16:30:00+00:00",
           "principal": "claude@hearthcorp.com", "receipt": {"requires_approval": False}, "grant": None}]
    found = discover(root, home, managed, evidence=ev)
    state = [x for x in found if x["kind"] == sd.CLIENT_STATE_IN_ROOT]
    assert len(state) == 1 and state[0]["path"] == str(root / ".claude") and "outside the root" in state[0]["remedy"]
    assert [x["path"] for x in found if x["kind"] == sd.EXECUTABLE_WRITTEN] == ["C:\\share\\TICKET-1016-trailing-dot.ps1."]
    shutil.rmtree(root / ".claude")
    assert not [x for x in discover(root, home, managed) if x["kind"] == sd.CLIENT_STATE_IN_ROOT]
