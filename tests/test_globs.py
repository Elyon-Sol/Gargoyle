"""Second review, finding 7: argument globs over paths are matched on a
normalized form, so traversal, separators and letter case cannot slip a
rule or a plan step."""

import json

from gargoyle.globs import glob_match, is_pathlike, normalize_path
from gargoyle.plans import step_matches
from gargoyle.policy import ELIGIBLE
from gargoyle.rules import RulesPolicy, _glob_covers, _globs_may_overlap


def test_paths_normalize_and_other_values_do_not():
    assert normalize_path("C:\\proj\\..\\secrets\\x.md") == "c:/secrets/x.md"
    assert normalize_path("c:/PROJ//sub/./a.MD") == "c:/proj/sub/a.md"
    assert normalize_path("\\\\server\\share\\f") == "//server/share/f"
    assert normalize_path("/srv/shared/../etc/passwd") == "/srv/etc/passwd"
    assert normalize_path("../x") == "../x"
    assert is_pathlike("C:\\a") and is_pathlike("/a") and is_pathlike("a/b") and not is_pathlike("cfo@contoso.com") and not is_pathlike("acct-9")


def test_glob_match_closes_the_holes_and_keeps_exact_values_exact():
    rule = "C:\\proj\\*"
    assert glob_match(rule, "C:\\proj\\a.md") and glob_match(rule, "C:\\proj\\sub\\a.md")      # `*` spans folders
    assert glob_match(rule, "c:\\PROJ\\a.md") and glob_match(rule, "C:/proj/a.md")                 # case, separators
    assert not glob_match(rule, "C:\\proj\\..\\secrets\\x") and not glob_match(rule, "C:\\proj2\\x")  # traversal
    assert glob_match("*proj*", "C:\\Proj\\a.md")                                                  # a bare glob against a path folds case too
    assert glob_match("*.md", "notes.md") and not glob_match("*.md", "NOTES.MD")                      # no path: exact
    assert glob_match("cfo@contoso.com", "cfo@contoso.com") and not glob_match("cfo@contoso.com", "CFO@contoso.com")


def test_rules_and_plan_steps_use_the_same_matcher(tmp_path):
    doc = {"version": "t", "default": "deny", "rules": [
        {"tools": ["write_file"], "args": {"path": "C:\\proj\\*"}, "action": "hold"},
    ]}
    p = tmp_path / "rules.json"; p.write_text(json.dumps(doc)); pol = RulesPolicy(str(p))
    base = {"principal": "a@contoso.com", "groups": [], "roles": [], "tool": "write_file"}
    assert pol.decide("t", {**base, "args": {"path": "c:/PROJ/sub/a.md"}}).requires_approval
    assert not pol.decide("t", {**base, "args": {"path": "C:\\proj\\..\\Windows\\x"}}).eligible   # default deny, not the hold
    step = {"tool": "write_file", "match": {"path": "C:\\proj\\*"}}
    assert step_matches(step, "write_file", {"path": "c:/proj/A.MD"})
    assert not step_matches(step, "write_file", {"path": "C:\\proj\\..\\x"})
    # The pattern judgment compares normalized globs as well.
    assert _glob_covers("C:\\proj\\*", "c:/PROJ/*.md") and not _globs_may_overlap("C:\\proj\\*", "D:\\*")
    d = pol.decide_pattern("t", {**base, "args": {"path": "c:/proj/*.md"}})
    assert d.outcome == ELIGIBLE and d.requires_approval
