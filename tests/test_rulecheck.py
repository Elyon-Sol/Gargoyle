"""`gargoyle rules`: explain, test and lint a rules file with the issuer's
own decide_rules. The shipped example reproduces the pilot's live
decisions; a shadowed rule, a key the tool never sends and a misspelt role
are each named."""

import json
from pathlib import Path

from gargoyle.cli import main
from gargoyle.rulecheck import (ARG_KEY_UNKNOWN, ROLE_UNKNOWN, UNREACHABLE, explain, format_calls, format_explain,
                                format_lint, lint, read_calls, run_calls)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "rules"

RULES = {
    "version": "t", "default": "deny",
    "rules": [
        {"tools": ["read_*", "list_*"], "action": "allow"},
        {"tools": ["write_file", "edit_file"], "args": {"path": "/srv/shared/*"}, "action": "hold", "approver_roles": ["Approver.Business"]},
        {"tools": ["delete_*"], "action": "deny", "reason": "DESTRUCTIVE_TOOL"},
        {"tools": ["write_file"], "action": "hold", "approvals": 2, "approvers": ["a", "b"], "plan": False},
    ],
}


def test_explain_names_why_each_rule_did_not_match():
    ex = explain(RULES, {"tool": "write_file", "args": {"path": "/tmp/x"}, "groups": [], "roles": []})
    rows = ex["rules"]
    assert rows[0]["why_not"].startswith("tool 'write_file' not in")
    assert "does not match" in rows[1]["why_not"] and "/srv/shared/*" in rows[1]["why_not"]
    assert rows[2]["why_not"].startswith("tool")
    assert rows[3]["matched"] and ex["decision"] == {"action": "hold", "rule": 3, "approvals": 2, "approvers": ["a", "b"], "plannable": False}
    text = format_explain(ex)
    assert "=>  3 hold  matched" in text and "decision: hold by rule 3" in text


def test_explain_absent_key_and_default():
    ex = explain(RULES, {"tool": "edit_file", "args": {}, "groups": [], "roles": []})
    assert ex["rules"][1]["why_not"] == "args.path absent (rule wants '/srv/shared/*')"
    assert ex["decision"] == {"action": "deny", "rule": None, "default": "deny", "reason": "RULE_DENIED"}
    assert "default deny, no rule matched" in format_explain(ex)


def test_explain_roles_and_malformed():
    doc = {"version": "t", "rules": [{"tools": ["*"], "roles": ["IT.*"], "action": "allow"}]}
    ex = explain(doc, {"tool": "x", "args": {}, "groups": [], "roles": ["Sales"]})
    assert ex["rules"][0]["why_not"] == "none of roles ['Sales'] in ['IT.*']"
    assert explain({"version": "t", "rules": [{"tools": [], "action": "allow"}]}, {"tool": "x"}) == {"error": "rule 0: tools must be a non-empty list of globs"}


def test_run_calls_compares_only_the_keys_given():
    calls = [
        {"tool": "read_file", "args": {"path": "/a"}, "expect": {"action": "allow", "rule": 0}},
        {"tool": "write_file", "args": {"path": "/srv/shared/p.md"}, "expect": {"action": "hold", "roles": ["Approver.Business"]}},
        {"tool": "write_file", "args": {"path": "/srv/shared/p.md"}, "expect": {"action": "allow"}},
        {"tool": "delete_file", "args": {"path": "/a"}, "expect": {"reason": "DESTRUCTIVE_TOOL", "rule": 2}},
        {"tool": "nothing", "args": {}},
    ]
    rows = run_calls(RULES, calls)
    assert [r["ok"] for r in rows] == [True, True, False, True, True]
    assert rows[2]["diffs"] == ["action: expected 'allow', got 'hold'"]
    assert rows[4]["action"] == "deny" and rows[4]["rule"] is None
    text = format_calls(rows)
    assert "5 calls, 1 differ from expectation" in text and "! action: expected 'allow', got 'hold'" in text


def test_lint_unreachable_rule_is_named():
    doc = {"version": "t", "rules": [
        {"tools": ["write_*"], "action": "hold"},
        {"tools": ["write_file"], "args": {"path": "/x/*"}, "action": "deny"},        # shadowed: rule 0 catches every write
        {"tools": ["read_file"], "args": {"path": "/x/*"}, "action": "allow"},
        {"tools": ["read_file"], "args": {"path": "/x/sub/*"}, "action": "deny"},     # shadowed: /x/* covers /x/sub/*
        {"tools": ["read_file"], "args": {"path": "/y/*"}, "action": "deny"},         # reachable
    ]}
    found = lint(doc)
    assert [(f["rule"], f["kind"]) for f in found] == [(1, UNREACHABLE), (3, UNREACHABLE)]
    assert "rule 0 (hold) matches every call it would" in found[0]["detail"]
    assert "move rule 1 above rule 0" in found[0]["remedy"]


def test_lint_constraints_keep_a_rule_reachable():
    doc = {"version": "t", "rules": [
        {"tools": ["*"], "principals": ["agent-*"], "action": "allow"},
        {"tools": ["write_file"], "action": "hold"},                                   # other principals reach it
        {"tools": ["write_file"], "args": {"path": "*.ps1"}, "action": "hold"},
        {"tools": ["write_file"], "args": {"path": "*.psm1"}, "action": "hold"},       # *.ps1 does not cover *.psm1
    ]}
    found = lint(doc)
    assert [(f["rule"], f["kind"]) for f in found] == [(2, UNREACHABLE), (3, UNREACHABLE)]   # rule 1 (no args) catches every write


def test_lint_argument_key_the_tool_never_sends():
    doc = {"version": "t", "rules": [
        {"tools": ["move_file"], "args": {"path": "*.ps1"}, "action": "hold"},
        {"tools": ["Write", "Edit"], "args": {"path": "/x/*"}, "action": "hold"},
        {"tools": ["move_file"], "args": {"destination": "*.ps1"}, "action": "hold"},
        {"tools": ["custom_tool"], "args": {"anything": "*"}, "action": "hold"},        # unknown tool: not judged
        {"tools": ["*"], "args": {"path": "/x/*"}, "action": "allow"},                  # some known tool sends path
    ]}
    found = lint(doc)
    assert [(f["rule"], f["kind"]) for f in found] == [(0, ARG_KEY_UNKNOWN), (1, ARG_KEY_UNKNOWN)]
    assert "destination, source" in found[0]["detail"] and "file_path" in found[1]["detail"]


def test_lint_unknown_role_only_when_roles_are_given():
    doc = {"version": "t", "rules": [{"tools": ["write_file"], "action": "hold", "approver_roles": ["Approver.Buisness"]}]}
    assert lint(doc) == []
    found = lint(doc, known_roles=["Approver", "Approver.Business"])
    assert [(f["rule"], f["kind"]) for f in found] == [(0, ROLE_UNKNOWN)] and "Approver.Buisness" in found[0]["detail"]
    assert format_lint(found).startswith(ROLE_UNKNOWN) and format_lint([]) == "lint: nothing found"


def test_lint_malformed_file():
    assert lint({"version": "t", "rules": "no"})[0]["kind"] == "MALFORMED"


def test_shipped_example_reproduces_the_pilot_and_lints_clean():
    doc = json.loads((EXAMPLES / "win-observe-routed.rules.json").read_text())
    calls = read_calls(str(EXAMPLES / "win-observe-routed.calls.jsonl"))
    rows = run_calls(doc, calls)
    assert len(rows) == 14 and all(r["ok"] for r in rows), [r for r in rows if not r["ok"]]
    assert lint(doc, known_roles=["Approver", "Approver.Business", "Approver.Deputy"]) == []


def test_cli_test_explain_lint(tmp_path, capsys):
    rules = tmp_path / "rules.json"; rules.write_text(json.dumps(RULES))
    calls = tmp_path / "calls.jsonl"
    calls.write_text('# comment\n{"tool": "read_file", "args": {"path": "/a"}, "expect": {"action": "allow"}}\n'
                     '{"tool": "write_file", "args": {"path": "/srv/shared/x"}, "expect": {"action": "deny"}}\n')
    assert main(["rules", "test", "--rules", str(rules), "--calls", str(calls)]) == 1
    out = capsys.readouterr().out
    assert "2 calls, 1 differ" in out and "lint: nothing found" in out
    assert main(["rules", "explain", "--rules", str(rules), "--tool", "write_file", "--arg", "path=/srv/shared/x", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["decision"]["roles"] == ["Approver.Business"]
    assert main(["rules", "explain", "--rules", str(rules), "--tool", "write_file", "--arg", "nope"]) == 2
    capsys.readouterr()
    shadow = tmp_path / "shadow.json"
    shadow.write_text(json.dumps({"version": "t", "rules": [{"tools": ["*"], "action": "allow"}, {"tools": ["delete_*"], "action": "deny"}]}))
    assert main(["rules", "lint", "--rules", str(shadow)]) == 1
    assert UNREACHABLE in capsys.readouterr().out
    assert main(["rules", "lint", "--rules", str(rules), "--roles", "Approver,Approver.Business"]) == 0
