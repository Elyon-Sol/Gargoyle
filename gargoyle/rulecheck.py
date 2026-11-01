"""`gargoyle rules`: what a rules file would do, before it is the policy.

Rules are hand-written JSON and first match wins, so a rule placed one
line too late never fires, a glob written for `path` never sees a
`move_file` (which sends `source` and `destination`), and a role name
typed once wrong routes a hold to nobody. The pilot found the move_file
gap by hand. These three answer such questions from the file alone:

    explain(doc, interaction)   one call: every rule in order, matched or why not, the decision
    run_calls(doc, calls)       a calls file: one row per call, checked against its `expect`
    lint(doc)                   unreachable rules, argument keys a tool never sends, unknown roles

All three use `gargoyle.rules.decide_rules` for the decision itself, so
what they print is what the issuer would do with the same file. `explain`
walks the rules a second time only to say why each one did or did not
match.
"""

from __future__ import annotations

import fnmatch
import json
from typing import Any, Dict, Iterable, List, Mapping, Optional

from gargoyle.globs import glob_match
from gargoyle.rules import (RULE_DENIED, _any_match, _any_of_list, _args_cover, _glob_covers, decide_rules,
                            validate_rules)

# Which argument keys each known tool sends: the gate's own filesystem
# server (gargoyle.fs_server), the reference MCP filesystem server, and
# Claude Code's tools as the hook names them (gargoyle.claude_hook). A
# rule whose `args` names a key none of its tools send can never match.
KNOWN_TOOL_ARGS: Dict[str, frozenset] = {
    "list_directory": frozenset({"path"}), "read_file": frozenset({"path"}), "write_file": frozenset({"path", "content"}),
    "create_directory": frozenset({"path"}), "move_file": frozenset({"source", "destination"}),
    "delete_file": frozenset({"path"}), "list_allowed_directories": frozenset(),
    "read_multiple_files": frozenset({"paths"}), "edit_file": frozenset({"path", "edits", "dryRun"}),
    "directory_tree": frozenset({"path"}), "search_files": frozenset({"path", "pattern", "excludePatterns"}),
    "get_file_info": frozenset({"path"}), "read_text_file": frozenset({"path", "head", "tail"}),
    "read_media_file": frozenset({"path"}), "list_directory_with_sizes": frozenset({"path", "sortBy"}),
    # Claude Code via the hook
    "Write": frozenset({"file_path", "content"}), "Edit": frozenset({"file_path", "old_string", "new_string", "replace_all"}),
    "MultiEdit": frozenset({"file_path", "edits"}), "NotebookEdit": frozenset({"notebook_path", "new_source", "cell_id", "cell_type", "edit_mode"}),
    "Read": frozenset({"file_path", "offset", "limit"}), "Bash": frozenset({"command", "description", "timeout", "run_in_background"}),
    "WebFetch": frozenset({"url", "prompt"}), "Glob": frozenset({"pattern", "path"}), "Grep": frozenset({"pattern", "path", "glob"}),
}

CONSTRAINTS = ("principals", "on_behalf_of", "groups", "roles")

UNREACHABLE = "UNREACHABLE"
ARG_KEY_UNKNOWN = "ARG_KEY_UNKNOWN"
ROLE_UNKNOWN = "ROLE_UNKNOWN"
DENY_UNREACHABLE_BY_DEFAULT = "DENY_AFTER_CATCH_ALL"


def action_of(decision: Any) -> str:
    if not decision.eligible:
        return "deny"
    return "hold" if decision.requires_approval else "allow"


def _why_not(rule: Mapping[str, Any], interaction: Mapping[str, Any]) -> Optional[str]:
    """None when the rule matches; else the first reason it does not."""
    if not _any_match(interaction.get("tool"), rule["tools"]):
        return "tool %r not in %s" % (interaction.get("tool"), rule["tools"])
    for key in ("principals", "on_behalf_of"):
        if key in rule and not _any_match(interaction.get(key), rule[key]):
            return "%s %r not in %s" % (key, interaction.get(key), rule[key])
    for key in ("groups", "roles"):
        if key in rule and not _any_of_list(interaction.get(key), rule[key]):
            return "none of %s %s in %s" % (key, interaction.get(key) or [], rule[key])
    args = interaction.get("args") if isinstance(interaction.get("args"), Mapping) else {}
    for key, glob in (rule.get("args") or {}).items():
        value = args.get(key)
        if value is None:
            return "args.%s absent (rule wants %r)" % (key, glob)
        if not isinstance(value, str):
            return "args.%s is not a string" % key
        if not glob_match(glob, value):
            return "args.%s %r does not match %r" % (key, value, glob)
    return None


def explain(doc: Dict[str, Any], interaction: Mapping[str, Any]) -> Dict[str, Any]:
    """Every rule in order with matched/why-not, the index of the first match
    (None when the default decided), and the decision as the issuer would
    make it."""
    bad = validate_rules(doc)
    if bad:
        return {"error": bad}
    rows: List[Dict[str, Any]] = []
    matched: Optional[int] = None
    for i, rule in enumerate(doc["rules"]):
        why = _why_not(rule, interaction)
        rows.append({"index": i, "matched": why is None, "why_not": why, "action": rule["action"],
                     **({"comment": rule["comment"]} if isinstance(rule.get("comment"), str) else {})})
        if why is None:
            matched = i
            break
    d = decide_rules(doc, interaction)
    decision = {"action": action_of(d), "rule": matched}
    if matched is None:
        decision["default"] = doc.get("default", "deny")
    if not d.eligible:
        decision["reason"] = d.reason
    if d.requires_approval:
        decision["approvals"] = d.approvals_required
        if d.approvers:
            decision["approvers"] = sorted(d.approvers)
        if d.approver_roles:
            decision["roles"] = sorted(d.approver_roles)
        decision["plannable"] = d.plannable
    return {"decision": decision, "rules": rows}


def _call_interaction(call: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"tool": call.get("tool"), "args": call.get("args") or {}}
    for k in ("principal", "on_behalf_of", "groups", "roles"):
        if k in call:
            out[k] = call[k]
    out.setdefault("groups", []); out.setdefault("roles", [])
    return out


def run_calls(doc: Dict[str, Any], calls: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """One row per call: the decision, the rule that made it, and `ok`
    against the call's optional `expect` ({action, rule, reason, roles,
    approvals, plannable, approvers}; only the keys given are compared)."""
    rows = []
    for n, call in enumerate(calls, 1):
        ex = explain(doc, _call_interaction(call))
        if "error" in ex:
            rows.append({"n": n, "ok": False, "error": ex["error"]}); continue
        d = ex["decision"]
        row: Dict[str, Any] = {"n": n, "tool": call.get("tool"), "args": call.get("args") or {}, **d}
        if call.get("note"):
            row["note"] = call["note"]
        expect = call.get("expect")
        if isinstance(expect, Mapping):
            diffs = []
            for k, want in expect.items():
                got = d.get(k)
                if k in ("roles", "approvers") and isinstance(want, list):
                    want = sorted(want)
                if got != want:
                    diffs.append("%s: expected %r, got %r" % (k, want, got))
            row["expect"] = dict(expect)
            row["ok"] = not diffs
            if diffs:
                row["diffs"] = diffs
        else:
            row["ok"] = True
        rows.append(row)
    return rows


def _covers_globs(broad: List[str], narrow: List[str]) -> bool:
    """Does every glob in `narrow` match only strings some glob in `broad` matches?"""
    return all(any(_glob_covers(b, g) for b in broad) for g in narrow)


def _rule_covers(earlier: Mapping[str, Any], later: Mapping[str, Any]) -> bool:
    """Does every call the later rule would match reach the earlier rule
    first? Sound under-approximation: False when unsure."""
    if not _covers_globs(earlier["tools"], later["tools"]):
        return False
    for key in CONSTRAINTS:
        if key in earlier:
            if key not in later or not _covers_globs(earlier[key], later[key]):
                return False
    e_args = earlier.get("args") or {}
    if e_args:
        l_args = later.get("args") or {}
        if not all(k in l_args for k in e_args) or not _args_cover(l_args, e_args):
            return False
    return True


def _known_tools_for(globs: List[str]) -> List[str]:
    return [t for t in KNOWN_TOOL_ARGS if any(fnmatch.fnmatchcase(t, g) for g in globs)]


def lint(doc: Dict[str, Any], *, known_roles: Optional[Iterable[str]] = None,
         tool_args: Mapping[str, frozenset] = KNOWN_TOOL_ARGS) -> List[Dict[str, Any]]:
    """Findings, each {rule, kind, detail, remedy}. Empty list: nothing found."""
    bad = validate_rules(doc)
    if bad:
        return [{"rule": None, "kind": "MALFORMED", "detail": bad, "remedy": "fix the file; the issuer refuses every call under a malformed rules file"}]
    out: List[Dict[str, Any]] = []
    rules = doc["rules"]
    for j, later in enumerate(rules):
        for i in range(j):
            if _rule_covers(rules[i], later):
                out.append({"rule": j, "kind": UNREACHABLE,
                            "detail": "rule %d (%s) never fires: rule %d (%s) matches every call it would" % (j, later["action"], i, rules[i]["action"]),
                            "remedy": "move rule %d above rule %d, narrow rule %d, or delete rule %d" % (j, i, i, j)})
                break
    for j, rule in enumerate(rules):
        for key in (rule.get("args") or {}):
            tools = _known_tools_for(rule["tools"])
            if tools and not any(key in tool_args.get(t, frozenset()) for t in tools):
                sends = sorted({k for t in tools for k in tool_args.get(t, frozenset())})
                out.append({"rule": j, "kind": ARG_KEY_UNKNOWN,
                            "detail": "rule %d matches on args.%s, which none of %s sends (they send: %s)" % (
                                j, key, ", ".join(tools[:4]) + ("…" if len(tools) > 4 else ""), ", ".join(sends) or "nothing"),
                            "remedy": "use the key the tool sends (move_file: source/destination; Claude Code Write/Edit: file_path), or the rule never matches"})
        if known_roles is not None and "approver_roles" in rule:
            known = set(known_roles)
            for r in rule["approver_roles"]:
                if r not in known:
                    out.append({"rule": j, "kind": ROLE_UNKNOWN,
                                "detail": "rule %d routes to role %r, not among the known roles %s" % (j, r, sorted(known)),
                                "remedy": "fix the spelling, or create the app role in the tenant; a hold routed to a role nobody holds waits until it expires"})
    return out


# ---- text ------------------------------------------------------------------------

def format_explain(ex: Dict[str, Any]) -> str:
    if "error" in ex:
        return "rules file malformed: " + ex["error"]
    lines = []
    for r in ex["rules"]:
        mark = "=> " if r["matched"] else "   "
        text = "matched" if r["matched"] else r["why_not"]
        lines.append("%s%2d %-5s %s%s" % (mark, r["index"], r["action"], text, ("   # " + r["comment"]) if r.get("comment") else ""))
    d = ex["decision"]
    tail = "decision: %s" % d["action"]
    if d.get("rule") is None:
        tail += " (default %s, no rule matched)" % d.get("default")
    else:
        tail += " by rule %d" % d["rule"]
    extras = [k + "=" + json.dumps(d[k]) for k in ("reason", "approvals", "approvers", "roles", "plannable") if k in d]
    if extras:
        tail += "  " + " ".join(extras)
    lines.append(tail)
    return "\n".join(lines)


def format_calls(rows: List[Dict[str, Any]]) -> str:
    lines = []
    for r in rows:
        if "error" in r:
            lines.append("%3d FAIL  %s" % (r["n"], r["error"])); continue
        rule = "default" if r.get("rule") is None else "rule %d" % r["rule"]
        extra = " ".join(k + "=" + json.dumps(r[k]) for k in ("reason", "roles", "approvals") if k in r)
        args = ", ".join("%s=%s" % (k, v if len(str(v)) <= 48 else str(v)[:45] + "...") for k, v in (r.get("args") or {}).items()
                         if k not in ("content",))
        status = "ok  " if r["ok"] else "FAIL"
        lines.append("%3d %s %-5s %-8s %s(%s) %s" % (r["n"], status, r["action"], rule, r["tool"], args, extra))
        for dtxt in r.get("diffs", []):
            lines.append("         ! " + dtxt)
    bad = sum(1 for r in rows if not r["ok"])
    lines.append("%d calls, %d differ from expectation" % (len(rows), bad))
    return "\n".join(lines)


def format_lint(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "lint: nothing found"
    lines = []
    for f in findings:
        lines.append("%-18s %s" % (f["kind"], f["detail"]))
        lines.append("%-18s -> %s" % ("", f["remedy"]))
    lines.append("%d finding%s" % (len(findings), "" if len(findings) == 1 else "s"))
    return "\n".join(lines)


def read_calls(path: str) -> List[Dict[str, Any]]:
    """A JSON Lines file of calls, or one JSON list; `#` lines are comments."""
    text = open(path, "r", encoding="utf-8-sig").read()
    stripped = text.strip()
    if stripped.startswith("["):
        return json.loads(stripped)
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(json.loads(line))
    return out
