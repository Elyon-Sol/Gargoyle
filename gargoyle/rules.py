"""RulesPolicy: a policy from a plain JSON file, for deployments that do
not run a policy engine. First matching rule wins; no match is the default.

    {
      "version": "clients-2026-10",
      "default": "deny",
      "rules": [
        {"tools": ["read_*", "list_*", "get_*", "search_*"],   "action": "allow"},
        {"tools": ["write_file", "edit_file"], "args": {"path": "/srv/clients/*"},
                                                               "action": "hold"},
        {"tools": ["git_push", "deploy_*"],                     "action": "hold",
         "principals": ["spiffe://example.org/agents/*"]},
        {"tools": ["transfer_*", "pay_*"],                      "action": "hold",
         "approvals": 2, "approvers": ["finance-lead", "finance-controller"]},
        {"tools": ["delete_*", "rm", "drop_*"],                 "action": "deny",
         "reason": "DESTRUCTIVE_TOOL"}
      ]
    }

A rule matches when the call's tool matches one of its `tools` globs, and,
when given, its principal matches one of `principals`, its on_behalf_of one
of `on_behalf_of`, any of the caller's `groups` or `roles` (from the
identity token: Entra group ids or app roles) matches one of the rule's,
and every key in `args` is present in the call's arguments with a string
value matching the glob. Actions: "allow" (free),
"hold" (allowed, needs a human's grant), "deny" (refused; `reason` names
why, default RULE_DENIED). A hold may say how many distinct approvers must
sign (`approvals`, default 1) and which approver key ids count
(`approvers`); both go into the receipt. `"plan": false` on a hold keeps
that tool out of scoped grants (gargoyle.plans): every call is approved
on its own card. `default` is "deny" unless the
file says "allow" or "hold".

The pin is the SHA-256 of the file's bytes under policy_id
"gargoyle.rules/1": edit the file and every outstanding receipt stops
being honored until the call is decided again, exactly as with an engine.
Any malformed file, or any error while deciding, is a refusal.
"""

import fnmatch
import re

from gargoyle.globs import comparable, glob_match, is_pathlike
import hashlib
import json
from typing import Any, Dict, Mapping, Optional

from gargoyle.policy import ELIGIBLE, Decision, refuse

RULES_POLICY_ID = "gargoyle.rules/1"
RULES_MALFORMED = "RULES_MALFORMED"
RULE_DENIED = "RULE_DENIED"
RULES_INTERNAL = "RULES_INTERNAL"

_ACTIONS = ("allow", "hold", "deny")


def _globs(value: Any) -> Optional[list]:
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        return None
    return value


def validate_rules(doc: Any) -> Optional[str]:
    """None if `doc` is a well-formed rules document, else what is wrong."""
    if not isinstance(doc, dict):
        return "document is not an object"
    if not isinstance(doc.get("version"), str) or not doc["version"]:
        return "version must be a non-empty string"
    if doc.get("default", "deny") not in _ACTIONS:
        return "default must be allow, hold or deny"
    rules = doc.get("rules")
    if not isinstance(rules, list):
        return "rules must be a list"
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            return "rule %d is not an object" % i
        if _globs(rule.get("tools")) is None:
            return "rule %d: tools must be a non-empty list of globs" % i
        if rule.get("action") not in _ACTIONS:
            return "rule %d: action must be allow, hold or deny" % i
        for key in ("principals", "on_behalf_of", "groups", "roles"):
            if key in rule and _globs(rule[key]) is None:
                return "rule %d: %s must be a list of globs" % (i, key)
        if "args" in rule and (not isinstance(rule["args"], dict)
                               or not all(isinstance(k, str) and isinstance(v, str) for k, v in rule["args"].items())):
            return "rule %d: args must map argument names to globs" % i
        if "reason" in rule and (not isinstance(rule["reason"], str) or not rule["reason"]):
            return "rule %d: reason must be a non-empty string" % i
        if "approvals" in rule and (isinstance(rule["approvals"], bool) or not isinstance(rule["approvals"], int)
                                    or rule["approvals"] < 1):
            return "rule %d: approvals must be an integer >= 1" % i
        if "approvers" in rule and (_globs(rule["approvers"]) is None or len(set(rule["approvers"])) != len(rule["approvers"])
                                    or len(rule["approvers"]) < rule.get("approvals", 1)):
            return "rule %d: approvers must list at least `approvals` distinct approver key ids" % i
        if ("approvals" in rule or "approvers" in rule) and rule["action"] != "hold":
            return "rule %d: approvals and approvers belong to a hold" % i
        if "plan" in rule and (not isinstance(rule["plan"], bool) or rule["action"] != "hold"):
            return "rule %d: plan must be true or false, on a hold" % i
    return None


def _any_match(value: Any, globs: Optional[list]) -> bool:
    if globs is None:
        return True
    return isinstance(value, str) and any(fnmatch.fnmatchcase(value, g) for g in globs)


def _any_of_list(values: Any, globs: list) -> bool:
    if not isinstance(values, list):
        return False
    return any(_any_match(v, globs) for v in values)


def _args_match(args: Any, pattern: Dict[str, str]) -> bool:
    if not isinstance(args, dict):
        return False
    for key, glob in pattern.items():
        value = args.get(key)
        if not isinstance(value, str) or not glob_match(glob, value):
            return False
    return True


def _literal_prefix(glob: str):
    for i, ch in enumerate(glob):
        if ch in "*?[":
            return glob[:i], True
    return glob, False


def _globs_may_overlap(a: str, b: str) -> bool:
    """Could one string match both globs? Sound over-approximation: a glob
    only matches strings that start with its literal prefix, so two globs
    whose literal prefixes disagree are disjoint; anything else may overlap."""
    a, b = comparable(a, b) if (is_pathlike(a) or is_pathlike(b)) else (a, b)
    pa, wa = _literal_prefix(a)
    pb, wb = _literal_prefix(b)
    if not wa and not wb:
        return a == b
    if not wa:
        return fnmatch.fnmatchcase(a, b)
    if not wb:
        return fnmatch.fnmatchcase(b, a)
    n = min(len(pa), len(pb))
    return pa[:n] == pb[:n]


_WILD = re.compile(r"\*|\?|\[[^\]]*\]")


def _glob_covers(rule_glob: str, pattern: str) -> bool:
    """Does every string matching `pattern` also match `rule_glob`? Sound
    under-approximation (False when unsure). A rule glob made of literals and
    `*` covers the pattern when its first literal is a prefix of the pattern's
    literal prefix, its last literal a suffix of the pattern's literal suffix,
    and each literal between appears, in order, inside one of the pattern's
    literal pieces: every string the pattern admits carries those pieces in
    that order, whatever its wildcards expand to."""
    rule_glob, pattern = comparable(rule_glob, pattern)
    if not _WILD.search(pattern):
        return fnmatch.fnmatchcase(pattern, rule_glob)
    if "?" in rule_glob or "[" in rule_glob or "*" not in rule_glob:
        return rule_glob == pattern
    segments = rule_glob.split("*")
    pieces = _WILD.split(pattern)
    first, last, middle = segments[0], segments[-1], segments[1:-1]
    if not pieces[0].startswith(first) or not pieces[-1].endswith(last):
        return False
    pi, off = 0, len(first)
    for seg in middle:
        if not seg:
            continue
        while pi < len(pieces):
            at = pieces[pi].find(seg, off)
            if at >= 0:
                off = at + len(seg)
                break
            pi, off = pi + 1, 0
        else:
            return False
    if pi == len(pieces) - 1 and off > len(pieces[-1]) - len(last):
        return False
    return True


def _args_cover(pattern: Mapping[str, Any], rule_args: Dict[str, str]) -> bool:
    """Does the rule match every call the pattern admits? Each rule key must
    be constrained by the pattern and covered by the rule's glob."""
    for key, glob in rule_args.items():
        value = pattern.get(key)
        if not isinstance(value, str) or not _glob_covers(glob, value):
            return False
    return True


def _args_may_match(pattern: Mapping[str, Any], rule_args: Dict[str, str]) -> bool:
    """Could some call matching `pattern` (argument globs) also match the
    rule's argument globs? A key the pattern does not constrain may take any
    value, so it may match."""
    for key, glob in rule_args.items():
        value = pattern.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or not _globs_may_overlap(value, glob):
            return False
    return True


def decide_rules_pattern(doc: Dict[str, Any], interaction: Mapping[str, Any]) -> Decision:
    """The strictest decision any call matching the pattern in
    `interaction["args"]` could receive: for a plan step with argument
    globs (gargoyle.plans). Every rule the pattern could reach counts, in
    order, until a rule that matches every call the pattern admits catches
    the rest; the default counts when no such rule does. Any deny refuses; the hold terms
    are the maximum signatures required and the intersection of the named
    approver sets; a non-plannable rule, or an empty intersection, makes the
    step non-plannable. Sound and over-strict by design: a plan can never be
    weaker than a rule one of its calls could hit."""
    tool = interaction.get("tool")
    pattern = interaction.get("args") if isinstance(interaction.get("args"), Mapping) else {}
    reached = []
    caught_all = False
    for rule in doc["rules"]:
        if not _any_match(tool, rule["tools"]):
            continue
        if "principals" in rule and not _any_match(interaction.get("principal"), rule["principals"]):
            continue
        if "on_behalf_of" in rule and not _any_match(interaction.get("on_behalf_of"), rule["on_behalf_of"]):
            continue
        if "groups" in rule and not _any_of_list(interaction.get("groups"), rule["groups"]):
            continue
        if "roles" in rule and not _any_of_list(interaction.get("roles"), rule["roles"]):
            continue
        if "args" in rule and not _args_may_match(pattern, rule["args"]):
            continue
        reached.append(rule)
        if "args" not in rule or _args_cover(pattern, rule["args"]):
            caught_all = True        # no call matching the pattern gets past this rule
            break
    if not caught_all:
        default = doc.get("default", "deny")
        if default == "deny":
            return refuse(RULE_DENIED)
        reached.append({"action": default})
    for rule in reached:
        if rule["action"] == "deny":
            return refuse(rule.get("reason", RULE_DENIED))
    holds = [r for r in reached if r["action"] == "hold"]
    if not holds:
        return Decision(ELIGIBLE)
    plannable = all(r.get("plan", True) for r in holds)
    required = max(int(r.get("approvals", 1)) for r in holds)
    named = [set(r["approvers"]) for r in holds if "approvers" in r]
    approvers = None
    if named:
        common = set.intersection(*named)
        if len(common) < required:
            plannable = False        # no one grant set could satisfy every rule the pattern reaches
        approvers = tuple(sorted(common)) if common else None
    return Decision(ELIGIBLE, None, True, required, approvers, plannable)


def decide_rules(doc: Dict[str, Any], interaction: Mapping[str, Any]) -> Decision:
    """The decision for `interaction` under a validated rules document."""
    tool = interaction.get("tool")
    for rule in doc["rules"]:
        if not _any_match(tool, rule["tools"]):
            continue
        if "principals" in rule and not _any_match(interaction.get("principal"), rule["principals"]):
            continue
        if "on_behalf_of" in rule and not _any_match(interaction.get("on_behalf_of"), rule["on_behalf_of"]):
            continue
        if "groups" in rule and not _any_of_list(interaction.get("groups"), rule["groups"]):
            continue
        if "roles" in rule and not _any_of_list(interaction.get("roles"), rule["roles"]):
            continue
        if "args" in rule and not _args_match(interaction.get("args"), rule["args"]):
            continue
        action = rule["action"]
        if action == "deny":
            return refuse(rule.get("reason", RULE_DENIED))
        if action == "hold":
            return Decision(ELIGIBLE, None, True, rule.get("approvals", 1),
                            tuple(rule["approvers"]) if "approvers" in rule else None, rule.get("plan", True))
        return Decision(ELIGIBLE)
    default = doc.get("default", "deny")
    if default == "deny":
        return refuse(RULE_DENIED)
    return Decision(ELIGIBLE, None, default == "hold")


class RulesPolicy:
    """The rules file is read on every call, so an edit takes effect at once
    and moves the pin."""

    def __init__(self, path: str) -> None:
        if not isinstance(path, str) or not path:
            raise ValueError("RulesPolicy needs the path of its rules file")
        self.path = path

    def _load(self):
        with open(self.path, "rb") as f:
            raw = f.read()
        return raw, json.loads(raw.decode("utf-8"))

    def pin(self) -> Dict[str, str]:
        raw, _ = self._load()
        return {"policy_id": RULES_POLICY_ID, "policy_sha256": hashlib.sha256(raw).hexdigest()}

    def decide(self, target_url: str, interaction: Mapping[str, Any]) -> Decision:
        try:
            if not isinstance(interaction, Mapping):
                return refuse(RULES_MALFORMED)
            _, doc = self._load()
            if validate_rules(doc) is not None:
                return refuse(RULES_MALFORMED)
            return decide_rules(doc, interaction)
        except Exception:
            return refuse(RULES_INTERNAL)

    def decide_pattern(self, target_url: str, interaction: Mapping[str, Any]) -> Decision:
        """Judge a plan step whose args are globs: the strictest decision any
        call matching them could receive (decide_rules_pattern)."""
        try:
            if not isinstance(interaction, Mapping):
                return refuse(RULES_MALFORMED)
            _, doc = self._load()
            if validate_rules(doc) is not None:
                return refuse(RULES_MALFORMED)
            return decide_rules_pattern(doc, interaction)
        except Exception:
            return refuse(RULES_INTERNAL)
