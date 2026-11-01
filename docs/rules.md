# The rules file: how a call is decided

One page on `rules.json`, the policy most deployments run (`gargoyle.rules`).
Everything here is what `decide_rules` does; `gargoyle rules explain` shows
it for one call, `gargoyle rules test` for a file of them, `gargoyle rules
lint` for the rules themselves.

## The document

```json
{
  "version": "clients-2026-10",
  "default": "deny",
  "rules": [
    {"tools": ["read_*", "list_*"],                       "action": "allow"},
    {"tools": ["write_file", "edit_file"],
     "args": {"path": "/srv/shared/*"},                    "action": "hold",
     "approver_roles": ["Approver.Business"]},
    {"tools": ["move_file"], "args": {"destination": "*.ps1"}, "action": "hold"},
    {"tools": ["delete_*"], "action": "deny", "reason": "DESTRUCTIVE_TOOL"},
    {"tools": ["write_file", "edit_file", "create_directory", "move_file"], "action": "hold"}
  ]
}
```

`version` is any non-empty string, for people. `default` is what happens
when no rule matches: `deny` unless the file says `allow` or `hold`.
A `comment` on a rule is ignored by the engine and printed by `explain`.

## First match wins

Rules are read top to bottom. The first rule whose every condition holds
decides the call; nothing below it is consulted. So order is policy:

- a deny for deletes placed below an "allow anything on a drive letter"
  rule never fires (the pilot's finding B, 2026-11-01);
- a broad hold placed above a narrow routed hold sends the routed folder
  to the wrong approver.

`gargoyle rules lint` reports a rule that an earlier rule always
pre-empts as `UNREACHABLE`. The check is sound in one direction: when it
says unreachable, it is; when the globs are too intricate to be sure, it
says nothing.

## What a rule matches on

| key | matches when | values |
|---|---|---|
| `tools` | the call's tool name matches one glob | required, list of globs |
| `args` | every named argument is present, a string, and matches its glob | object: argument name → one glob |
| `principals` | the caller's principal (from the identity token) matches one glob | list of globs |
| `on_behalf_of` | the delegated user matches one glob | list of globs |
| `groups` | any of the caller's group ids (Entra) matches one glob | list of globs |
| `roles` | any of the caller's app roles matches one glob | list of globs |

A key the rule does not name is not a condition. A key the rule names must
be satisfiable by the call: a rule with `"args": {"path": ...}` can never
match `move_file`, which sends `source` and `destination`, nor Claude
Code's `Write`, which sends `file_path`. Lint reports that as
`ARG_KEY_UNKNOWN`.

### Which tools send which arguments

| tool | string arguments a rule can glob |
|---|---|
| `read_file`, `list_directory`, `create_directory`, `delete_file`, `directory_tree`, `get_file_info` | `path` |
| `write_file` | `path`, `content` |
| `edit_file` | `path` |
| `move_file` | `source`, `destination` |
| `search_files` | `path`, `pattern` |
| Claude Code `Write`, `Edit`, `MultiEdit`, `Read` (hook) | `file_path` |
| Claude Code `NotebookEdit` (hook) | `notebook_path` |
| Claude Code `Bash` (hook) | `command` (the whole command line as one string) |
| Claude Code `WebFetch` (hook) | `url` |

Other servers send their own keys; name them as the server does. Only
string arguments can be globbed; a number or a list never matches.

## Globs

Shell-style (`fnmatch`): `*` any run of characters including `/` and
`\`, `?` one character, `[abc]` a set, `[A-Za-z]` a range. There is no
`**`; `*` already crosses directory separators, so `/srv/shared/*`
matches `/srv/shared/a/b/c.md`.

When either side looks like a path, both are compared in one normalized
form: `\` and `/` are the same, `.` and `..` segments are collapsed,
repeated separators are one, a drive letter is kept, and the whole thing
is lower-cased, so path matching is case-insensitive. `C:\Share\*`
matches `c:/share/X.TXT`. A path is also tried in its canonical form
(trailing dots and spaces stripped per component, `name:stream` and
`::$DATA` dropped), so `*.ps1` matches `t1.ps1.` and `t2.ps1::$DATA`; on
Windows the gate refuses such names before the policy sees them anyway
(`REF_TARGET_PATH_NOT_CANONICAL`).

Tool names, principals, groups and roles are plain, case-sensitive globs
with none of the path treatment.

## What each action does

| action | the issuer | the receipt |
|---|---|---|
| `allow` | issues at once | allowed by rule and recorded; no approver sees it |
| `hold` | issues a held receipt and waits for a grant | carries the hold terms below |
| `deny` | refuses | the reason (`reason`, default `RULE_DENIED`) goes to the evidence log and witness |

Hold terms, all signed into the receipt: `approvals` (distinct approvers
needed, default 1), `approvers` (which approver key ids count),
`approver_roles` (which app roles a releasing approver's token must
carry; a hold routed to a role nobody holds waits until it expires, so
lint checks the names against `--roles` when given), `plan: false` (never
inside a scoped grant; every call on its own card).

## Plans

A plan step names argument globs instead of values. It is judged by
`decide_rules_pattern`: every rule any matching call could reach counts,
and the step gets the strictest of them. A plan is never weaker than a
rule one of its calls could hit.

## The pin

The policy pin is the SHA-256 of the file's bytes. Edit the file, even
a comment, and the pin moves: every outstanding receipt stops being
honored until its call is decided again. Gates that follow the issuer's
signed record (`GARGOYLE_MCP_RECORD_URL`) pick the change up within a
minute; a gate with a static `record.json` refuses everything until the
copy is refreshed (`gargoyle doctor` names this).

## Testing a file before it is the policy

```
gargoyle rules explain --rules rules.json --tool move_file --arg source=/a/x.txt --arg destination=/a/x.ps1
gargoyle rules test    --rules rules.json --calls calls.jsonl --roles Approver,Approver.Business,Approver.Deputy
gargoyle rules lint    --rules rules.json
```

`calls.jsonl` is one JSON object per line (`#` lines are comments):
`tool`, `args`, optionally `principal`, `groups`, `roles`, `on_behalf_of`,
a `note`, and `expect` with any of `action`, `rule` (index, or `null` for
the default), `reason`, `roles`, `approvers`, `approvals`, `plannable`.
Only the keys given are compared. `test` exits 1 when any call differs or
lint finds anything, so it belongs in CI next to the rules file.
`examples/rules/` ships the Windows observe-mode pilot's rules with the
fourteen calls it decided live; the test suite runs them.
