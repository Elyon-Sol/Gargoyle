# The gate as a Claude Code hook

Claude Code's own tools (Bash, Edit, Write, MultiEdit, NotebookEdit, Read,
WebFetch, and the MCP tools it calls directly) are not MCP calls through
a server the gate can front. Claude Code does run a command before and
after each tool call (a hook), with the call as JSON on stdin and a
decision read from stdout. `gargoyle hook` is that command. The receipt,
the hold, the approver's grant, the evidence log and the audit are the
ones the MCP gate uses; only the on-ramp is different.

## Set up

On the issuer's host:

    gargoyle init /path/the/agent/works/in --client claude-code --out gargoyle-deploy \
        --issuer-url https://gate.example --client-python "C:/Users/dev/AppData/Local/Programs/Python/Python312/python.exe" \
        --client-config-dir C:/gargoyle
    gargoyle issuer --out gargoyle-deploy

`--client claude-code` writes `rules.json` for Claude Code's tool names
(reads, searches and planning tools allowed; Write, Edit, MultiEdit,
NotebookEdit, Bash and PowerShell held) and `claude-settings.json`, the
hook entries, in place of `mcp-config.json`. `--observe` works the same
way as for the MCP gate: everything allowed and recorded for the first
week, rules from `gargoyle audit --summary` after.

On the workstation: `pip install gargoyle-receipts`, copy `middleware.env`
and `record.json` to the client config folder, run `gargoyle login` if the
issuer uses Entra, and merge the `hooks` object from `claude-settings.json`
into a settings file Claude Code reads:

| Where | File | Who can remove it |
|---|---|---|
| this project | `.claude/settings.json` | anyone with write access to the repo |
| this user | `~/.claude/settings.json` | the user |
| the whole machine (managed) | `managed-settings.json` under the OS's Claude Code policy folder (`/etc/claude-code/`, `/Library/Application Support/ClaudeCode/`, `C:\ProgramData\ClaudeCode\`) | an administrator; `allowManagedHooksOnly` then also blocks hooks added elsewhere |

The entry is the same in each:

    {"hooks": {
      "PreToolUse":         [{"hooks": [{"type": "command", "timeout": 330,
                               "command": "\"C:/.../python.exe\" -m gargoyle hook --env \"C:/gargoyle/middleware.env\""}]}],
      "PostToolUse":        [{"hooks": [{"type": "command", "timeout": 60, "command": "...the same..."}]}],
      "PostToolUseFailure": [{"hooks": [{"type": "command", "timeout": 60, "command": "...the same..."}]}],
      "PermissionDenied":   [{"hooks": [{"type": "command", "timeout": 60, "command": "...the same..."}]}]
    }}

The hook reads `middleware.env` itself, so the settings entry carries no
secret and can live in a repository. The PreToolUse `timeout` must exceed
`GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS` (300 by default): a held call
waits inside the hook for the approver.

## What happens on each call

- **Allowed by the rules.** The hook obtains a receipt, verifies it
  against the pinned issuer key, and lets the call proceed. By default
  Claude Code's own permission prompt still applies on top: the gate adds
  a signed decision and an evidence entry and takes nothing away. With
  `--final` on the command, the gate's allow is the decision and no local
  prompt is shown; that is the setting for a fleet whose approvals are
  meant to come from the named approvers and nobody else.
- **Held.** The hook waits for the grant. The approver sees the tool and
  its full arguments (the shell command, the file path and content) in the
  console or `gargoyle approve`, signs, and the call proceeds. A Write or
  Edit is bound to the file's state as it was when the approver saw it, is
  snapshotted, and the execution receipt records the state after.
- **Denied, declined, timed out, issuer unreachable, receipt not
  verifiable.** The call does not run. Claude sees the refusal code
  (`PreToolUse:Bash hook error: gargoyle: DESTRUCTIVE_COMMAND`) and says
  so. A hook that cannot build its own state, for any reason, denies.
- **After the tool ran.** The PostToolUse (or PostToolUseFailure) hook
  attests the execution receipt over the tool's actual result and writes
  the one evidence entry for the call. A call the gate allowed and Claude
  Code's own prompt then refused, or one whose session ended before the
  tool ran, is recorded as refused with `REF_HOOK_NOT_RUN`: the receipt
  was honored, the tool never ran. The honored receipt crosses from the
  PreToolUse process to the PostToolUse one through
  `audit.hook-pending.json` beside the evidence log, keyed by Claude
  Code's `tool_use_id`.

`gargoyle audit --log audit.jsonl` verifies the whole log offline, as for
the MCP gate; rows name the Claude Code session that made each call.

## Measured

On the reference VM, one hook invocation (process start, receipt, verify,
evidence write) takes about 150 ms for an allowed call; a held call takes
as long as the approver does. First live run (2026-10-22, Claude Code
2.1.307, `claude -p` in a scratch project): a Write and a `cat` were each
held and released, a `rm` was refused by rule and Claude reported the
refusal verbatim, the file state change was bound to the Write, and the
evidence log verified: 4 entries, 3 honored, 1 refused, 0 failed.

## What this does not do

- Claude Desktop, claude.ai and hosted connectors have no hook. This
  covers Claude Code.
- The shell and the files are on the workstation. A user with the rights
  to remove the hook can act without it. Managed settings with
  `allowManagedHooksOnly` make that an administrator's act, and
  `gargoyle audit --check-tree` reconciles gated files against the
  evidence; neither is containment. The MCP gate, where the tool server
  itself stands behind the receipt, is stronger; use it where it fits.
- The gate's own folder is refused to path arguments
  (`REF_TARGET_GATE_FILES`), not to a shell command that names it. Keep
  `middleware.env` and the evidence log out of the agent's working tree,
  and the hold on Bash is what stands between the agent and them.
- Rules match a shell command as one string (`"args": {"command": "rm *"}`).
  That catches the plain case, not every spelling. The default holds every
  Bash call, which is the honest setting.
