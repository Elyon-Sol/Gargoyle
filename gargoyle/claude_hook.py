"""The gate as a Claude Code hook: Claude Code's own tools (Bash, Edit,
Write, Read, WebFetch, the MCP tools it calls directly) go through the
same receipt, hold and evidence path as a call through the MCP gate.

Claude Code runs a hook command before (PreToolUse) and after
(PostToolUse) each tool call, with the call as JSON on stdin, and reads a
JSON decision from stdout. `gargoyle hook` is that command:

    {"hooks": {"PreToolUse":  [{"hooks": [{"type": "command", "timeout": 330,
                                "command": "gargoyle hook --env /path/middleware.env"}]}],
               "PostToolUse": [{"hooks": [{"type": "command",
                                "command": "gargoyle hook --env /path/middleware.env"}]}]}}

PreToolUse: the call is sent to the issuer under the same middleware.env
the MCP gate uses (target id, principal or Entra sign-in, pinned keys,
evidence log). An allowed call proceeds; by default Claude Code's own
permission prompt still applies on top (the gate adds a signed decision
and evidence, it does not remove the local prompt), and with --final the
gate's allow is the decision. A held call waits inside the hook for the
approver's grant, up to GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS; set the
hook's `timeout` above that. A denied, declined, timed-out or
unverifiable call is refused with the refusal code as the reason Claude
sees. Every decision is one entry in the evidence log, verified later by
`gargoyle audit --log`.

PostToolUse: the receipt the PreToolUse step honored is attested with the
executor key (the execution receipt), bound to the tool's result, and the
evidence entry carries it. The honored receipt crosses from one hook
process to the next through a sidecar beside the evidence log
(audit.hook-pending.json), keyed by Claude Code's tool_use_id.

What this does not do: Claude Desktop, claude.ai and hosted connectors have
no hook; the shell and the files are on the workstation, so a user with
the rights to remove the hook can act without it (deploy it from managed
settings, and reconcile the evidence against outcomes); the per-call cost
is one process start and one round trip to the issuer.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from gargoyle.adapters import FilesystemAdapter, Probe
from gargoyle.state import describe, read_target

PRE = "PreToolUse"
POST = "PostToolUse"
POST_FAILURE = "PostToolUseFailure"
PERMISSION_DENIED = "PermissionDenied"
REF_HOOK_NOT_RUN = "REF_HOOK_NOT_RUN"       # honored, but Claude Code never ran the tool (its own prompt refused it, or the session ended)
REF_TARGET_NOT_CONFIGURED = "REF_TARGET_NOT_CONFIGURED"
REAP_SECONDS = 3600.0         # an honored receipt nobody came back for after this long is recorded as not run
PENDING_SUFFIX = ".hook-pending.json"
PENDING_LIMIT = 200           # honored receipts awaiting their PostToolUse; older ones are dropped

# Claude Code tools whose first path argument is the file they change.
FILE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}


class ClaudeCodeAdapter(FilesystemAdapter):
    """Claude Code's file tools name their target as `file_path` (or
    `notebook_path`); a held Write or Edit is bound to that file's state
    and snapshotted exactly as a held write_file through the MCP gate."""

    name = "claude-code"

    def probe(self, tool: str, args: Any) -> Probe:
        key = FILE_TOOLS.get(tool)
        if key is None or not isinstance(args, dict):
            return None
        path = args.get(key)
        if not isinstance(path, str) or not path:
            return None
        try:
            with open(path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            data = None
        except IsADirectoryError:
            desc = describe(path, b"", with_text=False)
            return desc, read_target(desc)
        except OSError:
            return None
        desc = describe(path, data)
        return desc, data

    def restore(self, meta: Dict[str, Any], pre: Optional[bytes], post: Optional[bytes]) -> Dict[str, Any]:
        out = super().restore(meta, pre, post)
        if "params" in out:
            out["params"] = {"name": "Write", "arguments": {"file_path": meta["ref"], "content": out["params"]["arguments"]["content"]}}
        return out


def load_env_file(path: str, environ: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """KEY=VALUE lines (middleware.env) into the environment; a value
    already in the environment wins, so a settings.json `env` can override."""
    env = os.environ if environ is None else environ
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env.setdefault(k.strip(), v.strip())
    return env


class PendingReceipts:
    """The honored receipts between a PreToolUse and its PostToolUse, in a
    JSON file beside the evidence log, keyed by tool_use_id. Small, bounded,
    and only ever read by the next hook process on the same workstation.
    An entry nobody comes back for (Claude Code's own prompt refused the
    call, the session ended) is written to the evidence log as refused
    with REF_HOOK_NOT_RUN once it is older than REAP_SECONDS: the receipt
    was issued and honored, the tool never ran."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def _locked(self):
        """Pre- and PostToolUse hooks of parallel tool calls run as separate
        processes at once; each read-modify-write holds the lock, or one
        loses the other's entry (a call that ran with no evidence row, or an
        honored one resurrected and reaped as never run)."""
        from gargoyle.evidence import locked
        return locked(self.path.with_name(self.path.name + ".lock"))

    def _read(self) -> Dict[str, Any]:
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
            return doc if isinstance(doc, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write(self, doc: Dict[str, Any]) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(doc), encoding="utf-8")
        os.replace(tmp, self.path)

    def put(self, tool_use_id: str, gate: Dict[str, Any], params: Dict[str, Any], now: float) -> None:
        with self._locked():
            doc = self._read()
            doc[tool_use_id] = {"envelope": gate["envelope"], "grant": gate["grant"], "self_issued": gate["self_issued"],
                                "reason": gate["reason"], "ref": gate.get("ref"), "params": params, "at": now}
            for old in list(doc)[:-PENDING_LIMIT]:
                doc.pop(old, None)
            self._write(doc)

    def pop(self, tool_use_id: str) -> Optional[Dict[str, Any]]:
        with self._locked():
            doc = self._read()
            gate = doc.pop(tool_use_id, None)
            if gate is not None:
                self._write(doc)
        return gate

    def reap(self, now: float, max_age: float) -> List[Dict[str, Any]]:
        with self._locked():
            doc = self._read()
            stale = [k for k, v in doc.items() if not isinstance(v.get("at"), (int, float)) or now - v["at"] > max_age]
            out = [doc.pop(k) for k in stale]
            if out:
                self._write(doc)
        return out


def _deny(reason: str, detail: str = "") -> Dict[str, Any]:
    text = "gargoyle: %s" % reason
    if detail:
        text += " (%s)" % detail
    return {"hookSpecificOutput": {"hookEventName": PRE, "permissionDecision": "deny", "permissionDecisionReason": text}}


def _allow(final: bool, note: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"hookSpecificOutput": {"hookEventName": PRE, "additionalContext": note}}
    if final:
        out["hookSpecificOutput"]["permissionDecision"] = "allow"
        out["hookSpecificOutput"]["permissionDecisionReason"] = note
    return out


def _state_from_env(env: Dict[str, str], *, http: Any = None, sleep=None) -> Any:
    """A ServerState from middleware.env's variables, as the MCP gate builds
    its own, with the Claude Code adapter in place of the filesystem one."""
    from gargoyle.mcp_server import (ENV_ADAPTER_SPEC, ENV_AUDIT_LOG, ENV_STATE_PROBE, ServerState,
                                     config_from_env, issuer_client_from_env)
    saved = dict(os.environ)
    os.environ.update(env)
    try:
        config = config_from_env()
        client = issuer_client_from_env()
        if client is not None:
            if http is not None:
                client._http = http
            if sleep is not None:
                client._sleep = sleep
        probe = env.get(ENV_STATE_PROBE) or "claude-code"
        adapter: Any = ClaudeCodeAdapter() if probe == "claude-code" else probe
        state = ServerState(config, issuer_client=client, audit_log=env.get(ENV_AUDIT_LOG) or None,
                            state_probe=adapter, adapter_spec=env.get(ENV_ADAPTER_SPEC) or None)
        state.client = "claude-code"
        return state
    finally:
        os.environ.clear()
        os.environ.update(saved)


def _pending_for(state: Any) -> Optional[PendingReceipts]:
    if state.evidence is None:
        return None
    return PendingReceipts(str(state.evidence.path.with_name(state.evidence.path.stem + PENDING_SUFFIX)))


def decide(event: Dict[str, Any], state: Any, *, final: bool = False, now: Optional[float] = None) -> Dict[str, Any]:
    """One hook event to its stdout JSON. PreToolUse decides and, when the
    call is refused, records it; an honored call is recorded by the
    PostToolUse (or PostToolUseFailure) hook, with the execution receipt
    over the tool's actual result. Without a tool_use_id (an older Claude
    Code) the honored entry is written at once, attested over no output."""
    import time as _time
    from gargoyle.evidence import HONORED, REFUSED
    from gargoyle.mcp_server import _attest, _gate, _record

    now = _time.time() if now is None else now
    kind = event.get("hook_event_name")
    params = {"name": str(event.get("tool_name") or ""),
              "arguments": event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}}
    tool_use_id = str(event.get("tool_use_id") or "")
    session = str(event.get("session_id") or "")
    state.client = "claude-code" + (" session " + session[:12] if session else "")
    pending = _pending_for(state)
    if pending is not None:
        for stale in pending.reap(now, REAP_SECONDS):
            _record(state, REFUSED, dict(stale, reason=REF_HOOK_NOT_RUN), stale["params"])

    if kind == PRE:
        if not params["name"]:
            return _deny(REF_TARGET_NOT_CONFIGURED, "no tool name in the hook event")
        gate = _gate(state, params)
        if not gate["executed"]:
            _record(state, REFUSED, gate, params)
            envelope = gate.get("envelope")
            detail = ("hold %s" % envelope["approval_request_id"]
                      if isinstance(envelope, dict) and envelope.get("approval_request_id") else "")
            if gate.get("why"):
                detail = (detail + "; " if detail else "") + "the approver said: %s" % str(gate["why"])[:500]
            return _deny(str(gate["reason"]), detail)
        if pending is not None and tool_use_id:
            pending.put(tool_use_id, gate, params, now)
        else:
            _record(state, HONORED, gate, params, _attest(state, gate["envelope"], None, params))
        envelope = gate.get("envelope")
        decision_id = envelope.get("decision_id") if isinstance(envelope, dict) else None
        how = ("released by an approver" if (gate.get("grant") is not None or (isinstance(envelope, dict) and envelope.get("requires_approval") is True))
               else "allowed by rule and recorded; no approver saw it")
        note = "gargoyle: %s%s; %s" % (gate["reason"], (", receipt %s" % decision_id) if decision_id else "", how)
        return _allow(final, note)

    if kind == PERMISSION_DENIED:
        # The gate allowed it and Claude Code's own prompt refused it: the
        # receipt was honored, the tool never ran.
        gate = pending.pop(tool_use_id) if (pending is not None and tool_use_id) else None
        if gate is not None:
            _record(state, REFUSED, dict(gate, reason=REF_HOOK_NOT_RUN), gate["params"])
        return {}

    if kind in (POST, POST_FAILURE):
        gate = pending.pop(tool_use_id) if (pending is not None and tool_use_id) else None
        if gate is None:
            return {}
        # The receipt bound the arguments PreToolUse saw; Claude Code may
        # present some tools' input differently afterwards, so the entry is
        # written over what was gated, not what PostToolUse carries.
        params = gate["params"]
        outputs = event.get("tool_response") if kind == POST else {"error": event.get("error")}
        execution = _attest(state, gate["envelope"], outputs, params)
        _record(state, HONORED, gate, params, execution)
        if execution is None:
            return {}
        return {"hookSpecificOutput": {"hookEventName": kind,
                                       "additionalContext": "gargoyle: execution receipt for decision %s" % execution.get("decision_id", "")}}
    return {}


def run_hook(argv, stdin=None, stdout=None, *, environ: Optional[Dict[str, str]] = None) -> int:
    """`gargoyle hook [--env FILE] [--final]`: one event in, one decision out.
    Anything that goes wrong in the hook itself is a deny with the error on
    stderr: a gate that cannot decide does not let the call through."""
    import argparse
    p = argparse.ArgumentParser(prog="gargoyle hook")
    p.add_argument("--env", help="middleware.env from `gargoyle init` (the MCP gate's own settings)")
    p.add_argument("--final", action="store_true", help="an allowed call skips Claude Code's own permission prompt")
    args = p.parse_args(argv)
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    # The real run loads middleware.env into this process's own environment:
    # settings such as REQUESTS_CA_BUNDLE are read by the HTTP library at
    # request time, not at construction.
    env: Dict[str, str] = os.environ if environ is None else environ    # type: ignore[assignment]
    state = None
    try:
        if args.env:
            load_env_file(args.env, env)
        event = json.loads(stdin.read() or "{}")
        if not isinstance(event, dict):
            raise ValueError("hook event is not a JSON object")
        state = _state_from_env(env)
        out = decide(event, state, final=args.final)
    except Exception as exc:
        sys.stderr.write("gargoyle hook: %s: %s\n" % (type(exc).__name__, exc))
        out = _deny(REF_TARGET_NOT_CONFIGURED, "%s: %s" % (type(exc).__name__, str(exc)[:200]))
    stdout.write(json.dumps(out) + "\n")
    stdout.flush()
    # Discovery mode, after the decision is out: a hook has no long-running
    # process, so each run checks whether the daily look for side doors
    # (gargoyle.sidedoors) is due and takes it. Bounded, and never a reason
    # to change the decision already written.
    if state is not None:
        from gargoyle.sidedoors import run_for_state
        run_for_state(state, env=env)
    return 0


if __name__ == "__main__":
    sys.exit(run_hook(sys.argv[1:]))
