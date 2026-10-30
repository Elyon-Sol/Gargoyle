"""MCP middleware: a stdio MCP server that lets a tool call through only when
it carries a valid receipt.

JSON-RPC 2.0 over stdio. Put it in front of any stdio MCP server:

    python -m gargoyle.mcp_server -- python -m some_vendor.mcp_server

The client talks to Gargoyle; Gargoyle talks to the upstream. initialize,
tools/list and every other method are relayed as-is. tools/call is gated:
the receipt rides in params._meta["gargoyle/envelope"] (and a grant, for a
flagged call, in params._meta["gargoyle/grant"]); the server rebuilds the
call from the actual tool name and arguments plus the principal it serves
and asks a gargoyle.consumer.Consumer (signature, policy pin, binding,
expiry, grant, the single-use claims). Only a call the consumer honored is
forwarded, with the gargoyle keys stripped from its _meta; a refused call
is answered here with isError and never reaches the upstream. Without an
upstream command the server runs a built-in demo executor that records
honored calls instead of forwarding them.

The principal: a stdio server has exactly one client, the process that
spawned it, and that client's identity is established by whoever wired the
server up, not by anything on the wire. GARGOYLE_MCP_PRINCIPAL names it. A
receipt issued to any other principal is refused (REF_VERIFY_PRINCIPAL_MISMATCH),
so a receipt obtained by one agent cannot be spent through another agent's
server.

Self-issue mode, for clients that cannot attach a receipt themselves (an
IDE, a desktop app): with GARGOYLE_MCP_ISSUER_URL and
GARGOYLE_MCP_CLIENT_TOKEN set, a tools/call that carries no receipt is
taken to the issuing service (gargoyle.issuer_service) under the client
token, whose subject must be this server's principal. A refusal there is
answered here. A flagged receipt is held until the human's grant appears
at the issuer (polled every GARGOYLE_MCP_POLL_SECONDS, up to
GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS; default 2 and 300), then checked
and single-used exactly as a receipt the client brought. Verification does
not change: the issuer's key is still pinned here, so a compromised path
to the issuer yields nothing this server would honor.

Run as a stdio MCP server:  python3 -m gargoyle.mcp_server
"""

import json
import subprocess
import os
import sys
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from gargoyle.consumer import REF_TARGET_NOT_CONFIGURED, Consumer
from gargoyle.evidence import HONORED, REFUSED, EvidenceLog, TOOL_ERROR, UPSTREAM_ERROR, UPSTREAM_UNAVAILABLE
from gargoyle.envelope import valid_principal
from gargoyle.policy import valid_pin
from gargoyle.verifier import REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED
from gargoyle.replay_cache import InMemoryReplayCache, ReplayCache, SqliteReplayCache

# MCP protocol version this server speaks (a real MCP revision string).
PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "gargoyle", "version": "0.1.0"}

# The _meta key the receipt rides under in tools/call params (the MCP
# counterpart of the X-Gargoyle-Envelope header an issuer hands out over HTTP).
ENVELOPE_META_KEY = "gargoyle/envelope"
GRANT_META_KEY = "gargoyle/grant"
EXECUTED_META_KEY = "gargoyle/executed"
REASON_META_KEY = "gargoyle/reason"
EXECUTION_META_KEY = "gargoyle/execution"   # the signed execution receipt, when configured
# In self-issue mode the client never saw the receipt or the grant; they are
# returned with the honored result so the caller holds the whole audit chain.
RECEIPT_META_KEY = "gargoyle/receipt"
USED_GRANT_META_KEY = "gargoyle/used_grant"

# JSON-RPC error codes (subset).
JSONRPC_PARSE_ERROR = -32700
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_NOT_INITIALIZED = -32002

# Example tools advertised by tools/list. tools/call does not restrict to this
# set: the receipt's binding to the tool name is the control, so a receipt for
# tool A presented for tool B fails the binding check whether or not either is
# listed.
ADVERTISED_TOOLS = [
    {"name": "transfer_funds", "description": "Move funds between accounts (gated)."},
    {"name": "delete_database", "description": "Delete a database (gated)."},
]

# Out-of-band configuration, read from the environment (see config_from_env).
ENV_GATE_KEY_ID = "GARGOYLE_MCP_GATE_KEY_ID"
ENV_GATE_PUBLIC_KEY_HEX = "GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX"
ENV_TARGET_ID = "GARGOYLE_MCP_TARGET_ID"
ENV_RECORD_PATH = "GARGOYLE_MCP_RECORD_PATH"
ENV_RECORD_URL = "GARGOYLE_MCP_RECORD_URL"     # follow the issuer's signed record instead of a file (SPEC 9)
ENV_PRINCIPAL = "GARGOYLE_MCP_PRINCIPAL"
ENV_APPROVER_KEY_ID = "GARGOYLE_MCP_APPROVER_KEY_ID"
ENV_APPROVER_PUBLIC_KEY_HEX = "GARGOYLE_MCP_APPROVER_PUBLIC_KEY_HEX"
ENV_EXECUTOR_KEY_ID = "GARGOYLE_MCP_EXECUTOR_KEY_ID"
ENV_EXECUTOR_KEY_HEX = "GARGOYLE_MCP_EXECUTOR_KEY_HEX"
ENV_ISSUER_URL = "GARGOYLE_MCP_ISSUER_URL"
ENV_CLIENT_TOKEN = "GARGOYLE_MCP_CLIENT_TOKEN"
ENV_APPROVAL_TIMEOUT = "GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS"
ENV_POLL_SECONDS = "GARGOYLE_MCP_POLL_SECONDS"
ENV_AUDIT_LOG = "GARGOYLE_MCP_AUDIT_LOG"
ENV_STATE_PROBE = "GARGOYLE_MCP_STATE_PROBE"
ENV_STATE_ROOT = "GARGOYLE_MCP_STATE_ROOT"     # the upstream's root: relative path arguments are resolved against it (default: the path in a mcp://filesystem/ target id)
ENV_ADAPTER_SPEC = "GARGOYLE_MCP_ADAPTER_SPEC"    # with GARGOYLE_MCP_STATE_PROBE=graph: the tool mapping JSON
ENV_INSTRUCTIONS = "GARGOYLE_MCP_INSTRUCTIONS"   # override the standing instructions the gate gives the model (default: gate_instructions())
ENV_SNAPSHOT_DIR = "GARGOYLE_MCP_SNAPSHOT_DIR"   # where pre-change snapshots live (default: snapshots/ beside the audit log); "none" disables undo   # "filesystem" (default): bind held calls to the target file's state; "none" to disable
REF_TARGET_LOGIN_REQUIRED = "REF_TARGET_LOGIN_REQUIRED"   # Entra login mode and no usable token: run `gargoyle login`   # the evidence log: one hash-chained JSON line per decision, honored or refused

# Self-issue refusals.
REF_TARGET_ISSUER_UNAVAILABLE = "REF_TARGET_ISSUER_UNAVAILABLE"
REF_TARGET_APPROVAL_TIMEOUT = "REF_TARGET_APPROVAL_TIMEOUT"
REF_TARGET_APPROVAL_DECLINED = "REF_TARGET_APPROVAL_DECLINED"
REF_TARGET_GATE_FILES = "REF_TARGET_GATE_FILES"       # the call would touch the gate's own folder (config, keys, evidence, snapshots)


class IssuerClient:
    """The middleware's view of the issuing service. `http` is any object
    with requests-style get/post (a requests.Session by default; a test
    passes a TestClient). Every failure is a refusal reason, never an
    exception out of the gate."""

    def __init__(self, url: str, token: Any, *, http: Any = None, approval_timeout: float = 300.0,
                 poll_seconds: float = 2.0, request_timeout: float = 10.0, sleep=time.sleep) -> None:
        """`token` is the bearer token string, or an object with a token()
        method that returns the current one (gargoyle.entra_login.EntraTokenSource)."""
        import requests
        self.url = url.rstrip("/")
        self._token = token
        self._http = http if http is not None else requests.Session()
        self.approval_timeout = approval_timeout
        self.poll_seconds = poll_seconds
        self.request_timeout = request_timeout
        self._sleep = sleep

    def _headers(self) -> Dict[str, str]:
        token = self._token.token() if hasattr(self._token, "token") else self._token
        return {"Authorization": "Bearer " + token}

    def _post(self, path: str, body: Dict[str, Any]) -> Any:
        return self._http.post(self.url + path, json=body, headers=self._headers(), timeout=self.request_timeout)

    def _get(self, path: str) -> Any:
        return self._http.get(self.url + path, headers=self._headers(), timeout=self.request_timeout)

    def issue(self, target_url: str, tool: str, args: Any, state: Optional[Dict[str, Any]] = None,
              plan_id: Optional[str] = None) -> Dict[str, Any]:
        """{"envelope": ...} or {"envelope": None, "reason": ...}. The cause of
        an unavailable issuer (TLS, DNS, a refused connection) goes to stderr,
        where an MCP client's server log shows it; the refusal code stays
        generic."""
        try:
            body_out: Dict[str, Any] = {"target_url": target_url, "tool": tool, "args": args}
            if state is not None:
                body_out["state"] = state
            if plan_id is not None:
                body_out["plan_id"] = plan_id
            r = self._post("/issue", body_out)
        except Exception as exc:
            if type(exc).__name__ == "LoginRequired":
                sys.stderr.write("gargoyle: %s\n" % exc)
                return {"envelope": None, "reason": REF_TARGET_LOGIN_REQUIRED}
            sys.stderr.write("gargoyle: issuer unreachable at %s: %s: %s\n" % (self.url, type(exc).__name__, str(exc)[:300]))
            return {"envelope": None, "reason": REF_TARGET_ISSUER_UNAVAILABLE}
        try:
            if r.status_code != 200:
                detail = r.json().get("detail", {}) if r.headers.get("content-type", "").startswith("application/json") else {}
                sys.stderr.write("gargoyle: issuer answered %s: %s\n" % (r.status_code, r.text[:300]))
                return {"envelope": None, "reason": detail.get("reason", REF_TARGET_ISSUER_UNAVAILABLE)}
            body = r.json()
        except Exception as exc:
            sys.stderr.write("gargoyle: issuer unreachable at %s: %s: %s\n" % (self.url, type(exc).__name__, str(exc)[:300]))
            return {"envelope": None, "reason": REF_TARGET_ISSUER_UNAVAILABLE}
        if not body.get("issued"):
            return {"envelope": None, "reason": body.get("reason") or REF_TARGET_ISSUER_UNAVAILABLE}
        return {"envelope": body.get("envelope"), "reason": None}

    def plan(self, target_url: str, steps: List[Dict[str, Any]], note: str) -> Dict[str, Any]:
        """Ask for a scoped grant: {"plan": signed plan, "held": bool} or
        {"plan": None, "reason": ...}."""
        try:
            r = self._post("/plans", {"target_url": target_url, "steps": steps, "note": note})
            body = r.json() if r.status_code == 200 else {}
        except Exception as exc:
            sys.stderr.write("gargoyle: issuer unreachable for a plan: %s\n" % exc)
            return {"plan": None, "reason": REF_TARGET_ISSUER_UNAVAILABLE}
        if not body.get("issued"):
            return {"plan": None, "reason": body.get("reason") or REF_TARGET_ISSUER_UNAVAILABLE}
        return {"plan": body["plan"], "held": bool(body.get("held")), "reason": None}

    def approver_keys(self) -> Dict[str, Any]:
        """The issuer's enrolled approvers as {upn: public key}; {} when the
        issuer cannot be reached (the static map then stands alone)."""
        from gargoyle.approvers import keys_from_hex
        try:
            r = self._get("/approvers")
            return keys_from_hex(r.json().get("approvers", {})) if r.status_code == 200 else {}
        except Exception:
            return {}

    def decline(self, approval_request_id: str) -> bool:
        """Withdraw a hold this gate asked for (the hold's own principal may):
        when the gate stops waiting, the card must not stay approvable."""
        try:
            r = self._post("/decline", {"approval_request_id": approval_request_id})
            return r.status_code == 200 and bool(r.json().get("declined"))
        except Exception:
            return False

    def wait_for_grant(self, approval_request_id: str) -> Dict[str, Any]:
        """Poll until the hold has its grant (or, for a receipt that needs
        several approvers, the whole set), a human declined it, the hold
        disappears, or the timeout passes: {"grant": <grant>|[<grant>...]|None,
        "reason": None | REF_TARGET_APPROVAL_DECLINED | REF_TARGET_APPROVAL_TIMEOUT}."""
        deadline = time.monotonic() + self.approval_timeout
        while True:
            try:
                r = self._get("/grants/" + approval_request_id)
                body = r.json() if r.status_code == 200 else {}
            except Exception:
                body = {}
            if isinstance(body.get("grant"), dict):
                return {"grant": body["grant"], "reason": None}
            if isinstance(body.get("grants"), list) and body["grants"]:
                return {"grant": body["grants"], "reason": None}
            if body.get("declined") is True:
                return {"grant": None, "reason": REF_TARGET_APPROVAL_DECLINED}
            if body and not body.get("pending", True):
                return {"grant": None, "reason": REF_TARGET_APPROVAL_TIMEOUT}
            if time.monotonic() >= deadline:
                return {"grant": None, "reason": REF_TARGET_APPROVAL_TIMEOUT}
            self._sleep(self.poll_seconds)



JSONRPC_INTERNAL_ERROR = -32603


class StdioUpstream:
    """The MCP server this one fronts, spawned as a child on its own stdio.
    send() writes one message and, for a request, reads until the matching
    response, dropping anything else the upstream emits meanwhile (its
    notifications are not relayed). One message in flight at a time."""

    def __init__(self, command: List[str]) -> None:
        if not command:
            raise ValueError("upstream command must not be empty")
        self.command = list(command)
        # MCP stdio is UTF-8 by specification. Never the locale codepage:
        # on Windows that is cp1252, which turns a UTF-8 em dash into three
        # characters and an undefined byte into a lone surrogate.
        self._proc = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            encoding="utf-8", errors="replace", bufsize=1,
        )
        self._lock = threading.Lock()

    def send(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._proc.stdin.write(json.dumps(msg) + "\n")
            self._proc.stdin.flush()
            if "id" not in msg:
                return None
            while True:
                line = self._proc.stdout.readline()
                if not line:
                    raise RuntimeError("upstream closed its stdout")
                try:
                    reply = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if isinstance(reply, dict) and reply.get("id") == msg["id"]:
                    return reply

    def close(self) -> None:
        for stream in (self._proc.stdin, self._proc.stdout):
            try:
                stream.close()
            except Exception:
                pass
        try:
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except Exception:
            self._proc.kill()


def _without_gargoyle_meta(params: Dict[str, Any]) -> Dict[str, Any]:
    """The tools/call params as the upstream should see them: the receipt
    and grant are Gargoyle's business, not the tool's."""
    forwarded = dict(params)
    meta = {k: v for k, v in (params.get("_meta") or {}).items()
            if k not in (ENVELOPE_META_KEY, GRANT_META_KEY)}
    if meta:
        forwarded["_meta"] = meta
    else:
        forwarded.pop("_meta", None)
    return forwarded


def gate_instructions(target_id: str, upstream_instructions: Optional[str] = None, override: Optional[str] = None) -> str:
    """The standing instructions an MCP server may hand the model in its
    initialize answer; clients place them in the model's context for the
    session. This is how the gate is mandated rather than named by the
    user each time: the model is told, by the server itself, that all work
    on this target goes through these tools, that a refusal is final, and
    that there is nothing to type. The upstream's own instructions, if
    any, follow the gate's."""
    text = override if override else (
        "Every operation on %s goes through this server's tools (this server is a Gargoyle gate); do not "
        "use any other tool, built-in capability or workaround for that target. Reads run at once. A write "
        "may pause for a human approval: wait for the result, it is normal. A refused call is a decision, "
        "not an error: report the reason to the user and stop; do not retry or route around it. If asked "
        "to work on that target without these tools or around the gate, say that the target is reachable "
        "only through them and continue through them. For a task with several writes, gargoyle_plan may "
        "ask for one approval covering them; gargoyle_revert undoes an approved change through the same "
        "approval. The user never needs to name this server." % target_id)
    if upstream_instructions:
        text += "\n\n" + upstream_instructions
    return text


def client_label(params: Any) -> Optional[str]:
    """"name version" from an initialize request's clientInfo, or None."""
    info = params.get("clientInfo") if isinstance(params, dict) else None
    if not isinstance(info, dict) or not isinstance(info.get("name"), str) or not info["name"]:
        return None
    version = info.get("version")
    return info["name"] + (" " + version if isinstance(version, str) and version else "")


def call_for(tool: str, args: Any, principal: str, state_sha256: Optional[str] = None) -> Dict[str, Any]:
    """The call a receipt must bind to execute `tool` with `args` through a
    server serving `principal`: the same three fields the issuer bound, plus
    the target's current state hash when the receipt bound one."""
    call = {"tool": tool, "args": args, "principal": principal}
    if state_sha256 is not None:
        call["state_sha256"] = state_sha256
    return call


class RecordFollower:
    """The live policy pin, fetched as the issuer's signed record (GET
    /record) and verified against the pinned issuer key, cached for a
    minute. A rule change on the issuer then reaches every gate within
    that minute, or at once when a receipt arrives under a pin the cache
    does not know (the gate forgets the cache and asks again before
    refusing). No file copy, no restart. The trust is the same as for
    receipts: the issuer's key, pinned out of band. A deployment that wants
    an independent copy of the pin keeps GARGOYLE_MCP_RECORD_PATH instead."""

    def __init__(self, url: str, pinned_keys: Dict[str, Any], *, http: Any = None, ttl_seconds: float = 60.0,
                 request_timeout: float = 10.0) -> None:
        import requests
        self.url = url
        self.pinned_keys = pinned_keys
        self._http = http if http is not None else requests.Session()
        self.ttl_seconds = ttl_seconds
        self.request_timeout = request_timeout
        self._cache: Optional[tuple] = None
        self.fetches = 0

    def forget(self) -> None:
        self._cache = None

    def __call__(self, last_seen_serial: Optional[int]) -> Dict[str, Any]:
        from gargoyle.published_record_source import load_signed_record_from_bytes
        from gargoyle.verifier import REF_VERIFY_PUBLISHED_RECORD_INVALID
        cached = self._cache
        if cached is not None and time.monotonic() - cached[0] < self.ttl_seconds:
            return cached[1]
        self.fetches += 1
        try:
            r = self._http.get(self.url, timeout=self.request_timeout)
            if r.status_code != 200:
                res = {"record": None, "reason": REF_VERIFY_PUBLISHED_RECORD_INVALID}
            else:
                res = load_signed_record_from_bytes(r.content, self.pinned_keys, last_seen_serial=last_seen_serial)
        except Exception:
            res = {"record": None, "reason": REF_VERIFY_PUBLISHED_RECORD_INVALID}
        if res.get("record") is not None:
            self._cache = (time.monotonic(), res)      # a failure is not cached: the next check asks again
        return res


class ServerState:
    """The executor's out-of-band trust material (issuer keys, the policy record,
    target id, the principal it serves) as a Consumer, and the list of tool
    calls actually executed. `config` None, or a config without a usable
    principal, means unconfigured: every tools/call is refused with
    REF_TARGET_NOT_CONFIGURED."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]],
        replay_cache: Optional[ReplayCache] = None,
        upstream: Optional[StdioUpstream] = None,
        issuer_client: Optional[IssuerClient] = None,
        audit_log: Optional[str] = None,
        state_probe: Any = "filesystem",
        snapshot_dir: Optional[str] = None,
        adapter_spec: Optional[str] = None,
        state_root: Optional[str] = None,
    ) -> None:
        from gargoyle.adapters import adapter_from_name
        from gargoyle.revert import SnapshotStore
        self.config = config
        # Relative path arguments are resolved against the upstream's root
        # (gargoyle.state.resolve_path_args). Configured, or taken from a
        # filesystem target id, which init writes as mcp://filesystem/<root>.
        self.state_root: Optional[str] = state_root or _root_from_target((config or {}).get("target_id"))
        # The adapter describes, explains and undoes what a tool changes
        # (gargoyle.adapters): files on this host by default, a Graph server by spec.
        self.adapter = adapter_from_name(state_probe, upstream, adapter_spec)
        if snapshot_dir is None and audit_log:
            snapshot_dir = str(Path(audit_log).parent / "snapshots")
        self.snapshots: Optional[SnapshotStore] = (SnapshotStore(snapshot_dir)
                                                   if snapshot_dir and snapshot_dir != "none" and self.adapter is not None else None)
        self.upstream = upstream
        self.issuer_client = issuer_client
        self.evidence: Optional[EvidenceLog] = EvidenceLog(audit_log) if audit_log else None
        # The gate's own folder (config, keys, evidence, snapshots, replay
        # claims) is never a target: a call whose path arguments reach into
        # it is refused before any receipt is asked for.
        self.gate_dir: Optional[str] = None
        if audit_log:
            from gargoyle.globs import normalize_path
            self.gate_dir = normalize_path(str(Path(audit_log).resolve().parent)).rstrip("/")
        if replay_cache is None and audit_log:
            # Single use has to outlive this process: the claims sit in a
            # SQLite file beside the evidence log (audit.replay.sqlite), so a
            # restarted gate, or a second one on the same log, refuses a
            # receipt that was already honored (second review, finding 4).
            replay_cache = SqliteReplayCache(str(Path(audit_log).with_name(Path(audit_log).stem + ".replay.sqlite")))
        self.consumer: Optional[Consumer] = None
        self.record_follower: Optional[RecordFollower] = None
        if config is not None and valid_principal(config.get("principal")):
            if config.get("record_url"):
                self.record_follower = RecordFollower(config["record_url"], config["pinned_public_keys"],
                                                      http=getattr(issuer_client, "_http", None))
            self.consumer = Consumer(
                target_id=config["target_id"],
                pinned_public_keys=config["pinned_public_keys"],
                record=None if self.record_follower is not None else config["record"],
                record_source=self.record_follower,
                replay_cache=replay_cache,
                approver_public_keys=config.get("approver_public_keys"),
                approver_key_source=(issuer_client.approver_keys if issuer_client is not None else None),
                executor_signing_key=config.get("executor_signing_key"),
                executor_key_id=config.get("executor_key_id"),
            )
        self.executed: List[Dict[str, Any]] = []
        self.plans: List[Dict[str, Any]] = []     # approved scoped grants: {"plan", "grants", "consumed": set()}
        import os as _os
        self.instructions: Optional[str] = _os.environ.get(ENV_INSTRUCTIONS) or None
        self.initialized = False
        self.client: Optional[str] = None     # "name version" from the MCP initialize handshake


def gate_tool_call(state: ServerState, params: Dict[str, Any]) -> (bool, str):
    """Decide and, if honored, execute one tools/call. Returns (executed,
    reason). The side effect (appending to state.executed) happens only after
    the consumer honored the receipt, which includes its single-use claim."""
    g = _gate(state, params)
    return g["executed"], g["reason"]


def _gate(state: ServerState, params: Dict[str, Any]) -> Dict[str, Any]:
    """{"executed", "reason", "envelope", "grant", "self_issued"}: the
    receipt and grant that were honored, whether the client brought them or
    this server obtained them."""
    gate_ref: Dict[str, Any] = {"ref": None}

    def refused(reason, envelope=None):
        # A refusal keeps the receipt when there was one (a hold the human
        # declined or let lapse), so the evidence log can show what was asked.
        return {"executed": False, "reason": reason, "envelope": envelope, "grant": None, "self_issued": False, "ref": gate_ref["ref"]}
    if state.consumer is None:
        return refused(REF_TARGET_NOT_CONFIGURED)

    name = params.get("name")
    args = params.get("arguments", {})
    meta = params.get("_meta") or {}
    envelope = meta.get(ENVELOPE_META_KEY)
    grant = meta.get(GRANT_META_KEY)
    self_issued = False
    from gargoyle.adapters import FilesystemAdapter
    if isinstance(state.adapter, FilesystemAdapter):
        # One path for everyone: the rules, the gate-folder check, the state
        # probe and the upstream must all look at the same file.
        from gargoyle.state import resolve_path_args
        args, why = resolve_path_args(name, args, state.state_root)
        if why is not None:
            return refused(why)
        params["arguments"] = args
    if state.gate_dir is not None and _touches_gate_files(args, state.gate_dir):
        return refused(REF_TARGET_GATE_FILES)

    if envelope is None and state.issuer_client is not None:
        # Self-issue: ask the issuing service, and wait for the human if it
        # flagged the call. Nothing below trusts the answer: the receipt is
        # verified against the pinned issuer key like any other. The
        # target's current state goes with the request (gargoyle.state), so
        # a hold is approved against it and bound to it.
        probed = state.adapter.probe(name, args) if state.adapter is not None else None
        if probed is not None:
            gate_ref["ref"] = probed[0].get("ref")
        # An approved plan may already cover this call; say so, and the
        # issuer opens no hold for it.
        release = _plan_release_for(state, name, args)
        res = state.issuer_client.issue(state.config["target_id"], name, args, state=probed[0] if probed else None,
                                        plan_id=release["plan"]["plan_id"] if release else None)
        if res["envelope"] is None:
            return refused(res["reason"])
        envelope, self_issued = res["envelope"], True
        if isinstance(envelope, dict) and envelope.get("requires_approval") is True and grant is None:
            # A scoped grant the human already signed may cover this call;
            # otherwise wait for a card of its own.
            if release is None:
                arid = str(envelope.get("approval_request_id"))
                waited = state.issuer_client.wait_for_grant(arid)
                if waited["grant"] is None:
                    if waited["reason"] == REF_TARGET_APPROVAL_TIMEOUT:
                        # Nobody is waiting for this release any more: take
                        # the card down, or an approval minutes later would
                        # read as a change that happened.
                        state.issuer_client.decline(arid)
                    return refused(waited["reason"], envelope)
                grant = waited["grant"]
            else:
                grant = release

    # A state-bound receipt is checked against the state as it is now, after
    # any wait for approval: if the target moved, the call does not run.
    live_state, now_probe = None, None
    if isinstance(envelope, dict) and isinstance(envelope.get("request_context"), dict) \
            and "state_sha256" in envelope["request_context"] and state.adapter is not None:
        from gargoyle.state import state_sha256 as _state_hash
        now_probe = state.adapter.probe(name, args)
        live_state = _state_hash(now_probe[0]) if now_probe is not None else None
    from gargoyle.plans import is_plan_release
    if is_plan_release(grant):
        verdict = state.consumer.check(envelope, call_for(name, args, state.config["principal"], live_state),
                                       plan_release=grant)
    else:
        verdict = state.consumer.check(envelope, call_for(name, args, state.config["principal"], live_state),
                                       grant=grant)
    if (not verdict.honored and verdict.reason == REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED
            and state.record_follower is not None):
        # The receipt names a pin the cached record does not: the rules may
        # have just changed on the issuer. Ask once more before refusing.
        state.record_follower.forget()
        call = call_for(name, args, state.config["principal"], live_state)
        verdict = (state.consumer.check(envelope, call, plan_release=grant) if is_plan_release(grant)
                   else state.consumer.check(envelope, call, grant=grant))
    if not verdict.honored:
        return refused(verdict.reason, envelope)
    if is_plan_release(grant):
        for active in state.plans:
            if active["plan"]["plan_id"] == grant["plan"]["plan_id"]:
                active["consumed"].add(grant["step"])

    # Undo material: for a held, state-bound call, keep the target as it is
    # right now (the state the receipt bound and the check just confirmed).
    if (state.snapshots is not None and isinstance(envelope, dict) and envelope.get("requires_approval")
            and now_probe is not None and isinstance(envelope.get("decision_id"), str)):
        try:
            state.snapshots.put(envelope["decision_id"], now_probe[0], now_probe[1], name, args)
        except Exception as exc:
            sys.stderr.write("gargoyle: snapshot failed: %s\n" % exc)

    if now_probe is not None:
        gate_ref["ref"] = now_probe[0].get("ref")
    state.executed.append({"tool": name, "args": args})  # THE side effect
    return {"executed": True, "reason": verdict.reason, "envelope": envelope, "grant": grant,
            "self_issued": self_issued, "ref": gate_ref["ref"]}


_GATE_FILE_GLOBS = ("*.env", "*.json", "*.jsonl", "*.jsonl.lock", "*.sqlite", "*.sqlite-*", "snapshots")


def _root_from_target(target_id: Any) -> Optional[str]:
    """mcp://filesystem/<absolute root> -> <absolute root>; else None."""
    prefix = "mcp://filesystem/"
    if isinstance(target_id, str) and target_id.startswith(prefix):
        from gargoyle.state import is_absolute_path
        rest = target_id[len(prefix):]
        if rest and is_absolute_path(rest):
            return rest
    return None


def _touches_gate_files(args: Any, gate_dir: str) -> bool:
    """Does any path-like string argument (at the top level or in a list)
    name the gate's own folder, one of its files (env, json, the evidence
    log and its lock, the replay claims) or anything under its snapshots?
    Deeper subfolders are left alone: a deployment folder may hold the
    project it serves."""
    import fnmatch
    from gargoyle.globs import is_pathlike, normalize_path
    values = []
    if isinstance(args, dict):
        for v in args.values():
            if isinstance(v, str):
                values.append(v)
            elif isinstance(v, list):
                values.extend(x for x in v if isinstance(x, str))
    for v in values:
        if not is_pathlike(v):
            continue
        n = normalize_path(v)
        if n == gate_dir:
            return True
        if n.startswith(gate_dir + "/"):
            first = n[len(gate_dir) + 1:].split("/")[0]
            direct = "/" not in n[len(gate_dir) + 1:]
            if first == "snapshots" or (direct and any(fnmatch.fnmatchcase(first, g) for g in _GATE_FILE_GLOBS)):
                return True
    return False


def _plan_release_for(state: ServerState, tool: str, args: Any) -> Optional[Dict[str, Any]]:
    """The release record for the first active plan with an unconsumed step
    matching this call, or None."""
    from datetime import datetime, timezone
    from gargoyle.plans import match_step
    now = datetime.now(timezone.utc)
    for active in state.plans:
        plan = active["plan"]
        try:
            if datetime.fromisoformat(plan["not_after"]) <= now:
                continue
        except (ValueError, TypeError):
            continue
        i = match_step(plan, tool, args, active["consumed"])
        if i is not None:
            return {"plan": plan, "grants": active["grants"], "step": i, "args": args}
    return None


PLAN_TOOL = "gargoyle_plan"
PLAN_TOOL_DEF = {
    "name": PLAN_TOOL,
    "description": ("Ask the approver for one approval covering a bounded plan of changes instead of one card per "
                    "change. steps: a list of {tool, args} (exact) or {tool, match: {argument: glob}}; note: what the "
                    "plan is for, shown to the approver. Each later call matching an unused step runs without its "
                    "own card, until the plan expires. Tools the policy keeps individual are refused here."),
    "inputSchema": {"type": "object", "required": ["steps"],
                    "properties": {"steps": {"type": "array"}, "note": {"type": "string"}}},
}


def _handle_plan(state: ServerState, params: Dict[str, Any]) -> Dict[str, Any]:
    """gargoyle_plan: obtain the signed plan, wait for the human's grant,
    then keep it active for matching calls."""
    if state.issuer_client is None or state.consumer is None:
        return {"content": [{"type": "text", "text": "refused: plans need self-issue mode"}], "isError": True,
                "_meta": {EXECUTED_META_KEY: False, REASON_META_KEY: REF_TARGET_NOT_CONFIGURED}}
    args = params.get("arguments") or {}
    res = state.issuer_client.plan(state.config["target_id"], args.get("steps") or [], str(args.get("note") or ""))
    if res["plan"] is None:
        return {"content": [{"type": "text", "text": "refused: " + str(res["reason"])}], "isError": True,
                "_meta": {EXECUTED_META_KEY: False, REASON_META_KEY: res["reason"]}}
    plan, grants = res["plan"], []
    if res["held"]:
        waited = state.issuer_client.wait_for_grant(plan["approval_request_id"])
        if waited["grant"] is None:
            return {"content": [{"type": "text", "text": "refused: " + str(waited["reason"])}], "isError": True,
                    "_meta": {EXECUTED_META_KEY: False, REASON_META_KEY: waited["reason"]}}
        grants = waited["grant"] if isinstance(waited["grant"], list) else [waited["grant"]]
    state.plans.append({"plan": plan, "grants": grants, "consumed": set()})
    text = "plan %s approved: %d step(s) until %s" % (plan["plan_id"][:8], len(plan["steps"]), plan["not_after"])
    return {"content": [{"type": "text", "text": text}], "isError": False,
            "_meta": {EXECUTED_META_KEY: False, REASON_META_KEY: "PLAN_APPROVED", "gargoyle/plan": plan}}


def _audit_meta(state: ServerState, gate: Dict[str, Any], outputs: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    """What an honored result's _meta carries beyond executed/reason: the
    execution receipt when this server attests, and, when the receipt was
    self-issued, the receipt and grant the client never saw. The same chain
    goes into the evidence log when one is configured, so a client that
    discards _meta still leaves evidence."""
    meta: Dict[str, Any] = {}
    execution = _attest(state, gate["envelope"], outputs, params)
    if execution is not None:
        meta[EXECUTION_META_KEY] = execution
    if gate["self_issued"]:
        meta[RECEIPT_META_KEY] = gate["envelope"]
        if gate["grant"] is not None:
            meta[USED_GRANT_META_KEY] = gate["grant"]
    _record(state, HONORED, gate, params, execution)
    return meta


def _record(state: ServerState, kind: str, gate: Dict[str, Any], params: Dict[str, Any],
            execution: Optional[Dict[str, Any]] = None) -> None:
    """One evidence-log entry for a decision, honored or refused. The log
    is evidence, not admission: a log that cannot be written is reported on
    stderr and the call's outcome stands."""
    if state.evidence is None:
        return
    principal = (state.config or {}).get("principal") or ""
    try:
        state.evidence.append(kind, str(params.get("name")), params.get("arguments", {}), principal,
                              gate["reason"], receipt=gate["envelope"], grant=gate["grant"], execution=execution,
                              client=state.client, ref=gate.get("ref"))
    except (OSError, ValueError) as exc:
        sys.stderr.write("gargoyle: evidence log unwritable: %s\n" % exc)


def _attest(state: ServerState, envelope: Optional[Dict[str, Any]], outputs: Any,
            params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """The signed execution receipt for an honored call, or None when this
    server has no executor key. For a state-bound call the target is
    probed again after the run, so the receipt says what it changed."""
    if state.consumer is None or not state.consumer.attests or envelope is None:
        return None
    post, post_data = None, None
    if params is not None and state.adapter is not None and "state_sha256" in (envelope.get("request_context") or {}):
        from gargoyle.state import state_sha256 as _state_hash
        probed = state.adapter.probe(str(params.get("name")), params.get("arguments", {}))
        if probed is not None:
            post, post_data = _state_hash(probed[0]), probed[1]
    if post is not None and state.snapshots is not None and isinstance(envelope.get("decision_id"), str):
        try:
            state.snapshots.record_post(envelope["decision_id"], post, post_data)
        except Exception:
            pass
    return state.consumer.attest(envelope, outputs, post_state_sha256=post)


def _success(msg_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def handle_message(state: ServerState, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Dispatch one JSON-RPC message. Returns a response dict, or None for a notification (a
    message with no `id`, e.g. notifications/initialized)."""
    method = msg.get("method")
    msg_id = msg.get("id")
    is_notification = "id" not in msg
    params = msg.get("params") or {}

    if state.upstream is not None and method in ("initialize", "tools/list"):
        if method == "initialize":
            state.client = client_label(params)
        reply = _relay(state, msg)
        if method == "initialize" and isinstance(reply, dict) and isinstance(reply.get("result"), dict) and state.config:
            reply["result"]["instructions"] = gate_instructions(state.config.get("target_id", "the gated target"),
                                                                reply["result"].get("instructions"), state.instructions)
        if method == "tools/list" and state.snapshots is not None and isinstance(reply, dict) \
                and isinstance(reply.get("result"), dict) and isinstance(reply["result"].get("tools"), list):
            from gargoyle.revert import REVERT_TOOL_DEF
            reply["result"]["tools"] = list(reply["result"]["tools"]) + [REVERT_TOOL_DEF]
        if method == "tools/list" and state.issuer_client is not None and isinstance(reply, dict) \
                and isinstance(reply.get("result"), dict) and isinstance(reply["result"].get("tools"), list):
            reply["result"]["tools"] = list(reply["result"]["tools"]) + [PLAN_TOOL_DEF]
        return reply

    if method == "initialize":
        state.client = client_label(params)
        # The handshake completes when the client sends notifications/initialized;
        # tools are served only after that.
        return _success(
            msg_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
                "instructions": gate_instructions((state.config or {}).get("target_id", "the gated target"), None, state.instructions),
            },
        )

    if method == "notifications/initialized":
        state.initialized = True
        if state.upstream is not None:
            try:
                state.upstream.send(msg)
            except Exception:
                pass
        return None

    if method == "ping":
        return _success(msg_id, {})

    if method == "gargoyle/executed_count":
        # Read-only observability: how many tool calls actually fired. Not part
        # of admission; it discloses only a count, so a test driving the stdio
        # server can confirm exactly-once across the process boundary.
        return _success(msg_id, {"count": len(state.executed)})

    if method in ("tools/list", "tools/call") and not state.initialized:
        if is_notification:
            return None
        return _error(msg_id, JSONRPC_NOT_INITIALIZED, "server not initialized")

    if method == "tools/list":
        from gargoyle.revert import REVERT_TOOL_DEF
        return _success(msg_id, {"tools": ADVERTISED_TOOLS + ([REVERT_TOOL_DEF] if state.snapshots is not None else [])
                                 + ([PLAN_TOOL_DEF] if state.issuer_client is not None else [])})

    if method == "tools/call":
        from gargoyle.revert import REVERT_TOOL, plan_revert
        if params.get("name") == PLAN_TOOL:
            return _success(msg_id, _handle_plan(state, params))
        if params.get("name") == REVERT_TOOL:
            # An undo is a write the middleware composes from its snapshot; it
            # then goes through the gate exactly as the assistant's own writes.
            if state.snapshots is None:
                return _success(msg_id, {"content": [{"type": "text", "text": "refused: undo is not enabled"}], "isError": True,
                                         "_meta": {EXECUTED_META_KEY: False, REASON_META_KEY: "REF_REVERT_UNKNOWN"}})
            plan = plan_revert(state.snapshots, str((params.get("arguments") or {}).get("decision_id") or "last"), state.adapter)
            if "reason" in plan:
                return _success(msg_id, {"content": [{"type": "text", "text": "refused: " + plan["reason"]}], "isError": True,
                                         "_meta": {EXECUTED_META_KEY: False, REASON_META_KEY: plan["reason"]}})
            params = plan["params"]
            msg = dict(msg, params=params)
        gate = _gate(state, params)
        executed, reason = gate["executed"], gate["reason"]
        if executed and state.upstream is not None:
            # Honored: the upstream runs it. Its answer is the answer, plus
            # the verdict in _meta.
            forwarded = dict(msg)
            forwarded["params"] = _without_gargoyle_meta(params)
            # The receipt is claimed from here on, so every way out leaves an
            # evidence entry: the verdict says whether the upstream did the
            # work (second review, finding 5).
            try:
                reply = state.upstream.send(forwarded)
            except Exception as exc:
                _record(state, HONORED, dict(gate, reason=UPSTREAM_UNAVAILABLE), params,
                        _attest(state, gate["envelope"], {"error": str(exc)}, params))
                return _error(msg_id, JSONRPC_INTERNAL_ERROR, "upstream unavailable: %s" % exc)
            if isinstance(reply, dict) and isinstance(reply.get("result"), dict):
                meta = dict(reply["result"].get("_meta") or {})
                meta.update({EXECUTED_META_KEY: True, REASON_META_KEY: reason})
                # The outputs the execution receipt attests to are the
                # upstream's result minus the metadata we are adding. A tool
                # error is recorded as one, not as a change that happened.
                outputs = {k: v for k, v in reply["result"].items() if k != "_meta"}
                verdict = TOOL_ERROR if reply["result"].get("isError") is True else reason
                meta.update(_audit_meta(state, dict(gate, reason=verdict), outputs, params))
                reply["result"]["_meta"] = meta
            else:
                err = reply.get("error") if isinstance(reply, dict) else None
                _record(state, HONORED, dict(gate, reason=UPSTREAM_ERROR), params,
                        _attest(state, gate["envelope"], {"error": err}, params))
            return reply
        if not executed:
            _record(state, REFUSED, gate, params)
        text = ("executed %s" % params.get("name")) if executed else ("refused: %s" % reason)
        result = {
            "content": [{"type": "text", "text": text}],
            "isError": (not executed),
            "_meta": {EXECUTED_META_KEY: executed, REASON_META_KEY: reason},
        }
        if executed:
            result["_meta"].update(_audit_meta(state, gate, {k: v for k, v in result.items() if k != "_meta"}, params))
        return _success(msg_id, result)

    if state.upstream is not None:
        return _relay(state, msg)
    if is_notification:
        return None
    return _error(msg_id, JSONRPC_METHOD_NOT_FOUND, "method not found: %s" % method)


def _relay(state: ServerState, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Pass a message to the upstream unchanged and return its answer; an
    upstream failure is a JSON-RPC error, never a silent drop."""
    try:
        return state.upstream.send(msg)
    except Exception as exc:
        if "id" not in msg:
            return None
        return _error(msg.get("id"), JSONRPC_INTERNAL_ERROR, "upstream unavailable: %s" % exc)


def config_from_env() -> Optional[Dict[str, Any]]:
    """The executor's configuration from the environment, or None (then every
    tool call is refused). GARGOYLE_MCP_GATE_KEY_ID and
    GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX pin the issuer's public key;
    GARGOYLE_MCP_TARGET_ID is the identity receipts bind to;
    GARGOYLE_MCP_PRINCIPAL is the client this server serves (see the module
    docstring); the published record (the live policy pin, {policy_id,
    policy_sha256}) is read from GARGOYLE_MCP_RECORD_PATH, or followed live
    from GARGOYLE_MCP_RECORD_URL (the issuer's signed record; a rule change
    then needs no file copy). One of the two is required with the other
    four settings; there is no default record. GARGOYLE_MCP_APPROVER_KEY_ID and
    GARGOYLE_MCP_APPROVER_PUBLIC_KEY_HEX, both or neither, pin the approver
    keys whose grants release flagged receipts (comma-separated lists for
    several)."""
    import os

    key_id = os.environ.get(ENV_GATE_KEY_ID)
    key_hex = os.environ.get(ENV_GATE_PUBLIC_KEY_HEX)
    target_id = os.environ.get(ENV_TARGET_ID)
    principal = os.environ.get(ENV_PRINCIPAL)
    record_path = os.environ.get(ENV_RECORD_PATH)
    record_url = os.environ.get(ENV_RECORD_URL)
    if not (key_id and key_hex and target_id and principal and (record_path or record_url)):
        return None
    ap_key_id = os.environ.get(ENV_APPROVER_KEY_ID)
    ap_key_hex = os.environ.get(ENV_APPROVER_PUBLIC_KEY_HEX)
    if bool(ap_key_id) != bool(ap_key_hex):
        return None
    ex_key_id = os.environ.get(ENV_EXECUTOR_KEY_ID)
    ex_key_hex = os.environ.get(ENV_EXECUTOR_KEY_HEX)
    if bool(ex_key_id) != bool(ex_key_hex):
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
        executor_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ex_key_hex)) if ex_key_id else None
        approver_keys = None
        if ap_key_id:
            # Several approvers: comma-separated ids and hexes, in the same order.
            ids = [x.strip() for x in ap_key_id.split(",")]
            hexes = [x.strip() for x in ap_key_hex.split(",")]
            if len(ids) != len(hexes) or not all(ids):
                return None
            approver_keys = {i: Ed25519PublicKey.from_public_bytes(bytes.fromhex(h)) for i, h in zip(ids, hexes)}
        record = None
        if not record_url:
            with open(record_path, "rb") as f:
                record = json.loads(f.read().decode("utf-8"))
            if not valid_pin(record):
                return None
    except Exception:
        return None
    return {
        "pinned_public_keys": {key_id: public_key},
        "record": record,
        "record_url": record_url or None,
        "target_id": target_id,
        "principal": principal,
        "approver_public_keys": approver_keys,
        "executor_signing_key": executor_key,
        "executor_key_id": ex_key_id,
    }


def serve_stdio(state: ServerState, stdin=None, stdout=None) -> None:
    """The MCP stdio transport: newline-delimited JSON-RPC in on stdin, responses
    out on stdout. A parse error yields a JSON-RPC parse error; a notification
    yields no line."""
    stdin, stdout = utf8_stdio(stdin, stdout)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            stdout.write(json.dumps(_error(None, JSONRPC_PARSE_ERROR, "parse error")) + "\n")
            stdout.flush()
            continue
        response = handle_message(state, msg)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


def utf8_stdio(stdin=None, stdout=None):
    """The process's stdin and stdout as UTF-8 text streams, whatever the
    locale says (MCP stdio is UTF-8). Streams passed in are used as they are;
    a stream with no underlying buffer (a StringIO in a test) likewise."""
    import io
    if stdin is None:
        stdin = sys.stdin
        if hasattr(stdin, "buffer"):
            stdin = io.TextIOWrapper(stdin.buffer, encoding="utf-8", errors="replace")
    if stdout is None:
        stdout = sys.stdout
        if hasattr(stdout, "buffer"):
            stdout = io.TextIOWrapper(stdout.buffer, encoding="utf-8", line_buffering=True)
    return stdin, stdout


def issuer_client_from_env() -> Optional[IssuerClient]:
    """Self-issue mode when GARGOYLE_MCP_ISSUER_URL is set together with
    either GARGOYLE_MCP_CLIENT_TOKEN (a fixed token from `gargoyle init`) or
    the GARGOYLE_MCP_ENTRA_* set written by `gargoyle login` (a per-user
    token refreshed from MSAL's cache). None when none is set; a URL without
    a token source, or the reverse, raises."""
    import os
    from gargoyle.entra_login import token_source_from_env

    url, token = os.environ.get(ENV_ISSUER_URL), os.environ.get(ENV_CLIENT_TOKEN)
    source = token_source_from_env(os.environ)
    if not url and not token and source is None:
        return None
    if not url or (not token and source is None):
        raise RuntimeError("%s goes with %s or the GARGOYLE_MCP_ENTRA_* set" % (ENV_ISSUER_URL, ENV_CLIENT_TOKEN))
    return IssuerClient(url, source if source is not None else token,
                        approval_timeout=float(os.environ.get(ENV_APPROVAL_TIMEOUT, "300")),
                        poll_seconds=float(os.environ.get(ENV_POLL_SECONDS, "2")))


def upstream_from_argv(argv: List[str]) -> Optional[StdioUpstream]:
    """`-- <command...>` names the upstream MCP server to front; nothing
    after `--` (or no `--`) means the built-in demo executor."""
    if "--" not in argv:
        return None
    command = argv[argv.index("--") + 1:]
    return StdioUpstream(command) if command else None


def load_env_file(path: str, environ: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """`KEY=VALUE` lines (blank lines and `#` comments skipped) into the
    environment, without overriding a variable the process already has:
    the operator's explicit setting wins over the file. Returns what was
    set. This is how a managed MCP entry (Claude Code's managed-mcp.json,
    readable by every local user) names the gate's settings without
    carrying the executor key: `--env C:\\gargoyle\\middleware.env`."""
    env = os.environ if environ is None else environ
    applied: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8-sig") as f:        # a BOM, if a Windows editor left one, is not part of the first key
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key and key not in env:
                env[key] = value.strip()
                applied[key] = value.strip()
    return applied


def main_args(argv: List[str]) -> Tuple[Optional[str], List[str]]:
    """The gate's own options, which come before `--`: `--env FILE`.
    Returns (env file or None, the argv to hand to upstream_from_argv)."""
    own = argv[:argv.index("--")] if "--" in argv else list(argv)
    rest = argv[len(own):]
    env_path = None
    i = 0
    while i < len(own):
        if own[i] == "--env" and i + 1 < len(own):
            env_path, i = own[i + 1], i + 2
        elif own[i].startswith("--env="):
            env_path, i = own[i][len("--env="):], i + 1
        else:
            raise SystemExit("gargoyle.mcp_server: unknown option %s (usage: python -m gargoyle.mcp_server [--env FILE] -- <upstream command>)" % own[i])
    return env_path, rest


if __name__ == "__main__":
    import os as _os
    _env_path, _rest = main_args(sys.argv[1:])
    if _env_path:
        load_env_file(_env_path)
    _upstream = upstream_from_argv(_rest)
    try:
        serve_stdio(ServerState(config_from_env(), upstream=_upstream, issuer_client=issuer_client_from_env(),
                                audit_log=_os.environ.get(ENV_AUDIT_LOG) or None,
                                state_probe=_os.environ.get(ENV_STATE_PROBE) or "filesystem",
                                adapter_spec=_os.environ.get(ENV_ADAPTER_SPEC) or None,
                                state_root=_os.environ.get(ENV_STATE_ROOT) or None))
    finally:
        if _upstream is not None:
            _upstream.close()
