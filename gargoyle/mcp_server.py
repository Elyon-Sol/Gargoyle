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
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from gargoyle.consumer import REF_TARGET_NOT_CONFIGURED, Consumer
from gargoyle.evidence import HONORED, REFUSED, EvidenceLog
from gargoyle.envelope import valid_principal
from gargoyle.policy import valid_pin
from gargoyle.replay_cache import InMemoryReplayCache

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
ENV_PRINCIPAL = "GARGOYLE_MCP_PRINCIPAL"
ENV_APPROVER_KEY_ID = "GARGOYLE_MCP_APPROVER_KEY_ID"
ENV_APPROVER_PUBLIC_KEY_HEX = "GARGOYLE_MCP_APPROVER_PUBLIC_KEY_HEX"
ENV_EXECUTOR_KEY_ID = "GARGOYLE_MCP_EXECUTOR_KEY_ID"
ENV_EXECUTOR_KEY_HEX = "GARGOYLE_MCP_EXECUTOR_KEY_HEX"
ENV_ISSUER_URL = "GARGOYLE_MCP_ISSUER_URL"
ENV_CLIENT_TOKEN = "GARGOYLE_MCP_CLIENT_TOKEN"
ENV_APPROVAL_TIMEOUT = "GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS"
ENV_POLL_SECONDS = "GARGOYLE_MCP_POLL_SECONDS"
ENV_AUDIT_LOG = "GARGOYLE_MCP_AUDIT_LOG"   # the evidence log: one hash-chained JSON line per decision, honored or refused

# Self-issue refusals.
REF_TARGET_ISSUER_UNAVAILABLE = "REF_TARGET_ISSUER_UNAVAILABLE"
REF_TARGET_APPROVAL_TIMEOUT = "REF_TARGET_APPROVAL_TIMEOUT"
REF_TARGET_APPROVAL_DECLINED = "REF_TARGET_APPROVAL_DECLINED"


class IssuerClient:
    """The middleware's view of the issuing service. `http` is any object
    with requests-style get/post (a requests.Session by default; a test
    passes a TestClient). Every failure is a refusal reason, never an
    exception out of the gate."""

    def __init__(self, url: str, token: str, *, http: Any = None, approval_timeout: float = 300.0,
                 poll_seconds: float = 2.0, request_timeout: float = 10.0, sleep=time.sleep) -> None:
        import requests
        self.url = url.rstrip("/")
        self._headers = {"Authorization": "Bearer " + token}
        self._http = http if http is not None else requests.Session()
        self.approval_timeout = approval_timeout
        self.poll_seconds = poll_seconds
        self.request_timeout = request_timeout
        self._sleep = sleep

    def _post(self, path: str, body: Dict[str, Any]) -> Any:
        return self._http.post(self.url + path, json=body, headers=self._headers, timeout=self.request_timeout)

    def _get(self, path: str) -> Any:
        return self._http.get(self.url + path, headers=self._headers, timeout=self.request_timeout)

    def issue(self, target_url: str, tool: str, args: Any) -> Dict[str, Any]:
        """{"envelope": ...} or {"envelope": None, "reason": ...}. The cause of
        an unavailable issuer (TLS, DNS, a refused connection) goes to stderr,
        where an MCP client's server log shows it; the refusal code stays
        generic."""
        try:
            r = self._post("/issue", {"target_url": target_url, "tool": tool, "args": args})
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

    def wait_for_grant(self, approval_request_id: str) -> Dict[str, Any]:
        """Poll until the hold has a grant, a human declined it, the hold
        disappears, or the timeout passes: {"grant": <grant>|None,
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


def call_for(tool: str, args: Any, principal: str) -> Dict[str, Any]:
    """The call a receipt must bind to execute `tool` with `args` through a
    server serving `principal`: the same three fields the issuer bound."""
    return {"tool": tool, "args": args, "principal": principal}


class ServerState:
    """The executor's out-of-band trust material (issuer keys, the policy record,
    target id, the principal it serves) as a Consumer, and the list of tool
    calls actually executed. `config` None, or a config without a usable
    principal, means unconfigured: every tools/call is refused with
    REF_TARGET_NOT_CONFIGURED."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]],
        replay_cache: Optional[InMemoryReplayCache] = None,
        upstream: Optional[StdioUpstream] = None,
        issuer_client: Optional[IssuerClient] = None,
        audit_log: Optional[str] = None,
    ) -> None:
        self.config = config
        self.upstream = upstream
        self.issuer_client = issuer_client
        self.evidence: Optional[EvidenceLog] = EvidenceLog(audit_log) if audit_log else None
        self.consumer: Optional[Consumer] = None
        if config is not None and valid_principal(config.get("principal")):
            self.consumer = Consumer(
                target_id=config["target_id"],
                pinned_public_keys=config["pinned_public_keys"],
                record=config["record"],
                replay_cache=replay_cache,
                approver_public_keys=config.get("approver_public_keys"),
                executor_signing_key=config.get("executor_signing_key"),
                executor_key_id=config.get("executor_key_id"),
            )
        self.executed: List[Dict[str, Any]] = []
        self.initialized = False


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
    def refused(reason, envelope=None):
        # A refusal keeps the receipt when there was one (a hold the human
        # declined or let lapse), so the evidence log can show what was asked.
        return {"executed": False, "reason": reason, "envelope": envelope, "grant": None, "self_issued": False}
    if state.consumer is None:
        return refused(REF_TARGET_NOT_CONFIGURED)

    name = params.get("name")
    args = params.get("arguments", {})
    meta = params.get("_meta") or {}
    envelope = meta.get(ENVELOPE_META_KEY)
    grant = meta.get(GRANT_META_KEY)
    self_issued = False

    if envelope is None and state.issuer_client is not None:
        # Self-issue: ask the issuing service, and wait for the human if it
        # flagged the call. Nothing below trusts the answer: the receipt is
        # verified against the pinned issuer key like any other.
        res = state.issuer_client.issue(state.config["target_id"], name, args)
        if res["envelope"] is None:
            return refused(res["reason"])
        envelope, self_issued = res["envelope"], True
        if isinstance(envelope, dict) and envelope.get("requires_approval") is True and grant is None:
            waited = state.issuer_client.wait_for_grant(str(envelope.get("approval_request_id")))
            if waited["grant"] is None:
                return refused(waited["reason"], envelope)
            grant = waited["grant"]

    verdict = state.consumer.check(envelope, call_for(name, args, state.config["principal"]),
                                   grant=grant)
    if not verdict.honored:
        return refused(verdict.reason, envelope)

    state.executed.append({"tool": name, "args": args})  # THE side effect
    return {"executed": True, "reason": verdict.reason, "envelope": envelope, "grant": grant,
            "self_issued": self_issued}


def _audit_meta(state: ServerState, gate: Dict[str, Any], outputs: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    """What an honored result's _meta carries beyond executed/reason: the
    execution receipt when this server attests, and, when the receipt was
    self-issued, the receipt and grant the client never saw. The same chain
    goes into the evidence log when one is configured, so a client that
    discards _meta still leaves evidence."""
    meta: Dict[str, Any] = {}
    execution = _attest(state, gate["envelope"], outputs)
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
                              gate["reason"], receipt=gate["envelope"], grant=gate["grant"], execution=execution)
    except (OSError, ValueError) as exc:
        sys.stderr.write("gargoyle: evidence log unwritable: %s\n" % exc)


def _attest(state: ServerState, envelope: Optional[Dict[str, Any]], outputs: Any) -> Optional[Dict[str, Any]]:
    """The signed execution receipt for an honored call, or None when this
    server has no executor key."""
    if state.consumer is None or not state.consumer.attests or envelope is None:
        return None
    return state.consumer.attest(envelope, outputs)


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
        return _relay(state, msg)

    if method == "initialize":
        # The handshake completes when the client sends notifications/initialized;
        # tools are served only after that.
        return _success(
            msg_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
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
        return _success(msg_id, {"tools": ADVERTISED_TOOLS})

    if method == "tools/call":
        gate = _gate(state, params)
        executed, reason = gate["executed"], gate["reason"]
        if executed and state.upstream is not None:
            # Honored: the upstream runs it. Its answer is the answer, plus
            # the verdict in _meta.
            forwarded = dict(msg)
            forwarded["params"] = _without_gargoyle_meta(params)
            try:
                reply = state.upstream.send(forwarded)
            except Exception as exc:
                return _error(msg_id, JSONRPC_INTERNAL_ERROR, "upstream unavailable: %s" % exc)
            if isinstance(reply, dict) and isinstance(reply.get("result"), dict):
                meta = dict(reply["result"].get("_meta") or {})
                meta.update({EXECUTED_META_KEY: True, REASON_META_KEY: reason})
                # The outputs the execution receipt attests to are the
                # upstream's result minus the metadata we are adding.
                outputs = {k: v for k, v in reply["result"].items() if k != "_meta"}
                meta.update(_audit_meta(state, gate, outputs, params))
                reply["result"]["_meta"] = meta
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
    policy_sha256}) is read from GARGOYLE_MCP_RECORD_PATH. All five are
    required; there is no default record. GARGOYLE_MCP_APPROVER_KEY_ID and
    GARGOYLE_MCP_APPROVER_PUBLIC_KEY_HEX, both or neither, pin the approver
    key whose grants release flagged receipts."""
    import os

    key_id = os.environ.get(ENV_GATE_KEY_ID)
    key_hex = os.environ.get(ENV_GATE_PUBLIC_KEY_HEX)
    target_id = os.environ.get(ENV_TARGET_ID)
    principal = os.environ.get(ENV_PRINCIPAL)
    record_path = os.environ.get(ENV_RECORD_PATH)
    if not (key_id and key_hex and target_id and principal and record_path):
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
        approver_keys = (
            {ap_key_id: Ed25519PublicKey.from_public_bytes(bytes.fromhex(ap_key_hex))}
            if ap_key_id else None
        )
        with open(record_path, "rb") as f:
            record = json.loads(f.read().decode("utf-8"))
        if not valid_pin(record):
            return None
    except Exception:
        return None
    return {
        "pinned_public_keys": {key_id: public_key},
        "record": record,
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
    """Self-issue mode when GARGOYLE_MCP_ISSUER_URL and
    GARGOYLE_MCP_CLIENT_TOKEN are both set; None otherwise. One without the
    other is a configuration error and raises."""
    import os

    url, token = os.environ.get(ENV_ISSUER_URL), os.environ.get(ENV_CLIENT_TOKEN)
    if not url and not token:
        return None
    if not (url and token):
        raise RuntimeError("%s and %s go together" % (ENV_ISSUER_URL, ENV_CLIENT_TOKEN))
    return IssuerClient(url, token,
                        approval_timeout=float(os.environ.get(ENV_APPROVAL_TIMEOUT, "300")),
                        poll_seconds=float(os.environ.get(ENV_POLL_SECONDS, "2")))


def upstream_from_argv(argv: List[str]) -> Optional[StdioUpstream]:
    """`-- <command...>` names the upstream MCP server to front; nothing
    after `--` (or no `--`) means the built-in demo executor."""
    if "--" not in argv:
        return None
    command = argv[argv.index("--") + 1:]
    return StdioUpstream(command) if command else None


if __name__ == "__main__":
    import os as _os
    _upstream = upstream_from_argv(sys.argv[1:])
    try:
        serve_stdio(ServerState(config_from_env(), upstream=_upstream, issuer_client=issuer_client_from_env(),
                                audit_log=_os.environ.get(ENV_AUDIT_LOG) or None))
    finally:
        if _upstream is not None:
            _upstream.close()
