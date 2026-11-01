"""`gargoyle doctor`: the client-side preflight, one line per check.

A gate that fails closed looks broken to the person installing it: the
submitter's token cannot be refreshed, the issuer's certificate is not
trusted by the process that calls it, the client's own permission layer
refuses the gate's tools before the gate sees them, the console's key is
not the one on record. Each of those took a specialist half an hour on
the first tenant (RESUME 2026-11-01). The doctor reads the same
middleware.env the gate reads and says, per concern, PASS, WARN or FAIL
with the one fix that applies. It changes nothing and sends nothing but
GET /health and GET /record and, in Entra mode, one silent token refresh.

Every check is a function of (env, context) that returns a Check, and the
context's HTTP, clock, filesystem and subprocess are injectable, so the
suite runs offline in tests and the same code runs on a client's
workstation.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"

# What a workstation's EDR will say the first time Claude Code starts: the
# native build is one packed executable of some 300 MB that unpacks itself
# and attaches a console to its shell. Verified 2026-11-01 (Acronis,
# "ransomware injection"): signatures valid, nothing written. Printed on
# every run so the installer has the words before the alert.
EDR_NOTE = ("If an endpoint protection product flags claude.exe on first launch, check the Authenticode "
            "signature (signer \"Anthropic, PBC\", status Valid) and exclude that exact path; do not exclude a folder.")

REQUIRED_KEYS = ("GARGOYLE_MCP_ISSUER_URL", "GARGOYLE_MCP_TARGET_ID", "GARGOYLE_MCP_GATE_KEY_ID",
                 "GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX", "GARGOYLE_MCP_EXECUTOR_KEY_ID", "GARGOYLE_MCP_EXECUTOR_KEY_HEX")
ENTRA_KEYS = ("GARGOYLE_MCP_ENTRA_TENANT", "GARGOYLE_MCP_ENTRA_CLIENT_ID", "GARGOYLE_MCP_ENTRA_SCOPE",
              "GARGOYLE_MCP_ENTRA_TOKEN_CACHE")
CLOCK_SKEW_WARN_SECONDS = 60
CLOCK_SKEW_FAIL_SECONDS = 300


@dataclass
class Check:
    name: str
    status: str
    detail: str
    fix: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "status": self.status, "detail": self.detail, **({"fix": self.fix} if self.fix else {})}


@dataclass
class Context:
    """What the checks touch in the world. Tests replace any of it."""
    http: Any = None                                  # requests-style .get(url, verify=, timeout=) -> response
    now: Callable[[], float] = time.time
    home: Optional[Path] = None
    system: str = field(default_factory=platform.system)
    which: Callable[[str], Optional[str]] = shutil.which
    run: Callable[..., Any] = subprocess.run
    token_source_factory: Optional[Callable[[Dict[str, str]], Any]] = None  # env -> object with .token()/.principal
    timeout: float = 10.0
    server_name: str = "filesystem-gargoyle"          # the MCP server name the client knows the gate by

    def __post_init__(self) -> None:
        if self.home is None:
            self.home = Path.home()
        if self.http is None:
            import requests
            self.http = requests.Session()


def _ca(env: Dict[str, str]) -> Any:
    return env.get("REQUESTS_CA_BUNDLE") or True


# ---- the checks --------------------------------------------------------------

def check_env_file(path: Optional[str], env: Dict[str, str]) -> Check:
    if not path:
        return Check("env file", FAIL, "no --env given", "run: gargoyle doctor --env /path/middleware.env")
    p = Path(path)
    if not p.exists():
        return Check("env file", FAIL, "%s does not exist" % p, "point --env at the middleware.env the gate's MCP entry names")
    missing = [k for k in REQUIRED_KEYS if not env.get(k)]
    if missing:
        return Check("env file", FAIL, "%s lacks %s" % (p, ", ".join(missing)),
                     "re-run the installer, or gargoyle init; the gate refuses to start without these")
    if not (env.get("GARGOYLE_MCP_RECORD_URL") or env.get("GARGOYLE_MCP_RECORD_PATH")):
        return Check("env file", FAIL, "neither GARGOYLE_MCP_RECORD_URL nor GARGOYLE_MCP_RECORD_PATH is set",
                     "set GARGOYLE_MCP_RECORD_URL to the issuer's /record so rule changes follow the issuer")
    if not env.get("GARGOYLE_MCP_CLIENT_TOKEN") and not all(env.get(k) for k in ENTRA_KEYS):
        return Check("env file", FAIL, "no submitter identity: GARGOYLE_MCP_CLIENT_TOKEN or the four GARGOYLE_MCP_ENTRA_* keys",
                     "run: gargoyle login (Entra) or gargoyle tokens (static token)")
    try:
        own = sum(1 for l in p.read_text(encoding="utf-8-sig").splitlines() if "=" in l and not l.strip().startswith("#"))
    except OSError:
        own = 0
    detail = "%s, %d keys" % (p, own)
    if os.name == "posix":
        mode = p.stat().st_mode & 0o077
        if mode:
            return Check("env file", WARN, detail + ", readable by others (mode %o)" % (p.stat().st_mode & 0o777),
                         "chmod 600 %s; it carries the executor key" % p)
    return Check("env file", PASS, detail)


def check_ca_bundle(env: Dict[str, str], ctx: Context) -> Check:
    """The certificate the Python side will trust, and whether it names the issuer's host."""
    ca = env.get("REQUESTS_CA_BUNDLE")
    url = env.get("GARGOYLE_MCP_ISSUER_URL", "")
    host = urlsplit(url).hostname or ""
    if not ca:
        if url.startswith("https://"):
            return Check("CA bundle", WARN, "REQUESTS_CA_BUNDLE not set; Python uses the system trust store",
                         "fine for a public certificate; for the lab's self-signed gate set REQUESTS_CA_BUNDLE to gate.crt in middleware.env")
        return Check("CA bundle", SKIP, "issuer is not https")
    p = Path(ca)
    if not p.exists():
        return Check("CA bundle", FAIL, "%s does not exist" % p, "copy the issuer's gate.crt there, or fix REQUESTS_CA_BUNDLE")
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(p.read_bytes())
    except Exception as exc:
        return Check("CA bundle", FAIL, "%s is not a PEM certificate (%s)" % (p, type(exc).__name__), "replace it with the issuer's gate.crt")
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    if not_after.timestamp() < ctx.now():
        return Check("CA bundle", FAIL, "%s expired %s" % (p, not_after.date()), "issue a new gate certificate and redistribute gate.crt")
    names: List[str] = []
    try:
        from cryptography.x509.oid import ExtensionOID
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        names = [str(v) for v in san.get_values_for_type(x509.DNSName)] + [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except Exception:
        pass
    if host and names and host not in names:
        return Check("CA bundle", FAIL, "%s names %s, the issuer URL says %s" % (p.name, ", ".join(names), host),
                     "the certificate must carry the issuer's host as a SAN; reissue it or use the name it carries")
    return Check("CA bundle", PASS, "%s, valid to %s, names %s" % (p.name, not_after.date(), ", ".join(names) or "(no SAN)"))


def check_issuer(env: Dict[str, str], ctx: Context) -> Dict[str, Any]:
    """GET /health through Python's trust. Returns {"check", "health", "date"}."""
    url = env.get("GARGOYLE_MCP_ISSUER_URL", "").rstrip("/")
    if not url:
        return {"check": Check("issuer", FAIL, "GARGOYLE_MCP_ISSUER_URL not set", "set it to the issuer's https address"), "health": None}
    try:
        r = ctx.http.get(url + "/health", verify=_ca(env), timeout=ctx.timeout)
    except Exception as exc:
        text = "%s: %s" % (type(exc).__name__, str(exc)[:160])
        fix = "start the issuer, open the port, or fix the address"
        if "CERTIFICATE_VERIFY_FAILED" in text or "SSLError" in text:
            fix = "Python does not trust the issuer's certificate: set REQUESTS_CA_BUNDLE to gate.crt in middleware.env"
        return {"check": Check("issuer", FAIL, "%s unreachable: %s" % (url, text), fix), "health": None}
    if r.status_code != 200:
        return {"check": Check("issuer", FAIL, "%s/health answered %s" % (url, r.status_code), "look at the issuer's log"), "health": None}
    try:
        h = r.json()
    except Exception:
        return {"check": Check("issuer", FAIL, "%s/health is not JSON" % url, "something else answers on that port"), "health": None}
    pin = (h.get("policy") or {}).get("policy_sha256", "")[:8]
    detail = "%s ok, rules %s, entra %s, persistent %s, pending %s, approvers %s" % (
        url, pin or "?", h.get("entra"), h.get("persistent"), h.get("pending_receipts"), h.get("enrolled_approvers"))
    head = h.get("witness_head")
    if isinstance(head, dict):
        detail += ", witness seq %s" % head.get("seq")
    date = None
    try:
        date = r.headers.get("Date") if hasattr(r, "headers") else None
    except Exception:
        date = None
    return {"check": Check("issuer", PASS, detail), "health": h, "date": date}


def check_clock(date_header: Optional[str], ctx: Context) -> Check:
    """Receipts and tokens carry times; a workstation clock minutes off refuses them."""
    if not date_header:
        return Check("clock", SKIP, "issuer sent no Date header")
    try:
        remote = parsedate_to_datetime(date_header).timestamp()
    except Exception:
        return Check("clock", SKIP, "unreadable Date header %r" % date_header)
    skew = abs(ctx.now() - remote)
    if skew >= CLOCK_SKEW_FAIL_SECONDS:
        return Check("clock", FAIL, "this host is %d s from the issuer" % skew, "set the clock (time sync); receipts and Entra tokens will be refused")
    if skew >= CLOCK_SKEW_WARN_SECONDS:
        return Check("clock", WARN, "this host is %d s from the issuer" % skew, "enable time sync before it reaches 5 minutes")
    return Check("clock", PASS, "within %d s of the issuer" % skew)


def check_rules_pin(env: Dict[str, str], health: Optional[Dict[str, Any]], ctx: Context) -> Check:
    """The rules the gate will enforce are the rules the issuer runs."""
    if not health:
        return Check("rules pin", SKIP, "issuer not reachable")
    live = (health.get("policy") or {}).get("policy_sha256", "")
    url = env.get("GARGOYLE_MCP_RECORD_URL")
    path = env.get("GARGOYLE_MCP_RECORD_PATH")
    if url:
        try:
            r = ctx.http.get(url, verify=_ca(env), timeout=ctx.timeout)
            rec = r.json() if r.status_code == 200 else {}
        except Exception as exc:
            return Check("rules pin", FAIL, "record %s unreachable: %s" % (url, type(exc).__name__), "the gate follows this URL for rule changes; fix it or set GARGOYLE_MCP_RECORD_PATH")
        pinned = rec.get("policy_sha256") or (rec.get("pin") or {}).get("policy_sha256") or ""
        if pinned and live and pinned != live:
            return Check("rules pin", FAIL, "record says %s, issuer runs %s" % (pinned[:8], live[:8]), "the issuer and its published record disagree; restart the issuer")
        if not rec.get("publisher_key_id") and not rec.get("key_id"):
            return Check("rules pin", WARN, "record at %s carries no publisher key id" % url, "an unsigned record; the gate will refuse to follow it")
        return Check("rules pin", PASS, "%s, signed record followed from the issuer" % (live[:8] or "?"))
    if path:
        p = Path(path)
        if not p.exists():
            return Check("rules pin", FAIL, "%s does not exist" % p, "copy the issuer's record.json there, or switch to GARGOYLE_MCP_RECORD_URL")
        try:
            pinned = json.loads(p.read_text(encoding="utf-8-sig")).get("policy_sha256", "")
        except Exception:
            return Check("rules pin", FAIL, "%s is not a record" % p, "copy the issuer's record.json there")
        if pinned != live:
            return Check("rules pin", FAIL, "%s pins %s, issuer runs %s: every receipt will be refused" % (p.name, pinned[:8], live[:8]),
                         "copy the issuer's current record.json, or follow GARGOYLE_MCP_RECORD_URL instead")
        return Check("rules pin", PASS, "%s matches the issuer (static file; rule changes need a new copy)" % pinned[:8])
    return Check("rules pin", FAIL, "no record source", "set GARGOYLE_MCP_RECORD_URL")


def check_submitter(env: Dict[str, str], ctx: Context) -> Check:
    """Can this workstation's user get a token the issuer will accept, silently, now."""
    if env.get("GARGOYLE_MCP_CLIENT_TOKEN"):
        principal = env.get("GARGOYLE_MCP_PRINCIPAL") or "?"
        return Check("submitter", WARN if principal in ("?", "pending-entra-login") else PASS,
                     "static client token as %s (shared secret, not a person)" % principal,
                     "for a named person run: gargoyle login" if principal in ("?", "pending-entra-login") else "")
    if not all(env.get(k) for k in ENTRA_KEYS):
        return Check("submitter", FAIL, "no identity configured", "run: gargoyle login")
    cache = Path(env["GARGOYLE_MCP_ENTRA_TOKEN_CACHE"])
    if not cache.exists():
        return Check("submitter", FAIL, "no sign-in: token cache %s missing" % cache,
                     "run: gargoyle login (Windows: .\\install-gargoyle-client.ps1 -Relogin) as the user of this machine")
    try:
        if ctx.token_source_factory is not None:
            source = ctx.token_source_factory(env)
        else:
            from gargoyle.entra_login import token_source_from_env
            source = token_source_from_env(env)
        source.token()
        who = getattr(source, "principal", None) or env.get("GARGOYLE_MCP_PRINCIPAL") or "?"
    except Exception as exc:
        text = str(exc)
        fix = "run: gargoyle login (Windows: .\\install-gargoyle-client.ps1 -Relogin) as the user of this machine"
        if "AADSTS50105" in text:
            fix = ("Entra blocks this user from the API app: 'Assignment required' is set on the issuer API's enterprise application. "
                   "Set it to No there (keep it on the client app), or assign the user; see docs/entra-setup.md")
        elif "AADSTS65001" in text or "consent" in text.lower():
            fix = "admin consent is missing for the client app's API permission; grant it in Entra, then gargoyle login"
        elif "AADSTS7000" in text or "AADSTS70008" in text or "expired" in text.lower():
            fix = "the refresh token expired or was revoked; run: gargoyle login"
        return Check("submitter", FAIL, "cannot get a token: %s" % text[:220], fix)
    configured = env.get("GARGOYLE_MCP_PRINCIPAL")
    if configured and configured != who:
        return Check("submitter", WARN, "token is %s but GARGOYLE_MCP_PRINCIPAL says %s" % (who, configured),
                     "run: gargoyle login so the env names the signed-in user")
    return Check("submitter", PASS, "%s, silent token refresh works" % who)


def check_state_root(env: Dict[str, str]) -> Check:
    root = env.get("GARGOYLE_MCP_STATE_ROOT")
    if not root:
        return Check("state root", WARN, "GARGOYLE_MCP_STATE_ROOT not set", "set it to the folder the gate serves so held calls bind to file state")
    p = Path(root)
    if not p.is_dir():
        return Check("state root", FAIL, "%s is not a directory" % p, "create it, or fix GARGOYLE_MCP_STATE_ROOT")
    if not os.access(str(p), os.R_OK):
        return Check("state root", FAIL, "%s is not readable by this user" % p, "fix permissions; the gate reads file state here")
    inside = [n for n in (".claude", ".claude.json", ".mcp.json") if (p / n).exists()]
    try:
        is_home = p.resolve() == Path.home().resolve()
    except OSError:
        is_home = False
    if inside and is_home:
        return Check("state root", PASS, "%s (the home directory: a hook host; the client's own state lives here by nature)" % p)
    if inside:
        return Check("state root", WARN, "%s holds %s: a client's own state inside the gated folder" % (p, ", ".join(inside)),
                     "launch Claude Code from the user profile, not from the gated folder; discovery mode reports this as CLIENT_STATE_IN_ROOT")
    return Check("state root", PASS, str(p))


def check_evidence(env: Dict[str, str], ctx: Context) -> Check:
    log = env.get("GARGOYLE_MCP_AUDIT_LOG")
    if not log:
        return Check("evidence log", FAIL, "GARGOYLE_MCP_AUDIT_LOG not set", "set it; without it nothing this gate does is recorded locally")
    p = Path(log)
    parent = p.parent
    if not parent.is_dir():
        return Check("evidence log", FAIL, "%s: folder does not exist" % parent, "create it")
    if not os.access(str(parent), os.W_OK):
        return Check("evidence log", FAIL, "%s is not writable" % parent, "fix permissions; the gate refuses calls it cannot record")
    snap = env.get("GARGOYLE_MCP_SNAPSHOT_DIR")
    snap_note = ""
    if snap and snap.lower() != "none":
        sp = Path(snap)
        if not sp.is_dir() or not os.access(str(sp), os.W_OK):
            return Check("evidence log", FAIL, "snapshot dir %s missing or not writable" % sp, "create it; undo needs it")
        snap_note = ", snapshots in %s" % sp.name
    elif snap and snap.lower() == "none":
        snap_note = ", undo disabled"
    if not p.exists():
        return Check("evidence log", PASS, "%s (not yet written)%s" % (p, snap_note))
    try:
        from gargoyle.evidence import read_log
        entries = read_log(str(p))
        last = entries[-1].get("at") if entries else None
    except Exception as exc:
        return Check("evidence log", FAIL, "%s unreadable: %s" % (p, type(exc).__name__), "run: gargoyle audit --log %s" % p)
    try:
        from gargoyle.sidedoors import discovery_hours, report_age_seconds
        hours = discovery_hours(env)
        age = report_age_seconds(str(p), ctx.now())
        if hours <= 0:
            disc = "discovery disabled"
        elif age is None:
            disc = "discovery never run (due at the gate's next start)"
        else:
            disc = "discovery %.0f h ago%s" % (age / 3600, " (due)" if age >= hours * 3600 else "")
    except Exception:
        disc = "discovery status unknown"
    return Check("evidence log", PASS, "%s, %d entries, last %s%s, %s" % (p.name, len(entries), last or "-", snap_note, disc))


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return None


def _hook_commands(doc: Any) -> List[str]:
    hooks = doc.get("hooks") if isinstance(doc, dict) else None
    out: List[str] = []
    if not isinstance(hooks, dict):
        return out
    for groups in hooks.values():
        for g in groups if isinstance(groups, list) else []:
            for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
                if isinstance(h, dict) and h.get("command"):
                    out.append(str(h["command"]))
    return out


def _same_path_in(command: str, path: str) -> bool:
    """Does a hook command name this file; slashes compared one way, since
    Windows paths appear with either kind and JSON doubles the backslash."""
    norm = lambda t: t.replace("\\", "/").lower()
    return norm(path) in norm(command)


def _allow_rules(doc: Any) -> List[str]:
    perms = doc.get("permissions") if isinstance(doc, dict) else None
    allow = perms.get("allow") if isinstance(perms, dict) else None
    return [str(a) for a in allow] if isinstance(allow, list) else []


def check_claude_code(env: Dict[str, str], ctx: Context) -> List[Check]:
    """Claude Code's own layers around the gate: managed settings deny the
    side doors, an allow rule lets the gate's tools through its own
    classifier, and on a hook host the hook is registered for this env."""
    from gargoyle.sidedoors import CLAUDE_CODE_FILE_TOOLS, _denies_tools, _hook_in, _server_entries, client_config_paths
    out: List[Check] = []
    paths = client_config_paths(ctx.home, ctx.system, env)
    managed = None
    for d in paths["managed_dir"]:
        doc = _read_json(d / "managed-settings.json")
        if doc is not None:
            managed = (d / "managed-settings.json", doc)
            break
    user_docs = [(p, _read_json(p)) for p in paths["code_settings"]]
    user_docs = [(p, d) for p, d in user_docs if d is not None]
    all_docs = ([managed[1]] if managed else []) + [d for _, d in user_docs]

    # 1. the gate's tools are allowed by rule, so auto mode's classifier never gets a vote
    want = "mcp__" + ctx.server_name
    allowed = any(a == want or a.startswith(want + "__") for d in all_docs for a in _allow_rules(d))
    client_docs = [_read_json(p) for p in paths["desktop"] + paths["code_user"]]
    managed_mcp = [_read_json(d / "managed-mcp.json") for d in paths["managed_dir"]]
    has_entry = any(e.get("_name", "").split(" ")[0] == ctx.server_name
                    for d in client_docs + managed_mcp if d is not None for e in _server_entries(d))
    if not has_entry and not allowed:
        out.append(Check("claude code allow", SKIP, "no MCP server named %s in this host's client configs (hook-only host, or the entry is elsewhere; --server NAME)" % ctx.server_name))
    elif allowed:
        out.append(Check("claude code allow", PASS, "%s allowed by rule" % want))
    else:
        out.append(Check("claude code allow", WARN, "no allow rule for %s" % want,
                         "add \"%s\" to permissions.allow (managed-settings.json or /permissions); without it Claude Code's auto-mode "
                         "classifier can refuse the gate's writes before the gate sees them" % want))

    # 2. the side doors are shut: Edit/Write/Bash denied somewhere that applies
    denied = sorted({t for d in all_docs for t in _denies_tools(d)})
    hooked = any(_hook_in(d) for d in all_docs)
    if managed and _denies_tools(managed[1]):
        out.append(Check("claude code deny", PASS, "%s denies %s" % (managed[0], ", ".join(_denies_tools(managed[1])))))
    elif hooked:
        out.append(Check("claude code deny", PASS, "gargoyle hook registered (Claude Code's own tools go through the gate)"))
    elif denied:
        out.append(Check("claude code deny", WARN, "denied only in user settings (%s); a user can undo that" % ", ".join(denied),
                         "put the deny list in managed-settings.json (" + str(paths["managed_dir"][0]) + ")"))
    else:
        out.append(Check("claude code deny", FAIL, "Claude Code's %s are neither denied nor hooked" % "/".join(CLAUDE_CODE_FILE_TOOLS[:3]),
                         "install managed-settings.json with the deny list, or register the gargoyle hook; otherwise the model writes around the gate"))

    # 3. hook points at this env file (where a hook exists)
    if hooked:
        env_path = env.get("_GARGOYLE_DOCTOR_ENV_PATH", "")
        commands = [c for d in all_docs for c in _hook_commands(d) if "gargoyle" in c.lower()]
        names_env = any(_same_path_in(c, env_path) for c in commands) if env_path else True
        out.append(Check("claude code hook", PASS if names_env else WARN,
                         "registered" + ("" if names_env else ", but not with --env %s" % env_path),
                         "" if names_env else "the hook runs with a different env file than the one checked here"))
    return out


def check_node_trust(env: Dict[str, str], ctx: Context) -> Check:
    """Claude Code's HTTP MCP client is Node: a remote gate over https needs
    NODE_EXTRA_CA_CERTS, not REQUESTS_CA_BUNDLE. Spawn node when present."""
    url = env.get("GARGOYLE_MCP_ISSUER_URL", "").rstrip("/")
    if not url.startswith("https://"):
        return Check("node trust", SKIP, "issuer is not https")
    node = ctx.which("node")
    if not node:
        return Check("node trust", SKIP, "node not on PATH (a stdio gate needs only Python trust; a remote https gate needs NODE_EXTRA_CA_CERTS "
                     "in Claude Code's launch environment)")
    script = ("fetch(process.argv[1]).then(r=>{process.exit(r.ok?0:3)}).catch(e=>{console.error(e.cause&&e.cause.code||e.code||e.message);process.exit(2)})")
    node_env = dict(os.environ)
    if env.get("REQUESTS_CA_BUNDLE") and not node_env.get("NODE_EXTRA_CA_CERTS"):
        node_env["NODE_EXTRA_CA_CERTS"] = env["REQUESTS_CA_BUNDLE"]
    try:
        r = ctx.run([node, "-e", script, url + "/health"], capture_output=True, text=True, timeout=ctx.timeout, env=node_env)
    except Exception as exc:
        return Check("node trust", SKIP, "could not run node: %s" % type(exc).__name__)
    if r.returncode == 0:
        src = "NODE_EXTRA_CA_CERTS" if node_env.get("NODE_EXTRA_CA_CERTS") else "system store"
        note = "" if os.environ.get("NODE_EXTRA_CA_CERTS") or not env.get("REQUESTS_CA_BUNDLE") else \
            " (with NODE_EXTRA_CA_CERTS=%s; set it in Claude Code's launch environment for a remote gate)" % env["REQUESTS_CA_BUNDLE"]
        return Check("node trust", PASS, "node reaches the issuer via %s%s" % (src, note))
    err = (r.stderr or "").strip().splitlines()[-1:] or ["exit %s" % r.returncode]
    fix = "export NODE_EXTRA_CA_CERTS=%s in the environment Claude Code starts from" % (env.get("REQUESTS_CA_BUNDLE") or "<gate.crt>")
    return Check("node trust", FAIL, "node cannot reach the issuer: %s" % err[0], fix)


# ---- the suite ---------------------------------------------------------------

def run(env_path: Optional[str], *, ctx: Optional[Context] = None, environ: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Every check, in the order a person debugs: file, trust, issuer,
    clock, rules, identity, local state, client layers. Returns
    {"checks": [...], "ok": bool, "edr_note": str}."""
    ctx = ctx or Context()
    env: Dict[str, str] = dict(environ if environ is not None else os.environ)
    if env_path and Path(env_path).exists():
        from gargoyle.mcp_server import load_env_file
        load_env_file(env_path, env)
        env["_GARGOYLE_DOCTOR_ENV_PATH"] = str(Path(env_path).resolve())
    checks: List[Check] = [check_env_file(env_path, env)]
    if checks[0].status == FAIL:
        return {"checks": [c.as_dict() for c in checks], "ok": False, "edr_note": EDR_NOTE}
    checks.append(check_ca_bundle(env, ctx))
    issuer = check_issuer(env, ctx)
    checks.append(issuer["check"])
    checks.append(check_clock(issuer.get("date"), ctx))
    checks.append(check_rules_pin(env, issuer.get("health"), ctx))
    checks.append(check_submitter(env, ctx))
    checks.append(check_state_root(env))
    checks.append(check_evidence(env, ctx))
    checks.extend(check_claude_code(env, ctx))
    checks.append(check_node_trust(env, ctx))
    ok = all(c.status != FAIL for c in checks)
    return {"checks": [c.as_dict() for c in checks], "ok": ok, "edr_note": EDR_NOTE}


def format_report(result: Dict[str, Any]) -> str:
    width = max(len(c["name"]) for c in result["checks"]) if result["checks"] else 10
    lines = []
    for c in result["checks"]:
        lines.append("%-4s %-*s  %s" % (c["status"], width, c["name"], c["detail"]))
        if c.get("fix"):
            lines.append("     %-*s  -> %s" % (width, "", c["fix"]))
    fails = sum(1 for c in result["checks"] if c["status"] == FAIL)
    warns = sum(1 for c in result["checks"] if c["status"] == WARN)
    lines.append("")
    lines.append("note: " + result["edr_note"])
    lines.append("%s: %d fail, %d warn" % ("ready" if result["ok"] else "not ready", fails, warns))
    return "\n".join(lines)
