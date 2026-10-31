"""Side doors: every other way into the files the gate protects, found and
recorded during discovery.

A gate stands in front of one tool server. The files behind it can still
be reached around it: a second MCP server in a client's config that
serves the same folder without the gate, Claude Code's own Write and
Bash tools when no hook is installed, a project `.mcp.json` anyone with
write access can extend, a managed MCP file that is not exclusive, a
share that exports the folder, a world-writable folder, a symlink inside
the folder that lands outside it, and a gated file changed with no
evidence entry (gargoyle.reconcile.check_tree). None of these is an
attack; all of them are what an audit of the evidence log cannot see.

`discover()` enumerates them from the client configuration files on this
host and the state of the tree. The gate runs it at startup and once a
day (GARGOYLE_MCP_DISCOVERY_HOURS, 0 disables), the hook runs it when the
last report is older than that, and `gargoyle sidedoors` runs it on
demand. The findings are written beside the evidence log
(`audit.sidedoors.json`, with first-seen times carried over) and sent to
the issuer (`POST /sidedoors`), whose witness records the count and the
list, so the operator sees them in the console's Activity and the
observe-week summary names what the rules cannot reach.
"""

import json
import os
import platform as _platform
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

# Kinds. The remedy for each is a sentence the operator can act on.
UNGATED_MCP_SERVER = "UNGATED_MCP_SERVER"        # a client config runs a server on the root without the gate
PROJECT_MCP_CONFIG = "PROJECT_MCP_CONFIG"        # a .mcp.json under the root: writers of the root can add servers
CLIENT_TOOLS_UNGATED = "CLIENT_TOOLS_UNGATED"    # Claude Code's own Write/Edit/Bash with no hook and no managed deny
HOOK_REMOVABLE = "HOOK_REMOVABLE"                # the hook is in a settings file the user can edit
MANAGED_NOT_EXCLUSIVE = "MANAGED_NOT_EXCLUSIVE"  # managed MCP servers present, but user-added ones not blocked
WORLD_WRITABLE = "WORLD_WRITABLE"                # the root (or a folder in it) is writable by everyone
SMB_SHARE = "SMB_SHARE"                          # a share exports the root or a parent of it
SYMLINK_OUT = "SYMLINK_OUT"                      # a symlink inside the root points outside it
UNATTRIBUTED_CHANGE = "UNATTRIBUTED_CHANGE"      # a gated file is not as the gate left it (reconcile.check_tree)

DISCOVERY_VERSION = "gargoyle-sidedoors/1"
REPORT_SUFFIX = ".sidedoors.json"
ENV_DISCOVERY_HOURS = "GARGOYLE_MCP_DISCOVERY_HOURS"
DEFAULT_DISCOVERY_HOURS = 24.0
MAX_WALK_ENTRIES = 5000       # the tree walk is bounded: a root that is a whole home directory is sampled, not read
MAX_FINDINGS_REPORTED = 100
GATE_MARKERS = ("gargoyle",)  # a server whose command or args name the gate is the gate
FILESYSTEM_SERVER_MARKERS = ("server-filesystem", "mcp-server-filesystem", "filesystem")
CLAUDE_CODE_FILE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit", "Bash")


def _finding(kind: str, path: str, detail: str, remedy: str) -> Dict[str, Any]:
    return {"kind": kind, "path": str(path), "detail": detail, "remedy": remedy}


def _norm(p: str) -> str:
    from gargoyle.globs import normalize_path
    return normalize_path(str(p)).rstrip("/") or "/"


def _within(path: str, root: str) -> bool:
    """Is `path` the root or inside it (case- and separator-insensitive)?"""
    a, b = _norm(path), _norm(root)
    return a == b or a.startswith(b + "/")


def _touches(path: str, root: str) -> bool:
    """Does serving `path` reach the root: the path is the root, inside it, or a parent of it."""
    return _within(path, root) or _within(root, path)


def _read_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None


def _is_gate(entry: Dict[str, Any]) -> bool:
    text = " ".join([str(entry.get("command", ""))] + [str(a) for a in entry.get("args", []) if isinstance(a, (str, int))]
                    + [str(entry.get("url", ""))])
    return any(m in text.lower() for m in GATE_MARKERS)


def _paths_in(entry: Dict[str, Any]) -> List[str]:
    """Absolute paths among a server entry's args and env values."""
    from gargoyle.state import is_absolute_path
    out = []
    for a in list(entry.get("args", [])) + list((entry.get("env") or {}).values()):
        if isinstance(a, str) and is_absolute_path(a) and not a.lower().endswith((".js", ".py", ".exe", ".cmd", ".env", ".json")):
            out.append(a)
    return out


def _serves_root(entry: Dict[str, Any], root: str) -> Optional[str]:
    """The path this server entry serves that reaches the root, if any. A
    filesystem server with no path argument serves wherever it is pointed,
    so it counts too."""
    for p in _paths_in(entry):
        if _touches(p, root):
            return p
    text = (" ".join([str(entry.get("command", ""))] + [str(a) for a in entry.get("args", []) if isinstance(a, str)])).lower()
    if any(m in text for m in FILESYSTEM_SERVER_MARKERS) and not _paths_in(entry):
        return "(any path)"
    return None


def client_config_paths(home: Path, system: str, env: Optional[Dict[str, str]] = None) -> Dict[str, List[Path]]:
    """Where the clients on this host keep MCP server lists and settings."""
    env = os.environ if env is None else env
    out: Dict[str, List[Path]] = {"desktop": [], "code_user": [], "code_settings": [], "managed_dir": []}
    if system == "Windows":
        appdata = Path(env.get("APPDATA") or (home / "AppData/Roaming"))
        local = Path(env.get("LOCALAPPDATA") or (home / "AppData/Local"))
        out["desktop"].append(appdata / "Claude" / "claude_desktop_config.json")
        try:
            out["desktop"] += sorted((local / "Claude-Data").glob("claude_*/claude_desktop_config.json"))
        except OSError:
            pass
        out["managed_dir"].append(Path(env.get("ProgramFiles", r"C:\Program Files")) / "ClaudeCode")
    elif system == "Darwin":
        out["desktop"].append(home / "Library/Application Support/Claude/claude_desktop_config.json")
        out["managed_dir"].append(Path("/Library/Application Support/ClaudeCode"))
    else:
        out["desktop"].append(home / ".config/Claude/claude_desktop_config.json")
        out["managed_dir"].append(Path("/etc/claude-code"))
    out["code_user"].append(home / ".claude.json")
    out["code_settings"].append(home / ".claude/settings.json")
    out["code_settings"].append(home / ".claude/settings.local.json")
    return out


def _server_entries(doc: Any) -> List[Dict[str, Any]]:
    """Every mcpServers entry in a client file, flattened: top level and, for
    Claude Code's ~/.claude.json, under each project."""
    found: List[Dict[str, Any]] = []
    if not isinstance(doc, dict):
        return found
    for name, entry in (doc.get("mcpServers") or {}).items():
        if isinstance(entry, dict):
            found.append(dict(entry, _name=str(name)))
    for proj, pdoc in (doc.get("projects") or {}).items():
        if isinstance(pdoc, dict):
            for name, entry in (pdoc.get("mcpServers") or {}).items():
                if isinstance(entry, dict):
                    found.append(dict(entry, _name="%s (project %s)" % (name, proj)))
    return found


def _hook_in(doc: Any) -> bool:
    hooks = doc.get("hooks") if isinstance(doc, dict) else None
    if not isinstance(hooks, dict):
        return False
    for groups in hooks.values():
        for g in groups if isinstance(groups, list) else []:
            for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
                if isinstance(h, dict) and "gargoyle" in str(h.get("command", "")).lower():
                    return True
    return False


def _denies_tools(doc: Any) -> List[str]:
    perms = doc.get("permissions") if isinstance(doc, dict) else None
    deny = perms.get("deny") if isinstance(perms, dict) else None
    if not isinstance(deny, list):
        return []
    denied = {str(d).split("(")[0] for d in deny}
    return [t for t in CLAUDE_CODE_FILE_TOOLS if t in denied]


def discover(root: str, *, home: Optional[str] = None, system: Optional[str] = None, env: Optional[Dict[str, str]] = None,
             evidence: Optional[Iterable[Any]] = None, project_dirs: Iterable[str] = (), smb_conf: str = "/etc/samba/smb.conf",
             run: Callable[..., Any] = subprocess.run, max_entries: int = MAX_WALK_ENTRIES) -> List[Dict[str, Any]]:
    """Every side door into `root` this host shows. Pure apart from reading
    files and, on Windows, asking PowerShell for the SMB shares; `run` and
    the paths are injectable for tests."""
    system = system or _platform.system()
    home_p = Path(home) if home else Path.home()
    env = os.environ if env is None else env
    findings: List[Dict[str, Any]] = []
    paths = client_config_paths(home_p, system, env)

    # 1. Client configurations: a second route to the same files.
    for kind, files in (("Claude Desktop", paths["desktop"]), ("Claude Code", paths["code_user"])):
        for f in files:
            doc = _read_json(f)
            if doc is None:
                continue
            for entry in _server_entries(doc):
                if _is_gate(entry):
                    continue
                served = _serves_root(entry, root)
                if served:
                    findings.append(_finding(UNGATED_MCP_SERVER, str(f), "%s server '%s' serves %s without the gate" % (kind, entry["_name"], served),
                                             "remove the entry, or point it at the gate (python -m gargoyle.mcp_server --env middleware.env -- <server>)"))
    for mdir in paths["managed_dir"]:
        mmcp = _read_json(mdir / "managed-mcp.json")
        mset = _read_json(mdir / "managed-settings.json")
        if mmcp is not None:
            for entry in _server_entries(mmcp):
                if not _is_gate(entry) and _serves_root(entry, root):
                    findings.append(_finding(UNGATED_MCP_SERVER, str(mdir / "managed-mcp.json"), "managed server '%s' serves the root without the gate" % entry["_name"],
                                             "replace the managed entry with the gate's"))
            if not (isinstance(mset, dict) and mset.get("allowManagedMcpServersOnly") is True):
                findings.append(_finding(MANAGED_NOT_EXCLUSIVE, str(mdir / "managed-settings.json"),
                                         "managed-mcp.json is present but allowManagedMcpServersOnly is not true: a user may add servers of their own",
                                         'set "allowManagedMcpServersOnly": true in managed-settings.json'))
    # Project-level MCP config inside the root: anyone who can write the root can add a server.
    seen_proj = set()
    for d in list(project_dirs) + [root]:
        f = Path(d) / ".mcp.json"
        if f.exists() and str(f) not in seen_proj:
            seen_proj.add(str(f))
            doc = _read_json(f) or {}
            names = [e["_name"] for e in _server_entries(doc) if not _is_gate(e)]
            findings.append(_finding(PROJECT_MCP_CONFIG, str(f), "project MCP config with %d ungated server(s): %s" % (len(names), ", ".join(names) or "none"),
                                     "keep .mcp.json out of gated trees, or set allowManagedMcpServersOnly"))

    # 2. Claude Code's own tools: Write/Edit/Bash reach any file the user can; the hook or a managed deny closes it.
    hook_files, managed_hook, managed_deny = [], False, []
    for f in paths["code_settings"] + [Path(d) / ".claude" / "settings.json" for d in list(project_dirs) + [root]]:
        doc = _read_json(f)
        if doc is not None and _hook_in(doc):
            hook_files.append(str(f))
    for mdir in paths["managed_dir"]:
        mset = _read_json(mdir / "managed-settings.json")
        if isinstance(mset, dict):
            managed_hook = managed_hook or _hook_in(mset)
            managed_deny = managed_deny or _denies_tools(mset)
    if not hook_files and not managed_hook and len(managed_deny) < len(CLAUDE_CODE_FILE_TOOLS):
        missing = [t for t in CLAUDE_CODE_FILE_TOOLS if t not in managed_deny]
        where = str(paths["code_settings"][0]) if paths["code_settings"] else str(Path(home_p) / ".claude" / "settings.json")
        findings.append(_finding(CLIENT_TOOLS_UNGATED, where, "Claude Code's own tools %s run with no gargoyle hook" % ", ".join(missing),
                                 "install the hook (docs/claude-code-hook.md) or deny these tools in managed-settings.json"))
    elif hook_files and not managed_hook:
        findings.append(_finding(HOOK_REMOVABLE, hook_files[0], "the gargoyle hook is in a settings file the user can edit",
                                 "move the hooks block to managed-settings.json with allowManagedHooksOnly"))

    # 3. The tree itself: who else can write it, and where writes inside it land.
    rootp = Path(root)
    if rootp.is_dir():
        if os.name != "nt":
            try:
                if stat.S_IMODE(rootp.stat().st_mode) & stat.S_IWOTH:
                    findings.append(_finding(WORLD_WRITABLE, root, "the root is writable by every local user", "chmod o-w the root"))
            except OSError:
                pass
        n = 0
        for dirpath, dirnames, filenames in os.walk(root):
            for name in dirnames + filenames:
                n += 1
                if n > max_entries:
                    break
                p = os.path.join(dirpath, name)
                if os.path.islink(p):
                    try:
                        target = os.path.realpath(p)
                    except OSError:
                        continue
                    if not _within(target, os.path.realpath(root)):
                        findings.append(_finding(SYMLINK_OUT, p, "symlink to %s: a write inside the root lands outside it" % target,
                                                 "replace the link with the file, or refuse symlinks in the rules"))
                if os.name != "nt" and name in dirnames:
                    try:
                        if stat.S_IMODE(os.lstat(p).st_mode) & stat.S_IWOTH and not os.path.islink(p):
                            findings.append(_finding(WORLD_WRITABLE, p, "folder writable by every local user", "chmod o-w"))
                    except OSError:
                        pass
            if n > max_entries:
                break
            # Hidden folders are checked where they sit but not descended: a
            # home directory's .cache would spend the whole budget.
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]

    # 4. Shares: the folder reachable over the network without any client.
    for share in _shares(system, smb_conf, run):
        if _touches(share["path"], root):
            findings.append(_finding(SMB_SHARE, share["path"], "share '%s' exports %s" % (share["name"], share["path"]),
                                     "remove the share, or make it read-only for everyone but the gate's account"))

    # 5. Gated files not as the gate left them (the evidence log knows their last state).
    if evidence is not None and rootp.is_dir():
        from gargoyle.reconcile import check_tree
        for f in check_tree(list(evidence), root)["findings"]:
            findings.append(_finding(UNATTRIBUTED_CHANGE, f["path"], "changed outside the gate%s" % (" (missing)" if f.get("missing") else ""),
                                     "find the writer: a side door above, or a person at the console; `gargoyle audit --check-tree` lists these"))
    return findings


def _shares(system: str, smb_conf: str, run: Callable[..., Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if system == "Windows":
        try:
            r = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-SmbShare | Select-Object Name,Path | ConvertTo-Json -Compress"],
                    capture_output=True, text=True, timeout=15)
            doc = json.loads(r.stdout or "[]")
            for s in doc if isinstance(doc, list) else [doc]:
                # Administrative shares (C$, ADMIN$, IPC$) exist on every Windows
                # host for its administrators; they are not a door the operator
                # opened, so they are not reported.
                if isinstance(s, dict) and s.get("Path") and not str(s.get("Name", "")).endswith("$"):
                    out.append({"name": str(s.get("Name")), "path": str(s["Path"])})
        except Exception:
            pass
        return out
    try:
        section, path = None, None
        for line in Path(smb_conf).read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            m = re.match(r"^\[(.+)\]$", line)
            if m:
                section = m.group(1)
                continue
            m = re.match(r"^path\s*=\s*(.+)$", line, re.I)
            if m and section and section.lower() not in ("global", "printers", "print$"):
                out.append({"name": section, "path": m.group(1).strip()})
    except OSError:
        pass
    return out


def report_path(evidence_path: str) -> Path:
    p = Path(evidence_path)
    return p.with_name(p.stem + REPORT_SUFFIX)


def write_report(findings: List[Dict[str, Any]], evidence_path: str, *, root: str, now: Optional[float] = None) -> Dict[str, Any]:
    """The latest findings beside the evidence log, each with the time it
    was first seen (carried over from the previous report) and now."""
    now = time.time() if now is None else now
    path = report_path(evidence_path)
    previous = _read_json(path) or {}
    first = {(f.get("kind"), f.get("path")): f.get("first_seen") for f in previous.get("findings", []) if isinstance(f, dict)}
    at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    out = {"version": DISCOVERY_VERSION, "at": at, "root": root,
           "findings": [dict(f, first_seen=first.get((f["kind"], f["path"])) or at) for f in findings]}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return out


def report_age_seconds(evidence_path: str, now: Optional[float] = None) -> Optional[float]:
    """Seconds since the last report beside this evidence log, or None when there is none."""
    doc = _read_json(report_path(evidence_path))
    if not isinstance(doc, dict) or not isinstance(doc.get("at"), str):
        return None
    try:
        then = _utc_to_epoch(doc["at"])
    except ValueError:
        return None
    return (time.time() if now is None else now) - then


def _utc_to_epoch(s: str) -> float:
    import calendar
    return float(calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ")))


def discovery_hours(env: Optional[Dict[str, str]] = None) -> float:
    env = os.environ if env is None else env
    try:
        return float(env.get(ENV_DISCOVERY_HOURS, DEFAULT_DISCOVERY_HOURS))
    except ValueError:
        return DEFAULT_DISCOVERY_HOURS


def due(evidence_path: Optional[str], env: Optional[Dict[str, str]] = None, now: Optional[float] = None) -> bool:
    """Is a discovery run due: enabled, and no report yet or an old one."""
    hours = discovery_hours(env)
    if hours <= 0 or not evidence_path:
        return False
    age = report_age_seconds(evidence_path, now)
    return age is None or age >= hours * 3600


def run_for_state(state: Any, *, force: bool = False, env: Optional[Dict[str, str]] = None, now: Optional[float] = None,
                  stderr: Any = None) -> Optional[List[Dict[str, Any]]]:
    """Discovery for a running gate or hook: the root is the state root (or
    the gate folder's parent when there is none), the evidence log supplies
    the gated files' last states, the report lands beside it and goes to
    the issuer. Never raises: discovery is notice, not admission."""
    stderr = stderr or sys.stderr
    evidence_path = str(state.evidence.path) if getattr(state, "evidence", None) is not None else None
    if not evidence_path or not (force or due(evidence_path, env, now)):
        return None
    try:
        # The root: the operator's GARGOYLE_MCP_STATE_ROOT first (the hook's
        # state does not carry it), then the gate's own, then the log's folder.
        root = (env or os.environ).get("GARGOYLE_MCP_STATE_ROOT") or getattr(state, "state_root", None) \
            or str(Path(evidence_path).resolve().parent)
        from gargoyle.evidence import read_log
        entries = read_log(evidence_path) if Path(evidence_path).exists() else []
        findings = discover(root, evidence=entries)
        write_report(findings, evidence_path, root=root, now=now)
        client = getattr(state, "issuer_client", None)
        target = (getattr(state, "config", None) or {}).get("target_id")
        if client is not None and target:
            try:
                client.report_sidedoors(target, findings)
            except Exception as exc:
                stderr.write("gargoyle: side-door report not sent to the issuer: %s\n" % exc)
        return findings
    except Exception as exc:
        stderr.write("gargoyle: side-door discovery failed: %s\n" % exc)
        return None


def summarize(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in findings:
        out[f["kind"]] = out.get(f["kind"], 0) + 1
    return out


def format_table(findings: List[Dict[str, Any]], root: str) -> str:
    if not findings:
        return "side doors into %s: none found" % root
    lines = ["side doors into %s: %d" % (root, len(findings))]
    for f in findings:
        lines.append("  %-22s %s" % (f["kind"], f["path"]))
        lines.append("  %-22s   %s" % ("", f["detail"]))
        lines.append("  %-22s   fix: %s" % ("", f["remedy"]))
    return "\n".join(lines)
