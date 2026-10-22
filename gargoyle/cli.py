"""The `gargoyle` command: set up, run and operate a deployment without a
policy engine, a container runtime, or any client changes.

    gargoyle init <dir-the-agent-may-touch> [--out DIR]   keys, config, rules file
        --issuer-url URL        what the client reaches the issuer at (behind TLS: https://host)
        --client-python PATH    the client's python.exe, for the MCP server entry
        --client-config-dir DIR where middleware.env, record.json and the evidence log live on the client
        --upstream npx-filesystem|python-fs   the filesystem MCP server the gate fronts (Node, or this package)
    gargoyle issuer ... [--ssl-certfile CRT --ssl-keyfile KEY]   serve TLS directly (no reverse proxy)
    gargoyle issuer [--out DIR] [--port 8080]            run the issuing service
    gargoyle approve [--out DIR] [--watch SECONDS]       sit and approve held calls
    gargoyle login --tenant T --client-id C --scope S   sign this workstation's user in with
                                                        Entra ID; the middleware then acts as them
    gargoyle remote --out DIR [--upstream-url URL | -- <command>]   the gate as an HTTPS MCP
                                                        server, for hosted connectors
    gargoyle remote-token --out DIR --principal UPN     a capability URL for one person
    gargoyle init DIR --client claude-code              the gate as a Claude Code hook over its
                                                        own tools (claude-settings.json)
    gargoyle hook --env middleware.env [--final]        the hook command itself
    gargoyle audit <receipt.json> <execution.json> [grant.json]
    gargoyle audit --log audit.jsonl            verify the middleware's evidence log

`init` writes, into --out (default: ./gargoyle-deploy):

    rules.json        the policy: reads free, writes held, the rest denied; edit it
    issuer.env        the issuer's key and trust (private)
    middleware.env    what the MCP client's server entry needs (private)
    approver.env      the approver's key and token (private; move it to the
                      approver's machine); with --approvers N also approver-2.env ...
    approver-web.json the same key and token in the form the browser approval
                      console loads (private; same machine as approver.env)
    gargoyle-issuer.service, apache-gargoyle.conf
                      a systemd unit and an Apache virtual host for the issuer
    mcp-config.json   the server entry to paste into the MCP client
    public-keys.json  issuer, approver and executor public keys, for audits

Then: `gargoyle issuer` in one terminal, the server entry in the client,
`gargoyle approve --watch 2` where the approver sits. Everything the
middleware honors comes back with receipt, grant and execution receipt in
the response metadata; `gargoyle audit` verifies them later, offline.
"""

import argparse
import json
from typing import Any, Dict
import os
import re
import stat
import sys

from gargoyle.approvers import DEFAULT_APPROVER_ROLE
from datetime import datetime, timedelta, timezone
from pathlib import Path

PRINCIPAL = "spiffe://gargoyle.local/agents/assistant"

OBSERVE_RULES = {
    # Observe mode: every call allowed (deletes too), every call recorded, none held. The
    # first week of a deployment, so the hold and deny rules are written
    # from the audit rather than guessed. The policy pin changes when the
    # rules do; the issuer applies the edit at once and clients that follow
    # its signed record pick the new pin up within a minute.
    "version": "1",
    "default": "allow",
    "rules": [],
}

DEFAULT_RULES = {
    "version": "1",
    "default": "deny",
    "rules": [
        {"tools": ["read_*", "list_*", "get_*", "search_*", "directory_tree"], "action": "allow"},
        {"tools": ["write_file", "edit_file", "create_directory", "move_file"], "action": "hold"},
        {"tools": ["delete_*", "remove_*", "rm*"], "action": "deny", "reason": "DESTRUCTIVE_TOOL"},
    ],
}

CLAUDE_CODE_RULES = {
    # Claude Code's own tools through the hook (gargoyle.claude_hook). Reads,
    # searches and planning tools are free; anything that changes a file or
    # runs a command waits for a named approver. MCP tools Claude Code calls
    # directly pass through the same hook: name them here per server.
    "version": "1",
    "default": "allow",
    "rules": [
        {"tools": ["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash", "PowerShell"], "action": "hold"},
    ],
}


def _env_lines(d):
    return "".join("%s=%s\n" % kv for kv in d.items())


def _read_env(path: Path):
    out = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v
    return out


def _write(path: Path, text: str, private: bool = False) -> None:
    path.write_text(text)
    if private:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    print("wrote", path)


def _observe_rules(rules: Path) -> int:
    """Switch a deployment's rules file to observe mode (allow and record
    everything), leaving a hand-edited file alone."""
    current = None
    if rules.exists():
        try:
            current = json.loads(rules.read_text())
        except ValueError as exc:
            print("%s is not valid JSON (%s); fix or remove it before --observe" % (rules, exc), file=sys.stderr)
            return 2
    if current is None or current in (DEFAULT_RULES, CLAUDE_CODE_RULES):
        _write(rules, json.dumps(OBSERVE_RULES, indent=2) + "\n")
    elif current != OBSERVE_RULES:
        print("rules.json was edited by hand and is left as it is; --observe changed nothing", file=sys.stderr)
    print("observe mode: rules.json allows every call, destructive ones included; the gate records all of "
          "them and holds none. Tighten rules.json from `gargoyle audit --summary`; the issuer applies the "
          "change at once and clients that follow its record (GARGOYLE_MCP_RECORD_URL) pick the new pin up "
          "within a minute. A client on a static record.json needs the new file.")
    return 0


def cmd_init(args) -> int:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
    from gargoyle.jws import encode

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if (out / "issuer.env").exists() and not args.force:
        # A deployment lives here. Its keys and tokens are what every client
        # and approver holds; regenerating them by accident strands them all.
        if args.observe:
            return _observe_rules(out / "rules.json")
        print("%s already holds a deployment; its keys and tokens are kept. New tokens: `gargoyle tokens --out %s`. "
              "Fresh keys: `gargoyle init --force` (every client and approver must then be re-provisioned), or a new --out."
              % (out, out), file=sys.stderr)
        return 2
    # A Windows path given on a Linux issuer host is the client's and is kept as typed.
    windows = re.match(r"^[A-Za-z]:[\\/]", args.directory) is not None
    allowed = args.directory if windows else str(Path(args.directory).resolve())
    sep = "\\" if windows else "/"
    client_dir = args.client_config_dir or str(out)
    client_python = args.client_python or sys.executable
    claude_code = getattr(args, "client", "mcp") == "claude-code"
    from gargoyle.globs import normalize_path
    if normalize_path(client_dir) == normalize_path(allowed) or normalize_path(client_dir).startswith(normalize_path(allowed).rstrip("/") + "/"):
        print("note: the client config folder %s is inside the folder the gate serves (%s). The gate refuses calls into its "
              "own files (REF_TARGET_GATE_FILES), but secrets are better kept out of the served tree: --client-config-dir."
              % (client_dir, allowed), file=sys.stderr)

    def new_key():
        k = Ed25519PrivateKey.generate()
        return (k, k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())

    issuer, issuer_hex, issuer_pub = new_key()
    approvers = [("approver-%d" % (i + 1),) + new_key() for i in range(args.approvers)]
    approver, approver_hex, approver_pub = approvers[0][1:]
    approver_ids = ",".join(a[0] for a in approvers)
    approver_pubs = ",".join(a[3] for a in approvers)
    idp, idp_hex, idp_pub = new_key()
    executor, executor_hex, executor_pub = new_key()
    exp = int((datetime.now(timezone.utc) + timedelta(days=args.token_days)).timestamp())
    client_token = encode({"sub": PRINCIPAL, "aud": "gargoyle-issuer", "exp": exp}, idp, "idp-1")
    # One identity token per approver, named by the key id it travels with and
    # carrying the approver role: the issuer shows the whole queue to approvers
    # and only a person's own holds to anyone else.
    def approver_token_for(kid: str) -> str:
        return encode({"sub": kid, "roles": [DEFAULT_APPROVER_ROLE], "aud": "gargoyle-issuer", "exp": exp}, idp, "idp-1")
    issuer_url = args.issuer_url or "http://%s:%d" % (args.host, args.port)

    rules = out / "rules.json"
    if args.observe:
        rc = _observe_rules(rules)
        if rc:
            return rc
    elif not rules.exists():
        _write(rules, json.dumps(CLAUDE_CODE_RULES if claude_code else DEFAULT_RULES, indent=2) + "\n")
    _write(out / "issuer.env", _env_lines({
        "GARGOYLE_ISSUER_KEY_ID": "issuer-1", "GARGOYLE_ISSUER_KEY_HEX": issuer_hex,
        "GARGOYLE_IDP_KEY_ID": "idp-1", "GARGOYLE_IDP_PUBLIC_KEY_HEX": idp_pub, "GARGOYLE_IDP_KEY_HEX": idp_hex,
        "GARGOYLE_ISSUER_AUDIENCE": "gargoyle-issuer",
        "GARGOYLE_APPROVER_KEY_ID": approver_ids, "GARGOYLE_APPROVER_PUBLIC_KEY_HEX": approver_pubs,
        "GARGOYLE_RULES_PATH": str(rules), "GARGOYLE_RECEIPT_TTL_SECONDS": "600",
        **({"GARGOYLE_ENTRA_TENANT": args.entra_tenant} if args.entra_tenant else {}),
        **({"GARGOYLE_ISSUER_AUDIENCE": args.entra_audience} if args.entra_audience else {}),
    }), private=True)
    middleware_env = {
        "GARGOYLE_MCP_GATE_KEY_ID": "issuer-1", "GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX": issuer_pub,
        "GARGOYLE_MCP_TARGET_ID": ("claude-code://" if claude_code else "mcp://filesystem/") + allowed, "GARGOYLE_MCP_PRINCIPAL": PRINCIPAL,
        "GARGOYLE_MCP_RECORD_PATH": client_dir + sep + "record.json",
        "GARGOYLE_MCP_RECORD_URL": issuer_url + "/record",       # follow the issuer's signed pin; the file is the offline fallback
        "GARGOYLE_MCP_APPROVER_KEY_ID": approver_ids, "GARGOYLE_MCP_APPROVER_PUBLIC_KEY_HEX": approver_pubs,
        "GARGOYLE_MCP_EXECUTOR_KEY_ID": "executor-1", "GARGOYLE_MCP_EXECUTOR_KEY_HEX": executor_hex,
        "GARGOYLE_MCP_ISSUER_URL": issuer_url, "GARGOYLE_MCP_CLIENT_TOKEN": client_token,
        "GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS": "300",
        "GARGOYLE_MCP_AUDIT_LOG": client_dir + sep + "audit.jsonl",
    }
    _write(out / "middleware.env", _env_lines(middleware_env), private=True)
    b64url = lambda b: __import__("base64").urlsafe_b64encode(b).rstrip(b"=").decode()
    for n, (kid, _k, khex, kpub) in enumerate(approvers, 1):
        approver_token = approver_token_for(kid)
        # approver.env / approver-web.json for the first; -2, -3 ... for the others.
        suffix = "" if n == 1 else "-%d" % n
        _write(out / ("approver%s.env" % suffix), _env_lines({
            "GARGOYLE_APPROVER_KEY_ID": kid, "GARGOYLE_APPROVER_KEY_HEX": khex,
            "GARGOYLE_APPROVER_TOKEN": approver_token, "GARGOYLE_ISSUER_URL": issuer_url,
        }), private=True)
        _write(out / ("approver-web%s.json" % suffix), json.dumps({
            "key_id": kid, "token": approver_token, "issuer_url": issuer_url, "grant_ttl_seconds": 300,
            "jwk": {"kty": "OKP", "crv": "Ed25519", "d": b64url(bytes.fromhex(khex)), "x": b64url(bytes.fromhex(kpub))},
        }, indent=2) + "\n", private=True)
    _write(out / "public-keys.json", json.dumps({
        "issuer": {"issuer-1": issuer_pub}, "approver": {a[0]: a[3] for a in approvers},
        "executor": {"executor-1": executor_pub}, "identity_provider": {"idp-1": idp_pub},
    }, indent=2) + "\n")
    _write(out / "gargoyle-issuer.service", """[Unit]
Description=Gargoyle issuing service
After=network-online.target

[Service]
User=gargoyle
WorkingDirectory=%(out)s
ExecStart=%(python)s -m gargoyle.cli issuer --out %(out)s --host 127.0.0.1 --port %(port)d
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
""" % {"out": str(out), "python": sys.executable, "port": args.port})
    _write(out / "apache-gargoyle.conf", """# Apache in front of the issuer: TLS from a trusted CA, one virtual host.
<VirtualHost *:443>
    ServerName %(host)s
    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/gargoyle.crt
    SSLCertificateKeyFile /etc/ssl/private/gargoyle.key
    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:%(port)d/
    ProxyPassReverse / http://127.0.0.1:%(port)d/
    ErrorLog  ${APACHE_LOG_DIR}/gargoyle-error.log
    # Remote-mode capability URLs carry a bearer token in the path; keep them out of the access log.
    SetEnvIf Request_URI "^/mcp/" gargoyle_capability_url
    CustomLog ${APACHE_LOG_DIR}/gargoyle-access.log combined env=!gargoyle_capability_url
</VirtualHost>
""" % {"host": (args.issuer_url or "gargoyle.example").replace("https://", "").replace("http://", "").split("/")[0].split(":")[0], "port": args.port})
    if claude_code:
        # The hook reads middleware.env itself, so the settings entry carries
        # no secrets and can go into a project, user or managed settings file.
        fwd = lambda s_: s_.replace("\\", "/")
        hook = '"%s" -m gargoyle hook --env "%s"' % (fwd(client_python), fwd(client_dir + sep + "middleware.env"))
        wait = int(middleware_env["GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS"]) + 30
        _write(out / "claude-settings.json", json.dumps({"hooks": {
            "PreToolUse": [{"hooks": [{"type": "command", "command": hook, "timeout": wait}]}],
            "PostToolUse": [{"hooks": [{"type": "command", "command": hook, "timeout": 60}]}],
            "PostToolUseFailure": [{"hooks": [{"type": "command", "command": hook, "timeout": 60}]}],
            "PermissionDenied": [{"hooks": [{"type": "command", "command": hook, "timeout": 60}]}],
        }}, indent=2) + "\n")
    else:
        upstream = (["npx", "-y", "@modelcontextprotocol/server-filesystem", allowed] if args.upstream == "npx-filesystem"
                    else [client_python, "-m", "gargoyle.fs_server", allowed])
        _write(out / "mcp-config.json", json.dumps({"mcpServers": {"filesystem-gargoyle": {
            "command": client_python,
            "args": ["-m", "gargoyle.mcp_server", "--", *upstream],
            "env": middleware_env,
        }}}, indent=2) + "\n", private=True)
    print("\nnext:  gargoyle issuer --out %s        (keeps running; writes record.json on start)" % out)
    if claude_code:
        print("       copy middleware.env (and record.json) to %s on the workstation" % client_dir)
        print("       merge claude-settings.json's hooks into the workstation's settings (managed settings for a fleet)")
    else:
        print("       paste mcp-config.json's server entry into your MCP client, restart it")
    print("       gargoyle approve --out %s --watch 2  (on the approver's machine)" % out)
    print("       or open %s/approve in a browser and load approver-web.json" % issuer_url)
    return 0


def cmd_hook(args) -> int:
    from gargoyle.claude_hook import run_hook
    return run_hook((["--env", args.env] if args.env else []) + (["--final"] if args.final else []))


def cmd_tokens(args) -> int:
    """New identity tokens from the deployment's existing identity key: the
    client's shared token (unless the client signs in with Entra, whose
    token renews itself) and every file-key approver's. Nothing else
    changes, so clients keep their keys and the audit its trust."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from gargoyle.jws import encode
    out = Path(args.out).resolve()
    issuer_env = out / "issuer.env"
    if not issuer_env.exists():
        print("%s holds no deployment (no issuer.env)" % out, file=sys.stderr)
        return 2
    env = _read_env(issuer_env)
    idp_hex = env.get("GARGOYLE_IDP_KEY_HEX")
    if not idp_hex:
        print("issuer.env keeps no identity key (a deployment older than 0.9); make a fresh one with `gargoyle init` to a new --out", file=sys.stderr)
        return 2
    idp = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(idp_hex))
    kid = env.get("GARGOYLE_IDP_KEY_ID", "idp-1")
    exp = int((datetime.now(timezone.utc) + timedelta(days=args.token_days)).timestamp())
    mw = out / "middleware.env"
    if mw.exists():
        menv = _read_env(mw)
        if "GARGOYLE_MCP_CLIENT_TOKEN" in menv:
            menv["GARGOYLE_MCP_CLIENT_TOKEN"] = encode({"sub": menv.get("GARGOYLE_MCP_PRINCIPAL", PRINCIPAL), "aud": "gargoyle-issuer", "exp": exp}, idp, kid)
            _write(mw, _env_lines(menv), private=True)
            mcp = out / "mcp-config.json"
            if mcp.exists():
                doc = json.loads(mcp.read_text())
                for server in doc.get("mcpServers", {}).values():
                    if "GARGOYLE_MCP_CLIENT_TOKEN" in server.get("env", {}):
                        server["env"]["GARGOYLE_MCP_CLIENT_TOKEN"] = menv["GARGOYLE_MCP_CLIENT_TOKEN"]
                _write(mcp, json.dumps(doc, indent=2) + "\n", private=True)
        else:
            print("middleware.env signs in with Entra; that token renews itself and was left alone")
    for env_path in sorted(out.glob("approver*.env")):
        aenv = _read_env(env_path)
        akid = aenv.get("GARGOYLE_APPROVER_KEY_ID")
        if not akid:
            continue
        tok = encode({"sub": akid, "roles": [DEFAULT_APPROVER_ROLE], "aud": "gargoyle-issuer", "exp": exp}, idp, kid)
        aenv["GARGOYLE_APPROVER_TOKEN"] = tok
        _write(env_path, _env_lines(aenv), private=True)
        web = out / env_path.name.replace("approver", "approver-web", 1).replace(".env", ".json")
        if web.exists():
            doc = json.loads(web.read_text())
            doc["token"] = tok
            _write(web, json.dumps(doc, indent=2) + "\n", private=True)
    print("new tokens, valid %d days; copy middleware.env (and approver-web*.json) to the machines that use them and restart their MCP clients" % args.token_days)
    return 0


def cmd_login(args) -> int:
    """Device-code sign-in; then middleware.env (and mcp-config.json when
    present) switch from the shared init token to this user's Entra token,
    and the principal becomes their UPN."""
    from gargoyle.entra_login import (ENV_ENTRA_CLIENT_ID, ENV_ENTRA_SCOPE, ENV_ENTRA_TENANT, ENV_ENTRA_TOKEN_CACHE,
                                      device_code_login)
    out = Path(args.out).resolve()
    client_dir = Path(args.client_config_dir or out)
    cache = client_dir / "entra-token-cache.json"
    result = device_code_login(args.tenant, args.client_id, args.scope, str(cache))
    principal = result["principal"]
    env_path = out / "middleware.env"
    env = _read_env(env_path) if env_path.exists() else {}
    env.pop("GARGOYLE_MCP_CLIENT_TOKEN", None)
    env.update({ENV_ENTRA_TENANT: args.tenant, ENV_ENTRA_CLIENT_ID: args.client_id, ENV_ENTRA_SCOPE: args.scope,
                ENV_ENTRA_TOKEN_CACHE: str(cache), "GARGOYLE_MCP_PRINCIPAL": principal})
    _write(env_path, _env_lines(env), private=True)
    mcp = out / "mcp-config.json"
    if mcp.exists():
        doc = json.loads(mcp.read_text())
        for server in doc.get("mcpServers", {}).values():
            if "GARGOYLE_MCP_TARGET_ID" in server.get("env", {}):
                server["env"].pop("GARGOYLE_MCP_CLIENT_TOKEN", None)
                server["env"].update({k: env[k] for k in (ENV_ENTRA_TENANT, ENV_ENTRA_CLIENT_ID, ENV_ENTRA_SCOPE,
                                                            ENV_ENTRA_TOKEN_CACHE, "GARGOYLE_MCP_PRINCIPAL")})
        _write(mcp, json.dumps(doc, indent=2) + "\n", private=True)
    print("signed in as %s; the middleware now acts as that user (restart the MCP client)" % principal)
    return 0


def cmd_remote_token(args) -> int:
    """Mint one person's capability token for the remote gate: an identity
    token the issuer trusts for that principal (signed by the pinned IdP key
    from init), mapped to a random URL segment in remote-tokens.json."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from gargoyle.remote import TokenMap, mint_identity_token
    out = Path(args.out).resolve()
    ienv = _read_env(out / "issuer.env")
    idp = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ienv["GARGOYLE_IDP_KEY_HEX"])) if "GARGOYLE_IDP_KEY_HEX" in ienv else None
    if idp is None:
        # init keeps the IdP private key only in the approver/client tokens' lineage; derive from the stored seed if present
        raise SystemExit("issuer.env has no GARGOYLE_IDP_KEY_HEX; run `gargoyle init` from this version first")
    audience = (ienv.get("GARGOYLE_ISSUER_AUDIENCE") or "gargoyle-issuer").split(",")[0].strip()
    token = mint_identity_token(args.principal, idp, ienv.get("GARGOYLE_IDP_KEY_ID", "idp-1"), audience, days=args.days)
    tokens = TokenMap(str(out / "remote-tokens.json"))
    cap = tokens.mint(args.principal, token)
    base = args.url or _read_env(out / "middleware.env").get("GARGOYLE_MCP_ISSUER_URL", "https://<gate host>")
    print("remote-tokens.json updated for %s" % args.principal)
    print("connector URL (treat as a credential): %s/mcp/%s" % (base.rstrip("/"), cap))
    return 0


def cmd_remote(args) -> int:
    """Run the gate as a Streamable HTTP MCP server on the deployment's
    middleware settings, fronting a stdio command or a remote MCP server."""
    import uvicorn
    from gargoyle.mcp_server import config_from_env, upstream_from_argv
    from gargoyle.remote import HttpUpstream, TokenMap, build_remote_app
    out = Path(args.out).resolve()
    env = _read_env(out / "middleware.env")
    env.setdefault("GARGOYLE_MCP_PRINCIPAL", "remote")        # each token supplies the real one
    env.setdefault("GARGOYLE_MCP_RECORD_PATH", str(out / "record.json"))
    os.environ.update(env)
    config = config_from_env()
    if config is None:
        raise SystemExit("middleware.env in %s is incomplete" % out)
    config.pop("principal", None)
    if args.upstream_url:
        upstream = HttpUpstream(args.upstream_url, args.upstream_token or os.environ.get("GARGOYLE_MCP_UPSTREAM_TOKEN"))
    else:
        upstream = upstream_from_argv(args.rest)
        if upstream is None:
            raise SystemExit("give --upstream-url URL or `-- <command>` for the server to front")
    tokens = TokenMap(str(out / "remote-tokens.json"))
    app = build_remote_app(config, tokens, upstream=upstream, issuer_url=env.get("GARGOYLE_MCP_ISSUER_URL"),
                           audit_log=env.get("GARGOYLE_MCP_AUDIT_LOG") or str(out / "remote-audit.jsonl"),
                           state_probe=args.state_probe, snapshot_dir=env.get("GARGOYLE_MCP_SNAPSHOT_DIR"),
                           adapter_spec=args.adapter_spec or env.get("GARGOYLE_MCP_ADAPTER_SPEC"),
                           approval_timeout=float(env.get("GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS", "300")))
    tls = {}
    if args.ssl_certfile or args.ssl_keyfile:
        if not (args.ssl_certfile and args.ssl_keyfile):
            raise SystemExit("--ssl-certfile and --ssl-keyfile go together")
        tls = {"ssl_certfile": args.ssl_certfile, "ssl_keyfile": args.ssl_keyfile}
    print("remote gate on %s://%s:%d/mcp/<token>" % ("https" if tls else "http", args.host, args.port), file=sys.stderr)
    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="info" if args.verbose else "warning", **tls)
    finally:
        upstream.close()
    return 0


def cmd_issuer(args) -> int:
    import uvicorn
    from gargoyle.issuer_service import app_from_env, redact_access_log

    out = Path(args.out).resolve()
    os.environ.update(_read_env(out / "issuer.env"))
    os.environ.setdefault("GARGOYLE_APPROVERS_PATH", str(out / "approvers.json"))   # enrolled approvers live beside the keys
    os.environ.setdefault("GARGOYLE_HOLDS_PATH", str(out / "holds.sqlite"))          # holds, grants, declines, plans survive restarts
    os.environ.setdefault("GARGOYLE_WITNESS_PATH", str(out / "witness.jsonl"))       # the issuer's signed record, for reconciliation
    os.environ.setdefault("GARGOYLE_LOG_JSON", "1")
    app = app_from_env()
    redact_access_log()                     # no sign-in codes in the access log
    # The middleware reads the policy pin from a file; write it next to the
    # config so the client-side entry finds it at the configured path.
    from gargoyle.rules import RulesPolicy
    policy = RulesPolicy(os.environ["GARGOYLE_RULES_PATH"])
    (out / "record.json").write_text(json.dumps(policy.pin(), indent=2) + "\n")
    tls = {}
    if args.ssl_certfile or args.ssl_keyfile:
        if not (args.ssl_certfile and args.ssl_keyfile):
            raise SystemExit("--ssl-certfile and --ssl-keyfile go together")
        tls = {"ssl_certfile": args.ssl_certfile, "ssl_keyfile": args.ssl_keyfile}
    print("record.json written; serving on %s://%s:%d" % ("https" if tls else "http", args.host, args.port), file=sys.stderr)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info" if args.verbose else "warning", **tls)
    return 0


def cmd_approve(args) -> int:
    from gargoyle.approver_cli import main as approver_main

    env = _read_env(Path(args.out).resolve() / "approver.env")
    os.environ.update(env)
    argv = ["--issuer", env.get("GARGOYLE_ISSUER_URL", "http://127.0.0.1:8080")]
    if args.watch:
        argv += ["--watch", str(args.watch)]
    if args.yes:
        argv.append("--yes")
    return approver_main(argv)


def cmd_approvers(args) -> int:
    """List the enrolled approvers, or revoke one. Works on the issuer's
    approvers.json; the running service re-reads the file, so a revocation
    takes effect without a restart and reaches the middleware at its next
    held call."""
    from gargoyle.approvers import ApproverRegistry

    reg = ApproverRegistry(str(Path(args.out).resolve() / "approvers.json"))
    if args.action == "list":
        entries = reg.entries()
        if not entries:
            print("no enrolled approvers (configured approver keys are in issuer.env)")
        for upn, e in sorted(entries.items()):
            print("%s  enrolled %s  key %s%s" % (upn, e.get("enrolled_at", "?"), e["public_key_hex"][:16],
                                                  ("  oid " + e["oid"]) if e.get("oid") else ""))
        revoked = reg.revoked_entries()
        if revoked:
            print("revoked: " + ", ".join("%s (key %s, %s by %s)" % (u, e["public_key_hex"][:16], e.get("revoked_at", "?")[:19], e.get("revoked_by", "?"))
                                          for u, e in sorted(revoked.items())))
        return 0
    import getpass
    if reg.revoke(args.upn, revoked_by="operator:" + getpass.getuser()):
        print("revoked %s; grants under that key are refused from now on, earlier ones still audit" % args.upn)
        return 0
    print("%s is not an enrolled approver" % args.upn, file=sys.stderr)
    return 1


def _zone_label(t: datetime) -> str:
    """A short name for t's zone: the abbreviation where the platform gives
    one (EDT), "UTC" at zero offset, else the offset (Windows names zones
    in words: "Coordinated Universal Time", "Eastern Daylight Time")."""
    off = t.utcoffset()
    if off is None or off.total_seconds() == 0:
        return "UTC"
    name = t.tzname() or ""
    if name and " " not in name and len(name) <= 6:
        return name
    words = [w for w in name.split() if w[0].isupper()]
    if 2 <= len(words) <= 4:
        return "".join(w[0] for w in words)        # Eastern Daylight Time -> EDT
    secs = int(off.total_seconds())
    return "UTC%s%02d:%02d" % ("+" if secs >= 0 else "-", abs(secs) // 3600, abs(secs) % 3600 // 60)


def cmd_witness(args) -> int:
    """Print the issuer's witness log as a table an operator reads: when,
    event, who, tool, outcome. A rendering of the file, not a verification
    of it (`gargoyle audit --witness` does that). `--follow` keeps printing
    as the issuer appends, which is how an observe-mode week is watched
    from the issuer's own shell, with no sign-in."""
    import time
    from gargoyle.witness import describe, read_witness
    path = Path(args.path)
    if not path.exists():
        print("%s does not exist; the issuer writes it where GARGOYLE_WITNESS_PATH points (the deployment folder)" % path, file=sys.stderr)
        return 2
    # The file holds UTC; the table shows this machine's local time (the
    # console shows the browser's), named in the header. --utc keeps the
    # file's own clock, for comparing against an audit.
    zone = "UTC" if args.utc else _zone_label(datetime.now().astimezone())
    print("  %-19s %-14s %-30s %-22s %s" % ("at (%s)" % zone, "event", "who", "tool", "outcome"))

    def when(iso: str) -> str:
        try:
            t = datetime.fromisoformat(iso)
        except ValueError:
            return iso[:19].replace("T", " ")
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return (t.astimezone(timezone.utc) if args.utc else t.astimezone()).strftime("%Y-%m-%d %H:%M:%S")

    def show(entry) -> None:
        d = describe(entry)
        print("  %-19s %-14s %-30s %-22s %s%s" % (when(d["at"]), d["event"][:14], d["who"][:30], d["tool"][:22], d["outcome"],
                                                  ("  " + d["ref"]) if d["ref"] and args.refs else ""))

    entries = read_witness(str(path))
    shown = entries[-args.tail:] if args.tail > 0 else entries
    for e in shown:
        show(e)
    if not args.follow:
        return 0
    seen = len(entries)
    try:
        while True:
            time.sleep(args.interval)
            entries = read_witness(str(path))
            if len(entries) < seen:
                print("  (the witness file was replaced; showing it from the start)")
                seen = 0
            for e in entries[seen:]:
                show(e)
            seen = len(entries)
            sys.stdout.flush()
    except KeyboardInterrupt:
        return 0


def _audit_summary(report, raw) -> None:
    """Calls by principal and tool with their outcomes, then who released
    and which clients: a week of observe mode as a table, the input for
    writing the hold and deny rules."""
    from collections import Counter
    counts: Dict[tuple, Counter] = {}
    releases: Counter = Counter()
    clients: Counter = Counter()
    ats = [e.get("at") for e in raw if isinstance(e, dict) and isinstance(e.get("at"), str)]
    from gargoyle.evidence import FAILED_VERDICTS
    for r in report:
        kind = r["kind"] or "?"
        if kind == "honored" and r.get("verdict") in FAILED_VERDICTS:
            kind = "failed"            # admitted, but the upstream did not do it
        counts.setdefault((r["principal"] or "?", r["tool"] or "?"), Counter())[kind] += 1
        for who in r.get("released_by") or []:
            releases[who] += 1
        clients[r.get("client") or "(client unnamed)"] += 1
    print("summary: %d call(s)%s" % (len(report), (", %s to %s" % (min(ats)[:19], max(ats)[:19])) if ats else ""))
    print("  %-28s %-24s %7s %7s %7s" % ("principal", "tool", "honored", "failed", "refused"))
    for (principal, tool), c in sorted(counts.items(), key=lambda kv: (kv[0][0], -sum(kv[1].values()), kv[0][1])):
        print("  %-28s %-24s %7d %7d %7d" % (principal[:28], tool[:24], c.get("honored", 0), c.get("failed", 0), c.get("refused", 0)))
    if releases:
        print("  releases: " + ", ".join("%s %d" % (w, n) for w, n in releases.most_common()))
    print("  clients: " + ", ".join("%s %d" % (w, n) for w, n in clients.most_common()))


def _trust_hex(out: Path) -> "tuple[Dict[str, Any], Dict[str, Any]]":
    """public-keys.json plus, when present, every key each enrolled approver
    ever held (approvers.json, current first): grants signed under a key
    since replaced in the browser or revoked still have to verify. Only the
    live service and middleware are limited to the current key. Copy the
    issuer's file beside the evidence first. Returns (keys, approvers_hex)."""
    keys = json.loads((out / "public-keys.json").read_text())
    approvers: Dict[str, Any] = dict(keys["approver"])
    enrolled = out / "approvers.json"          # approvers who enrolled through Entra, by UPN
    if enrolled.exists():
        from gargoyle.approvers import ApproverRegistry
        approvers.update(ApproverRegistry(str(enrolled)).audit_keys_hex())
    return keys, approvers


def cmd_emilia(args) -> int:
    """Export an evidence log's honored, approved calls as EMILIA Trust
    Receipts (docs/interop-emilia.md): one file in the format EMILIA's
    conformance runners read, every receipt carrying the signoff the
    approver's console made, the whole set under one Merkle checkpoint
    signed by this gate's executor key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from gargoyle.emilia import trust_receipts_from_entries, verification_for
    from gargoyle.evidence import read_log
    out = Path(args.out).resolve()
    keys, approvers = _trust_hex(out)
    env = _read_env(Path(args.env or (out / "middleware.env")))
    if "GARGOYLE_MCP_EXECUTOR_KEY_HEX" not in env:
        print("%s has no GARGOYLE_MCP_EXECUTOR_KEY_HEX; point --env at this gate's middleware.env" % (args.env or out / "middleware.env"), file=sys.stderr)
        return 2
    executor = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(env["GARGOYLE_MCP_EXECUTOR_KEY_HEX"]))
    log_key_id = env.get("GARGOYLE_MCP_EXECUTOR_KEY_ID", "executor-1")
    result = trust_receipts_from_entries(read_log(args.log), log_signing_key=executor, log_key_id=log_key_id)
    vectors = [{"id": r["receipt_id"], "expect": {"valid": True}, "trust_receipt": r,
                "verification": verification_for(r, approvers, executor.public_key())} for r in result["receipts"]]
    missing = [v["id"] for v in vectors if len(v["verification"]["approver_keys"]) < len(v["trust_receipt"]["signoffs"])]
    doc = {"suite": "GARGOYLE EP-TRUST-RECEIPT-v1 export", "source": "gargoyle-receipts", "log": str(Path(args.log).resolve()),
           "exported_at": datetime.now(timezone.utc).isoformat(), "count": len(vectors), "vectors": vectors}
    _write(Path(args.write), json.dumps(doc, indent=1) + "\n")
    print("%d trust receipts under one checkpoint (tree size %d) -> %s; %d approved calls skipped (no console signoff on every grant)%s"
          % (len(vectors), len(vectors), args.write, result["skipped"],
             ("; %d receipts name an approver key not in %s/public-keys.json or approvers.json" % (len(missing), out)) if missing else ""))
    return 0


def cmd_audit(args) -> int:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from gargoyle.execution import verify_chain

    keys, approvers = _trust_hex(Path(args.out).resolve())
    one = lambda h: Ed25519PublicKey.from_public_bytes(bytes.fromhex(h))
    load = lambda m: {k: ([one(x) for x in v] if isinstance(v, list) else one(v)) for k, v in m.items()}
    trust = dict(issuer_public_keys=load(keys["issuer"]), executor_public_keys=load(keys["executor"]),
                 approver_public_keys=load(approvers))
    if args.log:
        # The middleware's evidence log: every decision, honored or refused,
        # hash-chained. Each honored entry is a full receipt chain.
        from gargoyle.evidence import read_log, verify_log
        v = verify_log(read_log(args.log), **trust)
        for r in v["entries"]:
            # A refused row shows why the executor refused, beside the check outcome.
            why = (" (%s)" % r["verdict"]) if r["kind"] == "refused" and r["verdict"] else ""
            if r.get("released_by"):
                why += " released by " + ", ".join(r["released_by"])
            if r.get("plan"):
                why += " (plan %s step %d)" % (str(r["plan"].get("plan_id") or "?")[:8], r["plan"].get("step", -1) + 1)
            if r.get("state"):
                # A state-bound call: the target as it was approved, and as the run left it.
                pre, post = (r["state"].get("pre") or "")[:8], (r["state"].get("post") or "")[:8]
                why += " state %s -> %s" % (pre or "?", post or "?") if post else " state %s" % pre
            if r.get("reverts"):
                why += " reverts #%d" % r["reverts"]
            if r.get("client"):
                why += " via " + r["client"]
            print("%4s %-5s %-8s %-24s %-28s %s%s" % (r["seq"] if r["seq"] is not None else "?",
                                                      "ok" if r["accepted"] else "FAIL", r["kind"] or "?",
                                                      (r["tool"] or "?")[:24], (r["principal"] or "?")[:28], r["reason"], why))
        failed = sum(1 for r in v["entries"] if not r["accepted"])
        print("%d entries (%d honored, %d refused), %d failed; chain %s; tail %s"
              % (v["count"], v["honored"], v["refused"], failed, v["reason"], v["tail_sha256"][:16]))
        rc = 0 if v["accepted"] else 1
        entries = read_log(args.log)
        if args.summary:
            _audit_summary(v["entries"], entries)
        if args.witness and not Path(args.witness).exists():
            print("witness file not found: %s (copy the issuer's witness.jsonl here first)" % args.witness, file=sys.stderr)
            return 2
        if args.check_tree and not Path(args.check_tree).is_dir():
            print("not a directory: %s" % args.check_tree, file=sys.stderr)
            return 2
        if args.witness:
            # The issuer's signed record: the client's evidence must agree with it.
            from gargoyle.reconcile import reconcile
            from gargoyle.witness import read_witness, verify_witness
            w = verify_witness(read_witness(args.witness), issuer_public_keys=trust["issuer_public_keys"])
            print("witness: %d entries, %s, tail %s" % (w["count"], w["reason"], w["tail_sha256"][:16]))
            principal = next((e.get("principal") for e in entries if isinstance(e, dict) and e.get("principal")), None)
            r = reconcile(entries, read_witness(args.witness), principal=principal)
            older = [f for f in r["findings"] if f["finding"] == "PREDATES_WITNESS"]
            for f in r["findings"]:
                if f["finding"] == "PREDATES_WITNESS":
                    continue
                print("  FINDING %-22s %s" % (f["finding"], " ".join("%s=%s" % (k, str(v)[:40]) for k, v in f.items() if k != "finding")))
            if older:
                print("  note: %d honored row(s) predate the witness (started %s) and cannot be vouched for either way: seq %s"
                      % (len(older), (r.get("horizon") or "?")[:19], ", ".join(str(f["seq"]) for f in older[:12]) + (" ..." if len(older) > 12 else "")))
            hard = len(r["findings"]) - len(older)
            print("reconciled: %d issued by the issuer, %d in evidence, %d finding(s)" % (r["issued"], r["evidence_with_receipt"], hard))
            rc = rc or (0 if (w["accepted"] and r["accepted"]) else 1)
        if args.check_tree:
            # Every file the gate wrote must still be as the gate left it.
            from gargoyle.reconcile import check_tree
            t = check_tree(entries, args.check_tree)
            for f in t["findings"]:
                print("  FINDING %-22s %s%s" % (f["finding"], f["path"], " (missing)" if f.get("missing") else ""))
            print("tree: %d gated file(s) checked, %d untouched by the gate, %d changed outside it" % (t["checked"], t["untouched"], len(t["findings"])))
            rc = rc or (0 if t["accepted"] else 1)
        return rc
    receipt, execution = json.load(open(args.receipt)), json.load(open(args.execution))
    grant = json.load(open(args.grant)) if args.grant else None
    result = verify_chain(receipt, execution, grant=grant, **trust)
    for step, outcome in result["steps"]:
        print("%-14s %s" % (step, outcome))
    print("chain:", result["reason"])
    return 0 if result["accepted"] else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="gargoyle", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", help="generate keys, config and a rules file")
    p.add_argument("directory", help="the directory the agent's filesystem server may touch")
    p.add_argument("--out", default="gargoyle-deploy")
    p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=8080)
    p.add_argument("--token-days", type=int, default=30)
    p.add_argument("--issuer-url", help="URL the client reaches the issuer at (default http://HOST:PORT)")
    p.add_argument("--client-python", help="the client's Python executable for the MCP entry (default: this one)")
    p.add_argument("--client-config-dir", help="where the client keeps middleware.env, record.json, audit.jsonl (default: --out)")
    p.add_argument("--observe", action="store_true",
                   help="observe mode: allow and record every call, hold none; tighten rules.json later from the audit")
    p.add_argument("--approvers", type=int, default=1, metavar="N",
                   help="how many approver keys to create (approver-1..N); a rule with \"approvals\": 2 then needs two of them")
    p.add_argument("--upstream", choices=["npx-filesystem", "python-fs"], default="npx-filesystem",
                   help="the filesystem MCP server behind the gate: the official one via npx, or gargoyle.fs_server")
    p.add_argument("--entra-tenant", help="trust this Entra ID tenant's tokens at the issuer (users then run `gargoyle login`)")
    p.add_argument("--entra-audience", help="the issuer API app's client id or app id URI, required in Entra tokens")
    p.add_argument("--force", action="store_true",
                   help="regenerate keys and tokens in an existing --out (every client and approver must be re-provisioned)")
    p.add_argument("--client", choices=["mcp", "claude-code"], default="mcp",
                   help="mcp: the gate fronts a filesystem MCP server (mcp-config.json); claude-code: the gate is a Claude Code "
                        "hook over its own tools (claude-settings.json, rules for Write/Edit/Bash)")
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("hook", help="run as a Claude Code PreToolUse/PostToolUse hook (event on stdin, decision on stdout)")
    p.add_argument("--env", help="the workstation's middleware.env")
    p.add_argument("--final", action="store_true", help="an allowed call also skips Claude Code's own permission prompt")
    p.set_defaults(fn=cmd_hook)
    p = sub.add_parser("tokens", help="mint new client and approver tokens from a deployment's existing keys")
    p.add_argument("--out", default="gargoyle-deploy")
    p.add_argument("--token-days", type=int, default=30)
    p.set_defaults(fn=cmd_tokens)
    p = sub.add_parser("login", help="sign this workstation's user in with Entra ID (device code)")
    p.add_argument("--tenant", required=True, help="tenant id or domain")
    p.add_argument("--client-id", required=True, help="the public client app registration")
    p.add_argument("--scope", required=True, help="the issuer API scope, e.g. api://<api-client-id>/access")
    p.add_argument("--out", default="gargoyle-deploy", help="where middleware.env and mcp-config.json live")
    p.add_argument("--client-config-dir", help="where the token cache goes (default: --out)")
    p.set_defaults(fn=cmd_login)
    p = sub.add_parser("issuer", help="run the issuing service on the rules file")
    p.add_argument("--out", default="gargoyle-deploy")
    p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=8080)
    p.add_argument("--ssl-certfile"); p.add_argument("--ssl-keyfile")
    p.add_argument("--verbose", action="store_true", help="log every request")
    p.set_defaults(fn=cmd_issuer)
    p = sub.add_parser("approve", help="review and release held calls")
    p.add_argument("--out", default="gargoyle-deploy")
    p.add_argument("--watch", type=float, metavar="SECONDS"); p.add_argument("--yes", action="store_true")
    p.set_defaults(fn=cmd_approve)
    p = sub.add_parser("remote", help="run the gate as an HTTPS MCP server for hosted connectors")
    p.add_argument("--out", default="gargoyle-deploy")
    p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=8444)
    p.add_argument("--ssl-certfile"); p.add_argument("--ssl-keyfile")
    p.add_argument("--upstream-url", help="front a remote MCP server (Streamable HTTP)")
    p.add_argument("--upstream-token", help="bearer for that server (or GARGOYLE_MCP_UPSTREAM_TOKEN)")
    p.add_argument("--state-probe", default="none", choices=["none", "filesystem", "graph"],
                   help="filesystem when the upstream is a local filesystem server on this host; graph for a Microsoft Graph MCP server")
    p.add_argument("--adapter-spec", help="with --state-probe graph: the tool mapping JSON (default: the reference naming)")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("rest", nargs=argparse.REMAINDER, help="-- <command> for a stdio server to front")
    p.set_defaults(fn=cmd_remote)
    p = sub.add_parser("remote-token", help="mint one person's capability URL for the remote gate")
    p.add_argument("--out", default="gargoyle-deploy")
    p.add_argument("--principal", required=True, help="the UPN or principal the receipts will name")
    p.add_argument("--days", type=int, default=30, help="lifetime of the identity token inside the capability URL (default 30)")
    p.add_argument("--url", help="the gate's public base URL for the printed connector URL")
    p.set_defaults(fn=cmd_remote_token)
    p = sub.add_parser("approvers", help="list enrolled approvers, or revoke one on the issuer's host")
    p.add_argument("action", choices=["list", "revoke"])
    p.add_argument("upn", nargs="?", help="the approver to revoke")
    p.add_argument("--out", default="gargoyle-deploy")
    p.set_defaults(fn=cmd_approvers)
    p = sub.add_parser("witness", help="print the issuer's witness log as a table; --follow watches it grow")
    p.add_argument("path", nargs="?", default="gargoyle-deploy/witness.jsonl", help="the issuer's witness.jsonl")
    p.add_argument("--follow", "-f", action="store_true", help="keep printing new entries as the issuer writes them")
    p.add_argument("--tail", "-n", type=int, default=0, metavar="N", help="start with the last N entries only")
    p.add_argument("--interval", type=float, default=2.0, help="seconds between reads with --follow")
    p.add_argument("--refs", action="store_true", help="also print the decision, plan or hold id of each row")
    p.add_argument("--utc", action="store_true", help="show the file's UTC clock instead of this machine's local time")
    p.set_defaults(fn=cmd_witness)
    p = sub.add_parser("audit", help="verify a receipt chain offline, or a whole evidence log")
    p.add_argument("receipt", nargs="?"); p.add_argument("execution", nargs="?"); p.add_argument("grant", nargs="?")
    p.add_argument("--log", help="the middleware's audit.jsonl: verify every entry")
    p.add_argument("--witness", help="the issuer's witness.jsonl: reconcile the evidence against it")
    p.add_argument("--check-tree", metavar="DIR", help="verify every gated file under DIR is as the gate left it")
    p.add_argument("--summary", action="store_true", help="after the rows: calls by principal and tool with outcomes, releases, clients")
    p.add_argument("--out", default="gargoyle-deploy")
    p.set_defaults(fn=cmd_audit)
    p = sub.add_parser("emilia", help="export an evidence log's approved calls as EMILIA Trust Receipts")
    p.add_argument("--log", required=True, help="the middleware's audit.jsonl")
    p.add_argument("--write", default="emilia-trust-receipts.json", help="output file, in the format EMILIA's conformance runners read")
    p.add_argument("--env", help="this gate's middleware.env (executor key signs the checkpoint); default <out>/middleware.env")
    p.add_argument("--out", default="gargoyle-deploy")
    p.set_defaults(fn=cmd_emilia)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
