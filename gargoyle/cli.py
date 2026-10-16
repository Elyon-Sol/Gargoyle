"""The `gargoyle` command: set up, run and operate a deployment without a
policy engine, a container runtime, or any client changes.

    gargoyle init <dir-the-agent-may-touch> [--out DIR]   keys, config, rules file
    gargoyle issuer [--out DIR] [--port 8080]            run the issuing service
    gargoyle approve [--out DIR] [--watch SECONDS]       sit and approve held calls
    gargoyle audit <receipt.json> <execution.json> [grant.json]

`init` writes, into --out (default: ./gargoyle-deploy):

    rules.json        the policy: reads free, writes held, the rest denied; edit it
    issuer.env        the issuer's key and trust (private)
    middleware.env    what the MCP client's server entry needs (private)
    approver.env      the approver's key and token (private; move it to the
                      approver's machine)
    mcp-config.json   the server entry to paste into the MCP client
    public-keys.json  issuer, approver and executor public keys, for audits

Then: `gargoyle issuer` in one terminal, the server entry in the client,
`gargoyle approve --watch 2` where the approver sits. Everything the
middleware honors comes back with receipt, grant and execution receipt in
the response metadata; `gargoyle audit` verifies them later, offline.
"""

import argparse
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PRINCIPAL = "spiffe://gargoyle.local/agents/assistant"

DEFAULT_RULES = {
    "version": "1",
    "default": "deny",
    "rules": [
        {"tools": ["read_*", "list_*", "get_*", "search_*", "directory_tree"], "action": "allow"},
        {"tools": ["write_file", "edit_file", "create_directory", "move_file"], "action": "hold"},
        {"tools": ["delete_*", "remove_*", "rm*"], "action": "deny", "reason": "DESTRUCTIVE_TOOL"},
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


def cmd_init(args) -> int:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
    from gargoyle.jws import encode

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    allowed = str(Path(args.directory).resolve())

    def new_key():
        k = Ed25519PrivateKey.generate()
        return (k, k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())

    issuer, issuer_hex, issuer_pub = new_key()
    approver, approver_hex, approver_pub = new_key()
    idp, idp_hex, idp_pub = new_key()
    executor, executor_hex, executor_pub = new_key()
    exp = int((datetime.now(timezone.utc) + timedelta(days=args.token_days)).timestamp())
    client_token = encode({"sub": PRINCIPAL, "aud": "gargoyle-issuer", "exp": exp}, idp, "idp-1")
    approver_token = encode({"sub": "approver", "aud": "gargoyle-issuer", "exp": exp}, idp, "idp-1")
    issuer_url = "http://%s:%d" % (args.host, args.port)

    rules = out / "rules.json"
    if not rules.exists():
        _write(rules, json.dumps(DEFAULT_RULES, indent=2) + "\n")
    _write(out / "issuer.env", _env_lines({
        "GARGOYLE_ISSUER_KEY_ID": "issuer-1", "GARGOYLE_ISSUER_KEY_HEX": issuer_hex,
        "GARGOYLE_IDP_KEY_ID": "idp-1", "GARGOYLE_IDP_PUBLIC_KEY_HEX": idp_pub,
        "GARGOYLE_ISSUER_AUDIENCE": "gargoyle-issuer",
        "GARGOYLE_APPROVER_KEY_ID": "approver-1", "GARGOYLE_APPROVER_PUBLIC_KEY_HEX": approver_pub,
        "GARGOYLE_RULES_PATH": str(rules), "GARGOYLE_RECEIPT_TTL_SECONDS": "600",
    }), private=True)
    middleware_env = {
        "GARGOYLE_MCP_GATE_KEY_ID": "issuer-1", "GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX": issuer_pub,
        "GARGOYLE_MCP_TARGET_ID": "mcp://filesystem/" + allowed, "GARGOYLE_MCP_PRINCIPAL": PRINCIPAL,
        "GARGOYLE_MCP_RECORD_PATH": str(out / "record.json"),
        "GARGOYLE_MCP_APPROVER_KEY_ID": "approver-1", "GARGOYLE_MCP_APPROVER_PUBLIC_KEY_HEX": approver_pub,
        "GARGOYLE_MCP_EXECUTOR_KEY_ID": "executor-1", "GARGOYLE_MCP_EXECUTOR_KEY_HEX": executor_hex,
        "GARGOYLE_MCP_ISSUER_URL": issuer_url, "GARGOYLE_MCP_CLIENT_TOKEN": client_token,
        "GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS": "300",
    }
    _write(out / "middleware.env", _env_lines(middleware_env), private=True)
    _write(out / "approver.env", _env_lines({
        "GARGOYLE_APPROVER_KEY_ID": "approver-1", "GARGOYLE_APPROVER_KEY_HEX": approver_hex,
        "GARGOYLE_APPROVER_TOKEN": approver_token, "GARGOYLE_ISSUER_URL": issuer_url,
    }), private=True)
    _write(out / "public-keys.json", json.dumps({
        "issuer": {"issuer-1": issuer_pub}, "approver": {"approver-1": approver_pub},
        "executor": {"executor-1": executor_pub}, "identity_provider": {"idp-1": idp_pub},
    }, indent=2) + "\n")
    _write(out / "mcp-config.json", json.dumps({"mcpServers": {"filesystem-gargoyle": {
        "command": sys.executable,
        "args": ["-m", "gargoyle.mcp_server", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", allowed],
        "env": middleware_env,
    }}}, indent=2) + "\n", private=True)
    print("\nnext:  gargoyle issuer --out %s        (keeps running; writes record.json on start)" % out)
    print("       paste mcp-config.json's server entry into your MCP client, restart it")
    print("       gargoyle approve --out %s --watch 2  (on the approver's machine)" % out)
    return 0


def cmd_issuer(args) -> int:
    import uvicorn
    from gargoyle.issuer_service import app_from_env

    out = Path(args.out).resolve()
    os.environ.update(_read_env(out / "issuer.env"))
    app = app_from_env()
    # The middleware reads the policy pin from a file; write it next to the
    # config so the client-side entry finds it at the configured path.
    from gargoyle.rules import RulesPolicy
    policy = RulesPolicy(os.environ["GARGOYLE_RULES_PATH"])
    (out / "record.json").write_text(json.dumps(policy.pin(), indent=2) + "\n")
    print("record.json written; serving on %s:%d" % (args.host, args.port), file=sys.stderr)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
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


def cmd_audit(args) -> int:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from gargoyle.execution import verify_chain

    keys = json.loads((Path(args.out).resolve() / "public-keys.json").read_text())
    load = lambda m: {k: Ed25519PublicKey.from_public_bytes(bytes.fromhex(v)) for k, v in m.items()}
    receipt, execution = json.load(open(args.receipt)), json.load(open(args.execution))
    grant = json.load(open(args.grant)) if args.grant else None
    result = verify_chain(receipt, execution, issuer_public_keys=load(keys["issuer"]),
                          executor_public_keys=load(keys["executor"]), grant=grant,
                          approver_public_keys=load(keys["approver"]))
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
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("issuer", help="run the issuing service on the rules file")
    p.add_argument("--out", default="gargoyle-deploy")
    p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=8080)
    p.set_defaults(fn=cmd_issuer)
    p = sub.add_parser("approve", help="review and release held calls")
    p.add_argument("--out", default="gargoyle-deploy")
    p.add_argument("--watch", type=float, metavar="SECONDS"); p.add_argument("--yes", action="store_true")
    p.set_defaults(fn=cmd_approve)
    p = sub.add_parser("audit", help="verify a receipt chain offline")
    p.add_argument("receipt"); p.add_argument("execution"); p.add_argument("grant", nargs="?")
    p.add_argument("--out", default="gargoyle-deploy")
    p.set_defaults(fn=cmd_audit)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
