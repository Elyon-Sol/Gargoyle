"""One-time setup for the filesystem-agent example.

Generates four Ed25519 keys (issuer, approver, identity provider, executor),
mints the two identity tokens the identity provider would issue (one for the
middleware, one for the approver), and writes:

  issuer.env       for docker-compose (issuer key, trusted IdP key, approver key)
  middleware.env   for `python -m gargoyle.mcp_server` on your workstation
  approver.env     for `gargoyle-approver --issuer` on the approver's machine
  mcp-config.json  the server entry to paste into your MCP client's config

Private keys land only in these files; set their permissions accordingly.
In a real deployment the identity provider is yours (an OAuth server, SPIRE,
your IdP) and the approver's key never touches the same machine as the issuer.
"""

import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from gargoyle.jws import encode

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PRINCIPAL = "spiffe://example.org/agents/coder"


def new_key():
    k = Ed25519PrivateKey.generate()
    return (k, k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
            k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())


def write(path: Path, text: str, private: bool = False) -> None:
    path.write_text(text)
    if private:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    print("wrote", path.relative_to(ROOT))


def main(directory: str) -> int:
    allowed = str(Path(directory).resolve())
    issuer, issuer_hex, issuer_pub = new_key()
    approver, approver_hex, approver_pub = new_key()
    idp, idp_hex, idp_pub = new_key()
    executor, executor_hex, executor_pub = new_key()
    exp = int((datetime.now(timezone.utc) + timedelta(days=30)).timestamp())
    client_token = encode({"sub": PRINCIPAL, "aud": "gargoyle-issuer", "exp": exp}, idp, "idp-1")
    approver_token = encode({"sub": "approver-alice", "aud": "gargoyle-issuer", "exp": exp}, idp, "idp-1")

    write(HERE / "issuer.env", "\n".join([
        "GARGOYLE_ISSUER_KEY_ID=issuer-1", "GARGOYLE_ISSUER_KEY_HEX=" + issuer_hex,
        "GARGOYLE_IDP_KEY_ID=idp-1", "GARGOYLE_IDP_PUBLIC_KEY_HEX=" + idp_pub,
        "GARGOYLE_ISSUER_AUDIENCE=gargoyle-issuer",
        "GARGOYLE_APPROVER_KEY_ID=approver-alice", "GARGOYLE_APPROVER_PUBLIC_KEY_HEX=" + approver_pub,
        "GARGOYLE_RECEIPT_TTL_SECONDS=600", ""]), private=True)
    middleware_env = {
        "GARGOYLE_MCP_GATE_KEY_ID": "issuer-1", "GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX": issuer_pub,
        "GARGOYLE_MCP_TARGET_ID": "mcp://filesystem/" + allowed, "GARGOYLE_MCP_PRINCIPAL": PRINCIPAL,
        "GARGOYLE_MCP_RECORD_PATH": str(HERE / "record.json"),
        "GARGOYLE_MCP_APPROVER_KEY_ID": "approver-alice", "GARGOYLE_MCP_APPROVER_PUBLIC_KEY_HEX": approver_pub,
        "GARGOYLE_MCP_EXECUTOR_KEY_ID": "executor-1", "GARGOYLE_MCP_EXECUTOR_KEY_HEX": executor_hex,
        "GARGOYLE_MCP_ISSUER_URL": "http://127.0.0.1:8080", "GARGOYLE_MCP_CLIENT_TOKEN": client_token,
        "GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS": "300",
    }
    write(HERE / "middleware.env", "".join("%s=%s\n" % kv for kv in middleware_env.items()), private=True)
    write(HERE / "approver.env", "\n".join([
        "GARGOYLE_APPROVER_KEY_ID=approver-alice", "GARGOYLE_APPROVER_KEY_HEX=" + approver_hex,
        "GARGOYLE_APPROVER_TOKEN=" + approver_token, ""]), private=True)
    write(HERE / "mcp-config.json", json.dumps({"mcpServers": {"filesystem-gargoyle": {
        "command": sys.executable,
        "args": ["-m", "gargoyle.mcp_server", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", allowed],
        "env": middleware_env,
    }}}, indent=2) + "\n", private=True)
    print("\nnext: docker compose up -d --build; then  curl -s http://127.0.0.1:8080/record > record.json")
    print("executor public key (for auditors):", executor_pub)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python setup.py <directory the agent may touch>", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
