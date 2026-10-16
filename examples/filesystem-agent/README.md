# A coding agent with a filesystem MCP server, gated by Gargoyle

The scenario: an AI coding assistant (Claude Desktop, Claude Code, Cursor,
any MCP client) has a filesystem MCP server pointed at a project directory.
You want three things the client cannot give you on its own:

- reads are free, but every write needs a human's key, not a click in the
  agent's own UI, and the human sees exactly what they are releasing;
- the allow/deny decision lives in a policy engine you already run (OPA),
  and changing the policy invalidates every receipt issued under the old
  one;
- every call that ran leaves a signed receipt chain you can verify later
  with three public keys and no service running.

Nothing in the client changes. The middleware obtains receipts itself.

```
  MCP client --stdio--> gargoyle.mcp_server --stdio--> @modelcontextprotocol/server-filesystem
                              |  (self-issue, client token)
                              v
                        issuer service ----> OPA (policy.rego)
                              ^
                              |  gargoyle-approver --issuer  (approver's key, approver's machine)
```

## 1. Keys and config

From the repository root, with the package installed (`pip install -e .`):

    cd examples/filesystem-agent
    python setup.py /path/to/the/project/the/agent/may/touch

This writes `issuer.env`, `middleware.env`, `approver.env` and
`mcp-config.json` (all gitignored, all private) and prints the executor's
public key, which an auditor will need later.

## 2. The issuing side

    docker compose up -d --build
    curl -s http://127.0.0.1:8080/record > record.json

OPA loads `policy.rego` and watches it for changes. The issuer signs
receipts with its key, trusts identity tokens from the setup's identity
provider key, and accepts grants from the approver's public key.

## 3. The middleware in your MCP client

Paste the `filesystem-gargoyle` entry from `mcp-config.json` into your
client's MCP configuration (Claude Desktop: `claude_desktop_config.json`;
Claude Code: `claude mcp add-json filesystem-gargoyle "$(jq .mcpServers.\"filesystem-gargoyle\" mcp-config.json)"`).
It launches:

    python -m gargoyle.mcp_server -- npx -y @modelcontextprotocol/server-filesystem <dir>

with the environment from `middleware.env`. Restart the client.

## 4. Use it

Ask the assistant to list or read files: it works at once. Each call got
its own receipt from the issuer, verified against the pinned issuer key,
and ran once.

Ask it to write or edit a file: the call blocks (up to five minutes). On
the approver's machine:

    set -a; . ./approver.env; set +a
    gargoyle-approver --issuer http://127.0.0.1:8080

The approver sees the tool, the argument hash, the principal, the target
and the policy pin that are inside the issuer's signature, types
`approve`, and the grant is posted. The middleware verifies the grant
against the receipt and its pinned approver key, spends both once, and
the write happens. Type anything else and the write never happens: there
is no grant, and the hold expires with the receipt.

Ask it to delete something: refused by policy before any receipt exists
(`DEFAULT_DENY`), and the assistant is told so.

Edit `policy.rego` to move a tool between the sets: OPA reloads it, the
policy pin changes, and any receipt still in flight is refused with
`REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED` until the call is decided again.

## 5. Audit a call afterwards

Each honored response's `_meta` carries the whole chain: the receipt the
middleware obtained (`gargoyle/receipt`), the grant it spent for a write
(`gargoyle/used_grant`) and its own signed execution receipt
(`gargoyle/execution`). Save the three as JSON files, then, with no service
running:

    EXECUTOR_PUBLIC_KEY_HEX=<from setup.py> python audit.py receipt.json execution.json grant.json

prints each step and `chain: CHAIN_VERIFIED`: this policy version
authorized this call for this principal, this human released it, and
exactly this call ran.

## What this deployment does and does not give you

- The trust boundary is the issuer's key and the approver's key. The
  middleware pins both and verifies everything itself; a compromised path
  to the issuer yields nothing it would honor.
- The approver's private key should live on a machine the issuer and the
  agent cannot reach. The setup script writes it next to the others for
  convenience; move `approver.env` before relying on the separation.
- The identity provider here is the setup script's key. In production it
  is your OAuth server, SPIRE or IdP, and the middleware's token comes from
  it (`gargoyle.identity` reads bearer, delegation and transaction tokens).
- The middleware runs with your user's OS privileges and does not sandbox
  the filesystem server; the policy is the control, not isolation.
- One issuer instance: its pending set is in memory. Replicas would need a
  shared store (see `gargoyle.pending_store`).
