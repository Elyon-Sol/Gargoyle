# Gargoyle single-instance implementation guide

Ubuntu VM on Hyper-V, Apache in front, one Windows 11 client running Claude
Code, approvals reviewed in a browser.

2026-10-16. Applies to the repository at or after commit `d1df4a7`.

## What you end up with

```
Windows 11 host (Hyper-V)                         Ubuntu 26.04 VM "gargoyle" (192.168.60.10)
+--------------------------------------------+    +------------------------------------------+
| Claude Code                                |    | Apache 443 (TLS, your local CA)          |
|   .mcp.json -> python -m gargoyle.mcp_server|--->|   ProxyPass / -> 127.0.0.1:8080          |
|     -- npx server-filesystem C:\...\project|    | gargoyle issuer (systemd, user gargoyle) |
| C:\gargoyle\{middleware.env, record.json,  |    |   /opt/gargoyle/deploy/rules.json        |
|              ca.crt, audit.jsonl}          |    |   issuer key, approver public key        |
+--------------------------------------------+    +------------------------------------------+
                                                       ^
Any browser (your laptop, the host, a phone on the LAN) |  https://gargoyle.lan/approve
  loads approver-web.json once per tab; signs grants locally; never sends the key
```

Reads in the project are free. Writes, edits, new directories and moves
block until you press Approve in the browser; Decline tells the assistant
at once. Deletes are refused by policy. Every honored call is appended to
`C:\gargoyle\audit.jsonl` as a verifiable chain.

Time: about two hours the first time, most of it waiting on installers.

## Part 1: the Ubuntu VM on Hyper-V

**1.1 Network.** An internal switch with a fixed address, so the name
`gargoyle.lan` never moves. In an elevated PowerShell on the host:

```powershell
New-VMSwitch -SwitchType Internal -Name Gargoyle
New-NetIPAddress -IPAddress 192.168.60.1 -PrefixLength 24 -InterfaceAlias "vEthernet (Gargoyle)"
New-NetNat -Name GargoyleNAT -InternalIPInterfaceAddressPrefix 192.168.60.0/24
Add-Content C:\Windows\System32\drivers\etc\hosts "`n192.168.60.10 gargoyle.lan"
```

**1.2 Create the VM.** Hyper-V Manager, New, Virtual Machine:

| Setting | Value |
|---|---|
| Generation | 2 |
| Memory | 2048 MB, dynamic memory off |
| Network | switch `Gargoyle` |
| Disk | 20 GB |
| Install media | `ubuntu-26.04-live-server-amd64.iso` |
| Processors | 2 |
| Security | Secure Boot on, template `Microsoft UEFI Certificate Authority` |

Install Ubuntu Server with defaults, hostname `gargoyle`, a user for
yourself with OpenSSH server enabled. Skip snaps.

**1.3 Static address.** After first boot:

```bash
sudo tee /etc/netplan/60-gargoyle.yaml >/dev/null <<'YAML'
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: false
      addresses: [192.168.60.10/24]
      routes: [{to: default, via: 192.168.60.1}]
      nameservers: {addresses: [1.1.1.1, 9.9.9.9]}
YAML
sudo chmod 600 /etc/netplan/60-gargoyle.yaml
sudo netplan apply
ping -c1 archive.ubuntu.com
```

(`ip link` shows the interface name if it is not `eth0`.)

**1.4 Packages and a service user.**

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip apache2 git openssl ufw
python3 --version          # the package needs 3.12 or later
sudo useradd --system --home /opt/gargoyle --shell /usr/sbin/nologin gargoyle
sudo mkdir -p /opt/gargoyle && sudo chown gargoyle:gargoyle /opt/gargoyle
sudo -u gargoyle python3 -m venv /opt/gargoyle/venv
sudo -u gargoyle /opt/gargoyle/venv/bin/pip install gargoyle-receipts
sudo -u gargoyle /opt/gargoyle/venv/bin/gargoyle --help
```

## Part 2: keys, rules and the issuer service

**2.1 Generate the deployment.** The directory argument is the folder on
the *Windows* machine the assistant may touch; the other options describe
the Windows side too, so the generated config is right for it.

```bash
sudo -u gargoyle /opt/gargoyle/venv/bin/gargoyle init 'C:\Users\you\Projects\demo' \
    --out /opt/gargoyle/deploy \
    --issuer-url https://gargoyle.lan \
    --client-python 'C:\Users\you\AppData\Local\Programs\Python\Python314\python.exe' \
    --client-config-dir 'C:\gargoyle'
```

It writes, under `/opt/gargoyle/deploy`:

| File | Goes to | Holds |
|---|---|---|
| `rules.json` | stays here | the policy; edit it any time |
| `issuer.env` | stays here | issuer private key, trusted identity key, approver public key |
| `middleware.env` | Windows, `C:\gargoyle\` | issuer public key, client token, executor key, paths |
| `record.json` | Windows, `C:\gargoyle\` | the policy pin (written when the issuer starts) |
| `mcp-config.json` | Windows, into `.mcp.json` | the Claude Code server entry |
| `approver-web.json` | wherever you approve from | your approver key and token, for the browser |
| `approver.env` | optional, for the CLI approver | the same key and token |
| `public-keys.json` | Windows, `C:\gargoyle\` | for `gargoyle audit` |

**2.2 The policy.** `/opt/gargoyle/deploy/rules.json` starts as:

```json
{
  "version": "1",
  "default": "deny",
  "rules": [
    {"tools": ["read_*", "list_*", "get_*", "search_*", "directory_tree"], "action": "allow"},
    {"tools": ["write_file", "edit_file", "create_directory", "move_file"], "action": "hold"},
    {"tools": ["delete_*", "remove_*", "rm*"], "action": "deny", "reason": "DESTRUCTIVE_TOOL"}
  ]
}
```

First match wins. Rules may also carry `principals`, `on_behalf_of`,
`groups`, `roles` and `args` globs. Any edit changes the policy pin: the
issuer picks it up at once, and `record.json` on the Windows side must be
refreshed (Part 5).

**2.3 Run the issuer as a service.**

```bash
sudo tee /etc/systemd/system/gargoyle.service >/dev/null <<'UNIT'
[Unit]
Description=Gargoyle issuing service
After=network-online.target

[Service]
User=gargoyle
WorkingDirectory=/opt/gargoyle
ExecStart=/opt/gargoyle/venv/bin/gargoyle issuer --out /opt/gargoyle/deploy --host 127.0.0.1 --port 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload && sudo systemctl enable --now gargoyle
curl -s http://127.0.0.1:8080/record; echo
```

The issuer listens only on loopback. Apache is the only way in.

## Part 3: Apache with TLS

A browser signs grants only in a secure context, and the Windows client
should not trust a plaintext issuer, so Apache terminates TLS with a
certificate your machines trust. A two-file local CA is enough for one
site. The CA needs the `keyUsage` extension: the OpenSSL inside Windows
Python refuses a CA certificate without it, while browsers accept it.

```bash
sudo mkdir -p /etc/ssl/gargoyle && cd /etc/ssl/gargoyle
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=Gargoyle local CA" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout ca.key -out ca.crt
sudo openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj "/CN=gargoyle.lan" -addext "subjectAltName=DNS:gargoyle.lan,IP:192.168.60.10" \
    -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=serverAuth" \
    -keyout server.key -out server.csr
sudo openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 \
    -copy_extensions copy -out server.crt
sudo chmod 600 ca.key server.key

sudo tee /etc/apache2/sites-available/gargoyle.conf >/dev/null <<'CONF'
<VirtualHost *:80>
    ServerName gargoyle.lan
    Redirect permanent / https://gargoyle.lan/
</VirtualHost>
<VirtualHost *:443>
    ServerName gargoyle.lan
    SSLEngine on
    SSLCertificateFile /etc/ssl/gargoyle/server.crt
    SSLCertificateKeyFile /etc/ssl/gargoyle/server.key
    Header always set Strict-Transport-Security "max-age=31536000"
    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
    <Location />
        Require ip 192.168.60.0/24 127.0.0.1
    </Location>
    ErrorLog ${APACHE_LOG_DIR}/gargoyle-error.log
    # Remote-mode capability URLs carry a bearer token in the path; keep
    # them out of the access log. The issuer's own log has the decisions.
    SetEnvIf Request_URI "^/mcp/" gargoyle_capability_url
    CustomLog ${APACHE_LOG_DIR}/gargoyle-access.log combined env=!gargoyle_capability_url
</VirtualHost>
CONF
sudo a2enmod ssl proxy proxy_http headers
sudo a2dissite 000-default && sudo a2ensite gargoyle
sudo apache2ctl configtest && sudo systemctl reload apache2
sudo ufw allow OpenSSH && sudo ufw allow 443/tcp && sudo ufw --force enable
```

Widen `Require ip` to the networks your approvers sit on. Everything behind
it still needs a valid token; the IP rule only keeps strangers from
reaching the login-free console page.

Stage the files the Windows side needs where you can fetch them:

```bash
sudo mkdir -p /opt/gargoyle/handoff
sudo cp /opt/gargoyle/deploy/{middleware.env,record.json,mcp-config.json,public-keys.json,approver-web.json} \
        /etc/ssl/gargoyle/ca.crt /opt/gargoyle/handoff/
sudo chown -R "$USER" /opt/gargoyle/handoff && chmod 600 /opt/gargoyle/handoff/*
```

## Part 4: the Windows 11 client

**4.1 Install.** Python 3.12 or later from python.org (tick "Add python.exe to
PATH"), Node.js 22 LTS from nodejs.org (for the filesystem MCP server),
and Claude Code (`npm install -g @anthropic-ai/claude-code`). Then:

```powershell
pip install gargoyle-receipts
mkdir C:\gargoyle
scp you@gargoyle.lan:/opt/gargoyle/handoff/* C:\gargoyle\
certutil -addstore -f Root C:\gargoyle\ca.crt      # elevated: trust the local CA
```

Python's `requests` does not use the Windows certificate store, so the
middleware is told where the CA is through `REQUESTS_CA_BUNDLE` (next step).

**4.2 Wire it into Claude Code.** In the project folder you named at
`init`, create `.mcp.json` from `C:\gargoyle\mcp-config.json`, adding the
CA bundle to the environment:

```json
{
  "mcpServers": {
    "filesystem-gargoyle": {
      "command": "C:\\Users\\you\\AppData\\Local\\Programs\\Python\\Python314\\python.exe",
      "args": ["-m", "gargoyle.mcp_server", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\you\\Projects\\demo"],
      "env": {
        "GARGOYLE_MCP_GATE_KEY_ID": "issuer-1",
        "GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX": "...",
        "GARGOYLE_MCP_TARGET_ID": "mcp://filesystem/C:\\Users\\you\\Projects\\demo",
        "GARGOYLE_MCP_PRINCIPAL": "spiffe://gargoyle.local/agents/assistant",
        "GARGOYLE_MCP_RECORD_PATH": "C:\\gargoyle\\record.json",
        "GARGOYLE_MCP_APPROVER_KEY_ID": "approver-1",
        "GARGOYLE_MCP_APPROVER_PUBLIC_KEY_HEX": "...",
        "GARGOYLE_MCP_EXECUTOR_KEY_ID": "executor-1",
        "GARGOYLE_MCP_EXECUTOR_KEY_HEX": "...",
        "GARGOYLE_MCP_ISSUER_URL": "https://gargoyle.lan",
        "GARGOYLE_MCP_CLIENT_TOKEN": "...",
        "GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS": "300",
        "GARGOYLE_MCP_AUDIT_LOG": "C:\\gargoyle\\audit.jsonl",
        "REQUESTS_CA_BUNDLE": "C:\\gargoyle\\ca.crt"
      }
    }
  }
}
```

(`mcp-config.json` already contains every value except `REQUESTS_CA_BUNDLE`;
copy its `filesystem-gargoyle` entry and add that one line.)

**4.3 Close the side doors.** Claude Code's own Edit, Write and Bash tools
do not pass through the gate. For a supervised project, deny them in the
project's `.claude/settings.json`, so the assistant reaches the filesystem
only through the gated server:

```json
{
  "permissions": {
    "deny": ["Edit", "Write", "MultiEdit", "NotebookEdit", "Bash"]
  }
}
```

This is the trade-off of the whole design: the gate governs what passes
through it, and nothing else. A project where Bash stays allowed is a
project where the assistant can `echo > file` around the gate.

**4.4 Check.** Start `claude` in the project. `/mcp` should list
`filesystem-gargoyle` as connected. Ask it to list the project's files:
the answer comes back at once. The first honored call appears as a line in
`C:\gargoyle\audit.jsonl`.

**4.4a Nobody has to name the server.** The gate hands the model standing
instructions in the MCP handshake (the `instructions` field, which Claude
Code, Claude Desktop and the hosted connectors place in the model's
context for the whole session): all work on the gated target goes through
these tools, a wait is normal, a refusal is final, plans and undo exist.
"List the project folder" is enough once the side doors are closed (Part
8); the earlier need to say "using filesystem-gargoyle" came from Desktop
having other file tools to pick from. An operator can replace the text
with `GARGOYLE_MCP_INSTRUCTIONS` in the MCP entry's env. For a fleet, put
the MCP entry and the deny rules in Claude Code's managed settings file
(`C:\ProgramData\ClaudeCode\managed-settings.json`), which the user
cannot override, and the gate is mandated by the administrator rather
than typed by anyone.

**4.4b Ask it to bypass.** The standing instructions set the model's
default; they are not a control, and a user can talk the model out of
them in a sentence. The controls are the closed side doors. So the
acceptance test for a workstation is to ask: "write a small file into the
project folder without the gate." On a correctly closed workstation the
assistant answers that the folder is reachable only through the gated
tools and offers two routes, the gate or a file the user places by hand;
the second is the user's own hand, which the gate does not constrain and
the tree check detects. If instead a file appears in the folder, a side
door is open: find it with the audit's `--check-tree` and close it (Part
8). Run this once per workstation at enrollment and keep the exchange
with the client's evidence; it is the question the client's auditor will
ask. Run live on 2026-10-20 in Claude Desktop five times with varying
wording: the answers ranged from an offer to find another route (before
checking whether one existed), through a flat refusal with no tool call,
to a write through the gate that stopped at the approver's decline with
the refusal code reported and the side routes named as ones it would not
take. The model's answer varied; the folder never changed except through
a released hold.

**4.4c Observe first.** `gargoyle init --observe DIR ...` writes a rules
file that allows every call, destructive ones included: the gate records
all of them (receipt, evidence entry, witness entry) and holds none, so
the assistant can do in that week anything the upstream server lets it
do. Use it on a target you can restore from backup. Run a new client's first
week this way, then read `gargoyle audit --log ... --summary`, which
prints calls by principal and tool with their outcomes, and write the
hold and deny rules from what the assistants actually did rather than
from a guess. Switching rules changes the policy pin: edit `rules.json`,
restart the issuer (it rewrites `record.json`), and copy the new
`record.json` to each client's config folder; receipts under the old pin
die at once, which is the intended effect. Observe mode records the hash
of each call's arguments, never the arguments themselves.

**4.5 Claude Desktop instead of Claude Code.** The GUI app speaks MCP the
same way. `gargoyle init` already writes the entry in Desktop's shape
(`mcp-config.json`); use the full path to `python.exe` as the command,
because Desktop does not inherit the user's PATH, and add
`REQUESTS_CA_BUNDLE` to the env as in 4.2. The file is
`claude_desktop_config.json`, and its folder depends on the build:

| Build | Folder |
|---|---|
| download from claude.ai | `%APPDATA%\Claude\` |
| Microsoft Store | `%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\` |

Settings, Developer, Edit Config creates it in the right place for either.
Quit Desktop from the tray and start it again; the tools icon in the chat
box then lists the gated tools. Desktop asks "allow once or always" per
tool: answer always; the browser card is the approval that counts.
Desktop has no native file tools, but its Filesystem extension and browser
tools would bypass the gate; turn them off for a supervised user.

**4.6 One identity per user with Entra ID.** Every workstation set up so
far presents the same client token, so every receipt says the same
principal. For a team, each user should be themselves. Once per tenant,
in Entra admin center, App registrations:

1. Register `Gargoyle issuer` (an API). Under Expose an API, set the
   application ID URI and add a scope named `access`. Note the client id.
2. Register `Gargoyle client` (public). Under Authentication, enable
   "Allow public client flows". Under API permissions, add the `access`
   scope of the issuer app and grant admin consent. Note its client id.

On the VM, add to `issuer.env` (or pass `--entra-tenant` and
`--entra-audience` to `gargoyle init`), then restart the service:

```
GARGOYLE_ENTRA_TENANT=<tenant id or yourclient.onmicrosoft.com>
GARGOYLE_ISSUER_AUDIENCE=<issuer app client id>
```

On each Windows client:

```powershell
python -m pip install "gargoyle-receipts[entra]"
gargoyle login --tenant <tenant> --client-id <client app id> --scope api://<issuer app id>/access --out C:\gargoyle
```

The user signs in once from a browser with the code shown, under the
tenant's MFA. `middleware.env` and the MCP entry switch from the shared
token to that user's cached Entra token, and the principal becomes their
UPN; restart Claude Desktop or Claude Code. From then on each receipt,
each card and each audit row names the person, rules can match their
groups (`"groups": [...]` in rules.json), and disabling the account in
Entra stops the next call. The pinned init key stays trusted beside the
tenant's keys, so the approver console keeps working until approvers log
in with Entra too.

## Part 5: approving in the browser

Open `https://gargoyle.lan/approve` on any machine in `192.168.60.0/24`
that trusts the CA (the host, after `certutil`; a laptop, after importing
`ca.crt`). Load `approver-web.json` with the file picker. The key and token
live in that tab only and are gone when it closes.

Now ask Claude Code to create a file. Its tool call waits. Within three
seconds the console shows a card:

- the tool, with a green badge *arguments match the receipt* (the page
  re-hashes the arguments and compares them to the signed receipt; a red
  badge disables Approve);
- who asked, the target, the policy id and pin, when the hold expires;
- the full arguments, as JSON: the path and the content about to be written;
- **Approve** and **Decline**.

Approve signs a grant in the browser with your key and posts it; the
middleware verifies it against the approver public key it pinned, runs the
call once, and Claude Code sees the file created. Decline drops the hold;
Claude Code is told `REF_TARGET_APPROVAL_DECLINED` immediately. Doing
nothing lets the hold expire in five minutes with the same effect as a
decline.

Ask it to delete the file: refused with `DESTRUCTIVE_TOOL`, no card, no
wait.

**Changing the policy.** Edit `/opt/gargoyle/deploy/rules.json` on the VM.
The issuer applies it immediately and rewrites `record.json` on its next
start; run `sudo systemctl restart gargoyle`, copy the new `record.json` to
`C:\gargoyle\`, and restart Claude Code. Until the copy, the Windows side
refuses every call with `REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED`, which
is the design working: a receipt under the old policy is not honored.

**5.1 Two approvers.** For calls that should never rest on one person,
give the rule a threshold:

```json
{"tools": ["write_file"], "args": {"path": "*finance*"}, "action": "hold",
 "approvals": 2, "approvers": ["approver-1", "approver-2"]}
```

Run `gargoyle init ... --approvers 2` so two approver keys exist (the
second lands in `approver-2.env` and `approver-web-2.json`); each approver
loads their own file in the console. The card then reads "0 of 2
approvals", a signer sees "you signed; 1 more needed", and the assistant's
call runs only when the second key has signed. The receipt carries the
terms, so an audit shows that two named keys released that write.

**5.2 Hear about holds in Slack or Teams.** Add to `issuer.env`:

```
GARGOYLE_HOLD_WEBHOOK_URL=https://hooks.slack.com/services/T000/B000/XXXX
GARGOYLE_APPROVE_URL=https://gargoyle.lan/approve
```

Every new hold posts one line to the channel: the tool, who asked, the
target, when it expires, how many approvals it needs, and the console link.
The message cannot approve anything; the approver still opens the console
and signs with their key. Teams and most alerting products accept the same
`{"text": ...}` body.

**5.3 Approvers as themselves.** With Entra configured
(docs/entra-setup.md, section 7), the console offers "Sign in with
Microsoft". The approver's key is created in their browser, cannot be
exported, and is enrolled under their account; the card they approve is
released by their UPN, which is what the audit then shows. Threshold rules
can name those UPNs. No approver file changes hands.

**5.4 What you are approving.** A card for a file write shows the file's
current state when the assistant asked (size and a hash, or "does not
exist yet") and the proposed content as a diff against it: removed lines
struck through, added lines in green. That state is bound into the
receipt you release. If the file changes between your approval and the
run, the write is refused and the refusal is in the audit; nobody can
redirect an approval by editing the file underneath it. The execution
receipt records the file's state before and after, so the audit shows
what each approved write changed.

**5.5 Undoing an approved change.** The gate keeps what each approved
write replaced, in `C:\gargoyle\snapshots`. To undo, the user asks the
assistant: "Using filesystem-gargoyle, undo the last approved change" (the
tool is `gargoyle_revert`; it also takes a decision id from the audit).
The undo is a write like any other: a card shows the restore as a diff,
you approve or decline, and it runs only if the file is still as the
original change left it. The audit then shows the revert row with
"reverts #N" pointing at the row it undid, proven by the state hashes.

**5.6 One card for a whole task.** For a long task the assistant can ask
for a plan instead of a card per write:

> Using filesystem-gargoyle, request a plan for rewriting the three notes
> files under C:\gargoyle-poc\project, then do it.

The assistant calls `gargoyle_plan` with the steps; one card appears
listing them, with a warning that approving the plan releases every
matching call without showing its contents. Approve it, and the writes
run with no further cards until the steps are used up or the plan
expires. A write outside the plan still gets its own card. The audit
shows "(plan 1a2b3c4d step 2)" on each released row. To keep a tool out
of plans, add `"plan": false` to its hold rule; the reference rules keep
sends individual.

## Part 6: the audit trail

Every decision appended one line to `C:\gargoyle\audit.jsonl`, honored or
refused: what was asked, the verdict, and for an honored call the receipt,
the grant (for a held call) and the execution receipt. Each line is hashed
over the one before. Verify the whole file, offline, with the public keys:

```powershell
gargoyle audit --log C:\gargoyle\audit.jsonl --out C:\gargoyle
```

```
   1 ok    honored  list_directory           spiffe://gargoyle.local/agents/assistant CHAIN_VERIFIED
   2 ok    honored  write_file               spiffe://gargoyle.local/agents/assistant CHAIN_VERIFIED released by approver-1
   3 ok    refused  delete_file              spiffe://gargoyle.local/agents/assistant ENTRY_VERIFIED (DESTRUCTIVE_TOOL)
3 entries (2 honored, 1 refused), 0 failed; chain EVIDENCE_VERIFIED; tail 7c1e0a93b2d44f10
```

An edited, removed or inserted line prints `FAIL` with the reason at the
point the chain breaks. Two further checks close the gap between "what
the workstation says" and "what happened". Copy the issuer's
`witness.jsonl` and its current `approvers.json` from the VM beside the
client's files (the audit needs every key the approvers ever held, and the
client's copy goes stale each time an approver's browser key is replaced)
and run:

```powershell
python -m gargoyle.cli audit --log C:\gargoyle\audit.jsonl --out C:\gargoyle --witness C:\gargoyle\witness.jsonl --check-tree C:\gargoyle-poc\project
```

The witness is the issuer's own signed record; any evidence row the
issuer cannot vouch for is a FINDING line (a receipt it never issued, a
held call it never saw a grant for, a receipt it issued that the client
never recorded). The tree check hashes every file the gate has written
and names any that is no longer as the gate left it: a change made in
Notepad, by another tool, or by deleting the file. Neither check prevents
those; both make them visible, which on a machine the user administers is
the honest claim. Note the tail hash with each audit: a later copy of
the file that lost its end still verifies on its own, and only the tail
tells you it is shorter. Copy the file off the client on whatever schedule
your retention needs; nothing in it is secret.

## Part 7: the gate for hosted connectors (remote mode)

Claude.ai in the browser and Claude Desktop's custom connectors reach an
MCP server from Anthropic's side over HTTPS; the stdio middleware on the
workstation never sees those calls. Run the gate on the VM instead:

```bash
cd /opt/gargoyle/deploy
gargoyle remote-token --out . --principal dana@yourclient.com --url https://gargoyle.lan:8444
gargoyle remote --out . --host 0.0.0.0 --port 8444 --ssl-certfile /etc/gargoyle/tls/server.crt --ssl-keyfile /etc/gargoyle/tls/server.key -- /opt/gargoyle/venv/bin/python -m gargoyle.fs_server /srv/shared
```

Give each person their printed URL and treat it as a password: it names
them on every receipt. In Claude Desktop, Settings, Connectors, Add custom
connector, paste the URL. Reads, holds, cards, refusals, undo and the
audit work as in Parts 4 to 6, now for every client that connector is
used from. To front a Microsoft 365 MCP server instead, pass
`--upstream-url https://.../mcp --upstream-token ...` in place of the
command; state binding then needs that server's adapter (not yet built),
so start it with `--state-probe none`. Put Apache in front as in Part 3
and publish the gate only to the networks that need it; a hosted
connector must reach it from the internet, so this is the one Gargoyle
port that faces outward.

## Part 8: other assistants, and the side doors to close

The gate works with any MCP client; the receipts name the person and the
tool, never the model, and the audit shows which client asked ("via
Claude Desktop 1.4"). What differs per product is what else can reach the
same files or mailboxes without passing the gate. A deployment is complete
when those are closed, not when the connector is green.

| Client | How it reaches the gate | Side doors to close |
|---|---|---|
| Claude Code | `.mcp.json` (stdio) | deny Edit, Write, MultiEdit, NotebookEdit and Bash in the project's `.claude/settings.json` (Part 4.3); no other filesystem MCP server in the config |
| Claude Desktop | `claude_desktop_config.json` (stdio) or a custom connector (remote mode) | Filesystem extension off; browser and computer-use features off for supervised users; no second connector to the same data; "always allow" on the gated tools so the only prompts are the cards |
| claude.ai in the browser | custom connector to the remote gate only | the user must not also have a direct Microsoft 365 or Drive connector to the same data; Projects and memory hold copies of what was read, which is outside the gate |
| ChatGPT | custom connector (remote mode); choose "no authentication" for a capability URL or OAuth when built | code interpreter's file access and any direct connector to the same data; Actions in custom GPTs that reach the data by API |
| Microsoft 365 Copilot and Copilot Studio | MCP connector (remote mode) | Copilot's own Graph access is the side door: the gate only covers calls that go through the connector, so for Graph the policy must live in Entra app permissions as well |
| Cursor, VS Code Copilot, Gemini CLI | MCP config (stdio or remote) | the editor itself writes files with no tool call; the gate covers the agent's actions, not the keyboard |
| Custom applications | the Python or TypeScript consumer as a library, or the remote gate | whatever the application's own code can do without asking |

Two rules hold across all of them. The model's willingness to respect the
gate is welcome and never relied on: Claude declined to work around an
unreachable issuer during the PoC, and the design would be the same if it
had not. And a hosted client reaches the remote gate from the vendor's
servers, so that port faces the internet (Part 7); the capability URL is
the credential until OAuth is in place.

## Part 9: Microsoft 365 through a Graph MCP server

The same gate covers Outlook, calendar, contacts and Teams when the
upstream is a Microsoft Graph MCP server. Three decisions, then one
command.

1. **The server.** Any MCP server that exposes Graph as tools. Register it
   in Entra as its own application with the delegated permissions it
   needs (`MailboxSettings.ReadWrite` for inbox rules, `Mail.Send`,
   `Calendars.ReadWrite`, `Contacts.ReadWrite`, `ChannelMember.ReadWrite.All`
   as applicable); the gate never holds a Graph credential, it reads state
   through the server with the same identity the write will use.
2. **The mapping.** The gate's reference naming is
   `gargoyle/specs/graph-reference.json` (`list_mail_rules`,
   `create_mail_rule`, `send_mail` and so on). If your server names its
   tools differently, copy that file, change the tool names, and set
   `GARGOYLE_MCP_ADAPTER_SPEC` to your copy. Put your mail domains in
   `internal_domains` so the card calls out forwarding or sending to
   anyone else.
3. **The policy.** In `rules.json`, hold what matters and free the rest:

```json
{"tools": ["create_mail_rule", "update_mail_rule"], "action": "hold", "approvals": 1},
{"tools": ["send_mail", "reply_to_mail"], "action": "hold"},
{"tools": ["delete_mail_rule"], "action": "hold", "approvers": ["sysops@yourclient.com"]},
{"tools": ["list_*", "get_*", "read_*", "search_*"], "action": "allow"}
```

Then run the gate in remote mode in front of the server (Part 7), with
the Graph adapter:

```bash
gargoyle remote --out . --port 8444 --ssl-certfile ... --ssl-keyfile ... --state-probe graph --upstream-url https://graph-mcp.yourclient.com/mcp --upstream-token ...
```

What the approver sees for a rule: "creates inbox rule 'Fwd invoices' (to
an outside address: x@evil.example); 3 inbox rule(s) exist now", the
current rule set under a fold, and the proposed rule. For a send: "sends
mail to bob@partner.example, subject 'Q3 numbers' (to an outside address:
bob@partner.example). Cannot be undone." Undo works for rules, events,
contacts and membership through the inverse Graph call, held and
state-bound like everything else; a send has no undo and the gate says so
before it is approved.

## Operations

For a client beta, work through docs/beta-checklist.md. `gargoyle init`
writes `gargoyle-issuer.service` and `apache-gargoyle.conf` into the deploy
folder; `GET /health` is the monitor's endpoint and reports whether holds
are persistent.

| Task | How |
|---|---|
| Issuer logs | `journalctl -u gargoyle -f`; Apache: `/var/log/apache2/gargoyle-*.log` |
| Holds waiting | `https://gargoyle.lan/approve`, or `gargoyle approve --out /opt/gargoyle/deploy` on the VM |
| Issuer restart | `sudo systemctl restart gargoyle`; holds, grants, declines and plans are in `holds.sqlite`, so a restart loses nothing a person is acting on (`GET /health` reports it) |
| Rotate every key | re-run `gargoyle init` to a new `--out`, redistribute `middleware.env`, `record.json`, `approver-web.json`, update the unit's `--out` |
| Client token expiry | 30 days by default (`--token-days`); re-run `init` or mint a new token before it lapses |
| Second approver | `gargoyle init --approvers 2` for file keys, or Entra enrollment; a rule's `"approvals": 2` and `"approvers": [...]` set the threshold and who counts |
| Revoke an approver | `gargoyle approvers revoke <upn> --out /opt/gargoyle/deploy` on the VM; takes effect without a restart and is witnessed on the service's next read of the file. An approver retires their own key from the console's sign-in (`POST /approvers/revoke`). Revocation retires the key, not the person: remove the Approver role in Entra as well, or the next sign-in enrolls a fresh key. Removing the role alone also works at once: a grant under an enrolled key is accepted only from that account with the role in today's token |
| New browser for an approver | The console says a key is already on record. Run `gargoyle approvers revoke <upn> --out /opt/gargoyle/deploy`, then have the approver sign in from the new browser; a sign-in alone never replaces an enrolled key |
| Backup | `/opt/gargoyle/deploy` and `/etc/ssl/gargoyle`, both private |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| every call `REF_TARGET_NOT_CONFIGURED` | `record.json` missing or not a pin, or an env var missing in `.mcp.json` | check `C:\gargoyle\record.json` and the env block |
| `REF_TARGET_ISSUER_UNAVAILABLE` | the client cannot reach or trust the issuer | `curl https://gargoyle.lan/record` from Windows; hosts entry; `REQUESTS_CA_BUNDLE` path; Apache `Require ip` |
| `REF_VERIFY_PRINCIPAL_MISMATCH` | the token's subject is not `GARGOYLE_MCP_PRINCIPAL` | regenerate both with `init`; do not hand-edit one |
| `REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED` | rules changed, `record.json` on Windows is stale | restart the issuer, copy `record.json`, restart Claude Code |
| `REF_TARGET_APPROVAL_TIMEOUT` | nobody approved within five minutes | open the console; raise `GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS` if reviews take longer |
| console: `issuer unreachable` | token expired or Apache refused the address | reload the page after a new `approver-web.json`; check `Require ip` |
| console: red badge, Approve disabled | the arguments the issuer stored do not hash to the receipt | do not approve; restart the issuer and investigate |
| `/mcp` shows the server failed | Python or Node not on PATH for Claude Code, or `npx` cannot fetch the package | run the `command` line from `.mcp.json` by hand in PowerShell |

## What this instance does not do

- Govern Claude Code's native tools unless you deny them (4.3), or any
  credential the assistant holds outside the gate.
- Judge the change. The console proves you saw the exact arguments and
  signed; whether the file should be written is your call.
- Survive a VM restart with holds intact, or share holds across issuers.
- Distinguish approvers. One key approves everything; roles are on the
  roadmap.
- Replace Entra ID. The identity key here is the one `init` minted; the
  issuer can trust a tenant's keys instead (`GARGOYLE_ENTRA_TENANT`), which
  needs the middleware's token to come from Entra, a step still to build.
