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
python3 --version          # 3.14.x on Ubuntu 26.04; the package needs 3.14 or later
sudo useradd --system --home /opt/gargoyle --shell /usr/sbin/nologin gargoyle
sudo mkdir -p /opt/gargoyle && sudo chown gargoyle:gargoyle /opt/gargoyle
sudo -u gargoyle python3 -m venv /opt/gargoyle/venv
sudo -u gargoyle /opt/gargoyle/venv/bin/pip install "git+https://github.com/Elyon-Sol/Gargoyle"
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
site.

```bash
sudo mkdir -p /etc/ssl/gargoyle && cd /etc/ssl/gargoyle
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=Gargoyle local CA" -keyout ca.key -out ca.crt
sudo openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj "/CN=gargoyle.lan" -addext "subjectAltName=DNS:gargoyle.lan" -keyout server.key -out server.csr
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
    CustomLog ${APACHE_LOG_DIR}/gargoyle-access.log combined
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

**4.1 Install.** Python 3.14 from python.org (tick "Add python.exe to
PATH"), Node.js 22 LTS from nodejs.org (for the filesystem MCP server),
and Claude Code (`npm install -g @anthropic-ai/claude-code`). Then:

```powershell
pip install "git+https://github.com/Elyon-Sol/Gargoyle"
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

## Part 6: the audit trail

Every honored call appended one line to `C:\gargoyle\audit.jsonl`: the
receipt, the grant (for a held call) and the execution receipt. Verify the
whole file, offline, with the public keys:

```powershell
gargoyle audit --log C:\gargoyle\audit.jsonl --out C:\gargoyle
```

```
   1 ok        list_directory           spiffe://gargoyle.local/agents/assistant CHAIN_VERIFIED
   2 ok        write_file               spiffe://gargoyle.local/agents/assistant CHAIN_VERIFIED
2 entries, 0 failed
```

A tampered entry prints `FAIL` with the step that broke. Copy the file off
the client on whatever schedule your retention needs; nothing in it is
secret.

## Operations

| Task | How |
|---|---|
| Issuer logs | `journalctl -u gargoyle -f`; Apache: `/var/log/apache2/gargoyle-*.log` |
| Holds waiting | `https://gargoyle.lan/approve`, or `gargoyle approve --out /opt/gargoyle/deploy` on the VM |
| Issuer restart | `sudo systemctl restart gargoyle`; holds in memory at that moment are dropped and the assistant retries |
| Rotate every key | re-run `gargoyle init` to a new `--out`, redistribute `middleware.env`, `record.json`, `approver-web.json`, update the unit's `--out` |
| Client token expiry | 30 days by default (`--token-days`); re-run `init` or mint a new token before it lapses |
| Second approver | roadmap: approver roles and thresholds; today every trusted approver key releases every hold |
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
