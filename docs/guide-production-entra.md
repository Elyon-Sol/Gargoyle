# Gargoyle production guide: one tenant, one hosted gate, Entra ID

A small organization on Microsoft 365, every user on Claude Desktop or
claude.ai, one Gargoyle gate on a server the organization controls, the
Entra tenant as the control point. This guide gets an instance to the
state where the operator can say "in production" and mean something
specific, and it says plainly what that claim does not cover.

2026-10-28. Applies to gargoyle-receipts 0.19 with the remote gate's
OAuth sign-in (`gargoyle.oauth_broker`, branch `production-entra-guide`). It builds on `guide-hyperv-ubuntu-apache.md` (the VM, keys,
Apache, the console, the audit) and `entra-setup.md` (the app
registrations); where a step is identical it points there rather than
repeating it.

## What you end up with

```
Entra ID tenant (the control point)
  Anthropic "M365 MCP Server for Claude": NOT consented, assignment required, nobody assigned
  User consent: disabled for apps that are not admin-approved
  Gargoyle-Issuer-API: app role Approver -> the two or three people who release holds
  User-Client-Flow: SPA redirect https://gate.yourorg.example/approve (the approver console)
  Gargoyle-Gate: Web redirect https://gate.yourorg.example/{graph,sql,files}/oauth/callback (user sign-in
                 from the connector), assignment required -> the governed users
  Graph-MCP (your Graph server's registration): delegated Mail/Calendar/Contacts scopes, admin-consented

Ubuntu server "gate" (one VM, outward-facing on 443 only)
  Apache 443 -> issuer 127.0.0.1:8080  (/approve console, /record, /health, /witness, /approvers)
  Apache 443 /graph/mcp/* -> gate :8444 -> Graph MCP server (Outlook, calendar, contacts, Teams)  --state-probe graph
  Apache 443 /sql/mcp/*   -> gate :8445 -> read-only SQL MCP server (reports)                     --state-probe none
  Apache 443 /files/mcp/* -> gate :8446 -> gargoyle.fs_server /srv/shared (if files are in scope) --state-probe filesystem
  /opt/gargoyle/deploy: issuer.env, rules.json, approvers.json, holds.sqlite, witness.jsonl
  /opt/gargoyle/deploy/{graph,sql,files}: middleware.env, gate.env, oauth-state.json, audit.jsonl, snapshots/

Every user: Claude Desktop or claude.ai, one custom connector per upstream, the same URL for everyone;
            the first call opens a Microsoft sign-in, and every receipt names the account that signed in
Approvers: any browser, https://gate.yourorg.example/approve, Sign in with Microsoft
```

Reads are free and recorded. Sends, rule changes, calendar and contact
writes hold until an approver with the Entra role signs. Deletes and
anything not listed are refused. Every decision is in the issuer's
signed witness; every honored call is in the gate's evidence log; the
two are reconciled weekly. Nothing reaches Microsoft 365 from Claude
except through the gate, because the tenant admits no other door.

Time: a day for the tenant and server, a week of observe mode, an
afternoon to write the rules. Expect to iterate the rules twice.

## Part 0: what "in production" will mean here

Write these down before starting, because they are the claim. An
instance is in production when all eight hold and the operator can show
the evidence for each:

1. The tenant admits exactly one AI door to Microsoft 365 for the
   governed users: the Gargoyle custom connector. The Anthropic Microsoft
   365 enterprise app has no consent and no assignments. User consent
   for unverified apps is off. (Part 1)
2. The gate runs as a service on a server the organization controls,
   with a public TLS certificate, and `GET /health` reports persistent
   holds. (Part 2)
3. Approvers enroll by Entra sign-in with the Approver app role; no
   `approver-web.json` key file is in use. Removing the role ends the
   power. (Part 3)
4. Every user reaches Microsoft 365 through a connector that signs them
   in with the tenant. The receipt's principal is the UPN from their own
   Entra token; no operator-issued credential names anyone. (Part 4)
5. The rules were written from an observe week's `audit --summary`, not
   guessed. Sends, rule changes and external sharing hold; deletes are
   refused; reads are allowed. (Part 5)
6. The side doors are closed: no second connector, no Filesystem
   extension, no direct Graph app for the same users, Copilot's own Graph
   access accounted for. (Part 6)
7. Reconciliation runs weekly, its output is kept, and every FINDING has
   a written disposition. (Part 7)
8. Someone other than the operator can run the instance from Part 8.

What the claim does not cover is in "What this instance does not do" at
the end. Read it before telling anyone you are in production.

## Part 1: the tenant

You need Global Administrator or Application Administrator plus the
ability to change consent settings (Global Administrator or Privileged
Role Administrator).

**1.1 Block the vendor's own door.** Anthropic's Microsoft 365 connector
appears in the tenant as an enterprise application once any user has
tried it; its display name at time of writing is "M365 MCP Server for
Claude". In Entra admin center, **Identity**, **Applications**,
**Enterprise applications**, search for it.

- If it is present: open it, **Properties**, set **Assignment required**
  to **Yes** and **Enabled for users to sign in** to **No**. **Users and
  groups**: remove every assignment. **Permissions**: if admin consent
  was granted, **Review permissions** and revoke it.
- If it is absent: it will appear the first time a user connects. The
  consent setting in 1.2 stops that from succeeding.

**1.2 Stop users consenting to apps on their own.** **Identity**,
**Applications**, **Enterprise applications**, **Consent and
permissions**, **User consent settings**: choose **Do not allow user
consent**. Then **Admin consent settings**: turn on **Users can request
admin consent to apps they are unable to consent to**, and name the
reviewers. From now on a user who clicks "Connect Microsoft 365" inside
Claude gets a request form instead of a mailbox, and you get the request.

This is the one setting the whole design rests on. Without it, a user
can grant Claude Graph access in two clicks and the gate sees none of it.

**1.3 Register Gargoyle.** Follow `entra-setup.md` sections 1, 2, 7
and 8: Gargoyle-Issuer-API with the `access` scope and token version 2;
User-Client-Flow as a public client with the SPA redirect
`https://gate.yourorg.example/approve` for the approver console; the
**Approver** app role on Gargoyle-Issuer-API assigned to the people who
will release holds; and **Gargoyle-Gate**, the registration the hosted
connector signs users in through (section 8): a confidential Web client
with one redirect per gate, `https://gate.yourorg.example/graph/oauth/callback`
and likewise for `sql` and `files`, the delegated permission
`Gargoyle-Issuer-API / access` admin-consented, a client secret with a
dated expiry, and **Assignment required** set to **Yes** with the
governed users assigned. Section 5 (`gargoyle login` on each
workstation) is not used in this guide: with hosted connectors the user
signs in through the gate instead.

**1.4 Register the Graph MCP server.** Whatever Graph MCP server you
front (Part 2.4) needs its own app registration with the delegated
permissions its tools use. Grant the minimum: `Mail.Read`, `Mail.Send`,
`MailboxSettings.ReadWrite`, `Calendars.ReadWrite`, `Contacts.ReadWrite`,
and the Teams scopes only if Teams is in scope. Admin-consent it. Set
**Assignment required** to **Yes** and assign the governed users: this
registration and Gargoyle-Gate are the two places the list of governed
users lives; keep them the same group.

**1.5 Conditional Access.** Two policies. One targets Gargoyle-Gate for
the governed users: MFA, and whatever sign-in frequency the organization
wants for AI access (the gate refreshes the user's token silently until
the tenant says no, so this is where "sign in again every day" lives).
One targets Gargoyle-Issuer-API and User-Client-Flow for the Approver
group: MFA and a compliant or hybrid-joined device. Approvals and user
sessions are then gated by the same policy as everything else in the
tenant, and the gate never has to implement either.

**1.6 Write down the three lists.** Governed users (assigned to
Gargoyle-Gate and to the Graph registration), approvers (the Approver
role), and the operator (the one account with shell on the gate server).
Keep an approver out of the governed-user list, or set
`GARGOYLE_ALLOW_SELF_APPROVAL=1` knowingly; the issuer refuses a person
releasing their own call otherwise.

## Part 2: the gate server

**2.1 The server.** One Ubuntu 24.04 or 26.04 VM, two vCPU, four GB,
forty GB, on whatever hypervisor or cloud the organization already runs.
It needs inbound 443 from the internet (Anthropic's connector reaches it
from their side) and outbound 443 to `login.microsoftonline.com`,
`graph.microsoft.com` and PyPI. A public DNS name, `gate.yourorg.example`
here. Follow guide Part 1 for the OS, the `gargoyle` user, the venv and
`pip install "gargoyle-receipts[entra]"`, pinned to the version you
tested.

**2.2 Generate the deployment.** The directory argument names what a
filesystem upstream may touch; if files are not in scope give it the
shared folder anyway, you can leave that upstream unconfigured.

```bash
sudo -u gargoyle /opt/gargoyle/venv/bin/gargoyle init /srv/shared \
    --out /opt/gargoyle/deploy \
    --issuer-url https://gate.yourorg.example \
    --observe \
    --entra-tenant TENANT_ID \
    --entra-audience ISSUER_APP_ID
```

`--observe` writes a rules file that allows and records everything; Part
5 replaces it. `--entra-tenant` and `--entra-audience` put the tenant
into `issuer.env` at generation time, so there is nothing to patch by
hand. Then add the console sign-in and the hold notices to
`/opt/gargoyle/deploy/issuer.env`:

```
GARGOYLE_ENTRA_CLIENT_ID=CLIENT_APP_ID
GARGOYLE_HOLD_WEBHOOK_URL=https://yourorg.webhook.office.com/...   # Teams or Slack incoming webhook
GARGOYLE_APPROVE_URL=https://gate.yourorg.example/approve
GARGOYLE_MAX_OPEN_HOLDS=50
```

`init` writes `GARGOYLE_ISSUER_AUDIENCE=ISSUER_APP_ID`. Replace that line
with the list `gargoyle-issuer,ISSUER_APP_ID`: the init-minted tokens
carry the first entry, every Entra token (users through the gate,
approvers in the console) carries the second, and the issuer accepts
both. The gate's sign-in reads the scope from the last entry.

**2.3 The issuer service.** Guide 2.3 as written: `gargoyle issuer --out
/opt/gargoyle/deploy --host 127.0.0.1 --port 8080`, loopback only.

**2.4 One gate per upstream.** A remote gate fronts one upstream and
reads one `--out` folder for its settings, its token map, its evidence
log and its snapshots. Three upstreams means three gate processes, each
with its own folder under the deployment, all sharing the issuer, the
rules, the approvers and the witness: one policy, one approver set, one
signed record, three evidence logs.

```bash
cd /opt/gargoyle/deploy
for u in graph sql files; do
  sudo -u gargoyle mkdir -p $u/snapshots
  sudo -u gargoyle cp middleware.env $u/middleware.env
  sudo -u gargoyle ln -sf ../issuer.env $u/issuer.env          # the gate reads the tenant and audience from it
  sudo -u gargoyle sed -i \
    -e "s#^GARGOYLE_MCP_AUDIT_LOG=.*#GARGOYLE_MCP_AUDIT_LOG=/opt/gargoyle/deploy/$u/audit.jsonl#" \
    -e "s#^GARGOYLE_MCP_ISSUER_URL=.*#GARGOYLE_MCP_ISSUER_URL=http://127.0.0.1:8080#" \
    -e "s#^GARGOYLE_MCP_RECORD_URL=.*#GARGOYLE_MCP_RECORD_URL=http://127.0.0.1:8080/record#" \
    $u/middleware.env
  echo "GARGOYLE_MCP_SNAPSHOT_DIR=/opt/gargoyle/deploy/$u/snapshots" | sudo -u gargoyle tee -a $u/middleware.env >/dev/null
done
```

The gates talk to the issuer over loopback, so the public `/issue`
endpoint can be closed (2.6). Each folder gets a `gate.env` (mode 600,
owner `gargoyle`) naming its port, its upstream, and its sign-in:

```
# /opt/gargoyle/deploy/graph/gate.env
PORT=8444
GATE_ARGS=--state-probe graph --upstream-url https://127.0.0.1:9443/mcp
GARGOYLE_MCP_UPSTREAM_TOKEN=...
GARGOYLE_OAUTH_BASE_URL=https://gate.yourorg.example/graph
GARGOYLE_OAUTH_ENTRA_CLIENT_ID=GATE_APP_ID
GARGOYLE_OAUTH_ENTRA_CLIENT_SECRET=...
# /opt/gargoyle/deploy/sql/gate.env
PORT=8445
GATE_ARGS=--state-probe none -- /opt/sqlmcp/venv/bin/python -m sql_mcp_server --readonly --dsn-file /opt/sqlmcp/dsn
GARGOYLE_OAUTH_BASE_URL=https://gate.yourorg.example/sql
GARGOYLE_OAUTH_ENTRA_CLIENT_ID=GATE_APP_ID
GARGOYLE_OAUTH_ENTRA_CLIENT_SECRET=...
# /opt/gargoyle/deploy/files/gate.env
PORT=8446
GATE_ARGS=--state-probe filesystem -- /opt/gargoyle/venv/bin/python -m gargoyle.fs_server /srv/shared
GARGOYLE_OAUTH_BASE_URL=https://gate.yourorg.example/files
GARGOYLE_OAUTH_ENTRA_CLIENT_ID=GATE_APP_ID
GARGOYLE_OAUTH_ENTRA_CLIENT_SECRET=...
```

`GARGOYLE_OAUTH_BASE_URL` turns the sign-in on. The tenant and the scope
come from the issuer's `issuer.env` (`GARGOYLE_ENTRA_TENANT`, and
`api://<ISSUER_APP_ID>/access` from the audience list); override with
`GARGOYLE_OAUTH_ENTRA_TENANT` and `GARGOYLE_OAUTH_ENTRA_SCOPE` if the
deployment differs. The connector callbacks allowed to register default
to Claude's (`https://claude.ai/api/mcp/auth_callback` and the
`claude.com` twin); set `GARGOYLE_OAUTH_REDIRECT_ALLOW` to add another
client's. The gate's sessions live in `oauth-state.json` beside its keys,
mode 600: bearer and refresh tokens as hashes, the user's Entra tokens as
Entra issued them.

One templated unit runs all three:

```bash
sudo tee /etc/systemd/system/gargoyle-remote@.service >/dev/null <<'UNIT'
[Unit]
Description=Gargoyle remote gate (%i)
After=network-online.target gargoyle.service
Requires=gargoyle.service

[Service]
User=gargoyle
WorkingDirectory=/opt/gargoyle
EnvironmentFile=/opt/gargoyle/deploy/%i/gate.env
ExecStart=/opt/gargoyle/venv/bin/gargoyle remote --out /opt/gargoyle/deploy/%i --host 127.0.0.1 --port ${PORT} $GATE_ARGS
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now gargoyle-remote@graph gargoyle-remote@sql gargoyle-remote@files
```

Every gate listens on loopback; Apache terminates TLS and is the only
thing facing outward.

**2.5 The upstreams.**

| Upstream | How the gate fronts it | State binding |
|---|---|---|
| Graph MCP server (Outlook, calendar, contacts, Teams) | `--state-probe graph --upstream-url ...`; the server runs on the same host or a private network, registered in Entra per 1.4, never reachable from the internet directly | full: the card shows current inbox rules, the proposed rule, the outside addresses; undo for rules, events, contacts, membership |
| Read-only SQL MCP server (reports) | `--state-probe none` with `-- <command>` for a stdio server or `--upstream-url` for an HTTP one; the database login it uses is a read-only role, enforced in the database, not in the rules | none: the receipt binds the exact query text and the principal; there is no pre-state to show because nothing changes |
| Shared files, if in scope | `--state-probe filesystem -- python -m gargoyle.fs_server /srv/shared` | full: diffs on the card, snapshots, undo |

If your Graph server's tool names differ from
`gargoyle/specs/graph-reference.json` (`send_mail`, `create_mail_rule`,
`create_event` and so on), copy that file, rename the tools, put your
domains in `internal_domains`, and pass `--adapter-spec`. The adapter
reads state through the upstream with the user's own delegated token;
the gate holds no Graph credential.

**2.6 Apache.** Guide Part 3, with a public certificate (Let's Encrypt
via certbot, or the organization's CA, never the PoC's private CA), and
these locations in place of the single `ProxyPass /`:

```apache
    # remote gates: one path per upstream; everything under /graph/ is gate :8444
    #   /graph/mcp                      the connector endpoint (Bearer from the sign-in)
    #   /graph/oauth/*                  register, authorize, callback, token
    #   /graph/.well-known/*            resource and authorization-server metadata
    ProxyPass        /graph/ http://127.0.0.1:8444/
    ProxyPass        /sql/   http://127.0.0.1:8445/
    ProxyPass        /files/ http://127.0.0.1:8446/
    ProxyPassReverse /graph/ http://127.0.0.1:8444/
    ProxyPassReverse /sql/   http://127.0.0.1:8445/
    ProxyPassReverse /files/ http://127.0.0.1:8446/
    # RFC 8414 / RFC 9728 path-inserted metadata for an issuer with a path component
    ProxyPass        /.well-known/oauth-authorization-server/graph http://127.0.0.1:8444/.well-known/oauth-authorization-server
    ProxyPass        /.well-known/oauth-protected-resource/graph/mcp http://127.0.0.1:8444/.well-known/oauth-protected-resource
    ProxyPass        /.well-known/oauth-authorization-server/sql   http://127.0.0.1:8445/.well-known/oauth-authorization-server
    ProxyPass        /.well-known/oauth-protected-resource/sql/mcp   http://127.0.0.1:8445/.well-known/oauth-protected-resource
    ProxyPass        /.well-known/oauth-authorization-server/files http://127.0.0.1:8446/.well-known/oauth-authorization-server
    ProxyPass        /.well-known/oauth-protected-resource/files/mcp http://127.0.0.1:8446/.well-known/oauth-protected-resource
    <LocationMatch "^/(graph|sql|files)/|^/\.well-known/oauth-">
        Require all granted          # the connector arrives from Anthropic's side; the browser from wherever the user is
    </LocationMatch>

    # issuer: console, record, health, witness, approvers
    ProxyPass        / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
    <LocationMatch "^/(issue|plans)$">
        Require all denied           # the gates reach the issuer over loopback; no stdio clients in this design
    </LocationMatch>
    <LocationMatch "^/(approve|approve\.js|approve-config|pending|grants|decline|approvers|me|witness)">
        Require ip 203.0.113.0/24    # the approvers' networks; or Require all granted behind Conditional Access
    </LocationMatch>
```

The three `/<upstream>/` trees must be reachable from the internet: the
connector calls `/mcp` with its bearer, and the user's browser is sent
through `/oauth/authorize` and comes back to `/oauth/callback`. The
bearer is the credential and the sign-in is the tenant's. `/approve` and
`/witness` name every user, so restrict them to approver networks or sit
them behind Conditional Access and the Entra sign-in. `/health`, `/record`
and `/keys` are public by design and useful to monitors. If workstation
stdio clients are added later, reopen `/issue` and `/plans` to them.

**2.7 Check.**

```bash
curl -s https://gate.yourorg.example/health            # "ok": true, "persistent": true, "entra": true
curl -s https://gate.yourorg.example/record | head -c 200
curl -si https://gate.yourorg.example/graph/mcp -X POST -d '{}' | head -3      # 401 with WWW-Authenticate: Bearer resource_metadata=...
curl -s https://gate.yourorg.example/graph/.well-known/oauth-authorization-server | head -c 300
sudo journalctl -u gargoyle -u 'gargoyle-remote@*' --since -5min
```

## Part 3: approvers

`entra-setup.md` section 7 is the whole procedure. The production
additions:

- Two approvers minimum, three if one is often out. A rule can name
  them: `"approvers": ["ops@yourorg.example", "finance@yourorg.example"]`.
- Each approver signs in once at `https://gate.yourorg.example/approve`
  from the browser they will approve from. The key is non-exportable and
  bound to that browser profile. A second browser is refused until the
  operator revokes the first; this is a feature, record it in the
  runbook.
- Confirm `gargoyle approvers list --out /opt/gargoyle/deploy` shows
  exactly the UPNs with the role. Delete `approver-web.json` from the
  deployment folder; production approvals are Entra-enrolled only.
- Hold notices land in the approvers' Teams channel with the console
  link. The notice cannot approve anything; only the browser key can.
- Offboarding an approver is two steps, both required: remove the
  Approver role in Entra, and `gargoyle approvers revoke <upn>`. The
  first takes effect on their next grant (every grant is re-checked
  against a current token); the second retires the key so a later
  re-assignment does not silently revive it.

## Part 4: users, and what identity means in hosted mode

**4.1 One URL, for everyone.** The connector URL for each upstream is
the same for every user and holds no secret:

```
https://gate.yourorg.example/graph/mcp
https://gate.yourorg.example/sql/mcp
https://gate.yourorg.example/files/mcp
```

**4.2 In Claude Desktop or claude.ai.** Settings, Connectors, Add custom
connector, name "Outlook (governed)", paste the URL, leave the OAuth
client id and secret empty (the gate registers the client itself).
Connect. A Microsoft sign-in opens for the tenant; the user signs in as
themselves, under the tenant's MFA and Conditional Access; the connector
turns green. On the organization plan an admin adds the connector once
at the org level; each user still signs in as themselves on first use.

**4.3 What this identity is.** Be precise here, because it is the claim.

- The sign-in is the tenant's. The gate is the authorization server the
  connector talks to, and Entra is the one the user sees: the browser
  goes to `login.microsoftonline.com`, the tenant's MFA and Conditional
  Access apply, and the gate gets back an access token for
  Gargoyle-Issuer-API in the user's name plus a refresh token.
- The gate presents that token, the user's own, to the issuer on every
  call. The issuer verifies it against the tenant's published keys, as
  it would a `gargoyle login` token from a workstation. The receipt's
  principal is the token's UPN. No operator-issued credential names
  anyone.
- The connector holds an opaque bearer the gate minted, bound to that
  sign-in, rotated through refresh, stored on the gate as a hash. A
  leaked bearer is the user until it expires (one hour by default) or
  the session is dropped; it cannot be used to become anyone else, and
  everything done with it is held, recorded and witnessed under the
  user's name.
- The user's Entra token is refreshed silently until the tenant refuses:
  account disabled, assignment removed, Conditional Access changed,
  sign-in frequency reached. At that moment the gate drops the session
  and the connector is told to sign in again. Offboarding is therefore
  the tenant's action, not the operator's.
- What the gate does not carry forward is the user's identity to the
  upstream. The Graph MCP server behind the gate runs with the identity
  it was configured with (Part 2.5), so the mail goes out under that
  account's send-as rights while the receipt names the person who
  asked. Per-user delegation to the upstream (on-behalf-of) is the next
  build; until then, say "every action is attributed to and approved
  for the signed-in user, and executed by the gate's service identity".

The capability-URL mode of `gargoyle remote-token` still exists for
tenants without Entra, and `guide-hyperv-ubuntu-apache.md` Part 7
describes it. Do not mix the two on one gate in production; delete
`remote-tokens.json` from each gate folder.

## Part 5: the observe week, then the rules

**5.1 Run observe mode for five working days** with the real users and
the real connectors. Everything is allowed, including sends and deletes,
and everything is recorded: receipt, evidence row, witness row, argument
hash. Tell users nothing changes for them that week. Watch it live:

```bash
gargoyle witness /opt/gargoyle/deploy/witness.jsonl --follow --tail 50
```

or the **Activity** tab of the console, approvers only.

**5.2 Read the summary.**

```bash
cd /opt/gargoyle/deploy
for u in graph sql files; do
  gargoyle audit --log $u/audit.jsonl --witness witness.jsonl --summary --out .
done
```

Calls by principal and tool with outcomes, one table per upstream. This is the only honest source for the rules: what
the assistants actually did, who asked, how often, which tools never
appeared. The executive briefing in the sales material is this summary
with names redacted.

**5.3 Write `rules.json`.** First match wins; `"default": "deny"`. A
starting point for the three upstreams:

```json
{
  "version": "1",
  "default": "deny",
  "rules": [
    {"tools": ["list_*", "get_*", "read_*", "search_*", "find_*"], "action": "allow"},

    {"tools": ["query", "run_query", "execute_sql", "describe_*"], "action": "allow",
     "principals": ["dana@yourorg.example", "lee@yourorg.example"]},

    {"tools": ["send_mail", "reply_to_mail", "send_channel_message"], "action": "hold", "plan": false},
    {"tools": ["create_mail_rule", "update_mail_rule"], "action": "hold", "approvals": 1},
    {"tools": ["delete_mail_rule"], "action": "hold", "approvers": ["ops@yourorg.example"]},
    {"tools": ["create_event", "update_event", "create_contact", "update_contact"], "action": "hold"},
    {"tools": ["add_channel_member", "remove_channel_member"], "action": "hold", "approvers": ["ops@yourorg.example"]},

    {"tools": ["write_file", "edit_file", "create_directory", "move_file"], "action": "hold"},

    {"tools": ["delete_*", "remove_*", "rm*", "drop_*", "truncate*", "update", "insert", "execute"], "action": "deny", "reason": "DESTRUCTIVE_TOOL"}
  ]
}
```

Three notes. The SQL rule names the people allowed to run reports; the
database role is still read-only underneath, the rule is the second
fence. `"plan": false` on sends means a plan can never bundle a send;
every outgoing mail is its own card with the recipient and subject on
it. The deny list ends with the SQL write verbs in case the server
exposes them; the read-only database role is the fence that matters.

**5.4 Switch.** Edit the file in place. The issuer picks it up at once
and publishes a new pin; receipts under the observe pin die, which is
the intended effect. Tell users that day: writes now pause for an
approver; a refusal is a refusal.

**5.5 Tighten twice.** After week one with rules: refusals by tool (too
tight?), holds per person per day (card fatigue?), hold-to-grant time
(approvers slow?), grants that are never declined (rules too broad?).
Adjust, note the date and the reason in a `rules-changelog.md` beside
the file. After week three, freeze and declare production.

## Part 6: the side doors

A deployment is complete when these are closed, not when the connector
is green. For each, the check is something you can show.

| Door | Close it | Show it |
|---|---|---|
| Anthropic M365 connector | Part 1.1 and 1.2 | the enterprise app with no assignments and no consent; the user-consent setting |
| A second custom connector to the same data | organization-plan connector allowlist; otherwise the user-consent block stops any connector that would sign in to Graph, and one without sign-in needs a server the user does not have | the org's connector list |
| Claude Desktop Filesystem extension and computer use | off by policy on managed devices; Intune or GPO for the Desktop config if files are in scope | the Desktop config on a sampled machine |
| Claude.ai Projects and memory | out of scope for the gate; they hold copies of what was read | the data-handling note users sign |
| Microsoft 365 Copilot | Copilot's Graph access is not a connector and the gate does not see it; it is governed by Copilot's own licensing and Entra permissions | the Copilot license assignment list; if the organization uses Copilot, the gate governs Claude, not Copilot, say so |
| Power Automate, Graph Explorer, scripts | the user-consent block covers new apps; existing consented apps are in the enterprise application list | a quarterly review of enterprise applications with Graph delegated permissions |
| The operator | has the keys; the witness is signed and hash-chained so after-the-fact edits show, but the operator could stop the service | `/health` uptime from an external monitor; the witness tail hash recorded off-host weekly |
| Direct Outlook use by the person | not a side door; the gate governs the assistant, not the human | nothing |

## Part 7: reconciliation and the weekly run

Every Monday, on the gate host, as the operator:

```bash
cd /opt/gargoyle/deploy
for u in graph sql files; do
  gargoyle audit --log $u/audit.jsonl --witness witness.jsonl --out . | tee -a /var/log/gargoyle/reconcile-$(date +%F).txt
done
gargoyle audit --check-tree /srv/shared --out . | tee -a /var/log/gargoyle/reconcile-$(date +%F).txt   # files only
tail -1 witness.jsonl | sha256sum >> /var/log/gargoyle/witness-tail.txt
curl -s https://gate.yourorg.example/health >> /var/log/gargoyle/health-$(date +%F).txt
```

Then read the FINDING lines. `UNWITNESSED_*` is evidence the issuer did
not vouch for (a gate process ran against a different issuer, or the
witness was truncated). `MISSING_EVIDENCE` is a decision the issuer
recorded that the gate did not log (the gate crashed after issue, or the
audit file was edited). `CHANGED_OUTSIDE_GATE` is a file touched by
something other than the gate. Each finding gets one line in
`reconcile-findings.md`: date, finding, who was asked, what was
concluded. Zero findings is a line too.

Copy `/opt/gargoyle/deploy` (keys, rules, approvers, holds, witness,
tokens, audit logs) off-host nightly to storage the operator cannot
silently alter; a write-once bucket or a second administrator's share.
That copy is what makes "the operator could have edited it" answerable.

For a client that asks for an industry-shaped export, `gargoyle emilia
--log graph/audit.jsonl --out . --env graph/middleware.env` writes the
approved calls as EMILIA Trust Receipts, verifiable by the EMILIA
reference verifiers; the interop pack in that project's repository is the
independent check that the two agree.

## Part 8: operations

| Task | How |
|---|---|
| Logs | `journalctl -u gargoyle -u 'gargoyle-remote@*' -f`; Apache `/var/log/apache2/gargoyle-*.log`; the issuer's JSON event log on stderr |
| Holds waiting | console, or `curl -s https://gate.yourorg.example/health` (`pending_receipts`, `pending_plans`) |
| Restart | `sudo systemctl restart gargoyle 'gargoyle-remote@*'`; holds, grants and plans are in `holds.sqlite`; connector sessions reconnect; nothing a person is acting on is lost |
| New user | Entra: assign to Gargoyle-Gate and to the Graph registration; send them the connector URL; they add it and sign in; one free read |
| User leaves | Entra: remove the assignments or disable the account; their next refresh fails and the gate drops the session on its own |
| Bearer leaked or suspected | remove their sessions from that gate's `oauth-state.json` (or delete the file: every user signs in again), restart the gate, read the witness for that principal since the suspected date |
| Rotate the gate's client secret | Entra: new secret on Gargoyle-Gate; `gate.env`; restart the gates; calendar the expiry |
| Rotate every key | `gargoyle init --force` to the same `--out` regenerates issuer, IdP and executor keys; every URL and approver must be re-provisioned; keep the old `public-keys.json` for audits of the old evidence |
| Change a rule | edit `rules.json`, note it in `rules-changelog.md`; no restart |
| Add an approver | Entra role, then they sign in at `/approve` |
| Remove an approver | Entra role off, `gargoyle approvers revoke <upn>` |
| Upgrade gargoyle | pin the new version in a test deployment first; `pip install` into the venv; restart both units; run one held call end to end |
| Backup | nightly off-host copy of `/opt/gargoyle/deploy` and `/etc/letsencrypt` |
| Monitor | external HTTPS check of `/health` every five minutes; alert on non-200, on `"persistent": false`, and on pending holds above a threshold |

## Troubleshooting

The tables in `guide-hyperv-ubuntu-apache.md` and `entra-setup.md`
apply. Hosted-mode specifics:

| Symptom | Cause | Fix |
|---|---|---|
| connector shows "could not connect" in Claude | Anthropic cannot reach `/graph/mcp/` on 443, or the certificate is not publicly trusted | `curl -sI https://gate.yourorg.example/graph/mcp/x` from outside; check the `LocationMatch`; use a public CA |
| connector connects but tools list is empty | the upstream did not answer `initialize` | `journalctl -u gargoyle-remote`; test the upstream URL with the bearer by hand |
| connector loops on sign-in or says "authorization failed" | the connector's callback is not in the allowlist, or the gate's redirect in Entra does not match `GARGOYLE_OAUTH_BASE_URL` + `/oauth/callback` exactly | check `GARGOYLE_OAUTH_REDIRECT_ALLOW`; compare the Web redirect URI in Gargoyle-Gate character for character |
| sign-in returns `AADSTS50105` or `AADSTS65001` | the user is not assigned to Gargoyle-Gate, or the `access` permission was not admin-consented | assign; grant admin consent on Gargoyle-Gate |
| sign-in succeeds, then every call is refused with an identity reason | the token's audience is not in `GARGOYLE_ISSUER_AUDIENCE`, or the issuer's tenant differs | the list in `issuer.env` must contain `ISSUER_APP_ID`; `GARGOYLE_ENTRA_TENANT` is the same tenant |
| users are asked to sign in again every hour | refresh is failing (the gate bearer lives an hour, the refresh should renew it) | `journalctl -u gargoyle-remote@graph` for the refresh error text; check the Conditional Access sign-in frequency |
| the card shows no current state for a Graph write | `--state-probe none` on that gate, or the adapter spec does not name the tool | use `--state-probe graph` and a spec that maps the tool |
| approver sign-in refused `AADSTS9002326` | the SPA redirect does not match the public hostname exactly | add `https://gate.yourorg.example/approve` under the SPA platform |
| a user "connected Microsoft 365" inside Claude anyway | 1.2 not applied, or the user is an admin | check user consent settings; admins can consent for themselves, so keep admins out of the governed-user list or govern them by policy |

## What this instance does not do

- **Carry the user to the upstream.** The receipt and the hold name the
  signed-in user, and the issuer verified their token; the Graph server
  behind the gate still acts with its own configured identity. Per-user
  on-behalf-of to the upstream is the next build.
- **Keep the user's refresh token anywhere but on the gate.** It sits in
  `oauth-state.json`, mode 600, on the host the operator controls, which
  is the same trust as the token cache on a workstation; the off-host
  backup must treat that file as a credential.
- **See Copilot.** Microsoft 365 Copilot reaches Graph without a
  connector. The gate governs Claude's path. If both are in use, the
  claim is "every Claude action on Microsoft 365 is gated", not "every
  AI action".
- **See what the model read into Projects or memory.** Reads are
  recorded and free; what the vendor retains of them is the vendor's
  data-handling terms, outside the gate.
- **Judge the change.** The card proves an approver saw the exact
  arguments and signed. Whether the mail should have gone is their call.
- **Bind SQL state.** A read-only query has no pre-state to show; the
  receipt binds the query text and the principal, and the database role
  is the fence.
- **Run two issuers.** One issuer process; single use is not safe across
  instances yet. The hold store survives restarts, which is enough for
  one small organization.
- **Replace the operator's integrity.** The witness is signed and
  chained and copied off-host, so tampering shows. It does not stop the
  operator stopping the service; the external monitor does that.
- **Carry a Microsoft 365 adapter that has run against many tenants.**
  The Graph adapter has run against the reference naming and one
  server. The observe week is where it meets your server's tool names;
  budget time for the adapter spec.

## The claim, in one paragraph

"Our users reach Microsoft 365 from Claude through one connector that
our tenant admits and no other. Every call is recorded under the user's
name. Reads are free; sends, rule changes, calendar, contact and
membership writes pause until one of our named approvers, signed in with
our Entra ID, sees the exact arguments and signs with a key that never
leaves their browser. Deletes are refused. The gate's record and the
issuer's signed record are reconciled weekly and copied off the host.
Every user signs in to the connector with our Microsoft account under
our tenant's policy, and the record carries the name the directory gave,
not one we typed. Actions are executed by the gate's service identity on
the user's behalf; carrying the user's own delegation through to
Microsoft Graph is the next build."
