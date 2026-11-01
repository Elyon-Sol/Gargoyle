# Entra ID setup for Gargoyle

Two app registrations in your tenant, once. After this, each user runs
`gargoyle login` on their workstation and every receipt and audit row
names them.

- **Gargoyle-Issuer-API**: represents the issuing service on the VM. It
  exposes one scope. Tokens for it carry its client id as the audience.
- **User-Client-Flow**: the public client that `gargoyle login` uses to
  sign a user in by device code and obtain a token for the API.

You need a role that can create app registrations and grant admin consent
(Application Administrator or Global Administrator).

## 1. Gargoyle-Issuer-API

1. Open https://entra.microsoft.com and sign in. In the left menu choose
   **Identity**, then **Applications**, then **App registrations**.
2. Choose **New registration**.
   - Name: `Gargoyle-Issuer-API`
   - Supported account types: **Accounts in this organizational directory
     only** (single tenant)
   - Redirect URI: leave empty
   - **Register**
3. On the app's **Overview** page, copy two values and keep them:
   - **Application (client) ID**. Call it `ISSUER_APP_ID`.
   - **Directory (tenant) ID**. Call it `TENANT_ID`.
4. In the app's left menu choose **Expose an API**.
   - Next to **Application ID URI** choose **Add**, accept the default
     `api://ISSUER_APP_ID`, **Save**.
   - Choose **Add a scope**:
     - Scope name: `access`
     - Who can consent: **Admins and users**
     - Admin consent display name: `Access the Gargoyle issuer`
     - Admin consent description: `Obtain signed receipts for tool calls
       as the signed-in user`
     - User consent display name and description: same text
     - State: **Enabled**
     - **Add scope**
   - The full scope now reads `api://ISSUER_APP_ID/access`. Call it
     `SCOPE`.
5. In the left menu choose **Manifest**. Find
   `"requestedAccessTokenVersion"` (older tenants show
   `"accessTokenAcceptedVersion"`). Set it to `2` and **Save**. This makes
   the token's `aud` claim equal `ISSUER_APP_ID`, which is what the issuer
   checks.
6. Optional, for rules by department: in the left menu choose **Token
   configuration**, **Add groups claim**, tick **Security groups**, and
   under the Access token column choose **Group ID**. **Add**. Rules can
   then match `"groups": ["<group object id>"]`.

## 2. User-Client-Flow

1. Back in **App registrations**, choose **New registration**.
   - Name: `User-Client-Flow`
   - Supported account types: **Accounts in this organizational directory
     only**
   - Redirect URI: leave empty
   - **Register**
2. On **Overview**, copy the **Application (client) ID**. Call it
   `CLIENT_APP_ID`.
3. In the left menu choose **Authentication**.
   - Scroll to **Advanced settings**, **Allow public client flows**, set
     to **Yes**. **Save**. Device code sign-in does not work without this.
4. In the left menu choose **API permissions**.
   - **Add a permission**, tab **My APIs** (or **APIs my organization
     uses**), choose **Gargoyle-Issuer-API**.
   - **Delegated permissions**, tick **access**, **Add permissions**.
   - Choose **Grant admin consent for <your tenant>**, confirm **Yes**. The
     Status column shows a green check. Without consent each user would be
     asked to consent at first sign-in, which also works if your tenant
     allows user consent.
5. Optional: remove the default **User.Read** Microsoft Graph permission.
   Gargoyle does not use it.

## 3. Who may sign in

By default any user in the tenant can sign in to User-Client-Flow. To
restrict it: **Identity**, **Applications**, **Enterprise applications**,
open **User-Client-Flow**, **Properties**, set **Assignment required** to
**Yes**, then under **Users and groups** assign the people or a group.

Put that switch on the **client** app only. Leave **Assignment required**
at **No** on **Gargoyle-Issuer-API**: that app's assignments are its app
roles (`Approver`, `Approver.Business`, `Approver.Deputy`), and submitters
hold none by design. With it on, every submitter's token request fails with
`AADSTS50105` ("blocked because they are not a direct member of a group
with access"), which the gate reports as `REF_TARGET_LOGIN_REQUIRED` and
`gargoyle doctor` names. Two more portal facts, learned the slow way: a
user can hold one direct assignment to an app, so to change an approver's
role **Edit assignment** on the existing row rather than adding a second
("Application assignment failed"); and a role change needs no re-enrolment
of the approver's key, only a fresh console sign-in, because the issuer
reads roles from the token at grant time.
Conditional Access policies apply to this sign-in like any other, so MFA
and device requirements are enforced by the tenant, not by Gargoyle.

## 4. The issuer on the VM

Add to the issuer's environment file (`/opt/gargoyle/deploy/issuer.env`
in the guide):

```
GARGOYLE_ENTRA_TENANT=TENANT_ID
GARGOYLE_ISSUER_AUDIENCE=gargoyle-issuer,ISSUER_APP_ID
```

The audience is a list: `gargoyle-issuer` is what the init-minted tokens
carry, the app id is what Entra tokens carry, and both are accepted while
users move over. Replace the existing `GARGOYLE_ISSUER_AUDIENCE` line
rather than adding a second one. Keep the `GARGOYLE_IDP_KEY_ID` and
`GARGOYLE_IDP_PUBLIC_KEY_HEX` lines: the issuer trusts both key sources, so
the approver console's init-minted token keeps working. Restart the issuer (`sudo systemctl restart gargoyle`, or
stop and start the process). The issuer fetches the tenant's signing keys
from `login.microsoftonline.com` at start, so the VM needs outbound HTTPS.

## 5. Each Windows client

```powershell
python -m pip install --upgrade "gargoyle-receipts[entra]"
gargoyle login --tenant TENANT_ID --client-id CLIENT_APP_ID --scope api://ISSUER_APP_ID/access --out C:\gargoyle
```

`gargoyle` is installed as a script; if PowerShell cannot find it, use
`python -m gargoyle.cli login ...`. The command prints a URL and a code.
Open the URL in any browser, enter the code, sign in as the user. The
command then prints `signed in as <upn>` and rewrites
`C:\gargoyle\middleware.env` and `C:\gargoyle\mcp-config.json`: the shared
client token is gone, the four `GARGOYLE_MCP_ENTRA_*` settings are in, and
`GARGOYLE_MCP_PRINCIPAL` is the user's UPN. The token cache is
`C:\gargoyle\entra-token-cache.json`, readable by that user only.

If the MCP entry was pasted into Claude Desktop's or Claude Code's config
by hand, paste the updated entry from `mcp-config.json` again. Restart the
client (Desktop: quit from the tray and reopen).

## 6. Check

1. Ask the assistant to list the project folder. On the VM,
   `tail -f issuer.log` shows `POST /issue` 200.
2. Hold a write and approve it in the console: the card's **requested by**
   line now shows the UPN.
3. On the client, `python -m gargoyle.cli audit --log C:\gargoyle\audit.jsonl --out C:\gargoyle`
   shows the UPN in the principal column for new rows.

## 7. Approvers sign in with Entra too

With this, the console needs no `approver-web.json`. An approver signs in
with Microsoft, the browser creates a non-exportable signing key, and the
public half is enrolled under their UPN. Grants then read "released by
dana@yourclient.com", threshold rules can name UPNs, and removing the
role in Entra ends the ability to approve.

In Entra admin center:

1. **App registrations**, open **Gargoyle-Issuer-API**, **App roles**,
   **Create app role**: display name `Approver`, allowed member types
   **Users/Groups**, value `Approver`, description `May release held
   Gargoyle calls`, enabled. **Apply**.
   For routed approvals (rules with `"approver_roles"`), create two more
   app roles the same way: value `Approver.Deputy` (display name
   `Approver (deputy)`, description `May release held Gargoyle calls
   routed to deputies; sees the plain-language view`) and value
   `Approver.Business` (display name `Approver (business)`, description
   `May release routine content changes in plain language`). Any role
   whose value starts with `Approver.` counts as an approver for sign-in
   and enrolment; which holds it may release is the rule's
   `approver_roles` list, and a rule that should admit engineers too
   names `Approver` alongside.
2. **Enterprise applications**, open **Gargoyle-Issuer-API**, **Users and
   groups**, **Add user/group**: pick the approvers (or an approvers
   group), role **Approver** (or **Approver (deputy)** / **Approver
   (business)**), **Assign**. The role lands in their access token's
   `roles` claim and chooses the console's default view: technical for
   `Approver`, the plain-language views for the other two.
3. **App registrations**, open **User-Client-Flow**, **Authentication**,
   **Add a platform**, **Single-page application**, redirect URI
   `https://<issuer host>/approve` (for example `https://gargoyle.lan/approve`).
   **Configure**. Add one entry per hostname the console is opened at.

On the VM, add to `issuer.env` and restart the issuer:

```
GARGOYLE_ENTRA_CLIENT_ID=CLIENT_APP_ID
```

(`GARGOYLE_ENTRA_SCOPE` defaults to `api://<last audience>/access`;
`GARGOYLE_APPROVERS_PATH` defaults to `approvers.json` beside the keys;
`GARGOYLE_APPROVER_ROLE` defaults to `Approver`, or set
`GARGOYLE_APPROVER_GROUPS` to comma-separated group ids instead.)

Then open `https://<issuer host>/approve`: a **Sign in with Microsoft**
button appears above the file loader. Sign in, and the page reports
"this browser's key enrolled" and "approving as <upn>". One key per
account: a second browser or device is told that a key is already on
record and does not enroll until the operator revokes the first
(`gargoyle approvers revoke <upn>` on the issuer's host); a sign-in alone
never swaps the key holds are released with. Every grant is checked
against the directory again when it is posted: the key's own account must
post it, under a token that carries the Approver role now, so removing
the role in step 7.2 ends the power at once. To remove an approver, do
both: revoke the key and remove the role. The
enrolled public keys are published at `/approvers` for the middleware and
are read from `approvers.json` by `gargoyle audit`. The file loader stays
for sites that prefer key files.

## 8. Hosted connectors sign users in through the gate

The stdio middleware carries the user's token from `gargoyle login`. A
hosted connector (claude.ai, Claude Desktop's custom connectors) cannot,
so the remote gate signs the user in itself: it is the OAuth
authorization server the connector talks to, and it sends the browser to
the tenant for the actual sign-in. One more registration:

1. **App registrations**, **New registration**: name `Gargoyle-Gate`,
   single tenant, platform **Web**, redirect URI
   `https://<gate host>/<upstream>/oauth/callback` (one per gate, e.g.
   `https://gate.yourorg.example/graph/oauth/callback`). **Register**.
   Copy the **Application (client) ID**: `GATE_APP_ID`.
2. **Certificates & secrets**, **New client secret**, choose the longest
   expiry your policy allows and calendar it. Copy the value once.
3. **API permissions**, **Add a permission**, **My APIs**,
   **Gargoyle-Issuer-API**, delegated **access**, then **Grant admin
   consent**. Also keep **openid**, **profile** and **offline_access**
   (Microsoft Graph, delegated); the gate asks for them so Entra returns
   a refresh token.
4. **Enterprise applications**, **Gargoyle-Gate**, **Properties**,
   **Assignment required: Yes**; **Users and groups**: the governed users.
   This list, not anything on the gate, decides who can connect.
5. Conditional Access for Gargoyle-Gate as for any app: MFA, sign-in
   frequency.

On the gate host, in the gate's environment (`gate.env` in the production
guide):

```
GARGOYLE_OAUTH_BASE_URL=https://gate.yourorg.example/graph
GARGOYLE_OAUTH_ENTRA_CLIENT_ID=GATE_APP_ID
GARGOYLE_OAUTH_ENTRA_CLIENT_SECRET=<the secret>
```

The tenant and the scope (`api://ISSUER_APP_ID/access`) are read from the
issuer's `issuer.env` beside the gate's `--out`; `GARGOYLE_OAUTH_ENTRA_TENANT`
and `GARGOYLE_OAUTH_ENTRA_SCOPE` override them. The connector URL is then
`https://gate.yourorg.example/graph/mcp` for everyone; the first call
answers 401 with the metadata URL, the client registers itself (only
Claude's callbacks are accepted unless `GARGOYLE_OAUTH_REDIRECT_ALLOW`
adds others), the user signs in at Microsoft, and every receipt names
the UPN from their token. The issuer verifies that token exactly as it
verifies a `gargoyle login` token: `GARGOYLE_ENTRA_TENANT` and the
audience list must include `ISSUER_APP_ID`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `AADSTS7000218` or "public client flows" error at login | step 2.3 not saved | Authentication, Allow public client flows, Yes |
| `AADSTS65001` consent required | step 2.4 consent not granted | Grant admin consent, or let the user consent |
| issuer answers 401 `REF_JWS_AUDIENCE_MISMATCH` | token `aud` is `api://...` (v1) but audience is the client id, or the reverse | set manifest token version to 2 and audience to `ISSUER_APP_ID`, or set audience to `api://ISSUER_APP_ID` |
| issuer answers 401 `REF_JWS_KEY_UNKNOWN` | issuer started before the tenant was set, or tenant id wrong | check `GARGOYLE_ENTRA_TENANT`, restart |
| middleware refuses `REF_TARGET_LOGIN_REQUIRED` | no cached account, or refresh rejected by tenant policy | run `gargoyle login` again |
| middleware fails at start with `CERTIFICATE_VERIFY_FAILED` for `login.microsoftonline.com` (0.5.0 only) | `REQUESTS_CA_BUNDLE` pinned the private CA for MSAL too | upgrade to 0.5.2 or later: MSAL trusts the public roots on its own |
| console shows "signed in but has no Approver role" | step 7.2 assignment missing, or the token predates it | assign the role, sign out of the console tab (close it) and sign in again |
| console sign-in returns `AADSTS9002326` or a redirect URI error | step 7.3: the redirect URI is not registered as a Single-page application | add it under the SPA platform, exact scheme, host, port and path |
| login succeeds but the console still says the old principal | client not restarted, or the pasted MCP entry is stale | re-paste from `mcp-config.json`, restart |
