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
Conditional Access policies apply to this sign-in like any other, so MFA
and device requirements are enforced by the tenant, not by Gargoyle.

## 4. The issuer on the VM

Add to the issuer's environment file (`/opt/gargoyle/deploy/issuer.env`
in the guide; `/elyon/gargoyle-poc/deploy/issuer.env` in the PoC):

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
2. **Enterprise applications**, open **Gargoyle-Issuer-API**, **Users and
   groups**, **Add user/group**: pick the approvers (or an approvers
   group), role **Approver**, **Assign**. The role lands in their access
   token's `roles` claim.
3. **App registrations**, open **User-Client-Flow**, **Authentication**,
   **Add a platform**, **Single-page application**, redirect URI
   `https://<issuer host>/approve` (the PoC: `https://192.168.56.101:8443/approve`).
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
"this browser's key enrolled" and "approving as <upn>". A new browser or
device enrolls a new key, replacing the old one for that UPN. To remove
an approver, revoke the key (`gargoyle approvers revoke <upn>`) and remove
the role assignment in step 7.2; the key alone is not enough, since the
next sign-in with the role enrolls a fresh key. The
enrolled public keys are published at `/approvers` for the middleware and
are read from `approvers.json` by `gargoyle audit`. The file loader stays
for sites that prefer key files.

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
