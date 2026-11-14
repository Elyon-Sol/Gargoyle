# Identity from a second provider: the Keycloak run

Gargoyle's issuing service takes identity from any OpenID Connect
provider named in `GARGOYLE_OIDC_ISSUER` (SPEC.md section 14). The unit
tests in `tests/test_oidc_identity.py` exercise the rules with tokens the
tests sign themselves. This page records the same rules against a
provider that is not ours and not Microsoft's: Keycloak, configured and
driven by `tests/test_live_keycloak.py`. Every token in that test is one
Keycloak issued.

## Run it

A throwaway Keycloak on this machine only, and the test pointed at it.
The test deletes and recreates two realms (`gargoyle-lab-a`,
`gargoyle-lab-b`); do not point it at a Keycloak you use.

```
umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > /tmp/kc-admin.pw
docker run -d --name gargoyle-keycloak-lab -p 127.0.0.1:8089:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat /tmp/kc-admin.pw)" \
  quay.io/keycloak/keycloak:26.4 start-dev

GARGOYLE_LIVE_KEYCLOAK=http://127.0.0.1:8089 \
GARGOYLE_LIVE_KEYCLOAK_ADMIN_PASSWORD_FILE=/tmp/kc-admin.pw \
  python -m pytest -q -s tests/test_live_keycloak.py

docker rm -f gargoyle-keycloak-lab
```

Without `GARGOYLE_LIVE_KEYCLOAK` the test is skipped, so CI does not run it.

## Result

| Date | Provider | Result |
|---|---|---|
| 2026-11-14 03:50 UTC | Keycloak 26.4.7 (`quay.io/keycloak/keycloak:26.4`, `start-dev`, loopback http) | 8 passed |

What each test shows, with people and tokens Keycloak made:

| Test | Shown |
|---|---|
| discovery | The realm's discovery document is accepted under its exact issuer URL. With a trailing slash Keycloak still answers, but the document names the issuer without it, and it is refused. An unknown realm is refused. |
| a real token | The readable name is `preferred_username`; the permanent id is the realm's issuer URL and the user's Keycloak id (`sub`); the printed name is `name`; roles are read from `realm_access.roles`. |
| another application | A token the same realm issued for a different client is `REF_JWS_AUDIENCE_MISMATCH`. |
| two realms | The same sign-in name in two realms is two people (two permanent ids). A realm that is not configured is `REF_JWS_KEY_UNKNOWN`. A validly signed token presented under the other realm's key ownership is `REF_IDENTITY_WRONG_ISSUER`. |
| hold and release | A requester's call is held; a person without the approver role cannot enrol; an approver enrols and releases; the witness names both by permanent id, with the approver's printed name and `meaning`; the witness verifies. |
| a name reissued | An approver is deleted and the same sign-in name is created for a new person. The new person can neither enrol over the old key nor release under it: `REF_ISSUER_SUBJECT_MISMATCH`. |
| a key roll | Keycloak is given a new signing key while the service runs. The next token, under a key id the service has never seen, is accepted after one refresh. |
| sign-in age | With `GARGOYLE_RELEASE_MAX_AUTH_AGE` set, a token from Keycloak's login page (authorization code with PKCE) carries `auth_time` and releases; a password-grant token carries none and is `REF_ISSUER_AUTH_TIME_MISSING`; the same sign-in under a rule shorter than its age is `REF_ISSUER_AUTH_TOO_OLD`. |

Each of six checks (issuer match, discovery issuer match, nested claim
lookup, same-person comparison, provider key refresh, audience) was
disabled in turn; a live test failed every time.

## What the real provider changed

Three things the self-signed tests had not asked for:

1. **Roles are nested.** Keycloak puts realm roles in
   `realm_access.roles`, not a top-level `roles` claim. A claim setting may
   now be a path with dots (`GARGOYLE_CLAIM_ROLES=realm_access.roles`); a
   claim whose own name contains dots (a namespaced claim) still matches
   literally first.
2. **The key set holds an encryption key.** Keycloak publishes an
   `RSA-OAEP` key marked `"use": "enc"` beside its signing key. Keys so
   marked are no longer loaded as signing keys.
3. **Not every token says when the person signed in.** Only a sign-in at
   the provider's login page yields `auth_time`. Under a sign-in age rule
   a token without it releases nothing.

## Keycloak settings a deployment needs

- A client for the gate whose access tokens carry the gate's audience:
  an *Audience* protocol mapper with the value of
  `GARGOYLE_ISSUER_AUDIENCE`. Without it Keycloak's tokens carry
  `aud: account` and are refused.
- A realm role for approvers (default name `Approver`,
  `GARGOYLE_APPROVER_ROLE`), and `GARGOYLE_CLAIM_ROLES=realm_access.roles`.
- `GARGOYLE_OIDC_ISSUER=https://<host>/realms/<realm>`, exactly as the
  realm's discovery document spells it.

## What this run does not show

- **https.** It ran over plain http on the loopback address, which the
  service allows for a provider on the same machine only. A provider on
  another host must be https; that path is covered by unit tests, not by
  this run.
- **The approval console.** Its sign-in is still Entra-only. A Keycloak
  person can be identified, hold, enrol and release through the API, as
  here, but not yet in the browser console.
- **Other providers.** One product, one version. Okta, Auth0, Google and
  others are expected to work by the same rules and have not been run.
- **Per-provider claim settings.** The claim settings apply to every
  configured provider; two providers that lay out roles differently
  cannot both be configured yet.
