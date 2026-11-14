# SPDX-License-Identifier: Apache-2.0
"""The identity rules of tests/test_oidc_identity.py against a real OpenID
Connect provider: a throwaway Keycloak this test configures itself.

Skipped unless GARGOYLE_LIVE_KEYCLOAK names its base URL; the admin
password comes from GARGOYLE_LIVE_KEYCLOAK_ADMIN_PASSWORD or, better, a
file named in GARGOYLE_LIVE_KEYCLOAK_ADMIN_PASSWORD_FILE. The test deletes
and recreates two realms, gargoyle-lab-a and gargoyle-lab-b; point it at
nothing you want to keep. docs/interop-keycloak.md has the commands.

Nothing here signs a token: every token is one Keycloak issued."""

import base64
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

import pytest

BASE = (os.environ.get("GARGOYLE_LIVE_KEYCLOAK") or "").rstrip("/")
pytestmark = pytest.mark.skipif(not BASE, reason="set GARGOYLE_LIVE_KEYCLOAK to a throwaway Keycloak's base URL (docs/interop-keycloak.md)")

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from gargoyle.approval import build_grant, sign_grant
from gargoyle.approvers import ApproverRegistry
from gargoyle.identity import REF_IDENTITY_WRONG_ISSUER, oidc_discovery, principal_from_token
from gargoyle.issuer_service import REF_ISSUER_SUBJECT_MISMATCH, build_issuer_app, providers_from_env
from gargoyle.jws import REF_JWS_AUDIENCE_MISMATCH, REF_JWS_KEY_UNKNOWN
from gargoyle.policy import ELIGIBLE, Decision
from gargoyle.witness import WitnessLog, verify_witness

AUDIENCE = "gargoyle-issuer"
REDIRECT = "http://127.0.0.1:8765/callback"       # never contacted: the test reads the code off the redirect
REALM_A, REALM_B = "gargoyle-lab-a", "gargoyle-lab-b"
issuer_url = lambda realm: "%s/realms/%s" % (BASE, realm)
pub_hex = lambda k: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def claims_of(token):
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def kid_of(token):
    part = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))["kid"]


class Lab:
    """The Keycloak admin API, as much of it as this test needs."""

    def __init__(self):
        pw = os.environ.get("GARGOYLE_LIVE_KEYCLOAK_ADMIN_PASSWORD")
        if not pw and os.environ.get("GARGOYLE_LIVE_KEYCLOAK_ADMIN_PASSWORD_FILE"):
            pw = open(os.environ["GARGOYLE_LIVE_KEYCLOAK_ADMIN_PASSWORD_FILE"]).read().strip()
        self._admin_pw = pw
        self._passwords = {}
        for realm in (REALM_A, REALM_B):
            self.admin("DELETE", "/admin/realms/" + realm, ok=(204, 404))
            self.admin("POST", "/admin/realms", ok=(201,), json={
                "realm": realm, "enabled": True, "roles": {"realm": [{"name": "Approver"}]},
                "clients": [
                    # The client people sign in through for the gate: its tokens carry the gate's audience.
                    {"clientId": "gargoyle-cli", "publicClient": True, "directAccessGrantsEnabled": True,
                     "standardFlowEnabled": True, "redirectUris": [REDIRECT],
                     "protocolMappers": [{"name": "gate-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                                          "config": {"included.custom.audience": AUDIENCE, "access.token.claim": "true", "id.token.claim": "false"}}]},
                    # Some other application of the same provider: its tokens are not for the gate.
                    {"clientId": "other-app", "publicClient": True, "directAccessGrantsEnabled": True},
                ]})

    def admin(self, method, path, ok=(200, 201, 204), **kw):
        t = requests.post(BASE + "/realms/master/protocol/openid-connect/token", timeout=20,
                          data={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": self._admin_pw})
        assert t.status_code == 200, "admin sign-in failed (%s): is the admin password set?" % t.status_code
        r = requests.request(method, BASE + path, headers={"Authorization": "Bearer " + t.json()["access_token"]}, timeout=20, **kw)
        assert r.status_code in ok, "%s %s -> %s %s" % (method, path, r.status_code, r.text[:200])
        return r

    def user(self, realm, username, *, roles=(), first="Lab", last="Person"):
        """Create a person; returns their Keycloak id (the token's `sub`)."""
        pw = secrets.token_urlsafe(18)
        self.admin("POST", "/admin/realms/%s/users" % realm, ok=(201,), json={
            "username": username, "enabled": True, "email": "%s@%s.example" % (username, realm), "emailVerified": True,
            "firstName": first, "lastName": last, "credentials": [{"type": "password", "value": pw, "temporary": False}]})
        uid = self.user_id(realm, username)
        if roles:
            reps = [self.admin("GET", "/admin/realms/%s/roles/%s" % (realm, r)).json() for r in roles]
            self.admin("POST", "/admin/realms/%s/users/%s/role-mappings/realm" % (realm, uid), json=reps)
        self._passwords[(realm, username)] = pw
        return uid

    def user_id(self, realm, username):
        return self.admin("GET", "/admin/realms/%s/users" % realm, params={"username": username, "exact": "true"}).json()[0]["id"]

    def delete_user(self, realm, username):
        self.admin("DELETE", "/admin/realms/%s/users/%s" % (realm, self.user_id(realm, username)))

    def token(self, realm, username, client="gargoyle-cli"):
        r = requests.post(issuer_url(realm) + "/protocol/openid-connect/token", timeout=20,
                          data={"grant_type": "password", "client_id": client, "username": username,
                                "password": self._passwords[(realm, username)], "scope": "openid profile email"})
        assert r.status_code == 200, r.text[:200]
        return r.json()["access_token"]

    def browser_token(self, realm, username):
        """Sign in the way a person does in a browser (authorization code
        with PKCE, the provider's own login page), not with the password
        grant: this is the sign-in a console performs."""
        import hashlib, html, re
        from urllib.parse import parse_qs, urlsplit
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        web = requests.Session()
        page = web.get(issuer_url(realm) + "/protocol/openid-connect/auth", timeout=20, params={
            "client_id": "gargoyle-cli", "redirect_uri": REDIRECT, "response_type": "code", "scope": "openid profile",
            "state": secrets.token_urlsafe(8), "code_challenge": challenge, "code_challenge_method": "S256"})
        action = html.unescape(re.search(r'<form[^>]*action="([^"]+)"', page.text).group(1))
        # Keycloak marks its session cookies Secure. A browser still returns them to a loopback address over
        # plain http; this client does not unless told to, so they are passed back by hand.
        cookies = "; ".join("%s=%s" % (k.name, k.value) for k in web.cookies)
        back = requests.post(action, data={"username": username, "password": self._passwords[(realm, username)]},
                             headers={"Cookie": cookies}, allow_redirects=False, timeout=20)
        assert back.status_code == 302 and back.headers["Location"].startswith(REDIRECT), (back.status_code, back.text[:200])
        code = parse_qs(urlsplit(back.headers["Location"]).query)["code"][0]
        r = requests.post(issuer_url(realm) + "/protocol/openid-connect/token", timeout=20, data={
            "grant_type": "authorization_code", "client_id": "gargoyle-cli", "code": code, "redirect_uri": REDIRECT, "code_verifier": verifier})
        assert r.status_code == 200, r.text[:200]
        return r.json()["access_token"]

    def roll_signing_key(self, realm):
        realm_id = self.admin("GET", "/admin/realms/" + realm).json()["id"]
        self.admin("POST", "/admin/realms/%s/components" % realm, ok=(201,), json={
            "name": "rolled-%s" % secrets.token_hex(3), "providerId": "rsa-generated", "providerType": "org.keycloak.keys.KeyProvider",
            "parentId": realm_id, "config": {"priority": ["500"], "keySize": ["2048"], "algorithm": ["RS256"], "enabled": ["true"], "active": ["true"]}})


@pytest.fixture(scope="module")
def lab():
    return Lab()


def settings(*realms):
    return {"GARGOYLE_OIDC_ISSUER": ",".join(issuer_url(r) for r in realms), "GARGOYLE_CLAIM_ROLES": "realm_access.roles"}


# ---- discovery and the token rules -------------------------------------------

def test_the_providers_discovery_document_is_accepted_only_under_its_exact_issuer(lab):
    doc = oidc_discovery(issuer_url(REALM_A))
    assert doc["issuer"] == issuer_url(REALM_A) and doc["jwks_uri"].startswith(BASE)
    with pytest.raises(RuntimeError):
        oidc_discovery(issuer_url(REALM_A) + "/")              # Keycloak answers; the document names the issuer without the slash
    with pytest.raises(RuntimeError):
        oidc_discovery(issuer_url("no-such-realm"))


def test_a_real_token_yields_the_readable_name_the_permanent_id_and_the_roles(lab):
    uid = lab.user(REALM_A, "sam", first="Sam", last="Requester", roles=["Approver"])
    ps, keys = providers_from_env(settings(REALM_A))
    t = lab.token(REALM_A, "sam")
    c = claims_of(t)
    print("\nkeycloak access token claims:", sorted(c), "| alg kid:", kid_of(t)[:8], "| keys trusted:", len(keys))
    r = principal_from_token(t, keys, audience=AUDIENCE, providers=ps)
    assert r["reason"] is None
    assert r["principal"] == "sam" and r["subject_id"] == {"iss": issuer_url(REALM_A), "sub": uid} and r["name"] == "Sam Requester"
    assert "Approver" in r["roles"]                                           # read from realm_access.roles
    # With the default flat `roles` setting the same token carries no roles: a provider's layout is a setting, not a guess.
    flat, _ = providers_from_env({"GARGOYLE_OIDC_ISSUER": issuer_url(REALM_A)})
    assert principal_from_token(t, keys, audience=AUDIENCE, providers=flat)["roles"] == []


def test_a_token_for_another_application_of_the_same_provider_is_refused(lab):
    lab.user(REALM_A, "olga")
    ps, keys = providers_from_env(settings(REALM_A))
    t = lab.token(REALM_A, "olga", client="other-app")
    assert principal_from_token(t, keys, audience=AUDIENCE, providers=ps)["reason"] == REF_JWS_AUDIENCE_MISMATCH


def test_two_realms_are_two_providers_and_neither_speaks_for_the_other(lab):
    a_id, b_id = lab.user(REALM_A, "pat"), lab.user(REALM_B, "pat")
    ta, tb = lab.token(REALM_A, "pat"), lab.token(REALM_B, "pat")
    only_a, keys_a = providers_from_env(settings(REALM_A))
    assert principal_from_token(tb, keys_a, audience=AUDIENCE, providers=only_a)["reason"] == REF_JWS_KEY_UNKNOWN   # B is not trusted at all
    both, keys = providers_from_env(settings(REALM_A, REALM_B))
    ra, rb = (principal_from_token(t, keys, audience=AUDIENCE, providers=both) for t in (ta, tb))
    assert ra["principal"] == rb["principal"] == "pat"                         # one readable name
    assert ra["subject_id"] == {"iss": issuer_url(REALM_A), "sub": a_id} and rb["subject_id"] == {"iss": issuer_url(REALM_B), "sub": b_id}
    # Tell the gate that B's keys belong to A (a misconfiguration, or a provider claiming another's key ids):
    # B's token is validly signed and still refused, because it names B.
    swapped = [{**both[0], "key_ids": both[1]["key_ids"]}, {**both[1], "key_ids": both[0]["key_ids"]}]
    assert principal_from_token(tb, keys, audience=AUDIENCE, providers=swapped)["reason"] == REF_IDENTITY_WRONG_ISSUER


# ---- the issuing service, end to end ------------------------------------------

issuer_key = Ed25519PrivateKey.generate()


class Hold:
    def pin(self): return {"policy_id": "live/1", "policy_sha256": "b" * 64}
    def decide(self, target_url, interaction): return Decision(ELIGIBLE, None, True)


def service(tmp_path, *realms, **kw):
    ps, keys = providers_from_env(settings(*realms))
    witness = WitnessLog(str(tmp_path / "witness.jsonl"), issuer_key, "issuer-1", start_fields={"providers": [p["issuer"] for p in ps]})
    reg = ApproverRegistry(str(tmp_path / "approvers.json"))
    app = build_issuer_app(policy=Hold(), signing_key=issuer_key, key_id="issuer-1", idp_public_keys=keys, providers=ps,
                           audience=AUDIENCE, approver_registry=reg, witness=witness, **kw)
    return TestClient(app), witness, reg


bearer = lambda t: {"Authorization": "Bearer " + t}
events = lambda witness, kind: [e for e in witness.entries if e["event"] == kind]


def hold(c, token):
    r = c.post("/issue", json={"target_url": "mcp://fs", "tool": "write_file", "args": {"path": "batch.txt", "content": "x"}}, headers=bearer(token))
    assert r.status_code == 200 and r.json()["issued"] is True, r.text
    return r.json()["envelope"]


def grant_for(env, key, key_id):
    return sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                  grant_id="g-" + secrets.token_hex(4), not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), key, key_id)


def test_hold_and_release_with_keycloak_people_and_the_witness_names_them(lab, tmp_path):
    rita_id = lab.user(REALM_A, "rita", first="Rita", last="Requester")
    quinn_id = lab.user(REALM_A, "quinn", first="Quinn", last="Approver", roles=["Approver"])
    c, witness, _ = service(tmp_path, REALM_A)
    env = hold(c, lab.token(REALM_A, "rita"))
    key = Ed25519PrivateKey.generate()
    quinn = lab.token(REALM_A, "quinn")
    # Rita has no approver role in the directory: she cannot enrol a key.
    assert c.post("/approvers/enroll", json={"public_key_hex": pub_hex(key)}, headers=bearer(lab.token(REALM_A, "rita"))).status_code == 403
    assert c.post("/approvers/enroll", json={"public_key_hex": pub_hex(key)}, headers=bearer(quinn)).json()["enrolled"] is True
    assert c.post("/grants", json=grant_for(env, key, "quinn"), headers=bearer(quinn)).json()["accepted"] is True
    issued, granted = events(witness, "issued")[0], events(witness, "granted")[0]
    assert issued["principal"] == "rita" and issued["principal_id"] == {"iss": issuer_url(REALM_A), "sub": rita_id}
    assert granted["approver"] == "quinn" and granted["approver_id"] == {"iss": issuer_url(REALM_A), "sub": quinn_id}
    assert granted["approver_name"] == "Quinn Approver" and granted["meaning"] == "approval"
    print("\ngranted entry members:", sorted(k for k in granted if k not in ("entry_sha256", "issuer_signature", "prev_sha256")))
    assert verify_witness(witness.entries, issuer_public_keys={"issuer-1": issuer_key.public_key()})["accepted"]


def test_a_sign_in_name_given_to_a_new_person_does_not_inherit_the_old_persons_key(lab, tmp_path):
    first_id = lab.user(REALM_A, "nico", roles=["Approver"])
    lab.user(REALM_A, "rae")
    c, witness, reg = service(tmp_path, REALM_A)
    key = Ed25519PrivateKey.generate()
    assert c.post("/approvers/enroll", json={"public_key_hex": pub_hex(key)}, headers=bearer(lab.token(REALM_A, "nico"))).json()["enrolled"] is True
    # The first Nico leaves; the directory later issues the same sign-in name to someone new.
    lab.delete_user(REALM_A, "nico")
    second_id = lab.user(REALM_A, "nico", roles=["Approver"])
    assert second_id != first_id
    new_nico = lab.token(REALM_A, "nico")
    r = c.post("/approvers/enroll", json={"public_key_hex": pub_hex(Ed25519PrivateKey.generate())}, headers=bearer(new_nico))
    assert r.status_code == 409 and r.json()["detail"]["reason"] == REF_ISSUER_SUBJECT_MISMATCH
    env = hold(c, lab.token(REALM_A, "rae"))
    assert c.post("/grants", json=grant_for(env, key, "nico"), headers=bearer(new_nico)).json() == {"accepted": False, "reason": REF_ISSUER_SUBJECT_MISMATCH}
    assert not events(witness, "granted") and reg.entries()["nico"]["subject_id"]["sub"] == first_id


def test_a_signing_key_the_provider_rolls_while_the_service_runs_is_picked_up(lab, tmp_path):
    lab.user(REALM_B, "kai")
    c, witness, _ = service(tmp_path, REALM_B)
    before = lab.token(REALM_B, "kai")
    hold(c, before)
    lab.roll_signing_key(REALM_B)
    after = lab.token(REALM_B, "kai")
    assert kid_of(after) != kid_of(before)                                    # Keycloak now signs with a key the service has never seen
    hold(c, after)
    assert len(events(witness, "issued")) == 2


def test_the_sign_in_age_rule_with_the_providers_own_statement_of_when(lab, tmp_path):
    from gargoyle.issuer_service import REF_ISSUER_AUTH_TIME_MISSING, REF_ISSUER_AUTH_TOO_OLD
    lab.user(REALM_A, "uma")
    lab.user(REALM_A, "vic", first="Vic", last="Approver", roles=["Approver"])
    c, witness, _ = service(tmp_path, REALM_A, release_max_auth_age=300)
    key = Ed25519PrivateKey.generate()
    signed_in = lab.browser_token(REALM_A, "vic")                              # through Keycloak's login page
    at = claims_of(signed_in).get("auth_time")
    print("\nbrowser sign-in token: auth_time present:", at is not None, "| password-grant token:", "auth_time" in claims_of(lab.token(REALM_A, "vic")))
    assert isinstance(at, int) and abs(at - datetime.now(timezone.utc).timestamp()) < 120
    assert c.post("/approvers/enroll", json={"public_key_hex": pub_hex(key)}, headers=bearer(signed_in)).json()["enrolled"] is True
    env = hold(c, lab.token(REALM_A, "uma"))
    # A token obtained without the person signing in at a login page says nothing about when they did: no release on it.
    r = c.post("/grants", json=grant_for(env, key, "vic"), headers=bearer(lab.token(REALM_A, "vic")))
    assert r.json() == {"accepted": False, "reason": REF_ISSUER_AUTH_TIME_MISSING}
    assert c.post("/grants", json=grant_for(env, key, "vic"), headers=bearer(signed_in)).json()["accepted"] is True
    g = events(witness, "granted")[0]
    assert g["auth_time"] == at and 0 <= g["auth_age_seconds"] < 120
    # The same sign-in under a stricter rule than its age is refused as too old.
    import time
    time.sleep(3)
    strict, w2, _ = service(tmp_path / "strict", REALM_A, release_max_auth_age=2)
    strict.post("/approvers/enroll", json={"public_key_hex": pub_hex(key)}, headers=bearer(signed_in))
    env2 = hold(strict, lab.token(REALM_A, "uma"))
    assert strict.post("/grants", json=grant_for(env2, key, "vic"), headers=bearer(signed_in)).json() == {"accepted": False, "reason": REF_ISSUER_AUTH_TOO_OLD}
