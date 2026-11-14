# SPDX-License-Identifier: Apache-2.0
"""Identity from any standard OpenID Connect provider: a token is trusted
only under the provider that owns its signing key and names itself in
`iss`; a person is the pair (issuer, subject), with the readable name
beside it; the issuer's witness (gargoyle-witness/3) records both."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from gargoyle.approval import build_grant, sign_grant
from gargoyle.approvers import ApproverRegistry
from gargoyle.identity import (
    REF_IDENTITY_NO_SUBJECT, REF_IDENTITY_WRONG_ISSUER, oidc_discovery, oidc_keys, principal_from_token, provider,
)
from gargoyle.issuer_service import REF_ISSUER_SUBJECT_MISMATCH, build_issuer_app
from gargoyle.jws import encode
from gargoyle.policy import ELIGIBLE, Decision
from gargoyle.witness import WITNESS_VERSION, WitnessLog, verify_witness

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
EXP = int((NOW + timedelta(minutes=5)).timestamp())
ISS_A, ISS_B = "https://id.alpha.example/realms/lab", "https://beta.example"
key_a, key_b, pinned = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
KEYS = {"a-1": key_a.public_key(), "b-1": key_b.public_key(), "pin-1": pinned.public_key()}
pub_hex = lambda k: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def providers(**kw):
    return [provider(ISS_A, key_ids={"a-1"}, **kw), provider(ISS_B, key_ids={"b-1"})]


def tok(key=key_a, kid="a-1", **claims):
    return encode({"exp": EXP, **claims}, key, kid)


def who(token, **kw):
    return principal_from_token(token, KEYS, now=NOW, providers=kw.pop("providers", providers()), **kw)


# ---- refusals first ---------------------------------------------------------

def test_a_provider_token_must_name_its_own_issuer_exactly():
    assert who(tok(sub="u1"))["reason"] == REF_IDENTITY_WRONG_ISSUER                              # no iss at all
    assert who(tok(sub="u1", iss=ISS_A + "/"))["reason"] == REF_IDENTITY_WRONG_ISSUER             # near miss: trailing slash
    assert who(tok(sub="u1", iss=ISS_A.upper()))["reason"] == REF_IDENTITY_WRONG_ISSUER           # case is not folded
    assert who(tok(sub="u1", iss=["x", ISS_A]))["reason"] == REF_IDENTITY_WRONG_ISSUER            # not a string
    assert who(tok(sub="u1", iss=ISS_A))["reason"] is None


def test_one_providers_key_cannot_speak_for_another_provider():
    # Signed by A's key, claiming to be from B: A could otherwise mint B's people.
    assert who(tok(sub="u1", iss=ISS_B))["reason"] == REF_IDENTITY_WRONG_ISSUER
    assert who(tok(key=key_b, kid="b-1", sub="u1", iss=ISS_A))["reason"] == REF_IDENTITY_WRONG_ISSUER
    assert who(tok(key=key_b, kid="b-1", sub="u1", iss=ISS_B))["reason"] is None


def test_a_header_cannot_borrow_another_providers_key_id():
    # B's key signing under A's kid: the signature fails before any claim is read.
    assert who(tok(key=key_b, kid="a-1", sub="u1", iss=ISS_A))["reason"] is not None
    assert who(tok(key=key_b, kid="a-1", sub="u1", iss=ISS_A))["principal"] is None


def test_a_provider_token_without_a_subject_is_refused():
    assert who(tok(iss=ISS_A, preferred_username="dana@alpha.example"))["reason"] == REF_IDENTITY_NO_SUBJECT
    assert who(tok(iss=ISS_A, sub=""))["reason"] == REF_IDENTITY_NO_SUBJECT


def test_email_is_not_an_identity_unless_the_operator_says_so():
    # An address is often editable by its holder; it names nobody by default.
    r = who(tok(iss=ISS_A, sub="s-1", email="ceo@alpha.example"))
    assert r["principal"] == "s-1"
    r = who(tok(iss=ISS_A, sub="s-1", email="dana@alpha.example"), providers=providers(name_claims=["email", "sub"]))
    assert r["principal"] == "dana@alpha.example"


# ---- what a trusted token yields --------------------------------------------

def test_a_person_is_the_issuer_and_subject_with_the_readable_name_beside_it():
    r = who(tok(iss=ISS_A, sub="s-1", preferred_username="dana@alpha.example", name="Dana Okoro",
                roles=["Approver"], groups=["g-qa"]))
    assert r["reason"] is None and r["principal"] == "dana@alpha.example" and r["on_behalf_of"] is None
    assert r["subject_id"] == {"iss": ISS_A, "sub": "s-1"} and r["name"] == "Dana Okoro" and r["iss"] == ISS_A
    assert r["roles"] == ["Approver"] and r["groups"] == ["g-qa"]


def test_the_same_readable_name_from_two_providers_is_two_people():
    a = who(tok(iss=ISS_A, sub="s-1", preferred_username="dana"))
    b = who(tok(key=key_b, kid="b-1", iss=ISS_B, sub="s-1", preferred_username="dana"))
    assert a["principal"] == b["principal"] and a["subject_id"] != b["subject_id"]


def test_claim_names_are_configurable_per_provider():
    ps = providers(name_claims=["login", "sub"], display_claim="display", roles_claim="realm_roles", groups_claim="teams")
    r = who(tok(iss=ISS_A, sub="s-1", login="dana", display="Dana Okoro", realm_roles=["Approver"], teams="qa",
                roles=["ignored"], name="ignored"), providers=ps)
    assert (r["principal"], r["name"], r["roles"], r["groups"]) == ("dana", "Dana Okoro", ["Approver"], ["qa"])


def test_delegation_gives_both_parties_an_id():
    r = who(tok(iss=ISS_A, sub="s-user", act={"sub": "agent-7"}))
    assert (r["principal"], r["on_behalf_of"]) == ("agent-7", "s-user")
    assert r["subject_id"] == {"iss": ISS_A, "sub": "agent-7"} and r["on_behalf_of_id"] == {"iss": ISS_A, "sub": "s-user"}


def test_a_pinned_key_token_is_not_held_to_a_provider_and_is_named_by_its_key():
    r = who(tok(key=pinned, kid="pin-1", sub="svc-1"))
    assert r["reason"] is None and r["subject_id"] == {"iss": "key:pin-1", "sub": "svc-1"}
    # and it cannot borrow a provider's name for its id
    r = who(tok(key=pinned, kid="pin-1", sub="svc-1", iss=ISS_A))
    assert r["subject_id"] == {"iss": "key:pin-1", "sub": "svc-1"}


def test_without_providers_nothing_changes():
    r = principal_from_token(tok(key=pinned, kid="pin-1", sub="svc-1", iss="anything"), KEYS, now=NOW)
    assert r["reason"] is None and r["principal"] == "svc-1"


# ---- discovery ---------------------------------------------------------------

class Http:
    def __init__(self, docs): self.docs, self.seen = docs, []
    def get(self, url, timeout=None):
        self.seen.append(url)
        doc = self.docs.get(url)
        class R:
            status_code = 200 if doc is not None else 404
            def json(self_inner): return doc
        return R()


def test_discovery_reads_the_providers_own_document():
    http = Http({ISS_A + "/.well-known/openid-configuration": {"issuer": ISS_A, "jwks_uri": ISS_A + "/keys",
                                                               "authorization_endpoint": ISS_A + "/auth", "token_endpoint": ISS_A + "/token"},
                 ISS_A + "/keys": {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "a-1",
                                             "x": __import__("gargoyle.jws", fromlist=["b64url_encode"]).b64url_encode(
                                                 key_a.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))}]}})
    doc = oidc_discovery(ISS_A, http=http)
    assert doc["jwks_uri"] == ISS_A + "/keys" and doc["token_endpoint"] == ISS_A + "/token"
    assert set(oidc_keys(doc["jwks_uri"], http=http)) == {"a-1"}


@pytest.mark.parametrize("doc", [
    {"issuer": "https://someone.else.example", "jwks_uri": ISS_A + "/keys"},     # the document names another issuer
    {"issuer": ISS_A + "/", "jwks_uri": ISS_A + "/keys"},                        # not exactly the configured one
    {"issuer": ISS_A},                                                           # no key address
    {"issuer": ISS_A, "jwks_uri": "http://id.alpha.example/keys"},               # keys over plain http
    None,                                                                        # no document
])
def test_discovery_refuses_a_document_it_cannot_trust(doc):
    http = Http({ISS_A + "/.well-known/openid-configuration": doc} if doc is not None else {})
    with pytest.raises(RuntimeError):
        oidc_discovery(ISS_A, http=http)


def test_discovery_refuses_a_plain_http_provider_except_on_this_machine():
    with pytest.raises(RuntimeError):
        oidc_discovery("http://id.alpha.example", http=Http({}))
    local = "http://localhost:8080/realms/lab"
    http = Http({local + "/.well-known/openid-configuration": {"issuer": local, "jwks_uri": local + "/keys"}})
    assert oidc_discovery(local, http=http)["jwks_uri"] == local + "/keys"


# ---- the issuing service and its witness -------------------------------------

issuer_key = Ed25519PrivateKey.generate()
PIN = {"policy_id": "p/1", "policy_sha256": "a" * 64}


class Hold:
    def pin(self): return PIN
    def decide(self, target_url, interaction): return Decision(ELIGIBLE, None, True)


def live(sub, name, key=key_a, kid="a-1", iss=ISS_A, roles=(), display=None, **claims):
    c = {"iss": iss, "sub": sub, "preferred_username": name, "aud": "gate",
         "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()), **claims}
    if roles: c["roles"] = list(roles)
    if display: c["name"] = display
    return {"Authorization": "Bearer " + encode(c, key, kid)}


def service(tmp_path, **kw):
    witness = WitnessLog(str(tmp_path / "witness.jsonl"), issuer_key, "issuer-1",
                         start_fields={"providers": [ISS_A, ISS_B], "software_version": "test"})
    reg = ApproverRegistry(str(tmp_path / "approvers.json"))
    app = build_issuer_app(policy=Hold(), signing_key=issuer_key, key_id="issuer-1", idp_public_keys=dict(KEYS),
                           providers=providers(), audience="gate", approver_registry=reg, witness=witness, **kw)
    return TestClient(app), witness, reg


def events(witness, kind):
    return [e for e in witness.entries if e["event"] == kind]


def hold(c, headers):
    r = c.post("/issue", json={"target_url": "mcp://fs", "tool": "write_file", "args": {"path": "a.txt", "content": "x"}}, headers=headers)
    assert r.json()["issued"] is True
    return r.json()["envelope"]


def grant_for(env, key, key_id):
    return sign_grant(build_grant(decision_sha256=env["decision_sha256"], approval_request_id=env["approval_request_id"],
                                  grant_id="g-" + env["approval_request_id"],
                                  not_after=datetime.now(timezone.utc) + timedelta(minutes=5)), key, key_id)


def test_a_token_from_the_wrong_issuer_gets_nothing_and_leaves_no_receipt(tmp_path):
    c, witness, _ = service(tmp_path)
    r = c.post("/issue", json={"target_url": "mcp://fs", "tool": "write_file", "args": {}}, headers=live("s-1", "sam", iss=ISS_B))
    assert r.status_code == 401 and r.json()["detail"]["reason"] == REF_IDENTITY_WRONG_ISSUER
    assert not events(witness, "issued")


def test_the_witness_is_version_3_and_names_who_asked_by_permanent_id(tmp_path):
    c, witness, _ = service(tmp_path)
    hold(c, live("s-sam", "sam@alpha.example"))
    started, issued = events(witness, "started")[0], events(witness, "issued")[0]
    assert started["witness_version"] == WITNESS_VERSION == "gargoyle-witness/3"
    assert started["providers"] == [ISS_A, ISS_B] and started["software_version"] == "test"
    assert issued["principal"] == "sam@alpha.example" and issued["principal_id"] == {"iss": ISS_A, "sub": "s-sam"}
    assert verify_witness(witness.entries, issuer_public_keys={"issuer-1": issuer_key.public_key()})["accepted"]


def test_a_release_records_the_persons_id_printed_name_and_meaning(tmp_path):
    c, witness, _ = service(tmp_path)
    dana = Ed25519PrivateKey.generate()
    dana_h = live("s-dana", "dana@alpha.example", roles=["Approver"], display="Dana Okoro")
    assert c.post("/approvers/enroll", json={"public_key_hex": pub_hex(dana)}, headers=dana_h).json()["enrolled"] is True
    env = hold(c, live("s-sam", "sam@alpha.example"))
    r = c.post("/grants", json=grant_for(env, dana, "dana@alpha.example"), headers=dana_h)
    assert r.json()["accepted"] is True
    g = events(witness, "granted")[0]
    assert g["approver"] == "dana@alpha.example" and g["approver_id"] == {"iss": ISS_A, "sub": "s-dana"}
    assert g["approver_name"] == "Dana Okoro" and g["meaning"] == "approval"
    assert events(witness, "enrolled")[0]["approver_id"] == {"iss": ISS_A, "sub": "s-dana"}


def test_a_decline_records_who_and_what_it_meant(tmp_path):
    c, witness, _ = service(tmp_path)
    dana_h = live("s-dana", "dana@alpha.example", roles=["Approver"], display="Dana Okoro")
    env = hold(c, live("s-sam", "sam@alpha.example"))
    c.post("/decline", json={"approval_request_id": env["approval_request_id"], "reason": "wrong file"}, headers=dana_h)
    env2 = hold(c, live("s-sam", "sam@alpha.example"))
    c.post("/decline", json={"approval_request_id": env2["approval_request_id"]}, headers=live("s-sam", "sam@alpha.example"))
    by_approver, by_owner = events(witness, "declined")
    assert by_approver["by_id"] == {"iss": ISS_A, "sub": "s-dana"} and by_approver["by_name"] == "Dana Okoro"
    assert by_approver["meaning"] == "rejection" and by_approver["why"] == "wrong file"
    assert by_owner["meaning"] == "withdrawal" and by_owner["by_id"] == {"iss": ISS_A, "sub": "s-sam"}


def test_a_reassigned_name_cannot_enrol_over_or_release_under_the_first_persons_key(tmp_path):
    c, witness, reg = service(tmp_path)
    dana = Ed25519PrivateKey.generate()
    first = live("s-dana", "dana@alpha.example", roles=["Approver"])
    assert c.post("/approvers/enroll", json={"public_key_hex": pub_hex(dana)}, headers=first).json()["enrolled"] is True
    # The directory later gives the same sign-in name to someone else: a different subject.
    second = live("s-other", "dana@alpha.example", roles=["Approver"])
    newkey = Ed25519PrivateKey.generate()
    r = c.post("/approvers/enroll", json={"public_key_hex": pub_hex(newkey)}, headers=second)
    assert r.status_code == 409 and r.json()["detail"]["reason"] == REF_ISSUER_SUBJECT_MISMATCH
    assert reg.public_hex() == {"dana@alpha.example": pub_hex(dana)}                      # the binding did not move
    # Even holding the first person's key file, the second person's token releases nothing.
    env = hold(c, live("s-sam", "sam@alpha.example"))
    r = c.post("/grants", json=grant_for(env, dana, "dana@alpha.example"), headers=second)
    assert r.json() == {"accepted": False, "reason": REF_ISSUER_SUBJECT_MISMATCH}
    assert not events(witness, "granted")
    assert events(witness, "enroll_refused")[0]["reason"] == REF_ISSUER_SUBJECT_MISMATCH
    assert events(witness, "grant_refused")[0]["reason"] == REF_ISSUER_SUBJECT_MISMATCH
    # The same name from the other provider is also someone else.
    other = live("s-dana", "dana@alpha.example", key=key_b, kid="b-1", iss=ISS_B, roles=["Approver"])
    assert c.post("/grants", json=grant_for(env, dana, "dana@alpha.example"), headers=other).json()["reason"] == REF_ISSUER_SUBJECT_MISMATCH
    # The first person still can.
    assert c.post("/grants", json=grant_for(env, dana, "dana@alpha.example"), headers=first).json()["accepted"] is True


def test_after_the_operator_revokes_the_old_binding_the_name_may_enrol_again(tmp_path):
    c, _, reg = service(tmp_path)
    dana = Ed25519PrivateKey.generate()
    c.post("/approvers/enroll", json={"public_key_hex": pub_hex(dana)}, headers=live("s-dana", "dana@alpha.example", roles=["Approver"]))
    assert reg.revoke("dana@alpha.example", revoked_by="operator")
    newkey = Ed25519PrivateKey.generate()
    r = c.post("/approvers/enroll", json={"public_key_hex": pub_hex(newkey)}, headers=live("s-other", "dana@alpha.example", roles=["Approver"]))
    assert r.json()["enrolled"] is True and reg.public_hex() == {"dana@alpha.example": pub_hex(newkey)}


def test_a_key_roll_is_adopted_for_its_own_provider_only(tmp_path):
    rolled = Ed25519PrivateKey.generate()
    ps = providers()
    ps[0]["refresh"] = lambda: {"a-2": rolled.public_key(), "b-1": rolled.public_key()}     # A also offers a key under B's id
    witness = WitnessLog(str(tmp_path / "w.jsonl"), issuer_key, "issuer-1")
    app = build_issuer_app(policy=Hold(), signing_key=issuer_key, key_id="issuer-1", idp_public_keys=dict(KEYS),
                           providers=ps, audience="gate", witness=witness)
    c = TestClient(app)
    body = {"target_url": "mcp://fs", "tool": "write_file", "args": {}}
    # A's new key is picked up on the first token that names it.
    assert c.post("/issue", json=body, headers=live("s-1", "sam", key=rolled, kid="a-2")).json()["issued"] is True
    # B's key id was not replaced by what A published: B's real key still works, A's stand-in does not.
    assert c.post("/issue", json=body, headers=live("s-1", "sam", key=rolled, kid="b-1", iss=ISS_B)).status_code == 401
    assert c.post("/issue", json=body, headers=live("s-1", "sam", key=key_b, kid="b-1", iss=ISS_B)).json()["issued"] is True


def test_earlier_witness_versions_still_verify_beside_version_3(tmp_path, monkeypatch):
    import gargoyle.witness as wmod
    path = str(tmp_path / "w.jsonl")
    for v in ("gargoyle-witness/1", "gargoyle-witness/2", "gargoyle-witness/3"):
        monkeypatch.setattr(wmod, "WITNESS_VERSION", v)
        WitnessLog(path, issuer_key, "issuer-1").record("issued", principal="p", tool="t")
    entries = wmod.read_witness(path)
    assert [e["witness_version"] for e in entries] == ["gargoyle-witness/1"] * 2 + ["gargoyle-witness/2"] * 2 + ["gargoyle-witness/3"] * 2
    assert verify_witness(entries, issuer_public_keys={"issuer-1": issuer_key.public_key()})["accepted"]
    entries[-1] = {**entries[-1], "witness_version": "gargoyle-witness/4"}
    assert not verify_witness(entries, issuer_public_keys={"issuer-1": issuer_key.public_key()})["accepted"]


def test_a_second_sign_in_name_for_the_requester_cannot_release_their_own_call(tmp_path):
    c, witness, _ = service(tmp_path)
    key = Ed25519PrivateKey.generate()
    env = hold(c, live("s-sam", "sam@alpha.example"))
    # The same subject under another name, with the approver role and an enrolled key.
    alias = live("s-sam", "samuel@alpha.example", roles=["Approver"])
    assert c.post("/approvers/enroll", json={"public_key_hex": pub_hex(key)}, headers=alias).json()["enrolled"] is True
    r = c.post("/grants", json=grant_for(env, key, "samuel@alpha.example"), headers=alias)
    assert r.json() == {"accepted": False, "reason": "REF_ISSUER_SELF_APPROVAL"}
    assert not events(witness, "granted")
    refused = events(witness, "grant_refused")[0]
    assert refused["posted_by_id"] == {"iss": ISS_A, "sub": "s-sam"} and refused["requested_by_id"] == {"iss": ISS_A, "sub": "s-sam"}


def test_an_entry_enrolled_before_ids_were_kept_is_held_to_its_object_id_then_learns_its_person(tmp_path):
    c, witness, reg = service(tmp_path)
    dana, erin = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    reg.enroll("dana@alpha.example", pub_hex(dana), oid="oid-dana")            # as 1.0.0rc2 stored it
    reg.enroll("erin@alpha.example", pub_hex(erin))                            # older still: no id at all
    env = hold(c, live("s-sam", "sam@alpha.example"))
    wrong = live("s-x", "dana@alpha.example", roles=["Approver"], oid="oid-someone-else")
    assert c.post("/grants", json=grant_for(env, dana, "dana@alpha.example"), headers=wrong).json()["reason"] == REF_ISSUER_SUBJECT_MISMATCH
    none = live("s-x", "dana@alpha.example", roles=["Approver"])               # no oid in the token: not shown to be the same person
    assert c.post("/grants", json=grant_for(env, dana, "dana@alpha.example"), headers=none).json()["reason"] == REF_ISSUER_SUBJECT_MISMATCH
    # An entry with nothing on record is bound to the first person who releases under it...
    assert c.post("/grants", json=grant_for(env, erin, "erin@alpha.example"),
                  headers=live("s-erin", "erin@alpha.example", roles=["Approver"])).json()["accepted"] is True
    assert reg.entries()["erin@alpha.example"]["subject_id"] == {"iss": ISS_A, "sub": "s-erin"}
    # ...and from then on to nobody else.
    env2 = hold(c, live("s-sam", "sam@alpha.example"))
    r = c.post("/grants", json=grant_for(env2, erin, "erin@alpha.example"), headers=live("s-other", "erin@alpha.example", roles=["Approver"]))
    assert r.json()["reason"] == REF_ISSUER_SUBJECT_MISMATCH


def test_a_release_records_when_the_person_signed_in_if_the_token_says(tmp_path):
    c, witness, _ = service(tmp_path)
    dana = Ed25519PrivateKey.generate()
    at = int(datetime.now(timezone.utc).timestamp()) - 90
    dana_h = live("s-dana", "dana@alpha.example", roles=["Approver"], auth_time=at)
    c.post("/approvers/enroll", json={"public_key_hex": pub_hex(dana)}, headers=dana_h)
    env = hold(c, live("s-sam", "sam@alpha.example"))
    assert c.post("/grants", json=grant_for(env, dana, "dana@alpha.example"), headers=dana_h).json()["accepted"] is True
    g = events(witness, "granted")[0]
    assert g["auth_time"] == at and 90 <= g["auth_age_seconds"] < 100
    # No claim, no entry member: nothing is made up.
    env2 = hold(c, live("s-sam", "sam@alpha.example"))
    c.post("/grants", json=grant_for(env2, dana, "dana@alpha.example"), headers=live("s-dana", "dana@alpha.example", roles=["Approver"], auth_time="yesterday"))
    assert "auth_time" not in events(witness, "granted")[1]


def test_a_configured_keys_release_names_who_carried_it_in_not_a_person_who_signed(tmp_path):
    filekey = Ed25519PrivateKey.generate()
    c, witness, _ = service(tmp_path, approver_public_keys={"approver-file": filekey.public_key()})
    env = hold(c, live("s-sam", "sam@alpha.example"))
    assert c.post("/grants", json=grant_for(env, filekey, "approver-file"), headers=live("s-console", "console")).json()["accepted"] is True
    g = events(witness, "granted")[0]
    assert g["approver"] == "approver-file" and "approver_id" not in g
    assert g["posted_by"] == "console" and g["posted_by_id"] == {"iss": ISS_A, "sub": "s-console"}


def test_two_providers_may_not_claim_one_key_id():
    with pytest.raises(ValueError):
        build_issuer_app(policy=Hold(), signing_key=issuer_key, key_id="issuer-1", idp_public_keys=dict(KEYS),
                         providers=[provider(ISS_A, key_ids={"a-1"}), provider(ISS_B, key_ids={"a-1"})], audience="gate")


# ---- settings ----------------------------------------------------------------

def jwk(key, kid):
    from gargoyle.jws import b64url_encode
    return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64url_encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))}


def site(issuer, *jwks):
    return {issuer.rstrip("/") + "/.well-known/openid-configuration": {"issuer": issuer, "jwks_uri": issuer.rstrip("/") + "/keys"},
            issuer.rstrip("/") + "/keys": {"keys": list(jwks)}}


def test_providers_come_from_one_setting_and_their_own_discovery():
    from gargoyle.issuer_service import providers_from_env
    ms = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
    http = Http({**site(ISS_A, jwk(key_a, "a-1")), **site(ms, jwk(key_b, "ms-1"))})
    ps, keys = providers_from_env({"GARGOYLE_OIDC_ISSUER": ISS_A + " , " + ms, "GARGOYLE_CLAIM_NAME": "login,sub",
                                   "GARGOYLE_CLAIM_ROLES": "realm_roles"}, http=http)
    assert [p["issuer"] for p in ps] == [ISS_A, ms] and set(keys) == {"a-1", "ms-1"}
    assert ps[0]["key_ids"] == {"a-1"} and ps[0]["name_claims"] == ["login", "sub"] and ps[0]["roles_claim"] == "realm_roles"
    assert (ps[0]["subject_claim"], ps[1]["subject_claim"]) == ("sub", "oid")      # Microsoft is a preset, not a special path
    assert set(ps[0]["refresh"]()) == {"a-1"}
    assert providers_from_env({}, http=http) == ([], {})
    # The Microsoft preset end to end: the person is the object id, under the tenant's exact issuer.
    ps, keys = providers_from_env({"GARGOYLE_OIDC_ISSUER": ms}, http=http)
    t = encode({"exp": EXP, "iss": ms, "sub": "pairwise-per-app", "oid": "oid-9", "preferred_username": "dana@contoso.example"}, key_b, "ms-1")
    r = principal_from_token(t, keys, now=NOW, providers=ps)
    assert r["principal"] == "dana@contoso.example" and r["subject_id"] == {"iss": ms, "sub": "oid-9"}
    other_tenant = ms.replace("1111", "9999")
    t = encode({"exp": EXP, "iss": other_tenant, "sub": "x", "oid": "oid-9"}, key_b, "ms-1")
    assert principal_from_token(t, keys, now=NOW, providers=ps)["reason"] == REF_IDENTITY_WRONG_ISSUER


def test_settings_that_cannot_be_trusted_stop_the_service_at_startup():
    from gargoyle.issuer_service import providers_from_env
    with pytest.raises(RuntimeError):                                              # two providers, one key id
        providers_from_env({"GARGOYLE_OIDC_ISSUER": ISS_A + "," + ISS_B},
                           http=Http({**site(ISS_A, jwk(key_a, "k-1")), **site(ISS_B, jwk(key_b, "k-1"))}))
    with pytest.raises(RuntimeError):                                              # the same issuer twice
        providers_from_env({"GARGOYLE_OIDC_ISSUER": ISS_A + "," + ISS_A}, http=Http(site(ISS_A, jwk(key_a, "a-1"))))
    with pytest.raises(RuntimeError):                                              # a provider that does not answer
        providers_from_env({"GARGOYLE_OIDC_ISSUER": ISS_A}, http=Http({}))


def test_an_oidc_issuer_without_an_audience_does_not_start(monkeypatch):
    from gargoyle.issuer_service import app_from_env
    for k in ("GARGOYLE_ENTRA_TENANT", "GARGOYLE_ISSUER_AUDIENCE", "GARGOYLE_IDP_KEY_ID", "GARGOYLE_IDP_PUBLIC_KEY_HEX"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("GARGOYLE_ISSUER_KEY_ID", "issuer-1")
    monkeypatch.setenv("GARGOYLE_ISSUER_KEY_HEX", "11" * 32)
    monkeypatch.setenv("GARGOYLE_OIDC_ISSUER", ISS_A)
    with pytest.raises(RuntimeError, match="GARGOYLE_ISSUER_AUDIENCE"):
        app_from_env()


# ---- what a real provider's tokens look like (stage 3b) ----------------------

def test_a_claim_setting_may_name_a_nested_claim_and_a_literal_name_wins():
    # Keycloak: roles under realm_access.roles. Auth0: a namespaced claim whose name has dots in it.
    ps = providers(roles_claim="realm_access.roles", groups_claim="https://lab.example/groups", name_claims=["profile.login", "sub"])
    r = who(tok(iss=ISS_A, sub="s-1", realm_access={"roles": ["Approver", "offline_access"]}, roles=["Admin"],
                **{"https://lab.example/groups": ["qa"]}, profile={"login": "dana"}), providers=ps)
    assert r["roles"] == ["Approver", "offline_access"] and r["groups"] == ["qa"] and r["principal"] == "dana"
    # A path that leads nowhere, or through something that is not an object, gives nothing: never another claim's value.
    for bad in ({"realm_access": "Approver"}, {"realm_access": {"role": ["Approver"]}}, {"realm_access": ["Approver"]}, {}):
        assert who(tok(iss=ISS_A, sub="s-1", roles=["Approver"], **bad), providers=ps)["roles"] == []


def test_an_encryption_key_in_a_key_set_is_not_a_signing_key():
    from gargoyle.jws import keys_from_jwks
    ks = keys_from_jwks({"keys": [{**jwk(key_a, "sig-1"), "use": "sig"}, {**jwk(key_b, "enc-1"), "use": "enc"}, jwk(key_b, "plain-1")]})
    assert set(ks) == {"sig-1", "plain-1"}


# ---- how recently the approver signed in (stage 3b) ---------------------------

def test_with_a_sign_in_age_rule_a_release_needs_a_recent_sign_in(tmp_path):
    from gargoyle.issuer_service import REF_ISSUER_AUTH_TIME_MISSING, REF_ISSUER_AUTH_TOO_OLD
    c, witness, _ = service(tmp_path, release_max_auth_age=300)
    dana = Ed25519PrivateKey.generate()
    t = lambda: int(datetime.now(timezone.utc).timestamp())
    as_dana = lambda **claims: live("s-dana", "dana@alpha.example", roles=["Approver"], **claims)
    c.post("/approvers/enroll", json={"public_key_hex": pub_hex(dana)}, headers=as_dana())
    env = hold(c, live("s-sam", "sam@alpha.example"))
    post = lambda headers: c.post("/grants", json=grant_for(env, dana, "dana@alpha.example"), headers=headers).json()
    assert post(as_dana()) == {"accepted": False, "reason": REF_ISSUER_AUTH_TIME_MISSING}                    # the token does not say when
    assert post(as_dana(auth_time=str(t()))) == {"accepted": False, "reason": REF_ISSUER_AUTH_TIME_MISSING}  # not a number
    assert post(as_dana(auth_time=True)) == {"accepted": False, "reason": REF_ISSUER_AUTH_TIME_MISSING}
    assert post(as_dana(auth_time=t() + 3600)) == {"accepted": False, "reason": REF_ISSUER_AUTH_TIME_MISSING}  # a sign-in in the future is no sign-in
    assert post(as_dana(auth_time=t() - 301)) == {"accepted": False, "reason": REF_ISSUER_AUTH_TOO_OLD}
    assert post(as_dana(auth_time=t() - 86400)) == {"accepted": False, "reason": REF_ISSUER_AUTH_TOO_OLD}
    assert not events(witness, "granted") and len(events(witness, "grant_refused")) == 6                     # every refusal is on record
    assert events(witness, "grant_refused")[-1]["auth_age_seconds"] >= 86400
    ok = post(as_dana(auth_time=t() - 120))                                                                  # the hold stood through all of it
    assert ok["accepted"] is True and 120 <= events(witness, "granted")[0]["auth_age_seconds"] < 130


def test_the_sign_in_age_rule_is_about_people_and_is_off_unless_set(tmp_path):
    filekey = Ed25519PrivateKey.generate()
    c, witness, _ = service(tmp_path, release_max_auth_age=300, approver_public_keys={"approver-file": filekey.public_key()})
    env = hold(c, live("s-sam", "sam@alpha.example"))
    # A configured key is no person's sign-in: the rule does not reach it (the regulated profile excludes such keys instead).
    assert c.post("/grants", json=grant_for(env, filekey, "approver-file"), headers=live("s-console", "console")).json()["accepted"] is True


def test_a_sign_in_age_setting_that_is_not_a_positive_number_stops_the_service(monkeypatch):
    from gargoyle.issuer_service import release_max_auth_age_from_env
    assert release_max_auth_age_from_env({}) is None and release_max_auth_age_from_env({"GARGOYLE_RELEASE_MAX_AUTH_AGE": " 900 "}) == 900
    for bad in ("0", "-5", "ten", "1.5"):
        with pytest.raises(RuntimeError):
            release_max_auth_age_from_env({"GARGOYLE_RELEASE_MAX_AUTH_AGE": bad})


# ---- the approval console signs in with the same provider (stage 3b) ---------

def test_the_console_is_told_where_to_sign_in_from_the_providers_own_document():
    from gargoyle.issuer_service import console_oidc_from_env, providers_from_env
    docs = site(ISS_A, jwk(key_a, "a-1"))
    docs[ISS_A + "/.well-known/openid-configuration"].update(authorization_endpoint=ISS_A + "/auth", token_endpoint=ISS_A + "/token")
    ps, _ = providers_from_env({"GARGOYLE_OIDC_ISSUER": ISS_A}, http=Http(docs))
    assert console_oidc_from_env({}, ps) is None                                   # no client id: the console offers no provider sign-in
    cfg = console_oidc_from_env({"GARGOYLE_OIDC_CLIENT_ID": "console"}, ps, max_auth_age=900)
    assert cfg == {"issuer": ISS_A, "client_id": "console", "scope": "openid profile", "authorization_endpoint": ISS_A + "/auth",
                   "token_endpoint": ISS_A + "/token", "label": "id.alpha.example", "max_age": 900}
    cfg = console_oidc_from_env({"GARGOYLE_OIDC_CLIENT_ID": "console", "GARGOYLE_OIDC_SCOPE": "openid gate", "GARGOYLE_OIDC_LABEL": "Alpha SSO"}, ps)
    assert (cfg["scope"], cfg["label"]) == ("openid gate", "Alpha SSO") and "max_age" not in cfg
    with pytest.raises(RuntimeError):                                              # a client id and no provider
        console_oidc_from_env({"GARGOYLE_OIDC_CLIENT_ID": "console"}, [])
    with pytest.raises(RuntimeError):                                              # a console issuer that is not one of the trusted ones
        console_oidc_from_env({"GARGOYLE_OIDC_CLIENT_ID": "console", "GARGOYLE_OIDC_CONSOLE_ISSUER": ISS_B}, ps)


@pytest.mark.parametrize("endpoints", [
    {"token_endpoint": ISS_A + "/token"},                                                        # no sign-in page
    {"authorization_endpoint": ISS_A + "/auth"},                                                 # no token endpoint
    {"authorization_endpoint": "http://id.alpha.example/auth", "token_endpoint": ISS_A + "/token"},   # a sign-in page over plain http
    {"authorization_endpoint": ISS_A + "/auth", "token_endpoint": "javascript:alert(1)"},
])
def test_the_console_is_never_sent_to_an_endpoint_that_cannot_be_trusted(endpoints):
    from gargoyle.issuer_service import console_oidc_from_env, providers_from_env
    docs = site(ISS_A, jwk(key_a, "a-1"))
    docs[ISS_A + "/.well-known/openid-configuration"].update(endpoints)
    ps, _ = providers_from_env({"GARGOYLE_OIDC_ISSUER": ISS_A}, http=Http(docs))
    with pytest.raises(RuntimeError):
        console_oidc_from_env({"GARGOYLE_OIDC_CLIENT_ID": "console"}, ps)


def test_the_console_config_is_public_and_names_no_secret(tmp_path):
    cfg = {"issuer": ISS_A, "client_id": "console", "scope": "openid profile", "authorization_endpoint": ISS_A + "/auth",
           "token_endpoint": ISS_A + "/token", "label": "Alpha SSO"}
    c, _, _ = service(tmp_path, console_oidc=cfg)
    assert c.get("/approve-config").json() == {"entra": None, "oidc": cfg}
    plain, _, _ = service(tmp_path / "plain")
    assert plain.get("/approve-config").json() == {"entra": None}                  # as before when not configured
