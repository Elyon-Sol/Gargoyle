"""The issuer-side identity input: a transaction token or bearer JWT becomes
the receipt's principal (and on_behalf_of, for delegation)."""

from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyle.identity import REF_IDENTITY_NO_SUBJECT, principal_from_token
from gargoyle.issuer import issue
from gargoyle.jws import REF_JWS_AUDIENCE_MISMATCH, REF_JWS_EXPIRED, REF_JWS_KEY_UNKNOWN, encode
from gargoyle.policy import ELIGIBLE, Decision

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
idp = Ed25519PrivateKey.generate(); IDP = {"idp-1": idp.public_key()}
EXP = int((NOW + timedelta(minutes=5)).timestamp())


def token(**claims):
    return encode({"exp": EXP, **claims}, idp, "idp-1")


def test_bearer_subject_becomes_the_principal():
    r = principal_from_token(token(sub="spiffe://example.org/agents/payments", aud="gargoyle"), IDP, audience="gargoyle", now=NOW)
    assert (r["principal"], r["on_behalf_of"], r["reason"]) == ("spiffe://example.org/agents/payments", None, None)


def test_rfc8693_actor_is_the_principal_and_subject_the_party_acted_for():
    r = principal_from_token(token(sub="user-42", act={"sub": "agent-7"}), IDP, now=NOW)
    assert (r["principal"], r["on_behalf_of"]) == ("agent-7", "user-42")
    nested = token(sub="user-42", act={"sub": "orchestrator", "act": {"sub": "agent-7"}})
    r = principal_from_token(nested, IDP, now=NOW)
    assert (r["principal"], r["on_behalf_of"]) == ("agent-7", "user-42")


def test_transaction_token_for_agents_fields():
    r = principal_from_token(token(sub="user-42", agentic_ctx={"actor": "agent-7", "principal": "user-42"}), IDP, now=NOW)
    assert (r["principal"], r["on_behalf_of"]) == ("agent-7", "user-42")
    r = principal_from_token(token(actor="agent-7", principal="user-42"), IDP, now=NOW)
    assert (r["principal"], r["on_behalf_of"]) == ("agent-7", "user-42")
    r = principal_from_token(token(agentic_ctx={"actor": "autonomous-agent"}), IDP, now=NOW)
    assert (r["principal"], r["on_behalf_of"]) == ("autonomous-agent", None)


def test_identity_refusals():
    assert principal_from_token(token(sub="agent-7"), IDP, now=NOW + timedelta(hours=1))["reason"] == REF_JWS_EXPIRED
    assert principal_from_token(token(sub="agent-7", aud=["a", "b"]), IDP, audience="c", now=NOW)["reason"] == REF_JWS_AUDIENCE_MISMATCH
    assert principal_from_token(token(sub="agent-7", aud=["a", "b"]), IDP, audience="b", now=NOW)["reason"] is None
    assert principal_from_token(token(sub="agent-7"), {}, now=NOW)["reason"] == REF_JWS_KEY_UNKNOWN
    assert principal_from_token(token(name="nobody"), IDP, now=NOW)["reason"] == REF_IDENTITY_NO_SUBJECT
    assert principal_from_token(token(sub=""), IDP, now=NOW)["reason"] == REF_IDENTITY_NO_SUBJECT
    assert principal_from_token(encode({"sub": "x"}, idp, "idp-1"), IDP, now=NOW)["reason"] == REF_JWS_EXPIRED


def test_identity_flows_into_the_receipt():
    class AllowAll:
        def pin(self): return {"policy_id": "engine/1", "policy_sha256": "a" * 64}
        def decide(self, target_url, interaction): return Decision(ELIGIBLE)
    who = principal_from_token(token(sub="user-42", act={"sub": "agent-7"}), IDP, now=NOW)
    key = Ed25519PrivateKey.generate()
    r = issue(AllowAll(), "https://t", {"tool": "transfer", "args": {}, "principal": who["principal"],
                                        "on_behalf_of": who["on_behalf_of"]}, signing_key=key, key_id="k1")
    assert r.envelope["request_context"]["principal"] == "agent-7"
    assert r.envelope["request_context"]["on_behalf_of"] == "user-42"


def test_several_audiences_are_accepted_as_a_list_or_comma_string():
    assert principal_from_token(token(sub="agent-7", aud="gargoyle-issuer"), IDP, audience="gargoyle-issuer,88d5", now=NOW)["reason"] is None
    assert principal_from_token(token(sub="agent-7", aud="88d5"), IDP, audience="gargoyle-issuer, 88d5", now=NOW)["reason"] is None
    assert principal_from_token(token(sub="agent-7", aud="other"), IDP, audience=["gargoyle-issuer", "88d5"], now=NOW)["reason"] == REF_JWS_AUDIENCE_MISMATCH
