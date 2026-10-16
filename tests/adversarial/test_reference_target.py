"""
Tests for the reference target in gargoyle.consumer, the deployable enforcing target.

The app is driven through TestClient with an injected config_provider (the
out-of-band pins) and an injected fetch (the published-record request goes to
a publisher TestClient), so the suite needs no network.

The issuer keypair comes from the `gate_signing` conftest fixture. Receipts
are signed with it because the reference target pins the issuer key, which
makes verify_envelope require a signature. The anchor is computed from the
reference record bytes (tests/reference.py); receipts use a fixed timestamp_utc.
"""

import json
import uuid

from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from reference import reference_policy, reference_record_bytes
from gargoyle.policy import ManifestPolicy
from gargoyle.envelope import build_envelope, canonical_json, sign_envelope
from gargoyle.published_source import anchor_sha256, load_record_from_bytes
from gargoyle.consumer import (
    REF_TARGET_ANCHOR_MISMATCH,
    REF_TARGET_NO_PRINCIPAL,
    REF_TARGET_NOT_CONFIGURED,
    build_reference_target_app,
)
from gargoyle.verifier import (
    ACCEPT_REASSERTED_AND_BOUND,
    REF_VERIFY_BINDING_MISMATCH,
    REF_VERIFY_ENVELOPE_ABSENT,
    REF_VERIFY_PRINCIPAL_MISMATCH,
    REF_VERIFY_SIGNATURE_INVALID,
    REF_VERIFY_REPLAY,
)


TARGET_URL = "http://127.0.0.1:9000/target"
OTHER_URL = "http://127.0.0.1:9000/other"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _published_bytes():
    return reference_record_bytes()


def _pinned_root():
    """The pinned anchor: the SHA-256 of the record bytes."""
    return anchor_sha256(_published_bytes())


PRINCIPAL_HEADER = "X-Peer"  # the front proxy's identity header, in the config
PRINCIPAL = "agent-7"


def _normalized_interaction(tool="transfer", args=None, principal=PRINCIPAL):
    return {
        "tool": tool,
        "args": {"amount": 5} if args is None else args,
        "principal": principal,
    }


def _signed_envelope(gate_signing, interaction=None, target_url=TARGET_URL,
                     timestamp_utc="2026-06-08T00:00:00+00:00"):
    """Build and sign a receipt with the conftest issuer key."""
    if interaction is None:
        interaction = _normalized_interaction()
    env = build_envelope(
        policy_pin=reference_policy().pin(),
        decision="ELIGIBLE",
        target_url=target_url,
        call=interaction,
        timestamp_utc=timestamp_utc,
    )
    return sign_envelope(env, gate_signing["private_key"], gate_signing["key_id"],
                         decision_id=uuid.uuid4().hex)


def _publisher_client(serve_bytes):
    app = FastAPI()

    @app.get("/published_hashes.json")
    async def published():
        return Response(content=serve_bytes, media_type="application/json")

    return TestClient(app)


def _fetch_via(pub_client):
    def fetch(url, pinned_root):
        resp = pub_client.get("/published_hashes.json")
        if resp.status_code != 200:
            return None
        return load_record_from_bytes(resp.content, pinned_root)
    return fetch


def _make_target(gate_signing, target_url=TARGET_URL, serve_bytes=None, replay_cache=None,
                 principal_header=PRINCIPAL_HEADER, principal_resolver=None):
    """Build the reference target with injected config + fetch. Returns (app, client)."""
    if serve_bytes is None:
        serve_bytes = _published_bytes()
    config = {
        "target_url": target_url,
        "publisher_url": "http://publisher.test/published_hashes.json",
        "pinned_root_sha256": _pinned_root(),
        "pinned_public_keys": {
            gate_signing["key_id"]: gate_signing["public_key"]
        },
    }
    if principal_header is not None:
        config["principal_header"] = principal_header
    app = build_reference_target_app(
        config_provider=lambda: config,
        fetch=_fetch_via(_publisher_client(serve_bytes)),
        replay_cache=replay_cache,
        principal_resolver=principal_resolver,
    )
    return app, TestClient(app)


def _post(client, interaction, envelope=None, principal=PRINCIPAL, body=None):
    """POST the call: tool and args in the body, the principal in the proxy
    header (None sends no header), the receipt in its header."""
    headers = {}
    if envelope is not None:
        headers["X-Gargoyle-Envelope"] = canonical_json(envelope)
    if principal is not None:
        headers[PRINCIPAL_HEADER] = principal
    if body is None:
        body = {"tool": interaction["tool"], "args": interaction["args"]}
    return client.post("/target", json=body, headers=headers)


# ---------------------------------------------------------------------------
# Honor: a valid, signed, current, bound call is honored and acted on.
# ---------------------------------------------------------------------------


def test_reference_target_honors_valid_signed_routed_call(gate_signing):
    app, client = _make_target(gate_signing)
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction=interaction)
    resp = _post(client, interaction, env)
    assert resp.status_code == 200
    assert resp.json()["honored"] is True
    assert resp.json()["reason"] == ACCEPT_REASSERTED_AND_BOUND
    assert len(app.state.received) == 1  # acted exactly once


# ---------------------------------------------------------------------------
# Refusals. Each asserts non-200 AND that the target did not act.
# ---------------------------------------------------------------------------


def test_reference_target_refuses_absent_envelope_a1(gate_signing):
    """A direct caller sending no receipt header is refused by the target itself."""
    app, client = _make_target(gate_signing)
    resp = _post(client, _normalized_interaction(), envelope=None)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_ENVELOPE_ABSENT
    assert app.state.received == []


def test_reference_target_refuses_keyless_forge(gate_signing):
    """
    A receipt with its signature stripped, as a keyless attacker would send, is
    refused because the target pins the issuer key.
    """
    app, client = _make_target(gate_signing)
    env = _signed_envelope(gate_signing)
    forge = {k: v for k, v in env.items() if k != "issuer_signature"}
    resp = _post(client, _normalized_interaction(), forge)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_SIGNATURE_INVALID
    assert app.state.received == []


def test_reference_target_refuses_tampered_signed_envelope_a2(gate_signing):
    """
    A signed receipt whose request_context is changed after signing is refused:
    the edit is inside the signed region, so the signature fails.
    """
    app, client = _make_target(gate_signing)
    env = _signed_envelope(gate_signing)
    env["request_context"]["tool"] = "delete_database"  # tamper post-sign
    resp = _post(client, _normalized_interaction(), env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_SIGNATURE_INVALID
    assert app.state.received == []


def test_reference_target_refuses_replay_binding_mismatch_a3(gate_signing):
    """
    A genuine signed receipt for call X, delivered with a different call Y, is
    refused by the binding check.
    """
    app, client = _make_target(gate_signing)
    interaction_x = _normalized_interaction(args={"amount": 5})
    env = _signed_envelope(gate_signing, interaction=interaction_x)
    interaction_y = _normalized_interaction(args={"amount": 5000})
    resp = _post(client, interaction_y, env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_BINDING_MISMATCH
    assert app.state.received == []


def test_reference_target_refuses_body_with_unbound_fields(gate_signing):
    """The body is exactly {"tool", "args"}; anything more is unbound data."""
    app, client = _make_target(gate_signing)
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction=interaction)
    for body in ({"tool": "transfer", "args": {"amount": 5}, "mode": "force"},
                 {"tool": "transfer"},
                 ["transfer"]):
        resp = _post(client, interaction, env, body=body)
        assert resp.status_code == 403, body
        assert resp.json()["detail"]["reason"] == REF_VERIFY_BINDING_MISMATCH, body
    assert app.state.received == []


# ---------------------------------------------------------------------------
# The principal: the target's own authentication, never the body.
# ---------------------------------------------------------------------------


def test_reference_target_refuses_receipt_issued_to_another_principal(gate_signing):
    """agent-8 presents agent-7's receipt for the same call: refused."""
    app, client = _make_target(gate_signing)
    interaction = _normalized_interaction(principal="agent-7")
    env = _signed_envelope(gate_signing, interaction=interaction)
    resp = _post(client, interaction, env, principal="agent-8")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_PRINCIPAL_MISMATCH
    assert app.state.received == []


def test_reference_target_refuses_unauthenticated_caller(gate_signing):
    """No proxy header, an empty one, or two of them: nobody is calling, and
    nobody gets nothing, before the receipt is even looked at."""
    app, client = _make_target(gate_signing)
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction=interaction)
    for principal in (None, "", "   "):
        resp = _post(client, interaction, env, principal=principal)
        assert resp.status_code == 403, principal
        assert resp.json()["detail"]["reason"] == REF_TARGET_NO_PRINCIPAL, principal
    body = {"tool": interaction["tool"], "args": interaction["args"]}
    resp = client.post("/target", json=body,
                       headers=[("X-Gargoyle-Envelope", canonical_json(env)),
                                (PRINCIPAL_HEADER, "agent-7"), (PRINCIPAL_HEADER, "agent-7")])
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_TARGET_NO_PRINCIPAL
    assert app.state.received == []


def test_reference_target_ignores_principal_in_body(gate_signing):
    """A principal written into the body is not identity; it is an unbound
    field and the call is refused."""
    app, client = _make_target(gate_signing)
    interaction = _normalized_interaction(principal="agent-7")
    env = _signed_envelope(gate_signing, interaction=interaction)
    body = {"tool": "transfer", "args": {"amount": 5}, "principal": "agent-7"}
    resp = _post(client, interaction, env, principal="agent-8", body=body)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_BINDING_MISMATCH
    assert app.state.received == []


def test_reference_target_without_principal_source_refuses_everyone(gate_signing):
    """No principal header configured and no resolver injected: the default
    resolver authenticates nobody, so every call is refused."""
    app, client = _make_target(gate_signing, principal_header=None)
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction=interaction)
    resp = _post(client, interaction, env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_TARGET_NO_PRINCIPAL
    assert app.state.received == []


def test_reference_target_uses_an_injected_principal_resolver(gate_signing):
    """An integrator's resolver (an mTLS peer, a token subject) replaces the
    header; the header is then ignored, and a resolver that raises or
    returns nothing refuses."""
    app, client = _make_target(gate_signing, principal_header=None,
                               principal_resolver=lambda request, config: "agent-7")
    interaction = _normalized_interaction(principal="agent-7")
    env = _signed_envelope(gate_signing, interaction=interaction)
    assert _post(client, interaction, env, principal="agent-8").status_code == 200
    assert len(app.state.received) == 1

    def broken(request, config):
        raise RuntimeError("identity provider down")

    for resolver in (broken, lambda request, config: None, lambda request, config: 42):
        app, client = _make_target(gate_signing, principal_resolver=resolver)
        env = _signed_envelope(gate_signing, interaction=interaction)
        resp = _post(client, interaction, env)
        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == REF_TARGET_NO_PRINCIPAL
        assert app.state.received == []


def test_reference_target_refuses_target_url_swap(gate_signing):
    """
    A signed receipt bound to another target_url is refused: target_url is
    inside the signed region and part of the binding.
    """
    app, client = _make_target(gate_signing, target_url=TARGET_URL)
    env = _signed_envelope(gate_signing, target_url=OTHER_URL)
    resp = _post(client, _normalized_interaction(), env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_BINDING_MISMATCH
    assert app.state.received == []


def test_reference_target_refuses_record_failing_anchor(gate_signing):
    """
    The publisher serves bytes that do not hash to the pinned anchor, as a
    substituted record would. The fetch returns None and the target refuses
    before checking the receipt.
    """
    tampered = _published_bytes().replace(b"manifest-subset/1", b"manifest-subset/9")
    assert tampered != _published_bytes()
    app, client = _make_target(gate_signing, serve_bytes=tampered)
    env = _signed_envelope(gate_signing)
    resp = _post(client, _normalized_interaction(), env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_TARGET_ANCHOR_MISMATCH
    assert app.state.received == []


def test_reference_target_fails_closed_when_unconfigured(gate_signing):
    """
    With incomplete out-of-band configuration the target refuses every call
    rather than acting on a missing trust base.
    """
    app = build_reference_target_app(
        config_provider=lambda: None,
        fetch=_fetch_via(_publisher_client(_published_bytes())),
    )
    client = TestClient(app)
    env = _signed_envelope(gate_signing)
    resp = _post(client, _normalized_interaction(), env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_TARGET_NOT_CONFIGURED
    assert app.state.received == []


def test_reference_target_received_endpoint_reflects_acted_count(gate_signing):
    """
    The read-only /received endpoint reports how many calls the target acted on:
    0 before any honored call, 1 after one. It lets an external test confirm an
    honored call without resending the receipt; it plays no part in admission.
    """
    app, client = _make_target(gate_signing)
    assert client.get("/received").json()["count"] == 0
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction=interaction)
    assert _post(client, interaction, env).status_code == 200
    assert client.get("/received").json()["count"] == 1


def test_reference_target_refuses_replay(gate_signing):
    """
    Single use: the same receipt (same decision_id) is honored once and refused
    on replay; the target acts exactly once.
    """
    app, client = _make_target(gate_signing)
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction=interaction)
    first = _post(client, interaction, env)
    assert first.status_code == 200
    second = _post(client, interaction, env)  # exact replay -> same decision_id
    assert second.status_code == 403
    assert second.json()["detail"]["reason"] == REF_VERIFY_REPLAY
    assert len(app.state.received) == 1


def test_reference_target_decision_id_is_signed(gate_signing):
    """
    decision_id is inside the signed region, so changing it to dodge the replay
    check breaks the signature.
    """
    app, client = _make_target(gate_signing)
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction=interaction)
    env["decision_id"] = "tampered-id"
    resp = _post(client, interaction, env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_SIGNATURE_INVALID
    assert app.state.received == []


def test_shared_replay_cache_cross_instance(gate_signing):
    """
    Two target instances sharing one replay cache enforce single use across both:
    a decision_id honored on instance A is refused REF_VERIFY_REPLAY on instance
    B. One shared InMemoryReplayCache stands in for a shared Redis store.
    """
    from gargoyle.replay_cache import InMemoryReplayCache

    shared = InMemoryReplayCache()
    _, client_a = _make_target(gate_signing, replay_cache=shared)
    _, client_b = _make_target(gate_signing, replay_cache=shared)
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction)

    r1 = _post(client_a, interaction, env)
    assert r1.status_code == 200, r1.text                       # honored on instance A

    r2 = _post(client_b, interaction, env)                      # SAME envelope, instance B
    assert r2.status_code == 403
    assert r2.json()["detail"]["reason"] == REF_VERIFY_REPLAY   # cross-instance replay caught


def test_reference_target_refuses_duplicate_envelope_header_p01(gate_signing):
    """
    A valid receipt sent in two duplicate headers is treated as absent and
    refused, rather than honoring whichever header comes first.
    """
    app, client = _make_target(gate_signing)
    interaction = _normalized_interaction()
    env = _signed_envelope(gate_signing, interaction=interaction)
    body = canonical_json(env)
    resp = client.post("/target", json={"tool": interaction["tool"], "args": interaction["args"]},
                       headers=[("X-Gargoyle-Envelope", body), ("X-Gargoyle-Envelope", body),
                                (PRINCIPAL_HEADER, PRINCIPAL)])
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_ENVELOPE_ABSENT
    assert app.state.received == []
