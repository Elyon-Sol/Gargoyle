"""
Tests for gargoyle.reference_target, the deployable enforcing target.

The app is driven through TestClient with an injected config_provider (the
out-of-band pins) and an injected fetch (the published-record request goes to
a publisher TestClient), so the suite needs no network.

The issuer keypair comes from the `gate_signing` conftest fixture. Receipts
are signed with it because the reference target pins the issuer key, which
makes verify_envelope require a signature. The anchor is computed from the
committed published_hashes.json bytes, and receipts use a fixed timestamp_utc.
"""

import json
import uuid

from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from gargoyle.policy import ManifestPolicy
from gargoyle.envelope import build_envelope, canonical_json, sign_envelope
from gargoyle.policy import load_manifest, manifest_sha256
from gargoyle.published_source import anchor_sha256, load_record_from_bytes
from gargoyle.reference_target import (
    REF_TARGET_ANCHOR_MISMATCH,
    REF_TARGET_NOT_CONFIGURED,
    build_reference_target_app,
)
from gargoyle.verifier import (
    ACCEPT_REASSERTED_AND_BOUND,
    REF_VERIFY_BINDING_MISMATCH,
    REF_VERIFY_ENVELOPE_ABSENT,
    REF_VERIFY_SIGNATURE_INVALID,
    REF_VERIFY_REPLAY,
)


TARGET_URL = "http://127.0.0.1:9000/target"
OTHER_URL = "http://127.0.0.1:9000/other"
PUBLISHED_HASHES_PATH = "EVIDENCE/published_hashes.json"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _published_bytes():
    with open(PUBLISHED_HASHES_PATH, "rb") as f:
        return f.read()


def _pinned_root():
    """The pinned anchor: the SHA-256 of the record bytes."""
    return anchor_sha256(_published_bytes())


def _normalized_interaction(ap=None, op=None, context=None):
    return {
        "AP": ["identity", "role"] if ap is None else ap,
        "OP": ["session", "request"] if op is None else op,
        "context": {} if context is None else context,
        "expected_manifest_version": "1.0",
        "expected_manifest_sha256": manifest_sha256(),
    }


def _signed_envelope(gate_signing, interaction=None, target_url=TARGET_URL,
                     timestamp_utc="2026-06-08T00:00:00+00:00"):
    """Build and sign a receipt with the conftest issuer key."""
    if interaction is None:
        interaction = _normalized_interaction()
    env = build_envelope(
        policy_pin=ManifestPolicy().pin(),
        decision="ELIGIBLE",
        target_url=target_url,
        normalized_interaction=interaction,
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


def _make_target(gate_signing, target_url=TARGET_URL, serve_bytes=None, replay_cache=None):
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
    app = build_reference_target_app(
        config_provider=lambda: config,
        fetch=_fetch_via(_publisher_client(serve_bytes)),
        replay_cache=replay_cache,
    )
    return app, TestClient(app)


def _post(client, interaction, envelope=None):
    headers = {}
    if envelope is not None:
        headers["X-Gargoyle-Envelope"] = canonical_json(envelope)
    return client.post("/target", json=interaction, headers=headers)


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
    env["request_context"]["AP"] = ["identity", "role", "admin"]  # tamper post-sign
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
    interaction_x = _normalized_interaction(ap=["identity", "role"])
    env = _signed_envelope(gate_signing, interaction=interaction_x)
    interaction_y = _normalized_interaction(ap=["identity", "role", "admin"])
    resp = _post(client, interaction_y, env)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_BINDING_MISMATCH
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
    resp = client.post("/target", json=interaction,
                       headers=[("X-Gargoyle-Envelope", body), ("X-Gargoyle-Envelope", body)])
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == REF_VERIFY_ENVELOPE_ABSENT
    assert app.state.received == []
